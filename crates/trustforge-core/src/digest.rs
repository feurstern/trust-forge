//! Digest algorithms and streaming multi-algorithm hashing.
//!
//! TrustForge accepts a closed set of algorithms (SHA-256, SHA-512 and
//! BLAKE3). There is deliberately no extension point: an open hasher trait
//! would let weak algorithms in (`docs/architecture.md`, decision 4). Every
//! selected algorithm is fed from the same pass over the input, so each byte
//! is read once however many digests are computed.
//!
//! A digest identifies bytes. It says nothing about who produced them or
//! whether they are safe.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::str::FromStr;

use serde::ser::{Serialize, SerializeMap, Serializer};
use sha2::Digest as _;

use crate::name::EscapedBytes;

/// Size of the buffer that streams input into the hashers. BLAKE3 needs at
/// least 16 KiB per call to use every SIMD instruction set it supports.
pub(crate) const READ_BUFFER_SIZE: usize = 128 * 1024;

/// A digest algorithm accepted by TrustForge.
///
/// Variants are declared in the order of their names, so ordered collections
/// list them as `blake3`, `sha256`, `sha512`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    /// BLAKE3 with its default 32-byte output.
    Blake3,
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-512 (FIPS 180-4).
    Sha512,
}

impl DigestAlgorithm {
    /// Every accepted algorithm, in name order.
    pub const ALL: [DigestAlgorithm; 3] = [Self::Blake3, Self::Sha256, Self::Sha512];

    /// The algorithm's name as used in in-toto digest sets: `blake3`,
    /// `sha256` or `sha512`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest-set key for a directory tree digest computed with this
    /// algorithm over the tree's NAR serialization: `narBlake3`,
    /// `narSha256` or `narSha512`.
    pub const fn tree_name(self) -> &'static str {
        match self {
            Self::Blake3 => "narBlake3",
            Self::Sha256 => "narSha256",
            Self::Sha512 => "narSha512",
        }
    }

    /// Length of the digest in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = DigestError;

    /// Parses an exact, lowercase algorithm name. `md5` and `sha1` are
    /// recognized and rejected as insecure.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "md5" | "sha1" => Err(DigestError::InsecureAlgorithm { name: s.to_owned() }),
            _ => Err(DigestError::UnknownAlgorithm { name: s.to_owned() }),
        }
    }
}

/// Errors from the digest module.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// The algorithm is known to be broken and is never accepted.
    #[error("digest algorithm \"{shown}\" is insecure and not accepted", shown = EscapedBytes(.name.as_bytes()))]
    InsecureAlgorithm {
        /// The rejected name.
        name: String,
    },
    /// The algorithm name is not one TrustForge accepts.
    #[error("unknown digest algorithm \"{shown}\" (accepted: blake3, sha256, sha512)", shown = EscapedBytes(.name.as_bytes()))]
    UnknownAlgorithm {
        /// The rejected name.
        name: String,
    },
    /// An algorithm set must contain at least one algorithm.
    #[error("no digest algorithm selected")]
    EmptyAlgorithmSet,
}

/// A non-empty set of digest algorithms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmSet(BTreeSet<DigestAlgorithm>);

impl AlgorithmSet {
    /// Every accepted algorithm.
    pub fn all() -> Self {
        Self(DigestAlgorithm::ALL.into_iter().collect())
    }

    /// Builds a set from the given algorithms. Duplicates are ignored. An
    /// empty input is an error.
    pub fn new(algorithms: impl IntoIterator<Item = DigestAlgorithm>) -> Result<Self, DigestError> {
        let set: BTreeSet<_> = algorithms.into_iter().collect();
        if set.is_empty() {
            return Err(DigestError::EmptyAlgorithmSet);
        }
        Ok(Self(set))
    }

    /// Whether the set contains `algorithm`.
    pub fn contains(&self, algorithm: DigestAlgorithm) -> bool {
        self.0.contains(&algorithm)
    }

    /// The algorithms in name order.
    pub fn iter(&self) -> impl Iterator<Item = DigestAlgorithm> + '_ {
        self.0.iter().copied()
    }
}

impl Default for AlgorithmSet {
    fn default() -> Self {
        Self::all()
    }
}

/// A digest: an algorithm and its output. The length of the output always
/// matches the algorithm.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    bytes: Box<[u8]>,
}

impl Digest {
    /// The algorithm that produced this digest.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The digest as lowercase hexadecimal, as used in in-toto digest sets.
    pub fn to_hex(&self) -> String {
        to_hex(&self.bytes)
    }
}

/// Shows `<algorithm>:<hex>`, for example `sha256:e3b0…`.
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Digests of the same bytes under one or more algorithms. Never empty.
///
/// Serializes as a JSON object mapping each algorithm's [name] to its
/// lowercase hex digest, in name order.
///
/// [name]: DigestAlgorithm::name
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestSet(BTreeMap<DigestAlgorithm, Digest>);

impl DigestSet {
    /// The digest for `algorithm`, if it was computed.
    pub fn get(&self, algorithm: DigestAlgorithm) -> Option<&Digest> {
        self.0.get(&algorithm)
    }

    /// The digests in algorithm name order.
    pub fn iter(&self) -> impl Iterator<Item = &Digest> {
        self.0.values()
    }

    /// Serializes the set with `key` naming each algorithm.
    pub(crate) fn serialize_with_keys<S: Serializer>(
        &self,
        key: fn(DigestAlgorithm) -> &'static str,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for digest in self.0.values() {
            map.serialize_entry(key(digest.algorithm), &digest.to_hex())?;
        }
        map.end()
    }
}

impl Serialize for DigestSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize_with_keys(DigestAlgorithm::name, serializer)
    }
}

/// Feeds the same bytes to every selected algorithm in a single pass.
pub struct MultiHasher {
    blake3: Option<Box<blake3::Hasher>>,
    sha256: Option<sha2::Sha256>,
    sha512: Option<sha2::Sha512>,
    bytes: u64,
}

impl MultiHasher {
    /// Starts hashing with every algorithm in `algorithms`.
    pub fn new(algorithms: &AlgorithmSet) -> Self {
        Self {
            blake3: algorithms
                .contains(DigestAlgorithm::Blake3)
                .then(|| Box::new(blake3::Hasher::new())),
            sha256: algorithms
                .contains(DigestAlgorithm::Sha256)
                .then(sha2::Sha256::new),
            sha512: algorithms
                .contains(DigestAlgorithm::Sha512)
                .then(sha2::Sha512::new),
            bytes: 0,
        }
    }

    /// Hashes `data` with every selected algorithm.
    pub fn update(&mut self, data: &[u8]) {
        if let Some(h) = &mut self.blake3 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha512 {
            h.update(data);
        }
        self.bytes = self.bytes.saturating_add(data.len() as u64);
    }

    /// Number of bytes hashed so far.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes
    }

    /// Finishes hashing and returns one digest per selected algorithm.
    pub fn finalize(self) -> DigestSet {
        let mut set = BTreeMap::new();
        let mut put = |algorithm, bytes: &[u8]| {
            set.insert(
                algorithm,
                Digest {
                    algorithm,
                    bytes: bytes.into(),
                },
            );
        };
        if let Some(h) = self.blake3 {
            put(DigestAlgorithm::Blake3, h.finalize().as_bytes());
        }
        if let Some(h) = self.sha256 {
            put(DigestAlgorithm::Sha256, h.finalize().as_ref());
        }
        if let Some(h) = self.sha512 {
            put(DigestAlgorithm::Sha512, h.finalize().as_ref());
        }
        DigestSet(set)
    }
}

impl fmt::Debug for MultiHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiHasher")
            .field("blake3", &self.blake3.is_some())
            .field("sha256", &self.sha256.is_some())
            .field("sha512", &self.sha512.is_some())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Write for MultiHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The digests of everything read from a reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashOutput {
    /// One digest per selected algorithm.
    pub digests: DigestSet,
    /// Number of bytes read and hashed.
    pub bytes: u64,
}

/// Reads `reader` to the end and hashes everything with `algorithms`,
/// through a fixed-size buffer: memory use does not depend on input size.
pub fn hash_reader(mut reader: impl Read, algorithms: &AlgorithmSet) -> io::Result<HashOutput> {
    let mut hasher = MultiHasher::new(algorithms);
    let mut buf = vec![0; READ_BUFFER_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(read_chunk(&buf, n)?);
    }
    Ok(HashOutput {
        bytes: hasher.bytes_hashed(),
        digests: hasher.finalize(),
    })
}

/// The first `n` bytes of `buf`, or an error for a reader that claims to have
/// read more than it was given room for.
pub(crate) fn read_chunk(buf: &[u8], n: usize) -> io::Result<&[u8]> {
    buf.get(..n).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "reader returned more bytes than requested",
        )
    })
}

/// Lowercase hexadecimal encoding.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn names_round_trip_and_sort_by_name() {
        for algorithm in DigestAlgorithm::ALL {
            assert_eq!(algorithm.name().parse::<DigestAlgorithm>(), Ok(algorithm));
            assert_eq!(algorithm.to_string(), algorithm.name());
        }
        let names: Vec<_> = DigestAlgorithm::ALL.iter().map(|a| a.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "declaration order must be name order");
        let tree: Vec<_> = DigestAlgorithm::ALL.iter().map(|a| a.tree_name()).collect();
        assert_eq!(tree, ["narBlake3", "narSha256", "narSha512"]);
    }

    #[test]
    fn insecure_and_unknown_names_are_rejected() {
        for name in ["md5", "sha1"] {
            assert!(matches!(
                name.parse::<DigestAlgorithm>(),
                Err(DigestError::InsecureAlgorithm { .. })
            ));
        }
        // Parsing is exact: no case folding, no trimming, no aliases.
        for name in [
            "SHA256", "Sha256", " sha256", "sha-256", "sha384", "", "blake2b",
        ] {
            assert!(matches!(
                name.parse::<DigestAlgorithm>(),
                Err(DigestError::UnknownAlgorithm { .. })
            ));
        }
    }

    #[test]
    fn error_messages_escape_hostile_names() {
        let err = "\u{1b}[31mred\u{202e}"
            .parse::<DigestAlgorithm>()
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains('\u{1b}') && !msg.contains('\u{202e}'),
            "{msg}"
        );
        assert!(msg.contains(r"\u{1b}[31mred\u{202e}"), "{msg}");
    }

    #[test]
    fn algorithm_sets_are_never_empty() {
        assert_eq!(AlgorithmSet::new([]), Err(DigestError::EmptyAlgorithmSet));
        let set = AlgorithmSet::new([DigestAlgorithm::Sha512, DigestAlgorithm::Sha512]).unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), [DigestAlgorithm::Sha512]);
        assert_eq!(AlgorithmSet::default(), AlgorithmSet::all());
    }

    #[test]
    fn digests_have_the_algorithm_length_and_lowercase_hex() {
        let mut hasher = MultiHasher::new(&AlgorithmSet::all());
        hasher.update(b"abc");
        let set = hasher.finalize();
        for algorithm in DigestAlgorithm::ALL {
            let digest = set.get(algorithm).unwrap();
            assert_eq!(digest.algorithm(), algorithm);
            assert_eq!(digest.as_bytes().len(), algorithm.output_len());
            let hex = digest.to_hex();
            assert_eq!(hex.len(), 2 * algorithm.output_len());
            assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        }
        assert_eq!(
            set.get(DigestAlgorithm::Sha256).unwrap().to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn only_selected_algorithms_are_computed() {
        let set = AlgorithmSet::new([DigestAlgorithm::Blake3]).unwrap();
        let digests = MultiHasher::new(&set).finalize();
        assert_eq!(digests.iter().count(), 1);
        assert!(digests.get(DigestAlgorithm::Sha256).is_none());
    }

    #[test]
    fn digest_sets_serialize_in_name_order() {
        let mut hasher = MultiHasher::new(&AlgorithmSet::all());
        hasher.update(b"");
        let json = serde_json::to_string(&hasher.finalize()).unwrap();
        let keys: Vec<_> = ["\"blake3\"", "\"sha256\"", "\"sha512\""]
            .iter()
            .map(|k| json.find(k).unwrap())
            .collect();
        assert!(keys.is_sorted(), "{json}");
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(to_hex(&[]), "");
        assert_eq!(to_hex(&[0x00, 0x0f, 0xf0, 0xff, 0x5a]), "000ff0ff5a");
    }

    /// A reader that returns at most `step` bytes per call and an
    /// `Interrupted` error before every successful read.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
        interrupt: bool,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn hash_reader_retries_interrupts_and_counts_bytes() {
        let data = vec![7u8; 1000];
        let reader = Trickle {
            data: &data,
            step: 3,
            interrupt: false,
        };
        let out = hash_reader(reader, &AlgorithmSet::all()).unwrap();
        assert_eq!(out.bytes, 1000);
        let mut direct = MultiHasher::new(&AlgorithmSet::all());
        direct.update(&data);
        assert_eq!(out.digests, direct.finalize());
    }

    #[test]
    fn hash_reader_rejects_readers_that_overreport() {
        struct Liar;
        impl Read for Liar {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                Ok(buf.len() + 1)
            }
        }
        let err = hash_reader(Liar, &AlgorithmSet::all()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    proptest! {
        /// Streaming is independent of chunk boundaries, and one pass over
        /// several algorithms equals each algorithm computed on its own.
        #[test]
        fn chunking_and_combination_do_not_change_digests(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
            cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
        ) {
            let mut one_shot = MultiHasher::new(&AlgorithmSet::all());
            one_shot.update(&data);
            let one_shot = one_shot.finalize();

            let mut points: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            points.sort_unstable();
            let mut chunked = MultiHasher::new(&AlgorithmSet::all());
            let mut start = 0;
            for end in points.into_iter().chain([data.len()]) {
                chunked.update(&data[start..end]);
                start = end;
            }
            prop_assert_eq!(chunked.bytes_hashed(), data.len() as u64);
            prop_assert_eq!(&chunked.finalize(), &one_shot);

            for algorithm in DigestAlgorithm::ALL {
                let mut alone = MultiHasher::new(&AlgorithmSet::new([algorithm]).unwrap());
                alone.update(&data);
                let alone = alone.finalize();
                prop_assert_eq!(alone.get(algorithm), one_shot.get(algorithm));
            }
        }
    }
}
