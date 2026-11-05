//! Artifact inspection: what an artifact is, and exactly which bytes it
//! contains.
//!
//! [`inspect_path`] describes a regular file or a directory tree, and
//! [`inspect_reader`] describes a stream such as standard input. Digests are
//! computed in a single streaming pass through a fixed-size buffer.
//!
//! An inspection is **not a verification**. It establishes which bytes were
//! read; it compares them with nothing and says nothing about who produced
//! them or whether they are safe.
//!
//! The rules for directories, and the checks that detect concurrent
//! modification, are described in `docs/architecture.md` ("Directory
//! traversal rules"). Any error aborts the whole inspection: there are no
//! partial results.

use std::fmt;
use std::io::{self, Read};
use std::path::Path;

use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::digest::{
    AlgorithmSet, DigestAlgorithm, DigestSet, MultiHasher, READ_BUFFER_SIZE, read_chunk,
};
use crate::format::{FileFormat, HEAD_LEN, detect_format};
use crate::name::{EscapedBytes, NameError, RelPath};

mod time;

#[cfg(not(unix))]
mod portable;
#[cfg(unix)]
mod tree;
#[cfg(unix)]
mod unix;

/// Resource limits for one inspection. Exceeding a limit is an error: nothing
/// is ever silently truncated.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Content bytes read: the file, the stream, or all regular files of a
    /// tree together. Default: 64 GiB.
    pub max_bytes: u64,
    /// Entries of a tree, not counting its root. Default: 1,000,000.
    pub max_entries: u64,
    /// Path components of a tree entry (`a/b/c` has three). Default: 128.
    pub max_depth: u32,
    /// Total length in bytes of all entries' relative paths, which bounds
    /// the memory used by a listing. Default: 256 MiB.
    pub max_path_bytes: u64,
    /// Length of a symlink target in bytes. Default: 4,096. Values above
    /// 65,536 act as 65,536, which exceeds every common operating system's
    /// own limit.
    pub max_symlink_target_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 30,
            max_entries: 1_000_000,
            max_depth: 128,
            max_path_bytes: 256 << 20,
            max_symlink_target_len: 4096,
        }
    }
}

/// Options for one inspection.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InspectOptions {
    /// The digest algorithms to compute. Default: all.
    pub algorithms: AlgorithmSet,
    /// Resource limits.
    pub limits: Limits,
}

/// What kind of artifact was inspected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    /// A regular file.
    File,
    /// A directory tree.
    Directory,
    /// A stream, such as standard input.
    Stream,
}

/// The digests of an artifact. Content digests and tree digests are
/// different things and can never stand in for each other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactDigests {
    /// Digests of the bytes of a file or stream.
    Content(DigestSet),
    /// Digests of a directory tree's NAR serialization, published under the
    /// keys `narBlake3`, `narSha256` and `narSha512`.
    Tree(DigestSet),
}

/// One entry of a directory tree.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TreeEntry {
    path: RelPath,
    #[serde(flatten)]
    kind: EntryKind,
}

impl TreeEntry {
    /// The entry's path relative to the tree's root.
    pub fn path(&self) -> &RelPath {
        &self.path
    }

    /// What the entry is.
    pub fn kind(&self) -> &EntryKind {
        &self.kind
    }
}

/// What a tree entry is.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum EntryKind {
    /// A regular file.
    File {
        /// Whether the owner-execute permission bit is set: the only
        /// permission bit any digest covers.
        executable: bool,
        /// Size in bytes.
        size: u64,
        /// Digests of the file's contents.
        digest: DigestSet,
    },
    /// A directory. Its entries follow it.
    Directory,
    /// A symbolic link, which is recorded and never followed.
    Symlink {
        /// The link's target text.
        target: String,
        /// Whether the target is absolute or climbs above the tree's root
        /// with `..`. Computed from the text alone, for information.
        target_leaves_tree: bool,
    },
}

/// Number of entries of each kind in a tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct EntryCounts {
    /// Directories, not counting the root.
    pub directories: u64,
    /// Regular files.
    pub files: u64,
    /// Symbolic links.
    pub symlinks: u64,
}

/// File-system metadata of the inspected path. It is reported for
/// information only: it is not covered by any digest, and it can differ
/// between copies of the same artifact.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UntrustedMetadata {
    /// Unix permission bits, including setuid, setgid and sticky
    /// (`st_mode & 0o7777`). `None` on other platforms.
    pub mode: Option<u32>,
    /// Modification time in seconds since the Unix epoch.
    pub modified_unix_seconds: Option<i64>,
}

impl UntrustedMetadata {
    /// The modification time as an RFC 3339 UTC timestamp, such as
    /// `2026-11-05T09:30:00Z`, for years 0000 through 9999.
    pub fn modified_rfc3339(&self) -> Option<String> {
        time::rfc3339_utc(self.modified_unix_seconds?)
    }
}

/// The result of inspecting an artifact.
///
/// Serializes (for example to JSON) with only what is derived from the
/// artifact's content and structure, plus the name it was given. File-system
/// metadata is left out, so identical artifacts serialize identically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    name: String,
    kind: ArtifactKind,
    size: u64,
    digests: ArtifactDigests,
    format: Option<FileFormat>,
    tree: Option<(Vec<TreeEntry>, EntryCounts)>,
    root_symlink_followed: bool,
    untrusted: Option<UntrustedMetadata>,
}

impl Inspection {
    /// The artifact's name as given: the path argument, never canonicalized.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What kind of artifact this is.
    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Size in bytes; for a directory, the total size of its regular files.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Content digests for a file or stream, tree digests for a directory.
    pub fn digests(&self) -> &ArtifactDigests {
        &self.digests
    }

    /// The format detected from a file's or stream's header bytes.
    pub fn format(&self) -> Option<&FileFormat> {
        self.format.as_ref()
    }

    /// A directory's entries, depth-first with siblings in ascending byte
    /// order of their names: the order of the NAR serialization.
    pub fn entries(&self) -> Option<&[TreeEntry]> {
        self.tree.as_ref().map(|(entries, _)| entries.as_slice())
    }

    /// A directory's entry counts.
    pub fn counts(&self) -> Option<&EntryCounts> {
        self.tree.as_ref().map(|(_, counts)| counts)
    }

    /// Whether the given path was a symbolic link, followed once to reach
    /// the artifact.
    pub fn root_symlink_followed(&self) -> bool {
        self.root_symlink_followed
    }

    /// File-system metadata of the inspected path, if it is a path.
    pub fn untrusted_metadata(&self) -> Option<&UntrustedMetadata> {
        self.untrusted.as_ref()
    }
}

/// Serializes tree digests under the `nar…` keys.
struct TreeKeys<'a>(&'a DigestSet);

impl Serialize for TreeKeys<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .serialize_with_keys(DigestAlgorithm::tree_name, serializer)
    }
}

impl Serialize for Inspection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("Inspection", 8)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("kind", &self.kind)?;
        s.serialize_field("size", &self.size)?;
        s.serialize_field("rootSymlinkFollowed", &self.root_symlink_followed)?;
        match &self.digests {
            ArtifactDigests::Content(digests) => s.serialize_field("digest", digests)?,
            ArtifactDigests::Tree(digests) => {
                s.serialize_field("treeDigest", &TreeKeys(digests))?
            }
        }
        if let Some(format) = &self.format {
            s.serialize_field("format", format)?;
        }
        if let Some((entries, counts)) = &self.tree {
            s.serialize_field("counts", counts)?;
            s.serialize_field("entries", entries)?;
        }
        s.end()
    }
}

/// Which limit was exceeded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// [`Limits::max_bytes`].
    Bytes,
    /// [`Limits::max_entries`].
    Entries,
    /// [`Limits::max_depth`].
    Depth,
    /// [`Limits::max_path_bytes`].
    PathBytes,
    /// [`Limits::max_symlink_target_len`].
    SymlinkTargetLength,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bytes => "content bytes",
            Self::Entries => "entries",
            Self::Depth => "levels of nesting",
            Self::PathBytes => "bytes of entry paths",
            Self::SymlinkTargetLength => "bytes of symlink target",
        })
    }
}

/// The location of an error: the path as given, and the entry inside a tree.
/// Displayed with control characters, bidi controls and invalid UTF-8
/// escaped.
#[derive(Clone, PartialEq, Eq)]
pub struct ErrorPath {
    root: Vec<u8>,
    entry: Vec<u8>,
}

impl ErrorPath {
    pub(crate) fn root(path: &Path) -> Self {
        Self {
            root: path_bytes(path),
            entry: Vec::new(),
        }
    }

    pub(crate) fn stream(name: &str) -> Self {
        Self {
            root: name.as_bytes().to_vec(),
            entry: Vec::new(),
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn entry(root: &Path, entry: &RelPath) -> Self {
        Self {
            root: path_bytes(root),
            entry: entry.as_str().as_bytes().to_vec(),
        }
    }

    /// An entry whose name may be invalid, inside `parent`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn raw_entry(root: &Path, parent: Option<&RelPath>, name: &[u8]) -> Self {
        let mut entry = parent
            .map(|p| format!("{p}/").into_bytes())
            .unwrap_or_default();
        entry.extend_from_slice(name);
        Self {
            root: path_bytes(root),
            entry,
        }
    }
}

impl fmt::Display for ErrorPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EscapedBytes(&self.root))?;
        if !self.entry.is_empty() {
            if !self.root.ends_with(b"/") {
                f.write_str("/")?;
            }
            write!(f, "{}", EscapedBytes(&self.entry))?;
        }
        Ok(())
    }
}

impl fmt::Debug for ErrorPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    // Only used for display; escaping keeps the result unambiguous enough.
    path.to_string_lossy().into_owned().into_bytes()
}

/// Why an inspection failed. Every variant names the path involved.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    /// The operating system reported an error.
    #[error("{path}: {source}")]
    Io {
        /// Where.
        path: ErrorPath,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// Not a regular file, directory or symlink: FIFOs, sockets and device
    /// nodes are never opened or read.
    #[error(
        "{path}: is a {kind}; only regular files, directories and symbolic links inside directories are inspected"
    )]
    UnsupportedFileType {
        /// Where.
        path: ErrorPath,
        /// What was found.
        kind: &'static str,
    },
    /// A name that cannot be represented exactly and displayed safely.
    #[error("{path}: invalid name: {reason}")]
    InvalidName {
        /// Where.
        path: ErrorPath,
        /// Which rule it breaks.
        reason: NameError,
    },
    /// A symlink target that cannot be represented exactly and displayed
    /// safely.
    #[error("{path}: invalid symbolic link target: {reason}")]
    InvalidSymlinkTarget {
        /// Where.
        path: ErrorPath,
        /// Which rule it breaks.
        reason: NameError,
    },
    /// The file system listed the same name twice in one directory.
    #[error("{path}: the directory lists this name more than once")]
    DuplicateEntry {
        /// Where.
        path: ErrorPath,
    },
    /// The artifact changed while it was being inspected, or reported
    /// inconsistent metadata.
    #[error("{path}: changed while being inspected ({detail})")]
    ConcurrentModification {
        /// Where.
        path: ErrorPath,
        /// What was observed.
        detail: &'static str,
    },
    /// A directory on a different file system than its parent.
    #[error("{path}: is a mount point; inspection does not cross into other file systems")]
    MountPoint {
        /// Where.
        path: ErrorPath,
    },
    /// A directory that is the same directory as one of its ancestors.
    #[error("{path}: is the same directory as one of its ancestors")]
    DirectoryCycle {
        /// Where.
        path: ErrorPath,
    },
    /// A resource limit was exceeded.
    #[error("{path}: more than {max} {limit}")]
    LimitExceeded {
        /// Where.
        path: ErrorPath,
        /// Which limit.
        limit: Limit,
        /// The limit's value.
        max: u64,
    },
    /// Not supported on this platform.
    #[error("{path}: {what} is not supported on this platform")]
    Unsupported {
        /// Where.
        path: ErrorPath,
        /// What is unsupported.
        what: &'static str,
    },
}

/// Inspects the file or directory at `path`.
///
/// If `path` is a symbolic link, it is followed once and the result says so.
/// Below a directory's root, symbolic links are recorded and never followed.
/// Directory inspection is supported on Unix only: other platforms have no
/// executable bit, which tree digests cover.
pub fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<Inspection, InspectError> {
    #[cfg(unix)]
    return unix::inspect_path(path, opts);
    #[cfg(not(unix))]
    return portable::inspect_path(path, opts);
}

/// Inspects everything `reader` yields, as a stream named `name`.
pub fn inspect_reader(
    name: &str,
    mut reader: impl Read,
    opts: &InspectOptions,
) -> Result<Inspection, InspectError> {
    let io_err = |source| InspectError::Io {
        path: ErrorPath::stream(name),
        source,
    };
    let mut hasher = MultiHasher::new(&opts.algorithms);
    let mut head = Head::default();
    let mut buf = vec![0; READ_BUFFER_SIZE];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        };
        let chunk = read_chunk(&buf, n).map_err(io_err)?;
        if hasher.bytes_hashed().saturating_add(chunk.len() as u64) > opts.limits.max_bytes {
            return Err(InspectError::LimitExceeded {
                path: ErrorPath::stream(name),
                limit: Limit::Bytes,
                max: opts.limits.max_bytes,
            });
        }
        head.push(chunk);
        hasher.update(chunk);
    }
    Ok(Inspection {
        name: name.to_owned(),
        kind: ArtifactKind::Stream,
        size: hasher.bytes_hashed(),
        digests: ArtifactDigests::Content(hasher.finalize()),
        format: Some(detect_format(&head.0)),
        tree: None,
        root_symlink_followed: false,
        untrusted: None,
    })
}

/// The first [`HEAD_LEN`] bytes of a file, captured while it is hashed.
#[derive(Default)]
pub(crate) struct Head(Vec<u8>);

impl Head {
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        let room = HEAD_LEN.saturating_sub(self.0.len());
        self.0.extend_from_slice(&chunk[..room.min(chunk.len())]);
    }
}

/// Why reading a file of known length failed.
#[derive(Debug)]
pub(crate) enum ExactReadError {
    Io(io::Error),
    /// The file ended before its reported length.
    Shorter,
    /// The file continues after its reported length.
    Longer,
}

/// Reads exactly `len` bytes from `reader`, passing them to `sink`, then
/// checks that the reader is at its end. Never reads more than one byte past
/// `len`.
pub(crate) fn read_exact_len<R: Read>(
    reader: &mut R,
    len: u64,
    buf: &mut [u8],
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<(), ExactReadError> {
    let mut remaining = len;
    while remaining > 0 {
        let want = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let window = &mut buf[..want];
        let n = match reader.read(window) {
            Ok(0) => return Err(ExactReadError::Shorter),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExactReadError::Io(e)),
        };
        let chunk = read_chunk(window, n).map_err(ExactReadError::Io)?;
        sink(chunk).map_err(ExactReadError::Io)?;
        remaining -= chunk.len() as u64;
    }
    let mut probe = [0; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(ExactReadError::Longer),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ExactReadError::Io(e)),
        }
    }
}

impl ExactReadError {
    pub(crate) fn into_inspect_error(self, path: ErrorPath) -> InspectError {
        match self {
            Self::Io(source) => InspectError::Io { path, source },
            Self::Shorter => InspectError::ConcurrentModification {
                path,
                detail: "it ended before its reported size",
            },
            Self::Longer => InspectError::ConcurrentModification {
                path,
                detail: "it holds more data than its reported size",
            },
        }
    }
}

/// Checks a file's reported size against [`Limits::max_bytes`] before any of
/// it is read, given `already` bytes charged so far.
pub(crate) fn charge_bytes(
    already: u64,
    size: u64,
    limits: &Limits,
    path: impl FnOnce() -> ErrorPath,
) -> Result<u64, InspectError> {
    match already.checked_add(size) {
        Some(total) if total <= limits.max_bytes => Ok(total),
        _ => Err(InspectError::LimitExceeded {
            path: path(),
            limit: Limit::Bytes,
            max: limits.max_bytes,
        }),
    }
}

/// Inspects an already opened regular file of reported length `len`,
/// reading it exactly once.
pub(crate) fn hash_file<R: Read>(
    file: &mut R,
    len: u64,
    opts: &InspectOptions,
    path: impl Fn() -> ErrorPath,
) -> Result<(DigestSet, FileFormat), InspectError> {
    charge_bytes(0, len, &opts.limits, &path)?;
    let mut hasher = MultiHasher::new(&opts.algorithms);
    let mut head = Head::default();
    let mut buf = vec![0; READ_BUFFER_SIZE];
    read_exact_len(file, len, &mut buf, |chunk| {
        head.push(chunk);
        hasher.update(chunk);
        Ok(())
    })
    .map_err(|e| e.into_inspect_error(path()))?;
    Ok((hasher.finalize(), detect_format(&head.0)))
}

impl Inspection {
    pub(crate) fn file(
        name: String,
        size: u64,
        digests: DigestSet,
        format: FileFormat,
        root_symlink_followed: bool,
        untrusted: UntrustedMetadata,
    ) -> Self {
        Self {
            name,
            kind: ArtifactKind::File,
            size,
            digests: ArtifactDigests::Content(digests),
            format: Some(format),
            tree: None,
            root_symlink_followed,
            untrusted: Some(untrusted),
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn directory(
        name: String,
        size: u64,
        digests: DigestSet,
        entries: Vec<TreeEntry>,
        counts: EntryCounts,
        root_symlink_followed: bool,
        untrusted: UntrustedMetadata,
    ) -> Self {
        Self {
            name,
            kind: ArtifactKind::Directory,
            size,
            digests: ArtifactDigests::Tree(digests),
            format: None,
            tree: Some((entries, counts)),
            root_symlink_followed,
            untrusted: Some(untrusted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_reads_detect_short_and_long_files() {
        let mut buf = [0; 4];
        let mut seen = Vec::new();
        let mut sink = |c: &[u8]| {
            seen.extend_from_slice(c);
            Ok(())
        };
        read_exact_len(&mut &b"abcdefghij"[..], 10, &mut buf, &mut sink).unwrap();
        assert_eq!(seen, b"abcdefghij");
        assert!(matches!(
            read_exact_len(&mut &b"abc"[..], 4, &mut buf, |_| Ok(())),
            Err(ExactReadError::Shorter)
        ));
        assert!(matches!(
            read_exact_len(&mut &b"abcde"[..], 4, &mut buf, |_| Ok(())),
            Err(ExactReadError::Longer)
        ));
        read_exact_len(&mut &b""[..], 0, &mut buf, |_| Ok(())).unwrap();
        assert!(matches!(
            read_exact_len(&mut &b"x"[..], 0, &mut buf, |_| Ok(())),
            Err(ExactReadError::Longer)
        ));
    }

    #[test]
    fn the_head_keeps_only_the_first_bytes() {
        let mut head = Head::default();
        head.push(&[1; 3000]);
        head.push(&[2; 3000]);
        assert_eq!(head.0.len(), HEAD_LEN);
        assert_eq!(head.0[2999..3001], [1, 2]);
        head.push(&[3; 10]);
        assert_eq!(head.0.len(), HEAD_LEN);
    }

    #[test]
    fn streams_are_hashed_and_limited() {
        let opts = InspectOptions::default();
        let inspection = inspect_reader("-", &b"abc"[..], &opts).unwrap();
        assert_eq!(inspection.kind(), ArtifactKind::Stream);
        assert_eq!(inspection.size(), 3);
        let ArtifactDigests::Content(digests) = inspection.digests() else {
            panic!("stream digests are content digests")
        };
        assert_eq!(
            digests.get(DigestAlgorithm::Sha256).unwrap().to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(inspection.format(), Some(&FileFormat::Unknown));
        assert!(inspection.untrusted_metadata().is_none());

        let mut small = InspectOptions::default();
        small.limits.max_bytes = 2;
        assert!(matches!(
            inspect_reader("-", &b"abc"[..], &small),
            Err(InspectError::LimitExceeded {
                limit: Limit::Bytes,
                max: 2,
                ..
            })
        ));
        assert!(inspect_reader("-", &b"ab"[..], &small).is_ok());
    }

    #[test]
    fn error_paths_escape_hostile_bytes() {
        let path = ErrorPath::raw_entry(
            Path::new("dist/"),
            Some(&RelPath::child(None, "sub")),
            b"x\x1b[2J\xff",
        );
        assert_eq!(path.to_string(), r"dist/sub/x\u{1b}[2J\xff");
        let err = InspectError::InvalidName {
            path,
            reason: NameError::InvalidUtf8,
        };
        assert!(!err.to_string().contains('\u{1b}'));
    }
}
