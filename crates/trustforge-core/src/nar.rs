//! The NAR (Nix Archive) serialization of a file tree.
//!
//! A directory's tree digest is the hash of its NAR serialization
//! (`docs/manifest-spec.md`, "Tree digests"). The format is the one
//! `nix-store --dump` produces:
//!
//! ```text
//! nar       = str("nix-archive-1") node
//! node      = str("(") str("type") (regular | symlink | directory) str(")")
//! regular   = str("regular") [str("executable") str("")] str("contents") u64(n) bytes(n) pad(n)
//! symlink   = str("symlink") str("target") str(target)
//! directory = str("directory") { str("entry") str("(") str("name") str(name) str("node") node str(")") }
//! str(s)    = u64(len(s)) s pad(len(s))
//! ```
//!
//! `u64` is little-endian, and `pad(n)` is zero bytes up to the next multiple
//! of eight. Directory entries appear in ascending unsigned byte order of
//! their names. A regular file is `executable` when its owner-execute bit
//! (`S_IXUSR`) is set, exactly as in Nix.
//!
//! [`NarWriter`] is a state machine that enforces this framing: a regular
//! file accepts exactly the number of content bytes it declared, and entry
//! names must strictly increase. If a file shrank after its length was
//! written, the bytes that follow could otherwise be read back as file
//! content, and the stream could equal the valid serialization of a
//! different tree.

use std::io::{self, Write};

const MAGIC: &[u8] = b"nix-archive-1";

#[derive(Debug)]
enum State {
    /// A node is expected: the root, or the node of an entry just opened.
    Node,
    /// Inside a regular file's contents.
    Contents { remaining: u64, len: u64 },
    /// Inside a directory, between entries.
    Directory,
    /// The root node is complete.
    Done,
}

/// Writes a NAR serialization into `W`, without buffering it.
pub(crate) struct NarWriter<W: Write> {
    out: W,
    state: State,
    /// For each open directory, the name of its last entry.
    dirs: Vec<Option<Vec<u8>>>,
}

fn framing_error(msg: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("NAR framing violated: {msg}"),
    )
}

fn padding(len: u64) -> usize {
    // At most 7.
    (8 - (len % 8) as usize) % 8
}

impl<W: Write> NarWriter<W> {
    /// Starts a NAR by writing its magic string.
    pub(crate) fn new(out: W) -> io::Result<Self> {
        let mut nar = Self {
            out,
            state: State::Node,
            dirs: Vec::new(),
        };
        nar.str(MAGIC)?;
        Ok(nar)
    }

    fn str(&mut self, s: &[u8]) -> io::Result<()> {
        let len = s.len() as u64;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(s)?;
        self.out.write_all(&[0; 8][..padding(len)])
    }

    fn strs(&mut self, strs: &[&[u8]]) -> io::Result<()> {
        strs.iter().try_for_each(|s| self.str(s))
    }

    fn expect_node(&self) -> io::Result<()> {
        match self.state {
            State::Node => Ok(()),
            _ => Err(framing_error("a node is not expected here")),
        }
    }

    /// A node has been closed: close the entry around it, if any.
    fn node_done(&mut self) -> io::Result<()> {
        if self.dirs.is_empty() {
            self.state = State::Done;
            Ok(())
        } else {
            self.state = State::Directory;
            self.str(b")")
        }
    }

    /// Opens a directory node. Its entries follow, then [`Self::end_directory`].
    pub(crate) fn begin_directory(&mut self) -> io::Result<()> {
        self.expect_node()?;
        self.strs(&[b"(", b"type", b"directory"])?;
        self.dirs.push(None);
        self.state = State::Directory;
        Ok(())
    }

    /// Opens an entry of the current directory. Its node must follow.
    pub(crate) fn begin_entry(&mut self, name: &[u8]) -> io::Result<()> {
        if !matches!(self.state, State::Directory) {
            return Err(framing_error("an entry is only allowed inside a directory"));
        }
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.contains(&0)
        {
            return Err(framing_error("invalid entry name"));
        }
        let Some(last) = self.dirs.last_mut() else {
            return Err(framing_error("no open directory"));
        };
        if last.as_deref().is_some_and(|last| last >= name) {
            return Err(framing_error("entry names must strictly increase"));
        }
        *last = Some(name.to_vec());
        self.strs(&[b"entry", b"(", b"name", name, b"node"])?;
        self.state = State::Node;
        Ok(())
    }

    /// Closes the current directory node.
    pub(crate) fn end_directory(&mut self) -> io::Result<()> {
        if !matches!(self.state, State::Directory) || self.dirs.pop().is_none() {
            return Err(framing_error("no open directory to end"));
        }
        self.str(b")")?;
        self.node_done()
    }

    /// Opens a regular file node with `len` bytes of contents, which must
    /// then be written with [`Self::contents`] before [`Self::end_regular`].
    pub(crate) fn begin_regular(&mut self, executable: bool, len: u64) -> io::Result<()> {
        self.expect_node()?;
        self.strs(&[b"(", b"type", b"regular"])?;
        if executable {
            self.strs(&[b"executable", b""])?;
        }
        self.str(b"contents")?;
        self.out.write_all(&len.to_le_bytes())?;
        self.state = State::Contents {
            remaining: len,
            len,
        };
        Ok(())
    }

    /// Writes file contents. Writing more than the declared length is an error.
    pub(crate) fn contents(&mut self, data: &[u8]) -> io::Result<()> {
        let State::Contents { remaining, .. } = &mut self.state else {
            return Err(framing_error("contents outside a regular file"));
        };
        *remaining = remaining
            .checked_sub(data.len() as u64)
            .ok_or_else(|| framing_error("more contents than declared"))?;
        self.out.write_all(data)
    }

    /// Closes a regular file node. Fails unless exactly the declared length
    /// was written.
    pub(crate) fn end_regular(&mut self) -> io::Result<()> {
        let State::Contents { remaining: 0, len } = self.state else {
            return Err(framing_error(
                "regular file ended before its declared length",
            ));
        };
        self.out.write_all(&[0; 8][..padding(len)])?;
        self.str(b")")?;
        self.node_done()
    }

    /// Writes a complete symlink node.
    pub(crate) fn symlink(&mut self, target: &[u8]) -> io::Result<()> {
        self.expect_node()?;
        if target.is_empty() || target.contains(&0) {
            return Err(framing_error("invalid symlink target"));
        }
        self.strs(&[b"(", b"type", b"symlink", b"target", target, b")"])?;
        self.node_done()
    }

    /// Returns the output once the root node is complete.
    pub(crate) fn finish(self) -> io::Result<W> {
        match self.state {
            State::Done => Ok(self.out),
            _ => Err(framing_error("archive is incomplete")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{AlgorithmSet, DigestAlgorithm, MultiHasher};

    /// `str(s)` as defined by the format, written independently of the writer.
    fn s(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u64).to_le_bytes().to_vec();
        out.extend(bytes);
        out.resize(out.len().div_ceil(8) * 8, 0);
        out
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn strings_are_padded_to_eight_bytes() {
        for (len, padded) in [(0, 8), (1, 16), (7, 16), (8, 16), (9, 24)] {
            let mut nar = NarWriter {
                out: Vec::new(),
                state: State::Node,
                dirs: Vec::new(),
            };
            nar.str(&vec![b'x'; len]).unwrap();
            assert_eq!(nar.out.len(), padded, "len {len}");
            assert_eq!(nar.out, s(&vec![b'x'; len]));
        }
    }

    #[test]
    fn empty_directory_matches_the_known_digest() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_directory().unwrap();
        nar.end_directory().unwrap();
        let bytes = nar.finish().unwrap();
        assert_eq!(
            bytes,
            cat(&[s(MAGIC), s(b"("), s(b"type"), s(b"directory"), s(b")")])
        );
        assert_eq!(bytes.len(), 96);
        let mut hasher = MultiHasher::new(&AlgorithmSet::all());
        hasher.update(&bytes);
        // `nix hash path` of an empty directory: sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo=
        assert_eq!(
            hasher
                .finalize()
                .get(DigestAlgorithm::Sha256)
                .unwrap()
                .to_hex(),
            "a50a5ab6d992f5598edd92105059fae9acfc192981e08bd88534c2167e92526a"
        );
    }

    #[test]
    fn every_node_type_is_framed_as_specified() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_directory().unwrap();
        nar.begin_entry(b"bin").unwrap();
        nar.begin_regular(true, 3).unwrap();
        nar.contents(b"ab").unwrap();
        nar.contents(b"c").unwrap();
        nar.end_regular().unwrap();
        nar.begin_entry(b"link").unwrap();
        nar.symlink(b"bin").unwrap();
        nar.begin_entry(b"sub").unwrap();
        nar.begin_directory().unwrap();
        nar.begin_entry(b"empty").unwrap();
        nar.begin_regular(false, 0).unwrap();
        nar.end_regular().unwrap();
        nar.end_directory().unwrap();
        nar.end_directory().unwrap();
        let expected = cat(&[
            s(MAGIC),
            s(b"("),
            s(b"type"),
            s(b"directory"),
            s(b"entry"),
            s(b"("),
            s(b"name"),
            s(b"bin"),
            s(b"node"),
            s(b"("),
            s(b"type"),
            s(b"regular"),
            s(b"executable"),
            s(b""),
            s(b"contents"),
            s(b"abc"),
            s(b")"),
            s(b")"),
            s(b"entry"),
            s(b"("),
            s(b"name"),
            s(b"link"),
            s(b"node"),
            s(b"("),
            s(b"type"),
            s(b"symlink"),
            s(b"target"),
            s(b"bin"),
            s(b")"),
            s(b")"),
            s(b"entry"),
            s(b"("),
            s(b"name"),
            s(b"sub"),
            s(b"node"),
            s(b"("),
            s(b"type"),
            s(b"directory"),
            s(b"entry"),
            s(b"("),
            s(b"name"),
            s(b"empty"),
            s(b"node"),
            s(b"("),
            s(b"type"),
            s(b"regular"),
            s(b"contents"),
            s(b""),
            s(b")"),
            s(b")"),
            s(b")"),
            s(b")"),
            s(b")"),
        ]);
        assert_eq!(nar.finish().unwrap(), expected);
    }

    #[test]
    fn a_root_regular_file_is_a_complete_archive() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_regular(false, 5).unwrap();
        nar.contents(b"hello").unwrap();
        nar.end_regular().unwrap();
        let expected = cat(&[
            s(MAGIC),
            s(b"("),
            s(b"type"),
            s(b"regular"),
            s(b"contents"),
            s(b"hello"),
            s(b")"),
        ]);
        assert_eq!(nar.finish().unwrap(), expected);
    }

    #[test]
    fn contents_must_match_the_declared_length() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_regular(false, 2).unwrap();
        assert!(nar.contents(b"abc").is_err(), "longer than declared");

        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_regular(false, 2).unwrap();
        nar.contents(b"a").unwrap();
        assert!(nar.end_regular().is_err(), "shorter than declared");
        assert!(nar.finish().is_err());
    }

    #[test]
    fn entry_names_must_strictly_increase_and_be_valid() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        nar.begin_directory().unwrap();
        nar.begin_entry(b"b").unwrap();
        nar.symlink(b"x").unwrap();
        assert!(nar.begin_entry(b"b").is_err(), "duplicate");
        assert!(nar.begin_entry(b"a").is_err(), "decreasing");
        for bad in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert!(nar.begin_entry(bad).is_err(), "{bad:?}");
        }
        // Byte order: uppercase sorts before lowercase, a prefix before its extensions.
        nar.begin_entry(b"c").unwrap();
        nar.symlink(b"x").unwrap();
        nar.begin_entry(b"ca").unwrap();
        nar.symlink(b"x").unwrap();
        nar.begin_entry("\u{e4}".as_bytes()).unwrap();
        nar.symlink(b"x").unwrap();
        nar.end_directory().unwrap();
        nar.finish().unwrap();
    }

    #[test]
    fn misplaced_calls_are_rejected() {
        let mut nar = NarWriter::new(Vec::new()).unwrap();
        assert!(nar.begin_entry(b"a").is_err(), "entry outside a directory");
        assert!(nar.end_directory().is_err());
        assert!(nar.contents(b"x").is_err());
        nar.symlink(b"t").unwrap();
        assert!(nar.begin_directory().is_err(), "second root");
        assert!(nar.symlink(b"t").is_err(), "second root");
        assert!(
            NarWriter::new(Vec::new()).unwrap().finish().is_err(),
            "no root node"
        );
    }
}
