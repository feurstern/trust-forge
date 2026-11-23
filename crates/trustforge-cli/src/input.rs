//! Reading documents (manifests, recipes and reports) from files or
//! standard input.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::sanitize::sanitize;

/// Reads at most `max + 1` bytes, so that an oversized document is
/// recognized without reading it all.
pub fn read_limited(reader: impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// `path` for messages, with characters unsafe for a terminal escaped.
pub fn shown(path: &Path) -> String {
    sanitize(&path.to_string_lossy())
}

/// Reads the document at `path`, or standard input for `-`, up to `max + 1`
/// bytes. Returns the label to use in messages along with the bytes.
pub fn read_document(path: &str, max: usize) -> (String, io::Result<Vec<u8>>) {
    if path == "-" {
        (
            "(standard input)".to_owned(),
            read_limited(io::stdin().lock(), max),
        )
    } else {
        (
            sanitize(path),
            File::open(path).and_then(|file| read_limited(file, max)),
        )
    }
}
