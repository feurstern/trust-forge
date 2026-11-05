//! Inspection on platforms other than Unix, such as Windows: single files
//! only. Directory tree digests cover the executable bit, which these
//! platforms do not have, so directory inspection is unsupported rather than
//! computed differently (`docs/roadmap.md`, open question d).
//!
//! Without descriptor-relative `stat`, concurrent modification is detected
//! from the file's length and modification time only.

use std::fs::{self, File};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ErrorPath, InspectError, InspectOptions, Inspection, UntrustedMetadata, hash_file};
use crate::name::NameError;

pub(super) fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<Inspection, InspectError> {
    let at = || ErrorPath::root(path);
    let io = |source| InspectError::Io { path: at(), source };
    let name = path
        .to_str()
        .ok_or_else(|| InspectError::InvalidName {
            path: at(),
            reason: NameError::InvalidUtf8,
        })?
        .to_owned();

    let followed = fs::symlink_metadata(path)
        .map_err(io)?
        .file_type()
        .is_symlink();
    let target = fs::metadata(path).map_err(io)?;
    if target.is_dir() {
        return Err(InspectError::Unsupported {
            path: at(),
            what: "directory inspection (tree digests cover the executable bit, which this platform lacks)",
        });
    }
    if !target.is_file() {
        return Err(InspectError::UnsupportedFileType {
            path: at(),
            kind: "special file",
        });
    }

    let mut file = File::open(path).map_err(io)?;
    let before = file.metadata().map_err(io)?;
    if !before.is_file() {
        return Err(InspectError::ConcurrentModification {
            path: at(),
            detail: "it was replaced while being opened",
        });
    }
    let (digests, format) = hash_file(&mut file, before.len(), opts, at)?;
    let after = file.metadata().map_err(io)?;
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return Err(InspectError::ConcurrentModification {
            path: at(),
            detail: "it was modified while being read",
        });
    }
    let untrusted = UntrustedMetadata {
        mode: None,
        modified_unix_seconds: before.modified().ok().and_then(unix_seconds),
    };
    Ok(Inspection::file(
        name,
        before.len(),
        digests,
        format,
        followed,
        untrusted,
    ))
}

fn unix_seconds(time: SystemTime) -> Option<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).ok(),
        Err(before) => i64::try_from(before.duration().as_secs()).ok().map(|s| -s),
    }
}
