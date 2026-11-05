//! Inspection of paths on Unix, through file descriptors.

use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{self, AtFlags, CWD, FileType, Mode, OFlags};
use rustix::io::{Errno, retry_on_intr};

use super::tree::{NoHooks, walk};
use super::{ErrorPath, InspectError, InspectOptions, Inspection, UntrustedMetadata, hash_file};
use crate::name::NameError;

/// The fields of `stat` that inspection relies on, converted once to
/// lossless types: their native widths differ between platforms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    pub(crate) file_type: FileType,
    pub(crate) dev: i128,
    pub(crate) ino: i128,
    /// Permission bits, including setuid, setgid and sticky.
    pub(crate) permissions: u32,
    pub(crate) owner_executable: bool,
    pub(crate) nlink: i128,
    pub(crate) size: u64,
    pub(crate) mtime: (i128, i128),
    /// A writer can reset the modification time, but not the status change
    /// time, so this is what reveals a rewrite that preserved size and mtime.
    pub(crate) ctime: (i128, i128),
}

impl Meta {
    /// `None` if the reported size is negative, which a broken or hostile
    /// file system can do.
    pub(crate) fn from_stat(st: &fs::Stat) -> Option<Self> {
        let mode = i128::from(st.st_mode);
        Some(Self {
            file_type: FileType::from_raw_mode(st.st_mode),
            dev: i128::from(st.st_dev),
            ino: i128::from(st.st_ino),
            permissions: u32::try_from(mode & 0o7777).ok()?,
            owner_executable: mode & i128::from(Mode::XUSR.bits()) != 0,
            nlink: i128::from(st.st_nlink),
            size: u64::try_from(st.st_size).ok()?,
            mtime: (i128::from(st.st_mtime), i128::from(st.st_mtime_nsec)),
            ctime: (i128::from(st.st_ctime), i128::from(st.st_ctime_nsec)),
        })
    }

    /// Whether both describe the same file-system object.
    pub(crate) fn same_object(&self, other: &Meta) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    pub(crate) fn untrusted(&self) -> UntrustedMetadata {
        UntrustedMetadata {
            mode: Some(self.permissions),
            modified_unix_seconds: i64::try_from(self.mtime.0).ok(),
        }
    }
}

/// `stat` fails or returns metadata that cannot be represented.
pub(crate) fn meta_from(
    result: Result<fs::Stat, Errno>,
    path: impl FnOnce() -> ErrorPath,
) -> Result<Meta, InspectError> {
    match result {
        Ok(st) => Meta::from_stat(&st).ok_or_else(|| InspectError::ConcurrentModification {
            path: path(),
            detail: "the file system reported a negative size",
        }),
        Err(e) => Err(InspectError::Io {
            path: path(),
            source: e.into(),
        }),
    }
}

pub(crate) fn fstat_meta(
    fd: impl AsFd,
    path: impl FnOnce() -> ErrorPath,
) -> Result<Meta, InspectError> {
    meta_from(fs::fstat(fd), path)
}

/// A human-readable name for a file type that is never inspected.
pub(crate) fn describe(file_type: FileType) -> &'static str {
    match file_type {
        FileType::Fifo => "FIFO (named pipe)",
        FileType::Socket => "socket",
        FileType::CharacterDevice => "character device",
        FileType::BlockDevice => "block device",
        FileType::Symlink => "symbolic link",
        FileType::RegularFile => "regular file",
        FileType::Directory => "directory",
        _ => "file of unknown type",
    }
}

/// `path` without trailing slashes, which would make `lstat` follow a final
/// symbolic link. `/` stays `/`.
fn strip_trailing_slashes(path: &Path) -> &Path {
    let bytes = path.as_os_str().as_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != b'/')
        .map_or(bytes.len().min(1), |i| i + 1);
    Path::new(std::ffi::OsStr::from_bytes(&bytes[..end]))
}

pub(super) fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<Inspection, InspectError> {
    let at = || ErrorPath::root(path);
    let name = path
        .to_str()
        .ok_or_else(|| InspectError::InvalidName {
            path: at(),
            reason: NameError::InvalidUtf8,
        })?
        .to_owned();

    let link = meta_from(
        fs::statat(CWD, strip_trailing_slashes(path), AtFlags::SYMLINK_NOFOLLOW),
        at,
    )?;
    let followed = link.file_type == FileType::Symlink;
    let target = meta_from(fs::statat(CWD, path, AtFlags::empty()), at)?;
    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match target.file_type {
        FileType::RegularFile => {}
        FileType::Directory => flags |= OFlags::DIRECTORY,
        other => {
            // Never opened: opening a FIFO can block, opening a device can
            // have side effects.
            return Err(InspectError::UnsupportedFileType {
                path: at(),
                kind: describe(other),
            });
        }
    }
    let open_path = if followed {
        path
    } else {
        // The path was not a symlink a moment ago; do not follow one now.
        // A trailing slash would make the kernel follow it regardless.
        flags |= OFlags::NOFOLLOW;
        strip_trailing_slashes(path)
    };
    let fd: OwnedFd = retry_on_intr(|| fs::openat(CWD, open_path, flags, Mode::empty()))
        .map_err(|e| open_error(e, at()))?;
    let meta = fstat_meta(&fd, at)?;
    if meta.file_type != target.file_type || !meta.same_object(&target) {
        return Err(InspectError::ConcurrentModification {
            path: at(),
            detail: "it was replaced while being opened",
        });
    }

    let inspection = if meta.file_type == FileType::Directory {
        let tree = walk(path, fd, meta, opts, &mut NoHooks)?;
        Inspection::directory(
            name,
            tree.size,
            tree.digests,
            tree.entries,
            tree.counts,
            followed,
            meta.untrusted(),
        )
    } else {
        let mut file = File::from(fd);
        let (digests, format) = hash_file(&mut file, meta.size, opts, at)?;
        if fstat_meta(&file, at)? != meta {
            return Err(InspectError::ConcurrentModification {
                path: at(),
                detail: "it was modified while being read",
            });
        }
        Inspection::file(name, meta.size, digests, format, followed, meta.untrusted())
    };

    // The path must still lead to what was inspected.
    let after = meta_from(fs::statat(CWD, path, AtFlags::empty()), at)?;
    if !after.same_object(&meta) {
        return Err(InspectError::ConcurrentModification {
            path: at(),
            detail: "it was replaced during inspection",
        });
    }
    Ok(inspection)
}

/// Maps an error from opening something that `stat` just described. An
/// object that vanished or changed type in between is a modification, not an
/// I/O problem.
pub(crate) fn open_error(e: Errno, path: ErrorPath) -> InspectError {
    if e == Errno::NOENT || e == Errno::LOOP || e == Errno::NOTDIR || e == Errno::NXIO {
        InspectError::ConcurrentModification {
            path,
            detail: "it disappeared or changed type before it could be opened",
        }
    } else {
        InspectError::Io {
            path,
            source: e.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_slashes_are_stripped_but_root_stays() {
        assert_eq!(strip_trailing_slashes(Path::new("a/b//")), Path::new("a/b"));
        assert_eq!(strip_trailing_slashes(Path::new("a")), Path::new("a"));
        assert_eq!(strip_trailing_slashes(Path::new("/")), Path::new("/"));
        assert_eq!(strip_trailing_slashes(Path::new("///")), Path::new("/"));
    }

    #[test]
    fn metadata_compares_every_observable_field() {
        let st = fs::stat(".").unwrap();
        let meta = Meta::from_stat(&st).unwrap();
        assert_eq!(meta.file_type, FileType::Directory);
        let mut changed = meta;
        changed.ctime.1 += 1;
        assert_ne!(meta, changed);
        let mut moved = meta;
        moved.ino += 1;
        assert!(!meta.same_object(&moved));
    }
}
