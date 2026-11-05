//! Inspection of single files, streams and special paths.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::path::Path;

use support::{content_digests, hex, inspect};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm};
use trustforge_core::format::FileFormat;
use trustforge_core::inspect::{
    ArtifactKind, InspectError, InspectOptions, Limit, inspect_path, inspect_reader,
};

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn a_file_is_described_by_its_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("abc.txt");
    std::fs::write(&path, b"abc").unwrap();
    let inspection = inspect(&path);
    assert_eq!(inspection.kind(), ArtifactKind::File);
    assert_eq!(inspection.name(), path.to_str().unwrap());
    assert_eq!(inspection.size(), 3);
    assert_eq!(
        hex(content_digests(&inspection), DigestAlgorithm::Sha256),
        ABC_SHA256
    );
    assert_eq!(inspection.format(), Some(&FileFormat::Unknown));
    assert!(!inspection.root_symlink_followed());
    assert!(inspection.entries().is_none());
    let metadata = inspection.untrusted_metadata().unwrap();
    assert!(metadata.modified_rfc3339().is_some());
}

#[test]
fn only_the_selected_algorithms_are_computed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("f");
    std::fs::write(&path, b"abc").unwrap();
    let mut opts = InspectOptions::default();
    opts.algorithms = AlgorithmSet::new([DigestAlgorithm::Sha256]).unwrap();
    let inspection = inspect_path(&path, &opts).unwrap();
    let digests = content_digests(&inspection);
    assert_eq!(digests.iter().count(), 1);
    assert_eq!(hex(digests, DigestAlgorithm::Sha256), ABC_SHA256);
}

#[test]
fn the_format_is_detected_from_content_not_the_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("innocent.txt");
    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.resize(16, 0);
    elf.extend(2u16.to_le_bytes());
    elf.extend(183u16.to_le_bytes());
    elf.resize(200_000, 0);
    std::fs::write(&path, &elf).unwrap();
    let Some(FileFormat::Elf(header)) = inspect(&path).format().cloned() else {
        panic!("expected ELF");
    };
    assert_eq!(header.machine, Some("aarch64"));
    assert_eq!(header.object_type, Some("executable"));
}

#[test]
fn streams_are_inspected_without_metadata() {
    let inspection = inspect_reader("-", &b"abc"[..], &InspectOptions::default()).unwrap();
    assert_eq!(inspection.kind(), ArtifactKind::Stream);
    assert_eq!(inspection.name(), "-");
    assert_eq!(
        hex(content_digests(&inspection), DigestAlgorithm::Sha256),
        ABC_SHA256
    );
    assert!(inspection.untrusted_metadata().is_none());
}

#[test]
fn a_missing_path_is_an_io_error_naming_it() {
    let err = inspect_path(Path::new("does/not/exist"), &InspectOptions::default()).unwrap_err();
    assert!(matches!(err, InspectError::Io { .. }), "{err}");
    assert!(err.to_string().starts_with("does/not/exist: "), "{err}");
}

#[test]
fn a_file_over_the_byte_limit_is_rejected_before_reading() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("f");
    std::fs::write(&path, b"abcd").unwrap();
    let mut opts = InspectOptions::default();
    opts.limits.max_bytes = 3;
    let err = inspect_path(&path, &opts).unwrap_err();
    assert!(
        matches!(
            err,
            InspectError::LimitExceeded {
                limit: Limit::Bytes,
                max: 3,
                ..
            }
        ),
        "{err}"
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::symlink;
    use support::inspect_with_watchdog;

    #[test]
    fn a_huge_sparse_file_fails_instantly_under_the_default_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse");
        let file = std::fs::File::create(&path).unwrap();
        // One byte over the default 64 GiB limit, without allocating it.
        file.set_len((64 << 30) + 1).unwrap();
        let err = support::inspect_with_watchdog(&path).unwrap_err();
        assert!(
            matches!(
                err,
                InspectError::LimitExceeded {
                    limit: Limit::Bytes,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_root_symlink_is_followed_once_and_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("abc");
        std::fs::write(&target, b"abc").unwrap();
        let link = tmp.path().join("link");
        symlink(&target, &link).unwrap();
        let inspection = inspect(&link);
        assert!(inspection.root_symlink_followed());
        assert_eq!(
            hex(content_digests(&inspection), DigestAlgorithm::Sha256),
            ABC_SHA256
        );
        assert!(!inspect(&target).root_symlink_followed());
    }

    #[test]
    fn a_root_symlink_with_a_trailing_slash_is_still_reported() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("dir")).unwrap();
        symlink("dir", tmp.path().join("link")).unwrap();
        let mut with_slash = tmp.path().join("link").into_os_string();
        with_slash.push("/");
        assert!(inspect(Path::new(&with_slash)).root_symlink_followed());
    }

    #[test]
    fn a_device_is_never_opened() {
        let err = inspect_with_watchdog(Path::new("/dev/null")).unwrap_err();
        assert!(
            matches!(
                err,
                InspectError::UnsupportedFileType {
                    kind: "character device",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_symlink_to_a_device_is_rejected_as_the_device() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("zero");
        symlink("/dev/zero", &link).unwrap();
        let err = inspect_with_watchdog(&link).unwrap_err();
        assert!(
            matches!(err, InspectError::UnsupportedFileType { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_socket_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let err = inspect_with_watchdog(&path).unwrap_err();
        assert!(
            matches!(
                err,
                InspectError::UnsupportedFileType { kind: "socket", .. }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_non_utf8_path_is_rejected() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"bad\xff"));
        let err = inspect_path(path, &InspectOptions::default()).unwrap_err();
        assert!(matches!(err, InspectError::InvalidName { .. }), "{err}");
        assert!(err.to_string().contains(r"bad\xff"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_root_fails_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("fifo");
        mkfifo(&path);
        let err = inspect_with_watchdog(&path).unwrap_err();
        assert!(
            matches!(
                err,
                InspectError::UnsupportedFileType {
                    kind: "FIFO (named pipe)",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_whose_reported_size_is_wrong_is_rejected() {
        // procfs reports a size of 0 for files that do have content.
        let err = inspect_with_watchdog(Path::new("/proc/self/status")).unwrap_err();
        assert!(
            matches!(err, InspectError::ConcurrentModification { detail, .. } if detail.contains("more data")),
            "{err}"
        );
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn mkfifo(path: &Path) {
        use rustix::fs::{CWD, FileType, Mode, mknodat};
        mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
    }
}

#[cfg(windows)]
#[test]
fn directories_are_unsupported_on_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let err = inspect_path(tmp.path(), &InspectOptions::default()).unwrap_err();
    assert!(matches!(err, InspectError::Unsupported { .. }), "{err}");
}
