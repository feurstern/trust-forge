//! Helpers shared by the integration tests.

#![allow(dead_code)]

use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use trustforge_core::digest::{DigestAlgorithm, DigestSet};
use trustforge_core::inspect::{
    ArtifactDigests, InspectError, InspectOptions, Inspection, inspect_path,
};

/// Inspects `path` with default options on a worker thread, failing the test
/// if inspection does not finish within ten seconds (it must never block on
/// a FIFO or read a device).
pub fn inspect_with_watchdog(path: &Path) -> Result<Inspection, InspectError> {
    let (tx, rx) = mpsc::channel();
    let path = path.to_owned();
    thread::spawn(move || {
        let _ = tx.send(inspect_path(&path, &InspectOptions::default()));
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("inspection hung instead of failing fast")
}

pub fn inspect(path: &Path) -> Inspection {
    inspect_path(path, &InspectOptions::default()).unwrap()
}

pub fn tree_digests(inspection: &Inspection) -> &DigestSet {
    match inspection.digests() {
        ArtifactDigests::Tree(digests) => digests,
        ArtifactDigests::Content(_) => panic!("expected tree digests"),
    }
}

pub fn content_digests(inspection: &Inspection) -> &DigestSet {
    match inspection.digests() {
        ArtifactDigests::Content(digests) => digests,
        ArtifactDigests::Tree(_) => panic!("expected content digests"),
    }
}

pub fn hex(digests: &DigestSet, algorithm: DigestAlgorithm) -> String {
    digests.get(algorithm).unwrap().to_hex()
}

#[cfg(unix)]
pub fn write_file(path: &Path, contents: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Whether names differing only in letter case can coexist in `dir`
/// (macOS's default APFS cannot).
pub fn case_sensitive(dir: &Path) -> bool {
    let probe = tempfile::tempdir_in(dir).unwrap();
    std::fs::write(probe.path().join("probe"), b"").unwrap();
    !probe.path().join("PROBE").exists()
}

/// Whether the NFC and NFD spellings of "é" are different names in `dir`.
pub fn normalization_sensitive(dir: &Path) -> bool {
    let probe = tempfile::tempdir_in(dir).unwrap();
    std::fs::write(probe.path().join("\u{e9}"), b"").unwrap();
    !probe.path().join("e\u{301}").exists()
}
