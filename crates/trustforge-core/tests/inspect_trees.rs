//! Directory inspection on Unix: determinism, the NAR tree digest, symlinks,
//! special files, hostile names and limits.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use proptest::prelude::*;
use support::{
    case_sensitive, hex, inspect, inspect_with_watchdog, normalization_sensitive, tree_digests,
    write_file,
};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm, MultiHasher};
use trustforge_core::inspect::{
    ArtifactKind, EntryKind, InspectError, InspectOptions, Limit, inspect_path,
};

fn sha256_of_tree(dir: &Path) -> String {
    hex(tree_digests(&inspect(dir)), DigestAlgorithm::Sha256)
}

fn listing(dir: &Path) -> Vec<String> {
    inspect(dir)
        .entries()
        .unwrap()
        .iter()
        .map(|e| match e.kind() {
            EntryKind::File {
                executable, size, ..
            } => format!("{} file x={executable} {size}", e.path()),
            EntryKind::Directory => format!("{} dir", e.path()),
            EntryKind::Symlink {
                target,
                target_leaves_tree,
            } => {
                format!("{} -> {target} leaves={target_leaves_tree}", e.path())
            }
            _ => format!("{} other", e.path()),
        })
        .collect()
}

#[test]
fn an_empty_directory_has_the_known_nar_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let inspection = inspect(tmp.path());
    assert_eq!(inspection.kind(), ArtifactKind::Directory);
    assert_eq!(inspection.size(), 0);
    assert_eq!(inspection.entries().unwrap().len(), 0);
    assert_eq!(
        hex(tree_digests(&inspection), DigestAlgorithm::Sha256),
        "a50a5ab6d992f5598edd92105059fae9acfc192981e08bd88534c2167e92526a"
    );
}

#[test]
fn entries_are_listed_depth_first_in_byte_order() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir(root.join("a")).unwrap();
    write_file(&root.join("a/x"), b"x", 0o644);
    write_file(&root.join("a-b"), b"ab", 0o755);
    write_file(&root.join("B"), b"", 0o644);
    fs::create_dir(root.join("empty")).unwrap();
    symlink("a/x", root.join("link")).unwrap();
    // Depth-first, siblings by bytes: "B" < "a" < "a-b"; "a/x" precedes "a-b".
    assert_eq!(
        listing(root),
        [
            "B file x=false 0",
            "a dir",
            "a/x file x=false 1",
            "a-b file x=true 2",
            "empty dir",
            "link -> a/x leaves=false",
        ]
    );
    let inspection = inspect(root);
    assert_eq!(inspection.size(), 3);
    let counts = inspection.counts().unwrap();
    assert_eq!(
        (counts.files, counts.directories, counts.symlinks),
        (3, 2, 1)
    );
}

#[test]
fn creation_order_timestamps_and_other_permission_bits_do_not_matter() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for (root, order, mode) in [
        (first.path(), ["z", "m", "a"], 0o644),
        (second.path(), ["a", "m", "z"], 0o600),
    ] {
        for name in order {
            fs::create_dir_all(root.join("d")).unwrap();
            write_file(&root.join(name), name.as_bytes(), mode);
            write_file(&root.join("d").join(name), b"inner", mode);
        }
    }
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    fs::File::options()
        .write(true)
        .open(second.path().join("m"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert_eq!(sha256_of_tree(first.path()), sha256_of_tree(second.path()));
    assert_eq!(listing(first.path()), listing(second.path()));
}

#[test]
fn only_the_owner_execute_bit_is_covered() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tool");
    write_file(&path, b"#!/bin/sh\n", 0o644);
    let plain = sha256_of_tree(tmp.path());
    // Group and other execute bits are not part of the NAR serialization.
    write_file(&path, b"#!/bin/sh\n", 0o655);
    assert_eq!(sha256_of_tree(tmp.path()), plain);
    assert_eq!(listing(tmp.path()), ["tool file x=false 10"]);
    // The owner-execute bit is.
    write_file(&path, b"#!/bin/sh\n", 0o744);
    assert_ne!(sha256_of_tree(tmp.path()), plain);
    assert_eq!(listing(tmp.path()), ["tool file x=true 10"]);
}

#[test]
fn a_hard_link_hashes_like_a_copy() {
    let linked = tempfile::tempdir().unwrap();
    let copied = tempfile::tempdir().unwrap();
    write_file(&linked.path().join("x"), b"same", 0o644);
    fs::hard_link(linked.path().join("x"), linked.path().join("y")).unwrap();
    write_file(&copied.path().join("x"), b"same", 0o644);
    write_file(&copied.path().join("y"), b"same", 0o644);
    assert_eq!(sha256_of_tree(linked.path()), sha256_of_tree(copied.path()));
    assert_eq!(inspect(linked.path()).size(), 8, "counted once per path");
}

#[test]
fn symlinks_are_recorded_and_never_followed() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    fs::write(&secret, b"one").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    symlink(&secret, root.join("abs")).unwrap();
    symlink("../../escape", root.join("up")).unwrap();
    symlink("loop", root.join("loop")).unwrap();
    symlink("/dev/zero", root.join("zero")).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    write_file(&root.join("sub/file"), b"f", 0o644);
    symlink("sub", root.join("subdir-link")).unwrap();

    let before = sha256_of_tree(root);
    fs::write(&secret, b"two, longer").unwrap();
    assert_eq!(
        sha256_of_tree(root),
        before,
        "the target's content is never read"
    );

    let listing = listing(root);
    assert!(
        listing.contains(&format!("abs -> {} leaves=true", secret.display())),
        "{listing:?}"
    );
    assert!(listing.contains(&"up -> ../../escape leaves=true".to_string()));
    assert!(listing.contains(&"loop -> loop leaves=false".to_string()));
    assert!(listing.contains(&"zero -> /dev/zero leaves=true".to_string()));
    assert!(listing.contains(&"subdir-link -> sub leaves=false".to_string()));
    // The directory is listed once, under its own name only.
    assert_eq!(
        listing
            .iter()
            .filter(|l| l.ends_with("file x=false 1"))
            .count(),
        1
    );
}

#[test]
fn a_root_symlink_to_a_directory_is_followed_once() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dir");
    fs::create_dir(&dir).unwrap();
    write_file(&dir.join("f"), b"f", 0o644);
    symlink(&dir, tmp.path().join("link")).unwrap();
    let via_link = inspect(&tmp.path().join("link"));
    assert!(via_link.root_symlink_followed());
    assert_eq!(tree_digests(&via_link), tree_digests(&inspect(&dir)));
}

#[test]
fn a_socket_inside_a_tree_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(tmp.path().join("s")).unwrap();
    let err = inspect_with_watchdog(tmp.path()).unwrap_err();
    assert!(
        matches!(
            err,
            InspectError::UnsupportedFileType { kind: "socket", .. }
        ),
        "{err}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_fifo_inside_a_tree_is_rejected_without_blocking() {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("d")).unwrap();
    mknodat(
        CWD,
        tmp.path().join("d/fifo"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let err = inspect_with_watchdog(tmp.path()).unwrap_err();
    assert!(
        matches!(err, InspectError::UnsupportedFileType { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("d/fifo"), "{err}");
}

#[test]
fn hostile_names_are_rejected_and_escaped() {
    for name in [
        "red\u{1b}[31m",
        "rtl\u{202e}txt",
        "line\nbreak",
        "back\\slash",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(name), b"x").unwrap();
        let err = inspect_path(tmp.path(), &InspectOptions::default()).unwrap_err();
        assert!(
            matches!(err, InspectError::InvalidName { .. }),
            "{name:?}: {err}"
        );
        let message = err.to_string();
        assert!(
            !message.contains(['\u{1b}', '\u{202e}', '\n']),
            "raw control character in {message:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn names_that_would_collide_after_lossy_conversion_are_rejected() {
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    // Both would become "a\u{FFFD}" under lossy conversion.
    for raw in [&b"a\xfe"[..], b"a\xff"] {
        fs::write(tmp.path().join(std::ffi::OsStr::from_bytes(raw)), b"x").unwrap();
    }
    let err = inspect_path(tmp.path(), &InspectOptions::default()).unwrap_err();
    assert!(matches!(err, InspectError::InvalidName { .. }), "{err}");
    assert!(err.to_string().contains(r"a\xf"), "{err}");
}

#[test]
fn limits_are_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("a/b/c")).unwrap();
    write_file(&tmp.path().join("a/b/c/file"), b"0123456789", 0o644);
    symlink("x".repeat(20), tmp.path().join("long-link")).unwrap();

    let check = |configure: &dyn Fn(&mut InspectOptions), expected: Limit| {
        let mut opts = InspectOptions::default();
        configure(&mut opts);
        match inspect_path(tmp.path(), &opts) {
            Err(InspectError::LimitExceeded { limit, .. }) => assert_eq!(limit, expected),
            other => panic!("expected {expected:?} to be exceeded, got {other:?}"),
        }
    };
    check(&|o| o.limits.max_entries = 4, Limit::Entries);
    check(&|o| o.limits.max_depth = 3, Limit::Depth);
    check(&|o| o.limits.max_bytes = 9, Limit::Bytes);
    check(&|o| o.limits.max_path_bytes = 20, Limit::PathBytes);
    check(
        &|o| o.limits.max_symlink_target_len = 19,
        Limit::SymlinkTargetLength,
    );

    let mut exact = InspectOptions::default();
    exact.limits.max_entries = 5;
    exact.limits.max_depth = 4;
    exact.limits.max_bytes = 10;
    exact.limits.max_symlink_target_len = 20;
    inspect_path(tmp.path(), &exact).expect("limits are inclusive");
}

#[test]
fn a_sparse_file_inside_a_tree_fails_before_reading() {
    let tmp = tempfile::tempdir().unwrap();
    fs::File::create(tmp.path().join("sparse"))
        .unwrap()
        .set_len(1 << 40)
        .unwrap();
    let err = inspect_with_watchdog(tmp.path()).unwrap_err();
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
fn every_algorithm_hashes_the_same_serialization() {
    let tmp = tempfile::tempdir().unwrap();
    write_file(&tmp.path().join("f"), b"contents", 0o755);
    let one_pass = inspect(tmp.path());
    for algorithm in DigestAlgorithm::ALL {
        let mut opts = InspectOptions::default();
        opts.algorithms = AlgorithmSet::new([algorithm]).unwrap();
        let alone = inspect_path(tmp.path(), &opts).unwrap();
        assert_eq!(
            tree_digests(&alone).get(algorithm),
            tree_digests(&one_pass).get(algorithm),
            "{algorithm}"
        );
    }
}

/// A file tree described in memory, for property tests.
#[derive(Clone, Debug)]
enum Node {
    File { contents: Vec<u8>, executable: bool },
    Symlink(String),
    Dir(BTreeMap<String, Node>),
}

/// An independent, recursive NAR encoder, written from the format grammar
/// (see the `nar` module of the crate) without sharing its code.
fn encode(node: &Node, out: &mut Vec<u8>) {
    fn s(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend((bytes.len() as u64).to_le_bytes());
        out.extend(bytes);
        out.resize(out.len().div_ceil(8) * 8, 0);
    }
    s(out, b"(");
    s(out, b"type");
    match node {
        Node::File {
            contents,
            executable,
        } => {
            s(out, b"regular");
            if *executable {
                s(out, b"executable");
                s(out, b"");
            }
            s(out, b"contents");
            s(out, contents);
        }
        Node::Symlink(target) => {
            s(out, b"symlink");
            s(out, b"target");
            s(out, target.as_bytes());
        }
        Node::Dir(children) => {
            s(out, b"directory");
            // BTreeMap<String, _> iterates in byte order of the names.
            for (name, child) in children {
                for token in [&b"entry"[..], b"(", b"name", name.as_bytes(), b"node"] {
                    s(out, token);
                }
                encode(child, out);
                s(out, b")");
            }
        }
    }
    s(out, b")");
}

fn materialize(node: &Node, path: &Path) {
    match node {
        Node::File {
            contents,
            executable,
        } => write_file(path, contents, if *executable { 0o755 } else { 0o644 }),
        Node::Symlink(target) => symlink(target, path).unwrap(),
        Node::Dir(children) => {
            fs::create_dir_all(path).unwrap();
            for (name, child) in children {
                materialize(child, &path.join(name));
            }
        }
    }
}

/// Names chosen to exercise byte ordering: case, punctuation that sorts
/// before and after `/`, digits, and non-ASCII.
const NAMES: [&str; 12] = [
    "a",
    "B",
    "a-b",
    "a.b",
    "a_b",
    "aa",
    "Z",
    "z",
    "10",
    "9",
    "\u{e4}",
    "\u{1f600}",
];

fn tree(case_sensitive: bool) -> impl Strategy<Value = Node> {
    let names: Vec<&'static str> = NAMES
        .into_iter()
        .filter(|n| case_sensitive || !["B", "Z"].contains(n))
        .collect();
    let leaf = prop_oneof![
        (
            proptest::collection::vec(any::<u8>(), 0..300),
            any::<bool>()
        )
            .prop_map(|(contents, executable)| Node::File {
                contents,
                executable
            }),
        prop::sample::select(vec!["a", "../x", "/abs/path", "sub/dir/f", ".."])
            .prop_map(|t| Node::Symlink(t.into())),
    ];
    leaf.prop_recursive(4, 24, 5, move |inner| {
        proptest::collection::btree_map(
            prop::sample::select(names.clone()).prop_map(String::from),
            inner,
            0..5,
        )
        .prop_map(Node::Dir)
    })
    .prop_map(|node| match node {
        dir @ Node::Dir(_) => dir,
        leaf => Node::Dir(BTreeMap::from([("only".to_string(), leaf)])),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Walking a random tree yields exactly the NAR an independent recursive
    /// encoder produces, under every algorithm.
    #[test]
    fn walker_matches_an_independent_encoder(node in tree(case_sensitive(&std::env::temp_dir()))) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        materialize(&node, &root);

        let mut expected_nar = Vec::new();
        s_magic(&mut expected_nar);
        encode(&node, &mut expected_nar);
        let mut hasher = MultiHasher::new(&AlgorithmSet::all());
        hasher.update(&expected_nar);
        let expected = hasher.finalize();

        let inspection = inspect(&root);
        prop_assert_eq!(tree_digests(&inspection), &expected);
    }
}

fn s_magic(out: &mut Vec<u8>) {
    out.extend(13u64.to_le_bytes());
    out.extend(b"nix-archive-1\0\0\0");
}

#[test]
fn unicode_normalization_forms_are_distinct_names() {
    let tmp = tempfile::tempdir().unwrap();
    if !normalization_sensitive(tmp.path()) {
        eprintln!("skipped: this file system treats NFC and NFD names as one");
        return;
    }
    write_file(&tmp.path().join("\u{e9}"), b"nfc", 0o644);
    write_file(&tmp.path().join("e\u{301}"), b"nfd", 0o644);
    // "e" + U+0301 (65 cc 81) sorts before U+00E9 (c3 a9).
    assert_eq!(
        listing(tmp.path()),
        ["e\u{301} file x=false 3", "\u{e9} file x=false 3"]
    );
}
