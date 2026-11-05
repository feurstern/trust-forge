//! Tree digests agree with Nix itself.
//!
//! `fixtures/nar/*.nar` were produced once by `nix-store --dump` (Nix 2.35.4)
//! from the trees built by `scripts/nar-reference.sh`, and
//! `fixtures/nar/nix-hash.txt` holds `nix-hash --type sha256` of each. This
//! test rebuilds the same trees and checks that their tree digests (SHA-256,
//! SHA-512 and BLAKE3) are the digests of Nix's serialization. The trees here
//! and in the script must stay identical.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use support::{case_sensitive, inspect, normalization_sensitive, tree_digests, write_file};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm, MultiHasher};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/nar")
}

/// The first `len` bytes of "1\n2\n3\n…", as `seq 1 100000 | head -c len`.
fn numbers(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    let mut i = 1u32;
    while out.len() < len {
        out.extend(format!("{i}\n").bytes());
        i += 1;
    }
    out.truncate(len);
    out
}

fn build(tree: &str, root: &Path) {
    fs::create_dir(root).unwrap();
    let file =
        |path: &str, mode, contents: &str| write_file(&root.join(path), contents.as_bytes(), mode);
    match tree {
        "empty" => {}
        "sizes" => {
            for n in [0, 1, 7, 8, 9, 131_071, 131_072, 131_073] {
                write_file(&root.join(n.to_string()), &numbers(n), 0o644);
            }
        }
        "modes" => {
            file("a", 0o644, "mode a");
            file("b", 0o655, "mode b");
            file("c", 0o744, "mode c");
            file("d", 0o755, "mode d");
            fs::hard_link(root.join("d"), root.join("e")).unwrap();
            file("f", 0o755, "mode d");
        }
        "names" => {
            fs::create_dir(root.join("a")).unwrap();
            file("a/x", 0o644, "a/x");
            for name in ["B", "a-b", "a.b", "a_b", "\u{e4}", "Z", "z", "10", "9"] {
                file(name, 0o644, name);
            }
            for len in 1..=17 {
                let name = "n".repeat(len);
                file(&name, 0o644, &name);
            }
        }
        "unicode" => {
            file("\u{e9}", 0o644, "nfc");
            file("e\u{301}", 0o644, "nfd");
        }
        "links" => {
            fs::create_dir(root.join("dir")).unwrap();
            file("target", 0o644, "target");
            file("dir/f", 0o644, "f");
            symlink("target", root.join("rel")).unwrap();
            symlink("/nix/store/does-not-exist", root.join("abs")).unwrap();
            symlink("missing", root.join("dangling")).unwrap();
            symlink("dir", root.join("dirlink")).unwrap();
            symlink("../outside", root.join("up")).unwrap();
        }
        "nested" => {
            for dir in ["a/b/c/d", "a/empty", "a/b/empty2", "x/y"] {
                fs::create_dir_all(root.join(dir)).unwrap();
            }
            file("a/b/c/d/file", 0o644, "deep");
            file("top", 0o644, "top");
        }
        other => panic!("unknown fixture {other}"),
    }
}

/// `(tree, nix-hash)` pairs from `nix-hash.txt`.
fn nix_hashes() -> Vec<(String, String)> {
    fs::read_to_string(fixtures().join("nix-hash.txt"))
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let (hash, tree) = line.split_once("  ").unwrap();
            (tree.to_owned(), hash.to_owned())
        })
        .collect()
}

#[test]
fn tree_digests_match_nix() {
    let tmp = tempfile::tempdir().unwrap();
    let hashes = nix_hashes();
    assert_eq!(hashes.len(), 7, "every fixture has a recorded hash");
    let mut checked = 0;
    for (tree, nix_hash) in hashes {
        if (tree == "names" && !case_sensitive(tmp.path()))
            || (tree == "unicode" && !normalization_sensitive(tmp.path()))
        {
            eprintln!("skipped {tree}: this file system cannot hold its names side by side");
            continue;
        }
        let root = tmp.path().join(&tree);
        build(&tree, &root);
        let reference = fs::read(fixtures().join(format!("{tree}.nar"))).unwrap();
        let mut hasher = MultiHasher::new(&AlgorithmSet::all());
        hasher.update(&reference);
        let expected = hasher.finalize();
        assert_eq!(
            expected.get(DigestAlgorithm::Sha256).unwrap().to_hex(),
            nix_hash,
            "{tree}.nar is the dump nix-hash hashed"
        );
        assert_eq!(tree_digests(&inspect(&root)), &expected, "{tree}");
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} fixtures could be checked");
}
