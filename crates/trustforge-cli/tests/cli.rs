//! Command-line contract tests: exit codes, stdout discipline and output
//! formats.
//!
//! Exit codes are documented in docs/verification-semantics.md: 0 success,
//! 2 usage error, 4 operation failed.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use assert_cmd::Command;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

fn trustforge() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trustforge"));
    // Nothing the tool does should ever take long; never let a test hang.
    cmd.timeout(Duration::from_secs(30));
    cmd
}

fn stdout_of(cmd: &mut Command) -> String {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

const ABC_JSON: &str = r#"{
  "digest": {
    "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha512": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  },
  "format": {
    "type": "unknown"
  },
  "kind": "stream",
  "name": "-",
  "rootSymlinkFollowed": false,
  "size": 3
}
"#;

/// Fails unless every JSON object in the input has its keys in sorted order.
struct SortedKeys;

impl<'de> DeserializeSeed<'de> for SortedKeys {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for SortedKeys {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut previous: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            if previous.as_ref().is_some_and(|p| *p >= key) {
                return Err(serde::de::Error::custom(format!(
                    "key {key:?} after {previous:?}"
                )));
            }
            map.next_value_seed(SortedKeys)?;
            previous = Some(key);
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(SortedKeys)?.is_some() {}
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
}

/// Parses `text` as exactly one JSON document with sorted keys everywhere.
fn assert_single_sorted_json(text: &str) -> serde_json::Value {
    let mut de = serde_json::Deserializer::from_str(text);
    SortedKeys.deserialize(&mut de).unwrap();
    de.end().unwrap();
    // serde_json::from_str also rejects trailing data.
    serde_json::from_str(text).unwrap()
}

#[test]
fn version_prints_name_and_version_on_stdout_only() {
    trustforge()
        .arg("--version")
        .assert()
        .success()
        .stdout(concat!("trustforge ", env!("CARGO_PKG_VERSION"), "\n"))
        .stderr("");
}

#[test]
fn bare_invocation_is_a_usage_error() {
    trustforge().assert().code(2).stdout("");
}

#[test]
fn unknown_flag_is_a_usage_error() {
    trustforge()
        .arg("--no-such-flag")
        .assert()
        .code(2)
        .stdout("");
}

#[test]
fn stdin_json_is_one_sorted_document() {
    let stdout = stdout_of(
        trustforge()
            .args(["inspect", "--format", "json", "-"])
            .write_stdin("abc"),
    );
    assert_eq!(stdout, ABC_JSON);
    assert_single_sorted_json(&stdout);
}

#[test]
fn stdin_text_names_the_stream_and_ends_with_the_caveat() {
    let stdout = stdout_of(trustforge().args(["inspect", "-"]).write_stdin("abc"));
    assert!(
        stdout.starts_with("Artifact   (standard input)\nKind       stream\nSize       3 bytes\n"),
        "{stdout}"
    );
    assert!(stdout.contains(
        "\nsha256     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    ));
    assert!(stdout.ends_with(
        "\nDigests identify these bytes. They do not show who produced them or whether they are safe.\n"
    ));
}

#[test]
fn algorithms_can_be_selected() {
    let stdout = stdout_of(
        trustforge()
            .args(["inspect", "--format", "json", "-a", "sha256,blake3", "-"])
            .write_stdin("abc"),
    );
    let json = assert_single_sorted_json(&stdout);
    let digests = json["digest"].as_object().unwrap();
    assert_eq!(digests.keys().collect::<Vec<_>>(), ["blake3", "sha256"]);
}

#[test]
fn a_file_is_inspected() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("abc.txt"), b"abc").unwrap();
    let stdout = stdout_of(
        trustforge()
            .current_dir(tmp.path())
            .args(["inspect", "--format", "json", "abc.txt"]),
    );
    let json = assert_single_sorted_json(&stdout);
    assert_eq!(json["kind"], "file");
    assert_eq!(json["name"], "abc.txt");
    assert_eq!(json["size"], 3);
    assert_eq!(
        json["digest"],
        serde_json::from_str::<serde_json::Value>(ABC_JSON).unwrap()["digest"]
    );
    assert!(
        json.get("mode").is_none() && json.get("modified").is_none(),
        "no file-system metadata in JSON"
    );
}

#[test]
fn unknown_algorithms_are_usage_errors() {
    for algorithm in ["md5", "sha1", "SHA256"] {
        trustforge()
            .args(["inspect", "--algorithm", algorithm, "-"])
            .write_stdin("abc")
            .assert()
            .code(2)
            .stdout("");
    }
}

#[test]
fn a_missing_path_fails_with_code_4_and_names_it() {
    let output = trustforge()
        .args(["inspect", "no/such/file"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("error: no/such/file: "), "{stderr}");
}

#[test]
fn an_exceeded_limit_names_the_flag_that_raises_it() {
    let output = trustforge()
        .args(["inspect", "--max-bytes", "2", "-"])
        .write_stdin("abc")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("more than 2 content bytes"), "{stderr}");
    assert!(stderr.contains("--max-bytes"), "{stderr}");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    fn build_tree(root: &Path) {
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/tool"), b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(
            root.join("bin/tool"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(root.join("README"), b"hello\n").unwrap();
        symlink("/usr/lib/libc.so.6", root.join("libc")).unwrap();
    }

    #[test]
    fn a_directory_is_inspected_in_text_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        build_tree(&tmp.path().join("tree"));

        let text = stdout_of(
            trustforge()
                .current_dir(tmp.path())
                .args(["inspect", "tree"]),
        );
        assert!(
            text.contains("Kind       directory: 2 files, 1 subdirectory, 1 symbolic link\n"),
            "{text}"
        );
        assert!(text.contains("\nnarSha256  "), "{text}");
        assert!(
            text.contains("These point outside the tree:\n  libc -> /usr/lib/libc.so.6\n"),
            "{text}"
        );

        let json = assert_single_sorted_json(&stdout_of(
            trustforge()
                .current_dir(tmp.path())
                .args(["inspect", "--format", "json", "tree"]),
        ));
        assert_eq!(json["kind"], "directory");
        assert!(json.get("digest").is_none());
        let tree_digest = json["treeDigest"].as_object().unwrap();
        assert_eq!(
            tree_digest.keys().collect::<Vec<_>>(),
            ["narBlake3", "narSha256", "narSha512"]
        );
        let paths: Vec<&str> = json["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, ["README", "bin", "bin/tool", "libc"]);
        assert_eq!(json["entries"][2]["executable"], true);
        assert_eq!(json["entries"][3]["targetLeavesTree"], true);
    }

    #[test]
    fn identical_trees_give_identical_json() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        build_tree(&first.path().join("tree"));
        build_tree(&second.path().join("tree"));
        let run = |dir: &Path| {
            stdout_of(
                trustforge()
                    .current_dir(dir)
                    .args(["inspect", "--format", "json", "tree"]),
            )
        };
        assert_eq!(run(first.path()), run(second.path()));
    }

    #[test]
    fn a_fifo_fails_fast() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let output = trustforge()
            .timeout(Duration::from_secs(10))
            .arg("inspect")
            .arg(&fifo)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("FIFO"));
    }

    #[test]
    fn a_non_utf8_path_is_a_usage_error() {
        use std::os::unix::ffi::OsStrExt;
        trustforge()
            .arg("inspect")
            .arg(std::ffi::OsStr::from_bytes(b"bad\xff"))
            .assert()
            .code(2)
            .stdout("");
    }

    #[test]
    fn hostile_names_never_reach_the_terminal_raw() {
        let tmp = tempfile::tempdir().unwrap();
        // A root path that tries to clear the screen and set the clipboard.
        let hostile = "x\u{1b}[2J\u{1b}]52;c;aGk=\u{7}\u{202e}y";
        std::fs::write(tmp.path().join(hostile), b"abc").unwrap();
        let output = trustforge()
            .current_dir(tmp.path())
            .args(["inspect", hostile])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains(r"x\u{1b}[2J\u{1b}]52;c;aGk=\u{7}\u{202e}y"),
            "{stdout}"
        );
        assert!(!stdout.contains(['\u{1b}', '\u{7}', '\u{202e}']));

        // JSON keeps the exact name, spelled with escapes a terminal ignores.
        let hostile_c1 = format!("{hostile}\u{9b}31m\u{7f}\u{2028}");
        std::fs::write(tmp.path().join(&hostile_c1), b"abc").unwrap();
        let output = trustforge()
            .current_dir(tmp.path())
            .args(["inspect", "--format", "json", hostile_c1.as_str()])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            !stdout.contains([
                '\u{1b}', '\u{7}', '\u{202e}', '\u{9b}', '\u{7f}', '\u{2028}'
            ]),
            "{stdout:?}"
        );
        assert_eq!(
            assert_single_sorted_json(&stdout)["name"],
            hostile_c1.as_str()
        );

        // An entry inside a directory: rejected, and escaped in the error.
        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(hostile), b"abc").unwrap();
        let output = trustforge()
            .current_dir(tmp.path())
            .args(["inspect", "dir"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("invalid name"), "{stderr}");
        assert!(
            !stderr.contains(['\u{1b}', '\u{7}', '\u{202e}']),
            "{stderr:?}"
        );
    }

    #[test]
    fn running_out_of_file_descriptors_is_a_clean_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let mut deep = tmp.path().join("deep");
        for level in 0..40 {
            deep.push(format!("d{level}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"ulimit -n 24 && exec "$0" inspect "$1""#)
            .arg(env!("CARGO_BIN_EXE_trustforge"))
            .arg(tmp.path().join("deep"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(4), "{stderr}");
        assert!(stderr.starts_with("error: "), "{stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
    }

    #[test]
    fn a_closed_standard_error_does_not_turn_a_failure_into_a_crash() {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"exec "$0" inspect does-not-exist 2>&-"#)
            .arg(env!("CARGO_BIN_EXE_trustforge"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
    }

    #[test]
    fn an_exceeded_entry_limit_names_its_flag() {
        let tmp = tempfile::tempdir().unwrap();
        build_tree(&tmp.path().join("tree"));
        let output = trustforge()
            .current_dir(tmp.path())
            .args(["inspect", "--max-entries", "2", "tree"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--max-entries"));
    }
}

#[cfg(windows)]
#[test]
fn directories_are_unsupported_on_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let output = trustforge()
        .arg("inspect")
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not supported"));
}
