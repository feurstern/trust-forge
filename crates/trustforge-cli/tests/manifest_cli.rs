//! Command-line contract tests for `trustforge manifest create` and
//! `trustforge manifest validate`.
//!
//! Exit codes are documented in docs/verification-semantics.md: 0 success,
//! 2 usage error or invalid input document, 4 operation failed.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use assert_cmd::Command;
use serde_json::{Value, json};

fn trustforge() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trustforge"));
    cmd.timeout(Duration::from_secs(30));
    cmd
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/manifests/v0")
}

fn fixture(path: &str) -> String {
    std::fs::read_to_string(fixtures().join(path)).unwrap()
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(cmd: &mut Command) -> Run {
    let output = cmd.output().unwrap();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// The `buildDefinition` of the recipe fixture, as a standalone document.
fn recipe() -> Value {
    let manifest: Value = serde_json::from_str(&fixture("valid/file-recipe.json")).unwrap();
    manifest["predicate"]["buildDefinition"].clone()
}

#[test]
fn create_writes_the_pinned_manifest_for_standard_input() {
    let out = run(trustforge()
        .args(["manifest", "create", "--name", "hello.txt", "-"])
        .write_stdin("Hello, world.\n"));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stderr, "");
    assert_eq!(out.stdout, fixture("created/file.json"));
}

#[test]
fn create_can_write_the_canonical_form() {
    let out = run(trustforge()
        .args([
            "manifest",
            "create",
            "--canonical",
            "--name",
            "hello.txt",
            "-",
        ])
        .write_stdin("Hello, world.\n"));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stdout, fixture("canonical/created-file.json"));
}

#[test]
fn standard_input_needs_a_subject_name() {
    let out = run(trustforge()
        .args(["manifest", "create", "-"])
        .write_stdin("x"));
    assert_eq!(out.code, Some(2));
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("--name"), "{}", out.stderr);
}

#[test]
fn invalid_subject_names_are_usage_errors() {
    let out = run(trustforge()
        .args(["manifest", "create", "--name", "../escape", "-"])
        .write_stdin("x"));
    assert_eq!(out.code, Some(2), "{}", out.stderr);
    assert_eq!(out.stdout, "");
}

#[test]
fn a_recipe_file_is_validated_and_embedded() {
    let tmp = tempfile::tempdir().unwrap();
    let recipe_path = tmp.path().join("recipe.json");
    std::fs::write(&recipe_path, serde_json::to_vec(&recipe()).unwrap()).unwrap();
    let out = run(trustforge()
        .arg("manifest")
        .arg("create")
        .arg("--build-definition")
        .arg(&recipe_path)
        .args(["--name", "application", "-"])
        .write_stdin("TrustForge example binary\n"));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    let manifest: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(manifest["predicate"]["buildDefinition"], recipe());

    // A recipe that breaks a rule is refused before anything is inspected.
    let mut bad = recipe();
    bad["externalParameters"]["bin"] = json!("--config=evil");
    std::fs::write(&recipe_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let out = run(trustforge()
        .arg("manifest")
        .arg("create")
        .arg("--build-definition")
        .arg(&recipe_path)
        .args(["--name", "application", "-"])
        .write_stdin("x"));
    assert_eq!(out.code, Some(2));
    assert_eq!(out.stdout, "");
    assert!(
        out.stderr.contains("/externalParameters/bin"),
        "{}",
        out.stderr
    );
}

/// A misspelled build type would otherwise be embedded as an unsupported
/// recipe that nothing checked.
#[test]
fn create_refuses_an_unsupported_build_type() {
    let tmp = tempfile::tempdir().unwrap();
    let recipe_path = tmp.path().join("recipe.json");
    let mut misspelled = recipe();
    misspelled["buildType"] = json!("https://feurstern.github.io/trust-forge/build/cargo/V0");
    std::fs::write(&recipe_path, serde_json::to_vec(&misspelled).unwrap()).unwrap();
    let out = run(trustforge()
        .arg("manifest")
        .arg("create")
        .arg("--build-definition")
        .arg(&recipe_path)
        .args(["--name", "application", "-"])
        .write_stdin("x"));
    assert_eq!(out.code, Some(2), "{}", out.stderr);
    assert_eq!(out.stdout, "");
    assert!(
        out.stderr.contains(
            "build type https://feurstern.github.io/trust-forge/build/cargo/V0 is not supported"
        ),
        "{}",
        out.stderr
    );
}

#[test]
fn the_largest_size_limit_is_accepted() {
    let max = usize::MAX.to_string();
    let out = run(trustforge()
        .args(["manifest", "validate", "--max-manifest-size", &max])
        .arg(fixtures().join("valid/file-recipe.json")));
    assert_eq!(out.code, Some(0), "{}", out.stderr);

    let tmp = tempfile::tempdir().unwrap();
    let recipe_path = tmp.path().join("recipe.json");
    std::fs::write(&recipe_path, serde_json::to_vec(&recipe()).unwrap()).unwrap();
    let out = run(trustforge()
        .args(["manifest", "create", "--max-manifest-size", &max])
        .arg("--build-definition")
        .arg(&recipe_path)
        .args(["--name", "application", "-"])
        .write_stdin("x"));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

#[test]
fn an_oversized_manifest_is_not_written() {
    let out = run(trustforge()
        .args([
            "manifest",
            "create",
            "--max-manifest-size",
            "100",
            "--name",
            "x",
            "-",
        ])
        .write_stdin("x"));
    assert_eq!(out.code, Some(4));
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("--max-manifest-size"), "{}", out.stderr);
}

#[test]
fn validate_reports_a_valid_manifest() {
    let path = fixtures().join("valid/file-recipe.json");
    let out = run(trustforge().arg("manifest").arg("validate").arg(&path));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert_eq!(out.stderr, "");
    for expected in [
        "Recipe     cargo/v0: binary application for x86_64-unknown-linux-gnu, toolchain 1.99.1\n",
        "Source     https://github.com/example/project.git at refs/tags/v1.2.3, commit 8c3e1f6b2a9d4e5f60718293a4b5c6d7e8f90a1b\n",
        "Warnings   none\n",
        "A manifest is a claim, not evidence",
    ] {
        assert!(
            out.stdout.contains(expected),
            "missing {expected:?} in\n{}",
            out.stdout
        );
    }

    let out = run(trustforge()
        .arg("manifest")
        .arg("validate")
        .arg("--format=json")
        .arg(&path));
    assert_eq!(out.code, Some(0));
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(
        report["buildType"],
        "https://feurstern.github.io/trust-forge/build/cargo/v0"
    );
    assert_eq!(report["warnings"], json!([]));
    let bytes = std::fs::read(&path).unwrap();
    let expected = trustforge_core::digest::Digest::of(
        trustforge_core::digest::DigestAlgorithm::Sha256,
        &bytes,
    );
    assert_eq!(
        report["manifestDigest"]["sha256"],
        expected.to_hex(),
        "identity is the exact bytes"
    );
}

#[test]
fn validate_lists_warnings_and_strict_mode_rejects_them() {
    let path = fixtures().join("valid/extensions.json");
    let out = run(trustforge()
        .arg("manifest")
        .arg("validate")
        .arg("--format=json")
        .arg(&path));
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["warnings"].as_array().unwrap().len(), 7);
    assert_eq!(
        report["warnings"][0],
        json!({ "message": "unknown field, ignored", "pointer": "/x-note" })
    );

    let out = run(trustforge()
        .arg("manifest")
        .arg("validate")
        .arg("--strict")
        .arg(&path));
    assert_eq!(out.code, Some(2));
    assert_eq!(out.stdout, "");
    assert!(
        out.stderr.contains("/x-note: rejected in strict mode"),
        "{}",
        out.stderr
    );
}

#[test]
fn validate_rejects_invalid_documents() {
    let mut doc: Value = serde_json::from_str(&fixture("valid/file-recipe.json")).unwrap();
    doc["predicate"]["buildDefinition"]["internalParameters"]["env"]["LD_PRELOAD"] =
        json!("/tmp/x.so");
    let text = serde_json::to_string(&doc).unwrap();

    let out = run(trustforge()
        .args(["manifest", "validate", "-"])
        .write_stdin(text.clone()));
    assert_eq!(out.code, Some(2));
    assert_eq!(out.stdout, "");
    assert!(
        out.stderr
            .starts_with("error: (standard input): /predicate/buildDefinition/internalParameters/env/LD_PRELOAD: "),
        "{}",
        out.stderr
    );

    let out = run(trustforge()
        .args(["manifest", "validate", "--format", "json", "-"])
        .write_stdin(text));
    assert_eq!(out.code, Some(2));
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(
        report["error"]["pointer"],
        "/predicate/buildDefinition/internalParameters/env/LD_PRELOAD"
    );

    // Errors found while reading strict JSON have a location too.
    let duplicate = fixture("valid/file-minimal.json").replacen('{', r#"{"_type": "x","#, 1);
    let out = run(trustforge()
        .args(["manifest", "validate", "--format", "json", "-"])
        .write_stdin(duplicate));
    assert_eq!(out.code, Some(2));
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["error"]["pointer"], "/_type", "{report}");
}

#[test]
fn validate_never_prints_control_characters_from_a_document() {
    let hostile =
        fixture("valid/file-minimal.json").replace("\"tool\"", "\"to\\u001b]52;c;aGk=\\u0007ol\"");
    let out = run(trustforge()
        .args(["manifest", "validate", "--format", "json", "-"])
        .write_stdin(hostile));
    assert_eq!(out.code, Some(2));
    assert!(
        !out.stdout.contains(['\u{1b}', '\u{7}']),
        "{:?}",
        out.stdout
    );
    assert!(out.stdout.contains("U+001B"), "{}", out.stdout);
}

#[test]
fn oversized_and_missing_files() {
    let path = fixtures().join("valid/file-recipe.json");
    let out = run(trustforge()
        .args([
            "manifest",
            "validate",
            "--format",
            "json",
            "--max-manifest-size",
            "10",
        ])
        .arg(&path));
    assert_eq!(out.code, Some(2));
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(
        report["manifestDigest"],
        Value::Null,
        "a document read only in part is not hashed"
    );

    let out = run(trustforge().args(["manifest", "validate", "no/such/manifest.json"]));
    assert_eq!(out.code, Some(4));
    assert!(
        out.stderr.starts_with("error: no/such/manifest.json: "),
        "{}",
        out.stderr
    );
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};

    #[test]
    fn a_directory_manifest_matches_the_pinned_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(dist.join("bin")).unwrap();
        std::fs::write(dist.join("README"), b"Hello, world.\n").unwrap();
        std::fs::set_permissions(dist.join("README"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::write(dist.join("bin/hello"), b"#!/bin/sh\necho hello\n").unwrap();
        std::fs::set_permissions(
            dist.join("bin/hello"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("/usr/lib/libexample.so.1", dist.join("libexample.so")).unwrap();
        let out = run(trustforge()
            .current_dir(tmp.path())
            .args(["manifest", "create", "dist"]));
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_eq!(out.stdout, fixture("created/directory.json"));
    }

    fn create_to(path: &Path) -> Run {
        run(trustforge()
            .args(["manifest", "create", "--name", "hello.txt", "-o"])
            .arg(path)
            .arg("-")
            .write_stdin("Hello, world.\n"))
    }

    #[test]
    fn output_files_replace_a_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let out_path = tmp.path().join("app.manifest.json");
        std::fs::write(&out_path, b"old").unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = create_to(&out_path);
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_eq!(out.stdout, "");
        let metadata = std::fs::symlink_metadata(&out_path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read_to_string(&out_path).unwrap(),
            fixture("created/file.json")
        );
    }

    /// Renaming over anything but a regular file would replace the entry
    /// itself: a symlink planted in a shared directory, a FIFO, or as root
    /// `/dev/null` or `/dev/stdout`.
    #[test]
    fn output_files_never_replace_anything_else() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, b"must not change").unwrap();
        let link = tmp.path().join("link.json");
        symlink(&victim, &link).unwrap();
        let fifo = tmp.path().join("fifo.json");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let directory = tmp.path().join("directory.json");
        std::fs::create_dir(&directory).unwrap();

        for path in [&link, &fifo, &directory, Path::new("/dev/null")] {
            let out = create_to(path);
            assert_eq!(out.code, Some(4), "{}: {}", path.display(), out.stderr);
            assert_eq!(out.stdout, "");
            assert!(
                out.stderr.contains("not a regular file"),
                "{}: {}",
                path.display(),
                out.stderr
            );
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"must not change");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert!(std::fs::symlink_metadata(&directory).unwrap().is_dir());
    }
}
