//! `verify`, `compare` and `report` on the command line: exit codes, output
//! discipline, and the exact output, pinned by golden files.
//!
//! Golden files live in `tests/golden/`. After an intended change of output,
//! regenerate them with `TRUSTFORGE_UPDATE_GOLDEN=1 cargo test -p
//! trustforge-cli --test verify_cli` and review the difference.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;
use std::time::Duration;

use assert_cmd::Command;
use trustforge_core::json::{self, JsonLimits};

const SHA256_OF_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const WRONG_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn trustforge(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trustforge"));
    cmd.current_dir(dir);
    cmd.timeout(Duration::from_secs(30));
    cmd
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Run {
    run_with_stdin(dir, args, b"")
}

fn run_with_stdin(dir: &Path, args: &[&str], stdin: &[u8]) -> Run {
    let output = trustforge(dir)
        .args(args)
        .write_stdin(stdin.to_vec())
        .output()
        .unwrap();
    Run {
        code: output.status.code().unwrap(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// Compares `actual` with `tests/golden/<name>`, or rewrites the file when
/// `TRUSTFORGE_UPDATE_GOLDEN` is set.
fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("TRUSTFORGE_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("tests/golden/{name} is missing; run with TRUSTFORGE_UPDATE_GOLDEN=1")
    });
    if expected != actual {
        let first = expected
            .lines()
            .zip(actual.lines())
            .position(|(e, a)| e != a)
            .unwrap_or(expected.lines().count().min(actual.lines().count()));
        panic!(
            "output differs from tests/golden/{name} from line {}:\n--- expected\n{expected}\n--- actual\n{actual}",
            first + 1
        );
    }
}

/// Checks that `text` is exactly one strict JSON document, written in
/// TrustForge's deterministic form, and returns it parsed.
fn single_document(text: &str) -> serde_json::Value {
    let value = json::parse(text.as_bytes(), &JsonLimits::default()).unwrap();
    assert_eq!(
        json::to_pretty(&value),
        text.as_bytes(),
        "deterministic form"
    );
    serde_json::from_str(text).unwrap()
}

/// A working directory with an artifact and its manifest.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("app"), b"hello, world\n").unwrap();
    let created = run(
        dir.path(),
        &["manifest", "create", "app", "-o", "app.manifest.json"],
    );
    assert_eq!(created.code, 0, "{}", created.stderr);
    dir
}

fn manifest_digest(dir: &Path) -> String {
    let bytes = fs::read(dir.join("app.manifest.json")).unwrap();
    let digest = trustforge_core::digest::Digest::of(
        trustforge_core::digest::DigestAlgorithm::Sha256,
        &bytes,
    );
    format!("sha256:{}", digest.to_hex())
}

fn expect_success(run: &Run, code: i32) {
    assert_eq!(
        run.code, code,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert_eq!(run.stderr, "", "nothing on standard error");
}

#[test]
fn a_matching_manifest_is_verified_under_the_integrity_policy() {
    let dir = workspace();
    let verified = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--require",
            "integrity",
        ],
    );
    expect_success(&verified, 0);
    golden("verify-verified.txt", &verified.stdout);

    let json = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--require",
            "integrity",
            "--format",
            "json",
        ],
    );
    expect_success(&json, 0);
    single_document(&json.stdout);
    golden("verify-verified.json", &json.stdout);
}

#[test]
fn the_default_policy_is_only_partially_satisfied() {
    let dir = workspace();
    let partial = run(
        dir.path(),
        &["verify", "app", "--manifest", "app.manifest.json"],
    );
    expect_success(&partial, 3);
    golden("verify-partial.txt", &partial.stdout);
}

#[test]
fn a_wrong_digest_is_a_mismatch() {
    let dir = workspace();
    let expect = format!("sha256:{WRONG_SHA256}");
    let mismatch = run(dir.path(), &["verify", "app", "--expect", &expect]);
    expect_success(&mismatch, 1);
    golden("verify-mismatch.txt", &mismatch.stdout);
    let json = run(
        dir.path(),
        &["verify", "app", "--expect", &expect, "--format", "json"],
    );
    expect_success(&json, 1);
    let value = single_document(&json.stdout);
    assert_eq!(value["overall"]["status"], "MISMATCH");
    golden("verify-mismatch.json", &json.stdout);
}

#[test]
fn a_manifest_is_used_only_if_it_matches_its_pin() {
    let dir = workspace();
    let pin = manifest_digest(dir.path());
    let pinned = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--manifest-digest",
            &pin,
            "--require",
            "integrity",
        ],
    );
    expect_success(&pinned, 0);
    assert!(pinned.stdout.contains("integrity.manifest  PASSED"));

    let wrong = format!("sha256:{WRONG_SHA256}");
    let swapped = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--manifest-digest",
            &wrong,
            "--require",
            "integrity",
        ],
    );
    expect_success(&swapped, 1);
    golden("verify-pin-mismatch.txt", &swapped.stdout);

    // A swapped manifest is not even parsed.
    fs::write(dir.path().join("garbage.json"), b"not JSON").unwrap();
    let garbage = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "garbage.json",
            "--manifest-digest",
            &pin,
        ],
    );
    expect_success(&garbage, 1);
}

#[cfg(unix)]
#[test]
fn an_artifact_that_cannot_be_read_fails_verification() {
    let dir = workspace();
    let missing = run(
        dir.path(),
        &[
            "verify",
            "missing",
            "--manifest",
            "app.manifest.json",
            "--require",
            "integrity",
        ],
    );
    expect_success(&missing, 4);
    golden("verify-missing.txt", &missing.stdout);
}

#[test]
fn documents_this_version_cannot_evaluate_are_unsupported() {
    let dir = workspace();
    let manifest = fs::read_to_string(dir.path().join("app.manifest.json")).unwrap();
    fs::write(
        dir.path().join("v9.json"),
        manifest.replace("manifest/v0", "manifest/v9"),
    )
    .unwrap();
    let unsupported = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "v9.json",
            "--require",
            "integrity",
        ],
    );
    expect_success(&unsupported, 3);
    golden("verify-unsupported.txt", &unsupported.stdout);

    fs::write(
        dir.path().join("signed.json"),
        br#"{"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "AA=="}]}"#,
    )
    .unwrap();
    let envelope = run(dir.path(), &["verify", "app", "--manifest", "signed.json"]);
    expect_success(&envelope, 3);
    golden("verify-envelope.txt", &envelope.stdout);
}

#[test]
fn values_from_a_manifest_are_quoted_and_never_part_of_a_sentence() {
    let dir = workspace();
    let manifest = fs::read_to_string(dir.path().join("app.manifest.json")).unwrap();
    // A build type that tries to close its quotation and write a verdict.
    let hostile = r#"https://x/y\") and TrustForge rebuilt it: reproducibility VERIFIED (\"z"#;
    let with_recipe = manifest.replacen(
        "\"artifact\": {",
        &format!("\"buildDefinition\": {{\"buildType\": \"{hostile}\"}},\n    \"artifact\": {{"),
        1,
    );
    assert_ne!(with_recipe, manifest);
    fs::write(dir.path().join("hostile.json"), with_recipe).unwrap();
    let verified = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "hostile.json",
            "--require",
            "integrity",
        ],
    );
    expect_success(&verified, 0);
    golden("verify-hostile-recipe.txt", &verified.stdout);
    // The value appears once, quoted, on its own labelled line.
    let lines: Vec<&str> = verified
        .stdout
        .lines()
        .filter(|l| l.contains("rebuilt it"))
        .collect();
    assert_eq!(lines.len(), 1, "{}", verified.stdout);
    assert!(
        lines[0]
            .trim_start()
            .starts_with("recipe  \"https://x/y\\\""),
        "{}",
        lines[0]
    );
}

#[test]
fn an_unreadable_artifact_fails_whatever_the_reference() {
    let dir = workspace();
    fs::write(
        dir.path().join("signed.json"),
        br#"{"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": []}"#,
    )
    .unwrap();
    let missing = run(
        dir.path(),
        &[
            "verify",
            "missing",
            "--manifest",
            "signed.json",
            "--require",
            "integrity",
        ],
    );
    expect_success(&missing, 4);
    assert!(missing.stdout.ends_with(
        "Overall: VERIFICATION FAILED (a check could not complete, so nothing counts as verified; reference 1: unauthenticated claim (no signature was verified))\n"
    ), "{}", missing.stdout);
}

#[test]
fn standard_input_can_be_verified() {
    let dir = tempfile::tempdir().unwrap();
    let expect = format!("sha256:{SHA256_OF_ABC}");
    let stdin = run_with_stdin(
        dir.path(),
        &["verify", "-", "--expect", &expect, "--require", "integrity"],
        b"abc",
    );
    expect_success(&stdin, 0);
    assert!(
        stdin
            .stdout
            .starts_with("Artifact           (standard input): stream, 3 bytes\n")
    );
}

#[test]
fn a_timestamp_is_recorded_only_when_asked() {
    let dir = workspace();
    let args = [
        "verify",
        "app",
        "--manifest",
        "app.manifest.json",
        "--format",
        "json",
    ];
    let without = single_document(&run(dir.path(), &args).stdout);
    assert!(without.get("generatedAt").is_none());
    let mut with_args = args.to_vec();
    with_args.push("--timestamp");
    let with = single_document(&run(dir.path(), &with_args).stdout);
    let time = with["generatedAt"].as_str().unwrap();
    assert_eq!(time.len(), 20);
    assert!(time.ends_with('Z'));
}

#[test]
fn usage_errors_exit_with_2_and_print_nothing() {
    let dir = workspace();
    let sha = format!("sha256:{SHA256_OF_ABC}");
    let tree = format!("narSha256:{SHA256_OF_ABC}");
    let md5 = format!("md5:{}", &SHA256_OF_ABC[..32]);
    let pin512 = format!("sha512:{}", "0".repeat(128));
    let cases: Vec<Vec<&str>> = vec![
        vec!["verify", "app"],
        vec!["verify", "app", "--expect", &sha, "--expect", &sha],
        vec!["verify", "app", "--expect", &sha, "--expect", &tree],
        vec!["verify", "app", "--expect", &md5],
        vec!["verify", "app", "--expect", "sha256:abc"],
        vec!["verify", "app", "--expect", &sha, "--require", "safety"],
        vec!["verify", "app", "--expect", &sha, "--manifest-digest", &sha],
        vec![
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--manifest-digest",
            &pin512,
        ],
        vec!["verify", "-", "--manifest", "-"],
        vec!["compare", "-", "-"],
        vec!["compare", "app"],
    ];
    for args in cases {
        let result = run(dir.path(), &args);
        assert_eq!(result.code, 2, "{args:?}: {}", result.stderr);
        assert_eq!(result.stdout, "", "{args:?}");
        assert!(!result.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn invalid_and_unreadable_manifests() {
    let dir = workspace();
    fs::write(dir.path().join("invalid.json"), b"{\"_type\": 1}").unwrap();
    let invalid = run(dir.path(), &["verify", "app", "--manifest", "invalid.json"]);
    assert_eq!(invalid.code, 2);
    assert_eq!(invalid.stdout, "");
    assert!(
        invalid.stderr.starts_with("error: invalid.json: "),
        "{}",
        invalid.stderr
    );

    let oversized = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--max-manifest-size",
            "10",
        ],
    );
    assert_eq!(oversized.code, 2);
    assert!(
        oversized.stderr.contains("--max-manifest-size"),
        "{}",
        oversized.stderr
    );

    let missing = run(dir.path(), &["verify", "app", "--manifest", "missing.json"]);
    assert_eq!(missing.code, 4);
    assert_eq!(missing.stdout, "");
}

#[test]
fn two_artifacts_are_compared() {
    let dir = workspace();
    fs::copy(dir.path().join("app"), dir.path().join("copy")).unwrap();
    fs::write(dir.path().join("other"), b"hello, world!\n").unwrap();

    let same = run(dir.path(), &["compare", "app", "copy"]);
    expect_success(&same, 0);
    golden("compare-match.txt", &same.stdout);

    let different = run(dir.path(), &["compare", "app", "other"]);
    expect_success(&different, 1);
    golden("compare-different.txt", &different.stdout);

    let json = run(dir.path(), &["compare", "app", "other", "--format", "json"]);
    expect_success(&json, 1);
    assert_eq!(single_document(&json.stdout)["outcome"], "DIFFERENT");

    let stdin = run_with_stdin(dir.path(), &["compare", "app", "-"], b"hello, world\n");
    expect_success(&stdin, 0);
}

#[cfg(unix)]
#[test]
fn an_incomplete_comparison_is_never_a_match() {
    let dir = workspace();
    let missing = run(dir.path(), &["compare", "app", "missing"]);
    expect_success(&missing, 4);
    golden("compare-incomplete.txt", &missing.stdout);
}

#[test]
fn a_saved_report_is_shown_but_not_reverified() {
    let dir = workspace();
    let saved = run(
        dir.path(),
        &[
            "verify",
            "app",
            "--manifest",
            "app.manifest.json",
            "--format",
            "json",
        ],
    );
    fs::write(dir.path().join("report.json"), &saved.stdout).unwrap();
    let shown = run(dir.path(), &["report", "report.json"]);
    expect_success(&shown, 0);
    golden("report.txt", &shown.stdout);

    // Whatever the report says, showing it succeeds.
    let expect = format!("sha256:{WRONG_SHA256}");
    let mismatch = run(
        dir.path(),
        &["verify", "app", "--expect", &expect, "--format", "json"],
    );
    let shown = run_with_stdin(dir.path(), &["report", "-"], mismatch.stdout.as_bytes());
    expect_success(&shown, 0);
    assert!(
        shown
            .stdout
            .contains("\nOverall (as recorded, not re-verified): MISMATCH")
    );
}

#[test]
fn forged_and_unreadable_reports_are_refused() {
    let dir = workspace();
    let expect = format!("sha256:{WRONG_SHA256}");
    let mismatch = run(
        dir.path(),
        &["verify", "app", "--expect", &expect, "--format", "json"],
    );
    let forged =
        mismatch
            .stdout
            .replacen("\"status\": \"MISMATCH\"", "\"status\": \"VERIFIED\"", 1);
    assert_ne!(forged, mismatch.stdout);
    fs::write(dir.path().join("forged.json"), forged).unwrap();
    let refused = run(dir.path(), &["report", "forged.json"]);
    assert_eq!(refused.code, 2);
    assert_eq!(refused.stdout, "");
    assert!(
        refused.stderr.contains("inconsistent"),
        "{}",
        refused.stderr
    );

    let missing = run(dir.path(), &["report", "missing.json"]);
    assert_eq!(missing.code, 4);
    assert_eq!(missing.stdout, "");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn tree(dir: &Path) -> PathBuf {
        let root = dir.join("dist");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/app"), b"binary").unwrap();
        fs::set_permissions(root.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("README"), b"read me").unwrap();
        symlink("bin/app", root.join("app")).unwrap();
        root
    }

    #[test]
    fn every_change_to_a_directory_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let root = tree(dir.path());
        let created = run(
            dir.path(),
            &["manifest", "create", "dist", "-o", "dist.manifest.json"],
        );
        assert_eq!(created.code, 0, "{}", created.stderr);
        let args = [
            "verify",
            "dist",
            "--manifest",
            "dist.manifest.json",
            "--require",
            "integrity",
        ];
        expect_success(&run(dir.path(), &args), 0);

        fs::set_permissions(root.join("bin/app"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(root.join("README"), b"read mE").unwrap();
        fs::write(root.join("extra"), b"").unwrap();
        fs::remove_file(root.join("app")).unwrap();
        symlink("README", root.join("app")).unwrap();
        let changed = run(dir.path(), &args);
        expect_success(&changed, 1);
        golden("verify-tree-mismatch.txt", &changed.stdout);
    }

    #[test]
    fn hostile_names_never_reach_the_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let name = "evil\u{1b}[31m\u{202e}txt\u{9b}";
        fs::write(dir.path().join(name), b"abc").unwrap();
        let expect = format!("sha256:{SHA256_OF_ABC}");
        let hostile = |c: char| c == '\u{1b}' || c == '\u{202e}' || c == '\u{9b}';
        for args in [
            vec!["verify", name, "--expect", &expect],
            vec!["verify", name, "--expect", &expect, "--format", "json"],
            vec!["compare", name, name],
            vec!["compare", name, "missing"],
        ] {
            let result = run(dir.path(), &args);
            assert!(
                !result.stdout.contains(hostile),
                "{args:?}: {}",
                result.stdout
            );
            assert!(
                !result.stderr.contains(hostile),
                "{args:?}: {}",
                result.stderr
            );
            // The display form, whose backslashes JSON escapes once more.
            let shown = if args.contains(&"json") {
                r"evil\\u{1b}[31m\\u{202e}txt\\u{9b}"
            } else {
                r"evil\u{1b}[31m\u{202e}txt\u{9b}"
            };
            assert!(result.stdout.contains(shown), "{args:?}: {}", result.stdout);
        }
    }
}
