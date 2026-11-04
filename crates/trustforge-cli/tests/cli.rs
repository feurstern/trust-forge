//! Command-line contract tests: exit codes and stdout discipline.
//!
//! Exit code 2 is the documented code for usage errors
//! (see docs/verification-semantics.md).

use assert_cmd::Command;

fn trustforge() -> Command {
    Command::new(env!("CARGO_BIN_EXE_trustforge"))
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
