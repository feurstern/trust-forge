//! The `trustforge` command-line tool.
//!
//! Pre-alpha: `inspect` describes and hashes an artifact, `manifest` creates
//! and validates manifests, `verify` compares an artifact with references,
//! `compare` compares two artifacts, and `report` shows a saved report.
//! Commands are added one milestone at a time (see `docs/roadmap.md`). This
//! version can establish integrity only.
//!
//! Exit codes (`docs/verification-semantics.md`): 0 success, 1 mismatch,
//! 2 usage error or invalid input document, 3 policy not satisfied,
//! 4 operation failed, 101 internal error (panic).

mod artifact;
mod compare;
mod input;
mod inspect;
mod manifest;
mod output;
mod render;
mod render_compare;
mod render_report;
mod report;
mod sanitize;
mod verify;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Artifact integrity and reproducible build verification (pre-alpha).
///
/// This version establishes integrity only: whether an artifact's bytes are
/// the ones a reference describes. Authenticity, provenance and
/// reproducibility are reported as not evaluated. See docs/roadmap.md.
#[derive(Debug, Parser)]
#[command(name = "trustforge", version, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect(inspect::InspectArgs),
    /// Create and validate manifests: in-toto Statements that claim an
    /// artifact's digests and the recipe that builds it.
    #[command(subcommand)]
    Manifest(manifest::ManifestCommand),
    Verify(verify::VerifyArgs),
    Compare(compare::CompareArgs),
    Report(report::ReportArgs),
}

/// Exit code for a mismatch: evidence contradicts a claim, or two artifacts
/// differ.
const EXIT_MISMATCH: u8 = 1;

/// Exit code for a usage error or an invalid input document.
const EXIT_USAGE: u8 = 2;

/// Exit code for a verification that does not satisfy its policy.
const EXIT_POLICY: u8 = 3;

/// Exit code for an operation that could not be completed.
const EXIT_FAILED: u8 = 4;

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Inspect(args) => inspect::run(&args),
        Command::Manifest(command) => manifest::run(&command),
        Command::Verify(args) => verify::run(&args),
        Command::Compare(args) => compare::run(&args),
        Command::Report(args) => report::run(&args),
    }
}
