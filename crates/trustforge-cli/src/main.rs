//! The `trustforge` command-line tool.
//!
//! Pre-alpha: `inspect` describes and hashes an artifact, and `manifest`
//! creates and validates manifests. Commands are added one milestone at a
//! time (see `docs/roadmap.md`). None of them verifies anything yet.
//!
//! Exit codes (`docs/verification-semantics.md`): 0 success, 2 usage error or
//! invalid input document, 4 operation failed, 101 internal error (panic).

mod artifact;
mod inspect;
mod manifest;
mod output;
mod render;
mod sanitize;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Reproducible build verification engine (pre-alpha).
///
/// Nothing is verified yet: `inspect` reports what an artifact contains, and
/// `manifest` writes and checks claims about it, but nothing establishes
/// whether it can be trusted. See docs/roadmap.md.
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
}

/// Exit code for a usage error or an invalid input document.
const EXIT_USAGE: u8 = 2;

/// Exit code for an operation that could not be completed.
const EXIT_FAILED: u8 = 4;

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Inspect(args) => inspect::run(&args),
        Command::Manifest(command) => manifest::run(&command),
    }
}
