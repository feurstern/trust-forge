//! The `trustforge` command-line tool.
//!
//! Pre-alpha: `inspect` describes and hashes an artifact. Commands are added
//! one milestone at a time (see `docs/roadmap.md`). None of them verifies
//! anything yet.
//!
//! Exit codes (`docs/verification-semantics.md`): 0 success, 2 usage error,
//! 4 operation failed, 101 internal error (panic).

mod inspect;
mod render;
mod sanitize;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Reproducible build verification engine (pre-alpha).
///
/// Nothing is verified yet: `inspect` reports what an artifact contains,
/// not whether it can be trusted. See docs/roadmap.md.
#[derive(Debug, Parser)]
#[command(name = "trustforge", version, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect(inspect::InspectArgs),
}

/// Exit code for an operation that could not be completed.
const EXIT_FAILED: u8 = 4;

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Inspect(args) => inspect::run(&args),
    }
}
