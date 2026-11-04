//! The `trustforge` command-line tool.
//!
//! Pre-alpha: only `--help` and `--version` exist. Commands are added one
//! milestone at a time (see `docs/roadmap.md`). None of them verifies
//! anything yet.

use clap::Parser;

/// Reproducible build verification engine (pre-alpha).
///
/// No verification commands are implemented yet. See docs/roadmap.md.
#[derive(Debug, Parser)]
#[command(name = "trustforge", version, arg_required_else_help = true)]
struct Cli {}

fn main() {
    Cli::parse();
}
