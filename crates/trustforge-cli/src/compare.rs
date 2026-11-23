//! `trustforge compare`: whether two artifacts hold the same bytes.

use std::process::ExitCode;

use clap::Args;
use trustforge_core::compare::{CompareOptions, ComparisonOutcome, compare};

use crate::artifact::{LimitArgs, source};
use crate::output::{self, Format, diagnostic};
use crate::render_compare;
use crate::{EXIT_FAILED, EXIT_MISMATCH, EXIT_USAGE};

/// Compare two artifacts.
///
/// Inspects both with SHA-256, SHA-512 and BLAKE3. They MATCH only if they
/// are the same kind of artifact, with the same size and the same digests
/// (for directories, the same entries). A match shows that both hold the
/// same bytes, not that either can be trusted.
///
/// Exit codes: 0 match, 1 different, 2 usage error, 4 incomplete or failed.
#[derive(Debug, Args)]
pub struct CompareArgs {
    /// The first artifact: a file, a directory, or "-" for standard input.
    original: String,

    /// The second artifact. At most one side can be "-".
    candidate: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    #[command(flatten)]
    limits: LimitArgs,
}

pub fn run(args: &CompareArgs) -> ExitCode {
    if args.original == "-" && args.candidate == "-" {
        diagnostic("error: only one side can be read from standard input");
        return ExitCode::from(EXIT_USAGE);
    }
    let mut opts = CompareOptions::default();
    opts.limits = args.limits.limits();
    let comparison = compare(source(&args.original), source(&args.candidate), &opts);
    let code = ExitCode::from(match comparison.outcome() {
        ComparisonOutcome::Match => 0,
        ComparisonOutcome::Different => EXIT_MISMATCH,
        // INCOMPLETE, FAILED, and any outcome a later version adds: never
        // success.
        _ => EXIT_FAILED,
    });
    let bytes = match args.format {
        Format::Text => render_compare::text(&comparison).into_bytes(),
        Format::Json => comparison.to_pretty_json(),
    };
    output::to_stdout(&bytes, code)
}
