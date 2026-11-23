//! `trustforge report`: show a saved report again, without verifying
//! anything.

use std::process::ExitCode;

use clap::Args;
use trustforge_core::json::JsonLimits;
use trustforge_core::report::read_report;

use crate::input::read_document;
use crate::output::{self, diagnostic};
use crate::render_report::{self, Source};
use crate::sanitize::sanitize;
use crate::{EXIT_FAILED, EXIT_USAGE};

/// Show a report saved with `verify --format json`.
///
/// Nothing is verified again: the report is shown under the banner "loaded
/// from file: not re-verified; reports are unsigned". A saved report is never
/// evidence. It is read strictly, every status in it is recomputed from its
/// own evidence, and one whose recorded results do not follow is refused.
/// All explanations are regenerated, never taken from the file.
///
/// Exit codes: 0 shown (whatever the report says), 2 invalid or
/// inconsistent report, 4 the file could not be read.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// A saved report, or "-" to read standard input.
    path: String,

    /// Largest report to read, in bytes.
    #[arg(long, value_name = "BYTES", default_value_t = JsonLimits::default().max_bytes)]
    max_report_size: usize,
}

pub fn run(args: &ReportArgs) -> ExitCode {
    let (label, read) = read_document(&args.path, args.max_report_size);
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) => {
            diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let mut limits = JsonLimits::default();
    limits.max_bytes = args.max_report_size;
    match read_report(&bytes, &limits) {
        Ok(report) => output::to_stdout(
            render_report::text(&report, Source::Loaded).as_bytes(),
            ExitCode::SUCCESS,
        ),
        Err(e) => {
            diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
            ExitCode::from(EXIT_USAGE)
        }
    }
}
