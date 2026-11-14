//! `trustforge inspect`: describe an artifact and compute its digests.

use std::process::ExitCode;

use clap::Args;

use crate::EXIT_FAILED;
use crate::artifact::ArtifactArgs;
use crate::output::{self, Format, diagnostic};
use crate::render;
use crate::sanitize::sanitize;

/// Describe a file, directory or stream and compute its digests.
///
/// Reports what the artifact contains: its kind, size, format and SHA-256,
/// SHA-512 and BLAKE3 digests (for a directory, digests of its NAR
/// serialization). This verifies nothing: a digest identifies bytes, not who
/// produced them or whether they are safe.
#[derive(Debug, Args)]
pub struct InspectArgs {
    #[command(flatten)]
    artifact: ArtifactArgs,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

pub fn run(args: &InspectArgs) -> ExitCode {
    let Some(inspection) = args.artifact.inspect() else {
        return ExitCode::from(EXIT_FAILED);
    };
    let text = match args.format {
        Format::Text => render::text(&inspection),
        Format::Json => match render::json(&inspection) {
            Ok(text) => text,
            Err(e) => {
                diagnostic(&format!(
                    "error: cannot write the output: {}",
                    sanitize(&e.to_string())
                ));
                return ExitCode::from(EXIT_FAILED);
            }
        },
    };
    output::to_stdout(text.as_bytes(), ExitCode::SUCCESS)
}
