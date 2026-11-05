//! `trustforge inspect`: describe an artifact and compute its digests.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm};
use trustforge_core::inspect::{
    InspectError, InspectOptions, Limit, Limits, inspect_path, inspect_reader,
};

use crate::EXIT_FAILED;
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
    /// File or directory to inspect, or "-" to read standard input.
    path: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Digest algorithm to compute; repeat or separate with commas.
    /// [default: all]
    #[arg(
        short = 'a',
        long = "algorithm",
        value_enum,
        value_delimiter = ',',
        value_name = "ALGORITHM"
    )]
    algorithms: Vec<Algorithm>,

    /// Fail instead of reading more than this many content bytes.
    #[arg(long, value_name = "BYTES", default_value_t = Limits::default().max_bytes)]
    max_bytes: u64,

    /// Fail on a directory with more entries than this.
    #[arg(long, value_name = "N", default_value_t = Limits::default().max_entries)]
    max_entries: u64,

    /// Fail on a directory nested deeper than this.
    #[arg(long, value_name = "N", default_value_t = Limits::default().max_depth)]
    max_depth: u32,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    /// Human-readable text.
    Text,
    /// One JSON document.
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Algorithm {
    Sha256,
    Sha512,
    Blake3,
}

impl From<Algorithm> for DigestAlgorithm {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha256 => DigestAlgorithm::Sha256,
            Algorithm::Sha512 => DigestAlgorithm::Sha512,
            Algorithm::Blake3 => DigestAlgorithm::Blake3,
        }
    }
}

pub fn run(args: &InspectArgs) -> ExitCode {
    let mut opts = InspectOptions::default();
    if let Ok(algorithms) = AlgorithmSet::new(args.algorithms.iter().map(|&a| a.into())) {
        opts.algorithms = algorithms;
    }
    opts.limits.max_bytes = args.max_bytes;
    opts.limits.max_entries = args.max_entries;
    opts.limits.max_depth = args.max_depth;

    let result = if args.path == "-" {
        inspect_reader("-", io::stdin().lock(), &opts)
    } else {
        inspect_path(Path::new(&args.path), &opts)
    };
    let inspection = match result {
        Ok(inspection) => inspection,
        Err(err) => {
            report(&err);
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let output = match args.format {
        Format::Text => Ok(render::text(&inspection)),
        Format::Json => render::json(&inspection),
    };
    let written = output.map_err(io::Error::from).and_then(|text| {
        let mut stdout = io::stdout().lock();
        stdout.write_all(text.as_bytes())?;
        stdout.flush()
    });
    match written {
        Ok(()) => ExitCode::SUCCESS,
        // A reader that stopped early, such as `head`, wants no message.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::from(EXIT_FAILED),
        Err(e) => {
            diagnostic(&format!(
                "error: cannot write the output: {}",
                sanitize(&e.to_string())
            ));
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// Writes one line to standard error. Unlike `eprintln!`, it does not panic
/// if standard error is closed, which would turn a failure (exit code 4)
/// into an internal error (101).
fn diagnostic(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

fn report(err: &InspectError) {
    diagnostic(&format!("error: {}", sanitize(&err.to_string())));
    if let InspectError::LimitExceeded { limit, .. } = err {
        let flag = match limit {
            Limit::Bytes => Some("--max-bytes"),
            Limit::Entries => Some("--max-entries"),
            Limit::Depth => Some("--max-depth"),
            _ => None,
        };
        if let Some(flag) = flag {
            diagnostic(&format!(
                "hint: if this artifact is expected to be that large, raise the limit with {flag}"
            ));
        }
    }
}
