//! Choosing and inspecting an artifact: shared by `inspect` and
//! `manifest create`.

use std::io;
use std::path::Path;

use clap::{Args, ValueEnum};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm};
use trustforge_core::inspect::{
    InspectError, InspectOptions, Inspection, Limit, Limits, inspect_path, inspect_reader,
};

use crate::output::diagnostic;
use crate::sanitize::sanitize;

/// The artifact to inspect and how.
#[derive(Debug, Args)]
pub struct ArtifactArgs {
    /// File or directory to inspect, or "-" to read standard input.
    path: String,

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

impl ArtifactArgs {
    /// Whether the artifact is standard input.
    pub fn is_stdin(&self) -> bool {
        self.path == "-"
    }

    /// The digest algorithms selected.
    pub fn algorithms(&self) -> AlgorithmSet {
        AlgorithmSet::new(self.algorithms.iter().map(|&a| a.into())).unwrap_or_default()
    }

    /// Inspects the artifact, reporting any failure on standard error.
    pub fn inspect(&self) -> Option<Inspection> {
        let mut opts = InspectOptions::default();
        opts.algorithms = self.algorithms();
        opts.limits.max_bytes = self.max_bytes;
        opts.limits.max_entries = self.max_entries;
        opts.limits.max_depth = self.max_depth;
        let result = if self.is_stdin() {
            inspect_reader("-", io::stdin().lock(), &opts)
        } else {
            inspect_path(Path::new(&self.path), &opts)
        };
        result.map_err(|err| report(&err)).ok()
    }
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
