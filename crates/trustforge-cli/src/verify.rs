//! `trustforge verify`: compare an artifact with references, and report what
//! that establishes and what it does not.

use std::process::ExitCode;
use std::time::SystemTime;

use clap::Args;
use trustforge_core::digest::{Digest, DigestAlgorithm, DigestSet};
use trustforge_core::inspect::ArtifactDigests;
use trustforge_core::json::{JsonError, JsonLimits};
use trustforge_core::manifest::{ManifestError, ParseOptions};
use trustforge_core::verify::{
    Dimension, OverallStatus, Reference, VerificationPolicy, VerificationRequest, verify,
};

use crate::artifact::{LimitArgs, source};
use crate::input::read_document;
use crate::output::{self, Format, diagnostic};
use crate::render_report::{self, Source};
use crate::sanitize::sanitize;
use crate::{EXIT_FAILED, EXIT_MISMATCH, EXIT_POLICY, EXIT_USAGE};

/// Verify an artifact against a manifest or expected digests.
///
/// Compares the artifact with each reference and reports the four guarantees
/// separately. This version can establish integrity only, so under the
/// default policy, which requires all four, a match is PARTIALLY VERIFIED
/// (exit code 3). Use --require integrity to require integrity alone.
///
/// Exit codes: 0 verified, 1 mismatch, 2 usage error or invalid manifest,
/// 3 policy not satisfied, 4 verification could not complete.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File or directory to verify, or "-" to read standard input.
    path: String,

    /// A manifest describing the artifact, or "-" for standard input. An
    /// unsigned manifest is an unauthenticated claim.
    #[arg(long, value_name = "FILE")]
    manifest: Option<String>,

    /// The manifest's SHA-256, obtained through a channel you trust. The
    /// manifest is used only if its exact bytes have this digest.
    #[arg(long, value_name = "sha256:HEX")]
    manifest_digest: Option<String>,

    /// An expected digest: sha256, sha512 or blake3 for a file, narSha256,
    /// narSha512 or narBlake3 for a directory, as ALGORITHM:HEX. Repeat or
    /// separate with commas; every one must match.
    #[arg(long, value_name = "ALGORITHM:HEX", value_delimiter = ',')]
    expect: Vec<String>,

    /// What must be verified: "full" (all four dimensions), or a
    /// comma-separated list of integrity, authenticity, provenance and
    /// reproducibility.
    #[arg(long, value_name = "POLICY", default_value = "full")]
    require: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Record the current time in the report. Reports leave it out by
    /// default, so that the same inputs give the same report.
    #[arg(long)]
    timestamp: bool,

    #[command(flatten)]
    limits: LimitArgs,

    /// Largest manifest to read, in bytes.
    #[arg(long, value_name = "BYTES", default_value_t = JsonLimits::default().max_bytes)]
    max_manifest_size: usize,
}

fn usage(message: &str) -> ExitCode {
    diagnostic(&format!("error: {message}"));
    ExitCode::from(EXIT_USAGE)
}

pub fn run(args: &VerifyArgs) -> ExitCode {
    let policy = match parse_policy(&args.require) {
        Ok(policy) => policy,
        Err(message) => return usage(&message),
    };
    let expected = match parse_expected(&args.expect) {
        Ok(expected) => expected,
        Err(message) => return usage(&format!("--expect: {message}")),
    };
    let pin = match args.manifest_digest.as_deref().map(parse_pin).transpose() {
        Ok(pin) => pin,
        Err(message) => return usage(&format!("--manifest-digest: {message}")),
    };
    if pin.is_some() && args.manifest.is_none() {
        return usage("--manifest-digest pins a manifest: give the manifest with --manifest");
    }
    if args.manifest.is_none() && expected.is_none() {
        return usage(
            "nothing to verify against: give a manifest with --manifest, or digests with --expect",
        );
    }
    if args.path == "-" && args.manifest.as_deref() == Some("-") {
        return usage("the artifact and the manifest cannot both be read from standard input");
    }

    let mut references = Vec::new();
    if let Some(path) = &args.manifest {
        let (label, read) = read_document(path, args.max_manifest_size);
        let bytes = match read {
            Ok(bytes) => bytes,
            Err(e) => {
                diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
                return ExitCode::from(EXIT_FAILED);
            }
        };
        let mut opts = ParseOptions::default();
        opts.limits.max_bytes = args.max_manifest_size;
        match Reference::from_manifest(&bytes, path, pin.as_ref(), &opts) {
            Ok(reference) => references.push(reference),
            Err(e) => {
                diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
                if matches!(e, ManifestError::Json(JsonError::TooLarge { .. })) {
                    diagnostic("hint: raise the limit with --max-manifest-size");
                }
                return ExitCode::from(EXIT_USAGE);
            }
        }
    }
    references.extend(expected);

    let mut request = VerificationRequest::new(source(&args.path), references, policy);
    request.limits = args.limits.limits();
    let mut report = verify(request);
    if args.timestamp {
        report = report.with_generated_at(SystemTime::now());
    }
    let code = ExitCode::from(match report.overall() {
        OverallStatus::Verified => 0,
        OverallStatus::Mismatch => EXIT_MISMATCH,
        OverallStatus::PartiallyVerified | OverallStatus::Unverified => EXIT_POLICY,
        // VERIFICATION FAILED, and any status a later version adds: never
        // success.
        _ => EXIT_FAILED,
    });
    let bytes = match args.format {
        Format::Text => render_report::text(&report, Source::Fresh).into_bytes(),
        Format::Json => report.to_pretty_json(),
    };
    output::to_stdout(&bytes, code)
}

fn parse_policy(text: &str) -> Result<VerificationPolicy, String> {
    if text == "full" {
        return Ok(VerificationPolicy::full());
    }
    let mut dimensions = Vec::new();
    for name in text.split(',') {
        let dimension = Dimension::from_name(name).ok_or_else(|| {
            format!(
                "--require: unknown dimension \"{}\"; use full, or a list of integrity, authenticity, provenance and reproducibility",
                sanitize(name)
            )
        })?;
        dimensions.push(dimension);
    }
    VerificationPolicy::require(dimensions).map_err(|e| format!("--require: {e}"))
}

/// `ALGORITHM:HEX`, with the hexadecimal digits in either case.
fn parse_digest(text: &str) -> Result<(Digest, bool), String> {
    let (name, hex) = text
        .split_once(':')
        .ok_or_else(|| format!("\"{}\" is not ALGORITHM:HEX", sanitize(text)))?;
    let (algorithm, tree) = match DigestAlgorithm::from_tree_name(name) {
        Some(algorithm) => (algorithm, true),
        None => (
            name.parse::<DigestAlgorithm>().map_err(|e| e.to_string())?,
            false,
        ),
    };
    let digest =
        Digest::from_hex(algorithm, &hex.to_ascii_lowercase()).map_err(|e| e.to_string())?;
    Ok((digest, tree))
}

/// All `--expect` values, as one reference whose digests must all match.
fn parse_expected(values: &[String]) -> Result<Option<Reference>, String> {
    let mut digests = Vec::new();
    let mut tree = None;
    for value in values {
        let (digest, is_tree) = parse_digest(value)?;
        if tree.is_some_and(|t| t != is_tree) {
            return Err(
                "content digests (sha256, …) and tree digests (narSha256, …) cannot be mixed"
                    .to_owned(),
            );
        }
        tree = Some(is_tree);
        digests.push(digest);
    }
    let Some(tree) = tree else {
        return Ok(None);
    };
    let set = DigestSet::new(digests).map_err(|e| e.to_string())?;
    Ok(Some(Reference::expected(if tree {
        ArtifactDigests::Tree(set)
    } else {
        ArtifactDigests::Content(set)
    })))
}

fn parse_pin(text: &str) -> Result<Digest, String> {
    match parse_digest(text)? {
        (digest, false) if digest.algorithm() == DigestAlgorithm::Sha256 => Ok(digest),
        _ => Err("a manifest is identified by its SHA-256: give sha256:HEX".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_are_full_or_a_list() {
        assert_eq!(parse_policy("full").unwrap(), VerificationPolicy::full());
        assert_eq!(parse_policy("integrity").unwrap().name(), "integrity");
        assert_eq!(
            parse_policy("reproducibility,integrity").unwrap().name(),
            "integrity,reproducibility"
        );
        for bad in ["", "Integrity", "full,integrity", "integrity,", "safety"] {
            assert!(parse_policy(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn expected_digests_form_one_reference() {
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(parse_expected(&[]).unwrap().is_none());
        assert!(
            parse_expected(&[format!("sha256:{sha256}")])
                .unwrap()
                .is_some()
        );
        assert!(
            parse_expected(&[format!("sha256:{}", sha256.to_uppercase())])
                .unwrap()
                .is_some(),
            "uppercase hex from the user is accepted"
        );
        for bad in [
            vec![format!("sha256:{sha256}"), format!("sha256:{sha256}")],
            vec![format!("sha256:{sha256}"), format!("narSha256:{sha256}")],
            vec![format!("md5:{}", &sha256[..32])],
            vec![format!("sha1:{}", &sha256[..40])],
            vec![sha256.to_owned()],
            vec![format!("sha256:{}", &sha256[1..])],
            vec![format!("SHA256:{sha256}")],
        ] {
            assert!(parse_expected(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_pin_is_a_sha256() {
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(parse_pin(&format!("sha256:{sha256}")).is_ok());
        assert!(parse_pin(&format!("narSha256:{sha256}")).is_err());
        assert!(parse_pin(&format!("blake3:{sha256}")).is_err());
    }
}
