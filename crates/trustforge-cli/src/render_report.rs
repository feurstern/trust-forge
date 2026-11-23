//! Rendering verification reports as text (`docs/verification-semantics.md`,
//! "Reports"): the artifact, the references and their origins, one line per
//! dimension, the checks, the limitations, and the overall status last.
//!
//! Every line is built from the report's structured results; a report loaded
//! from a file never supplies its own text. Everything shown passes through
//! the sanitizer.

use std::fmt::Write as _;

use trustforge_core::inspect::{ArtifactDigests, ArtifactKind};
use trustforge_core::name::Quoted;
use trustforge_core::verify::{
    ArtifactSummary, Change, CheckResult, CheckStatus, ClaimSummary, Difference, DigestKind,
    Dimension, Evidence, ReferenceOrigin, ReferenceSource, ReferenceSummary, VerificationReport,
};

use crate::sanitize::sanitize;

/// At most this many listing differences are shown; the JSON report has the
/// rest that were kept.
const SHOWN_DIFFERENCES: usize = 20;

/// Whether a report was produced by this run or loaded from a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Produced by this run.
    Fresh,
    /// Loaded from a file: not re-verified.
    Loaded,
}

fn line(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<19}{value}");
}

fn continuation(out: &mut String, value: &str) {
    line(out, "", value);
}

/// The report as text.
pub fn text(report: &VerificationReport, source: Source) -> String {
    let mut out = String::new();
    if source == Source::Loaded {
        out.push_str("Loaded from file: not re-verified; reports are unsigned.\n");
        line(
            &mut out,
            "Written by",
            &format!("trustforge {}", sanitize(report.tool_version())),
        );
    }
    if let Some(time) = report.generated_at() {
        line(&mut out, "Generated", &time);
    }
    artifact(&mut out, report.artifact());
    for (i, reference) in report.references().iter().enumerate() {
        reference_lines(&mut out, i, reference);
    }
    let policy = report.policy();
    let required: Vec<&str> = policy.required().map(|d| d.name()).collect();
    let accepted: Vec<&str> = policy
        .accepted_algorithms()
        .iter()
        .map(|a| a.name())
        .collect();
    line(
        &mut out,
        "Policy",
        &format!(
            "{}: requires {}; digest algorithms accepted: {}",
            policy.name(),
            required.join(", "),
            accepted.join(", ")
        ),
    );

    out.push('\n');
    for &(dimension, status) in report.dimensions() {
        let summary = report.dimension_summary(dimension);
        let summary = match source {
            Source::Fresh => summary,
            Source::Loaded => format!("recorded: {summary}"),
        };
        let _ = writeln!(
            out,
            "{:<19}{:<16}{}",
            title(dimension),
            status.label(),
            sanitize(&summary)
        );
    }
    let _ = writeln!(
        out,
        "{:<19}{:<16}out of scope for TrustForge",
        "Software security", "NOT ASSESSED"
    );

    out.push_str("\nChecks\n");
    let width = report
        .checks()
        .iter()
        .map(|c| c.id().name().len())
        .max()
        .unwrap_or(0);
    for check in report.checks() {
        let about = check
            .reference()
            .map(|i| format!("reference {}: ", i + 1))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:<width$}  {:<13}{about}{}",
            check.id().name(),
            check.status().label(),
            sanitize(check.summary())
        );
        details(&mut out, check, source);
    }

    let causes = report.possible_causes();
    if !causes.is_empty() {
        out.push_str(
            "\nPossible causes (none of them is established; a mismatch is not a finding of malice)\n",
        );
        for cause in causes {
            let _ = writeln!(out, "  - {}", sanitize(&cause));
        }
    }
    out.push_str("\nLimitations\n");
    for limitation in report.limitations() {
        let _ = writeln!(out, "  - {}", sanitize(&limitation));
    }
    let overall = match source {
        Source::Fresh => "Overall",
        Source::Loaded => "Overall (as recorded, not re-verified)",
    };
    let _ = writeln!(
        out,
        "\n{overall}: {} ({}; {})",
        report.overall().label(),
        sanitize(&report.overall_summary()),
        sanitize(&report.origins())
    );
    out
}

fn title(dimension: Dimension) -> &'static str {
    match dimension {
        Dimension::Integrity => "Integrity",
        Dimension::Authenticity => "Authenticity",
        Dimension::Provenance => "Provenance",
        Dimension::Reproducibility => "Reproducibility",
        _ => "Other",
    }
}

pub(crate) fn kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::File => "file",
        ArtifactKind::Directory => "directory",
        ArtifactKind::Stream => "stream",
        _ => "other",
    }
}

pub(crate) fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The artifact's name, its kind and size, and its digests, or why it
/// could not be inspected.
pub(crate) fn artifact_lines(out: &mut String, label: &str, artifact: &ArtifactSummary) {
    let name = match artifact.result() {
        Ok(a) if a.kind() == ArtifactKind::Stream && artifact.name() == "-" => {
            "(standard input)".to_owned()
        }
        _ => sanitize(artifact.name()),
    };
    match artifact.result() {
        Ok(inspected) => {
            let size = if inspected.kind() == ArtifactKind::Directory {
                format!(
                    "{} in regular files",
                    plural(inspected.size(), "byte", "bytes")
                )
            } else {
                plural(inspected.size(), "byte", "bytes")
            };
            line(
                out,
                label,
                &format!("{name}: {}, {size}", kind_name(inspected.kind())),
            );
            let (kind, digests) = match inspected.digests() {
                ArtifactDigests::Content(d) => (DigestKind::Content, d),
                ArtifactDigests::Tree(d) => (DigestKind::Tree, d),
            };
            for digest in digests.iter() {
                continuation(
                    out,
                    &format!("{} {}", kind.key(digest.algorithm()), digest.to_hex()),
                );
            }
        }
        Err(failure) => {
            line(out, label, &name);
            continuation(out, &format!("error: {}", sanitize(failure.message())));
        }
    }
}

fn artifact(out: &mut String, artifact: &ArtifactSummary) {
    artifact_lines(out, "Artifact", artifact);
}

fn reference_lines(out: &mut String, index: usize, reference: &ReferenceSummary) {
    let label = format!("Reference {}", index + 1);
    match reference.source() {
        ReferenceSource::Manifest {
            path,
            sha256,
            pinned,
        } => {
            let path = if path == "-" {
                "(standard input)".to_owned()
            } else {
                sanitize(path)
            };
            line(out, &label, &format!("manifest {path}"));
            continuation(
                out,
                &format!("SHA-256 {} (identifies these exact bytes)", sha256.to_hex()),
            );
            if let Some(pinned) = pinned {
                continuation(out, &format!("pinned  {pinned}"));
            }
        }
        _ => line(out, &label, "digests given directly (--expect)"),
    }
    let origin = match reference.origin() {
        ReferenceOrigin::UnauthenticatedClaim => "unauthenticated claim: no signature was verified",
        ReferenceOrigin::UserPinned => "user-pinned: you pinned the manifest's digest",
        ReferenceOrigin::UserSupplied => "user-supplied",
        _ => "other",
    };
    continuation(out, &format!("origin  {origin}"));
    let size = |size: Option<u64>| {
        size.map(|n| format!(", {}", plural(n, "byte", "bytes")))
            .unwrap_or_default()
    };
    let claim = match reference.claim() {
        ClaimSummary::File { size: claimed } => format!("a file{}", size(*claimed)),
        ClaimSummary::Directory {
            size: claimed,
            entries: Some(entries),
        } => format!(
            "a directory: {}{}",
            plural(*entries, "entry", "entries"),
            size(*claimed)
        ),
        ClaimSummary::Directory {
            size: claimed,
            entries: None,
        } => format!("a directory (tree digests only){}", size(*claimed)),
        // The reason quotes any value taken from the document.
        ClaimSummary::Unsupported { reason } => format!(
            "nothing this version can evaluate: {}",
            sanitize(&reason.describe())
        ),
        ClaimSummary::Unusable => {
            "nothing usable: the manifest does not match its pinned digest".to_owned()
        }
        _ => "other".to_owned(),
    };
    continuation(out, &format!("claims  {claim}"));
    if let Some(recipe) = reference.recipe() {
        continuation(out, &format!("recipe  {}", Quoted(recipe)));
    }
    for warning in reference.warnings() {
        continuation(
            out,
            &format!(
                "warning {}: {}",
                Quoted(warning.pointer()),
                sanitize(&warning.kind().to_string())
            ),
        );
    }
    if reference.warnings_omitted() > 0 {
        continuation(
            out,
            &format!(
                "warning … and {} more",
                plural(reference.warnings_omitted(), "warning", "warnings")
            ),
        );
    }
}

/// Further lines under a check: what differed.
fn details(out: &mut String, check: &CheckResult, source: Source) {
    let indent = "      ";
    match check.evidence() {
        Evidence::Digests {
            kind,
            expected,
            actual,
        } if check.status() == CheckStatus::Failed => {
            for digest in actual {
                let algorithm = digest.algorithm();
                if let Some(claimed) = expected.get(algorithm)
                    && claimed != digest
                {
                    let key = kind.key(algorithm);
                    let _ = writeln!(out, "{indent}expected {key} {}", claimed.to_hex());
                    let _ = writeln!(out, "{indent}actual   {key} {}", digest.to_hex());
                }
            }
        }
        Evidence::Tree(comparison) => {
            for difference in comparison.differences().iter().take(SHOWN_DIFFERENCES) {
                let _ = writeln!(out, "{indent}{}", describe(difference));
            }
            let shown = comparison.differences().len().min(SHOWN_DIFFERENCES) as u64;
            let more = comparison.differences().len() as u64 + comparison.omitted() - shown;
            if more > 0 {
                let kept = comparison.differences().len() as u64 - shown;
                let place = match (source, kept) {
                    (_, 0) => String::new(),
                    (Source::Fresh, _) => format!(", {kept} of them listed with --format json"),
                    (Source::Loaded, _) => format!(", {kept} of them listed in the report file"),
                };
                let _ = writeln!(out, "{indent}… and {more} more{place}");
            }
        }
        _ => {}
    }
}

fn entry(kind: trustforge_core::verify::EntryType) -> &'static str {
    use trustforge_core::verify::EntryType;
    match kind {
        EntryType::File => "file",
        EntryType::Directory => "directory",
        EntryType::Symlink => "symbolic link",
        _ => "entry",
    }
}

/// One difference, for people. "Expected" is the reference's side.
pub(crate) fn describe(difference: &Difference) -> String {
    let path = Quoted(difference.path().as_str());
    match difference.change() {
        Change::Missing(kind) => format!("{path}: missing {}", entry(*kind)),
        Change::Unexpected(kind) => format!("{path}: unexpected {}", entry(*kind)),
        Change::Type { expected, actual } => format!(
            "{path}: is a {}, expected a {}",
            entry(*actual),
            entry(*expected)
        ),
        Change::Executable { actual, .. } => format!(
            "{path}: owner-execute bit {}",
            if *actual {
                "set, expected not set"
            } else {
                "not set, expected set"
            }
        ),
        Change::Size { expected, actual } => format!(
            "{path}: {}, expected {}",
            plural(*actual, "byte", "bytes"),
            plural(*expected, "byte", "bytes")
        ),
        Change::Digest(algorithms) => format!(
            "{path}: content differs ({})",
            algorithms
                .iter()
                .map(|a| a.name())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Change::Target { expected, actual } => format!(
            "{path}: points to {}, expected {}",
            Quoted(actual),
            Quoted(expected)
        ),
        _ => format!("{path}: differs"),
    }
}
