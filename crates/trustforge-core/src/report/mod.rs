//! Verification reports as JSON documents (`report/v0`), and the strict
//! reader for saved reports (`docs/verification-semantics.md`, "Reports").
//!
//! [`VerificationReport::to_value`] writes a report deterministically: keys
//! in RFC 8785 order, and no wall-clock time unless one was added with
//! [`VerificationReport::with_generated_at`]. Every string is written in
//! display form, with characters unsafe for a terminal escaped, so a report
//! is safe to print and always passes TrustForge's own strict parsing.
//!
//! [`read_report`] reads a saved report back. A saved report is **never
//! evidence**: it is untrusted input, and reading one fails closed. Every
//! status in it is recomputed from its evidence, and a report whose recorded
//! verdicts do not follow is rejected. Its explanations are regenerated
//! rather than taken from the file.

mod read;

use crate::digest::{Digest, DigestAlgorithm, DigestSet};
use crate::inspect::{ArtifactDigests, ArtifactKind};
use crate::json::{self, StrictValue};
use crate::name::EscapedBytes;
use crate::verify::{
    ArtifactSummary, Change, CheckResult, ClaimSummary, Difference, DigestKind, DimensionStatus,
    Evidence, ReferenceSource, ReferenceSummary, TreeComparison, UnsupportedReason,
    VerificationReport,
};

pub use read::{ReportError, read_report};

/// The type of a version 0 report.
pub const REPORT_TYPE_V0: &str = "https://feurstern.github.io/trust-forge/report/v0";

/// The tool that writes reports.
pub(crate) const TOOL_NAME: &str = "trustforge";

impl VerificationReport {
    /// The report as a JSON value.
    pub fn to_value(&self) -> StrictValue {
        let dimensions = self
            .dimensions()
            .iter()
            .map(|&(dimension, status)| {
                let reason = match status {
                    DimensionStatus::NotEvaluated(reason) => text(reason.code()),
                    _ => StrictValue::Null,
                };
                (
                    dimension.name().to_owned(),
                    object([
                        ("reason", reason),
                        ("status", text(status.code())),
                        ("summary", text(&self.dimension_summary(dimension))),
                    ]),
                )
            })
            .collect();
        let policy = self.policy();
        let mut fields = vec![
            ("_type", text(REPORT_TYPE_V0)),
            ("artifact", artifact_value(self.artifact())),
            (
                "checks",
                StrictValue::Array(self.checks().iter().map(check_value).collect()),
            ),
            ("dimensions", StrictValue::Object(dimensions)),
            ("limitations", texts(&self.limitations())),
            (
                "overall",
                object([
                    ("possibleCauses", texts(&self.possible_causes())),
                    ("status", text(self.overall().code())),
                    ("summary", text(&self.overall_summary())),
                ]),
            ),
            (
                "policy",
                object([
                    (
                        "acceptedAlgorithms",
                        StrictValue::Array(
                            policy
                                .accepted_algorithms()
                                .iter()
                                .map(|a| text(a.name()))
                                .collect(),
                        ),
                    ),
                    ("name", text(&policy.name())),
                    (
                        "require",
                        StrictValue::Array(policy.required().map(|d| text(d.name())).collect()),
                    ),
                ]),
            ),
            (
                "references",
                StrictValue::Array(self.references().iter().map(reference_value).collect()),
            ),
            (
                "tool",
                object([
                    ("name", text(TOOL_NAME)),
                    ("version", text(self.tool_version())),
                ]),
            ),
        ];
        if let Some(time) = self.generated_at() {
            fields.push(("generatedAt", text(&time)));
        }
        object(fields)
    }

    /// The deterministic, indented form.
    pub fn to_pretty_json(&self) -> Vec<u8> {
        json::to_pretty(&self.to_value())
    }

    /// The RFC 8785 (JCS) canonical form.
    pub fn to_canonical_json(&self) -> Vec<u8> {
        json::to_canonical(&self.to_value())
    }
}

/// A string in display form: every report string goes through here, so no
/// character unsafe for a terminal can reach a report.
pub(crate) fn text(s: &str) -> StrictValue {
    StrictValue::String(EscapedBytes(s.as_bytes()).to_string())
}

fn texts(items: &[String]) -> StrictValue {
    StrictValue::Array(items.iter().map(|s| text(s)).collect())
}

fn int(n: u64) -> StrictValue {
    StrictValue::Integer(n)
}

pub(crate) fn object<'k>(fields: impl IntoIterator<Item = (&'k str, StrictValue)>) -> StrictValue {
    StrictValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub(crate) fn kind_code(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::File => "file",
        ArtifactKind::Directory => "directory",
        ArtifactKind::Stream => "stream",
    }
}

pub(crate) fn digest_set_value<'a>(
    digests: impl IntoIterator<Item = &'a Digest>,
    kind: DigestKind,
) -> StrictValue {
    StrictValue::Object(
        digests
            .into_iter()
            .map(|d| (kind.key(d.algorithm()).to_owned(), text(&d.to_hex())))
            .collect(),
    )
}

fn single_digest(digest: &Digest) -> StrictValue {
    digest_set_value([digest], DigestKind::Content)
}

pub(crate) fn artifact_value(artifact: &ArtifactSummary) -> StrictValue {
    let mut fields = vec![("name", text(artifact.name()))];
    match artifact.result() {
        Ok(inspected) => {
            fields.push(("kind", text(kind_code(inspected.kind()))));
            fields.push(("size", int(inspected.size())));
            fields.push((
                "entries",
                inspected.entries().map_or(StrictValue::Null, int),
            ));
            match inspected.digests() {
                ArtifactDigests::Content(digests) => {
                    fields.push((
                        "digest",
                        digest_set_value(digests.iter(), DigestKind::Content),
                    ));
                }
                ArtifactDigests::Tree(digests) => {
                    fields.push((
                        "treeDigest",
                        digest_set_value(digests.iter(), DigestKind::Tree),
                    ));
                }
            }
        }
        Err(failure) => fields.push((
            "error",
            object([
                ("kind", text(failure.kind().code())),
                ("message", text(failure.message())),
            ]),
        )),
    }
    object(fields)
}

fn reference_value(reference: &ReferenceSummary) -> StrictValue {
    let claim = match reference.claim() {
        ClaimSummary::File { size } => object([
            ("kind", text("file")),
            ("size", size.map_or(StrictValue::Null, int)),
        ]),
        ClaimSummary::Directory { size, entries } => object([
            ("entries", entries.map_or(StrictValue::Null, int)),
            ("kind", text("directory")),
            ("size", size.map_or(StrictValue::Null, int)),
        ]),
        ClaimSummary::Unsupported { reason } => {
            let (value, pointer) = match reason {
                UnsupportedReason::StatementType { value }
                | UnsupportedReason::PredicateType { value } => (text(value), StrictValue::Null),
                UnsupportedReason::NoAcceptedAlgorithm { pointer } => {
                    (StrictValue::Null, text(pointer))
                }
                _ => (StrictValue::Null, StrictValue::Null),
            };
            object([
                ("kind", text("unsupported")),
                ("pointer", pointer),
                ("reason", text(reason.code())),
                ("value", value),
            ])
        }
        ClaimSummary::Unusable => object([("kind", text("unusable"))]),
    };
    let source = match reference.source() {
        ReferenceSource::Expected => object([("type", text("expected"))]),
        ReferenceSource::Manifest {
            path,
            sha256,
            pinned,
        } => object([
            ("path", text(path)),
            (
                "pinned",
                pinned.as_ref().map_or(StrictValue::Null, single_digest),
            ),
            ("sha256", text(&sha256.to_hex())),
            ("type", text("manifest")),
        ]),
    };
    let warnings = reference
        .warnings()
        .iter()
        .map(|w| {
            object([
                ("kind", text(w.kind().code())),
                ("message", text(&w.kind().to_string())),
                ("pointer", text(w.pointer())),
            ])
        })
        .collect();
    object([
        ("claim", claim),
        ("origin", text(reference.origin().code())),
        ("recipe", reference.recipe().map_or(StrictValue::Null, text)),
        ("source", source),
        ("warnings", StrictValue::Array(warnings)),
        ("warningsOmitted", int(reference.warnings_omitted())),
    ])
}

fn check_value(check: &CheckResult) -> StrictValue {
    object([
        ("dimension", text(check.dimension().name())),
        ("evidence", evidence_value(check.evidence())),
        ("id", text(check.id().name())),
        (
            "reference",
            check
                .reference()
                .map_or(StrictValue::Null, |i| int(i as u64)),
        ),
        ("status", text(check.status().code())),
        ("summary", text(check.summary())),
    ])
}

fn tagged<'k>(kind: &str, fields: impl IntoIterator<Item = (&'k str, StrictValue)>) -> StrictValue {
    let mut fields: Vec<_> = fields.into_iter().collect();
    fields.push(("type", text(kind)));
    object(fields)
}

fn evidence_value(evidence: &Evidence) -> StrictValue {
    match evidence {
        Evidence::NoReference => tagged("no-reference", []),
        Evidence::Digests {
            kind,
            expected,
            actual,
        } => tagged(
            "digests",
            [
                ("actual", digest_set_value(actual, *kind)),
                ("expected", digest_set_value(expected.iter(), *kind)),
            ],
        ),
        Evidence::KindMismatch { expected, actual } => tagged(
            "kind-mismatch",
            [
                ("actual", text(kind_code(*actual))),
                ("expected", text(expected.code())),
            ],
        ),
        Evidence::NotInspected { unsupported } => tagged(
            "not-inspected",
            [("unsupported", StrictValue::Bool(*unsupported))],
        ),
        Evidence::Skipped(reason) => tagged("skipped", [("reason", text(reason.code()))]),
        Evidence::UnsupportedReference => tagged("unsupported-reference", []),
        Evidence::Size { expected, actual } => tagged(
            "size",
            [("actual", int(*actual)), ("expected", int(*expected))],
        ),
        Evidence::Tree(comparison) => tagged("tree", tree_fields(comparison)),
        Evidence::Pin { pinned, actual } => tagged(
            "pin",
            [
                ("actual", single_digest(actual)),
                ("pinned", single_digest(pinned)),
            ],
        ),
        Evidence::NoCheck(unevaluated) => tagged("no-check", [("claim", text(unevaluated.code()))]),
        Evidence::DuplicateCheck => tagged("duplicate-check", []),
        Evidence::InvalidEvidence => tagged("invalid-evidence", []),
    }
}

/// The fields of a tree comparison, shared with comparison output.
pub(crate) fn tree_fields(comparison: &TreeComparison) -> Vec<(&'static str, StrictValue)> {
    let problem = match comparison.problem() {
        None => StrictValue::Null,
        Some(problem) => object([
            ("kind", text(problem.code())),
            (
                "path",
                problem
                    .path()
                    .map_or(StrictValue::Null, |p| text(p.as_str())),
            ),
        ]),
    };
    vec![
        (
            "differences",
            StrictValue::Array(
                comparison
                    .differences()
                    .iter()
                    .map(difference_value)
                    .collect(),
            ),
        ),
        ("differencesOmitted", int(comparison.omitted())),
        ("entries", int(comparison.entries())),
        ("problem", problem),
    ]
}

fn difference_value(difference: &Difference) -> StrictValue {
    let mut fields = vec![
        ("change", text(difference.change().code())),
        ("path", text(difference.path().as_str())),
    ];
    match difference.change() {
        Change::Missing(entry_type) | Change::Unexpected(entry_type) => {
            fields.push(("type", text(entry_type.code())));
        }
        Change::Type { expected, actual } => {
            fields.push(("actual", text(actual.code())));
            fields.push(("expected", text(expected.code())));
        }
        Change::Executable { expected, actual } => {
            fields.push(("actual", StrictValue::Bool(*actual)));
            fields.push(("expected", StrictValue::Bool(*expected)));
        }
        Change::Size { expected, actual } => {
            fields.push(("actual", int(*actual)));
            fields.push(("expected", int(*expected)));
        }
        Change::Digest(algorithms) => fields.push((
            "algorithms",
            StrictValue::Array(algorithms.iter().map(|a| text(a.name())).collect()),
        )),
        Change::Target { expected, actual } => {
            fields.push(("actual", text(actual)));
            fields.push(("expected", text(expected)));
        }
    }
    object(fields)
}

/// The algorithms of a digest-set value's keys, for the reader.
pub(crate) fn key_algorithm(key: &str, kind: DigestKind) -> Option<DigestAlgorithm> {
    DigestAlgorithm::ALL
        .into_iter()
        .find(|a| kind.key(*a) == key)
}

/// A set of digests read back from a digest-set value.
pub(crate) fn digest_set_of(digests: Vec<Digest>) -> Option<DigestSet> {
    DigestSet::new(digests).ok()
}

#[cfg(test)]
mod tests;
