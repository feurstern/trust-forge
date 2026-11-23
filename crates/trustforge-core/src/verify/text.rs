//! The text that explains results. All of it is derived from the structured
//! results, the same way when a report is produced and when a saved report is
//! read back, so a saved report never supplies its own explanations.

use super::digests::{DigestMatch, match_list};
use super::{
    CheckId, CheckStatus, ClaimedKind, Dimension, DimensionStatus, Evidence, NotEvaluatedReason,
    OverallStatus, ReferenceOrigin, SkipReason, TreeProblem, Unevaluated, VerificationReport,
};
use crate::digest::{AlgorithmSet, DigestAlgorithm};
use crate::inspect::ArtifactKind;
use crate::name::Quoted;

/// One line explaining a check's result.
pub(crate) fn check_summary(evidence: &Evidence, accepted: &AlgorithmSet) -> String {
    match evidence {
        Evidence::NoReference => "no reference supplied".to_owned(),
        Evidence::Digests {
            kind,
            expected,
            actual,
        } => {
            let names = |algorithms: &[DigestAlgorithm]| {
                algorithms
                    .iter()
                    .map(|a| kind.key(*a))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            // Claimed algorithms the policy does not accept are named, so
            // that a narrowed policy is never silent about what it skipped.
            let skipped: Vec<_> = expected
                .algorithms()
                .filter(|a| !accepted.contains(*a))
                .collect();
            let not_compared = if skipped.is_empty() {
                String::new()
            } else {
                format!(
                    "; {} not compared: the policy does not accept {}",
                    names(&skipped),
                    if skipped.len() == 1 { "it" } else { "them" }
                )
            };
            match match_list(expected, actual, accepted) {
                DigestMatch::Match(algorithms) => {
                    format!(
                        "{} {}{not_compared}",
                        names(&algorithms),
                        verb(&algorithms, "matches", "match")
                    )
                }
                DigestMatch::Mismatch(algorithms) => {
                    format!(
                        "{} {}",
                        names(&algorithms),
                        verb(&algorithms, "differs", "differ")
                    )
                }
                DigestMatch::NotComputed(algorithms) => format!(
                    "{} {} not computed",
                    names(&algorithms),
                    verb(&algorithms, "was", "were")
                ),
                DigestMatch::NothingComparable => {
                    let claimed: Vec<_> = expected.algorithms().collect();
                    format!(
                        "the policy accepts none of the reference's algorithms ({})",
                        names(&claimed)
                    )
                }
            }
        }
        Evidence::KindMismatch { expected, actual } => format!(
            "the reference describes {}, but the artifact is {}",
            claimed_kind(*expected),
            artifact_kind(*actual)
        ),
        Evidence::NotInspected { unsupported: true } => {
            "this platform cannot inspect the artifact".to_owned()
        }
        Evidence::NotInspected { unsupported: false } => {
            "the artifact could not be inspected".to_owned()
        }
        Evidence::Skipped(reason) => format!("not compared: {}", skip_reason(*reason)),
        Evidence::UnsupportedReference => {
            "this version cannot evaluate the reference (see what it claims)".to_owned()
        }
        Evidence::Size { expected, actual } if expected == actual => bytes(*actual),
        Evidence::Size { expected, actual } => {
            format!(
                "{}; the reference claims {}",
                bytes(*actual),
                bytes(*expected)
            )
        }
        Evidence::Tree(comparison) => {
            let found = comparison.differences().len() as u64 + comparison.omitted();
            match comparison.problem() {
                Some(TreeProblem::Unordered) => {
                    "a listing is not in tree order, so it cannot be compared".to_owned()
                }
                _ if found > 0 => format!(
                    "{found} {} in the listing",
                    if found == 1 {
                        "difference"
                    } else {
                        "differences"
                    }
                ),
                Some(TreeProblem::NotComputed { path }) => {
                    format!("the digests of {} were not computed", Quoted(path.as_str()))
                }
                Some(TreeProblem::NotComparable { path }) => format!(
                    "the policy accepts none of the algorithms claimed for {}",
                    Quoted(path.as_str())
                ),
                None if comparison.entries() == 1 => "the 1 entry matches".to_owned(),
                None => format!("all {} entries match", comparison.entries()),
            }
        }
        Evidence::Pin { pinned, actual } if pinned == actual => {
            "the manifest's SHA-256 matches the pinned digest".to_owned()
        }
        Evidence::Pin { pinned, actual } => format!(
            "the manifest's digest is {actual}, not the pinned {pinned}; its claims were not used"
        ),
        Evidence::NoCheck(Unevaluated::Recipe) => {
            "the manifest claims a recipe, but this version cannot rebuild it".to_owned()
        }
        Evidence::NoCheck(Unevaluated::Envelope) => {
            "the reference is a signed envelope, but this version cannot verify signatures"
                .to_owned()
        }
        Evidence::DuplicateCheck => "another check already uses this identifier".to_owned(),
        Evidence::InvalidEvidence => {
            "the check returned evidence its identifier does not allow".to_owned()
        }
    }
}

fn verb<'a, T>(items: &[T], one: &'a str, many: &'a str) -> &'a str {
    if items.len() == 1 { one } else { many }
}

fn bytes(n: u64) -> String {
    format!("{n} {}", if n == 1 { "byte" } else { "bytes" })
}

fn claimed_kind(kind: ClaimedKind) -> &'static str {
    match kind {
        ClaimedKind::File => "a file",
        ClaimedKind::Directory => "a directory",
    }
}

fn artifact_kind(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::File => "a file",
        ArtifactKind::Directory => "a directory",
        ArtifactKind::Stream => "a stream",
    }
}

fn skip_reason(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::PinMismatch => "the manifest does not match its pinned digest",
        SkipReason::NotInspected => "the artifact could not be inspected",
        SkipReason::KindMismatch => {
            "the artifact is not the kind of artifact the reference describes"
        }
    }
}

/// `a`, `a and b`, `a, b and c`.
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

impl VerificationReport {
    /// One line explaining the status of `dimension`.
    pub fn dimension_summary(&self, dimension: Dimension) -> String {
        match self.dimension(dimension) {
            DimensionStatus::Verified => match self.references.len() {
                1 => "the artifact matches the reference".to_owned(),
                _ => "the artifact matches every reference".to_owned(),
            },
            DimensionStatus::Failed => "evidence contradicts a claim".to_owned(),
            DimensionStatus::Error => "a check could not complete".to_owned(),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Skipped) => {
                "not evaluated: a prerequisite failed".to_owned()
            }
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported) => match dimension {
                Dimension::Integrity => "a reference cannot be evaluated by this version",
                Dimension::Authenticity => "signatures cannot be verified by this version",
                Dimension::Provenance => "provenance cannot be evaluated by this version",
                Dimension::Reproducibility => "this version cannot rebuild the claimed recipe",
            }
            .to_owned(),
            DimensionStatus::NotEvaluated(_) => match dimension {
                Dimension::Integrity if !self.references.is_empty() => {
                    "not every reference could be compared"
                }
                Dimension::Integrity => "no reference supplied",
                Dimension::Authenticity => "no signature supplied",
                Dimension::Provenance => "no provenance supplied",
                Dimension::Reproducibility => "no rebuild performed",
            }
            .to_owned(),
        }
    }

    /// Where every reference came from, such as `reference 1: unauthenticated
    /// claim (no signature was verified)`.
    pub fn origins(&self) -> String {
        if self.references.is_empty() {
            return "no reference".to_owned();
        }
        self.references
            .iter()
            .enumerate()
            .map(|(i, reference)| {
                let origin = match reference.origin() {
                    ReferenceOrigin::UnauthenticatedClaim => {
                        "unauthenticated claim (no signature was verified)"
                    }
                    ReferenceOrigin::UserPinned => {
                        "user-pinned (a manifest whose digest you pinned)"
                    }
                    ReferenceOrigin::UserSupplied => "user-supplied",
                };
                format!("reference {}: {origin}", i + 1)
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// One line explaining the overall status.
    pub fn overall_summary(&self) -> String {
        let policy = self.policy.name();
        match self.overall {
            OverallStatus::Mismatch => "evidence contradicts a claim".to_owned(),
            OverallStatus::VerificationFailed => {
                "a check could not complete, so nothing counts as verified".to_owned()
            }
            OverallStatus::Verified => format!("policy \"{policy}\" is satisfied"),
            OverallStatus::PartiallyVerified => {
                let missing: Vec<&str> = self
                    .policy
                    .required()
                    .filter(|d| self.dimension(*d) != DimensionStatus::Verified)
                    .map(Dimension::name)
                    .collect();
                format!(
                    "policy \"{policy}\" also requires {}, which {} not verified",
                    and_list(&missing),
                    if missing.len() == 1 { "is" } else { "are" }
                )
            }
            OverallStatus::Unverified => {
                format!("nothing was verified; policy \"{policy}\" is not satisfied")
            }
        }
    }

    /// Possible causes of a MISMATCH, never a claimed root cause. Empty for
    /// any other status.
    pub fn possible_causes(&self) -> Vec<String> {
        if self.overall != OverallStatus::Mismatch {
            return Vec::new();
        }
        let failed: Vec<_> = self
            .checks
            .iter()
            .filter(|c| c.status() == CheckStatus::Failed)
            .collect();
        let mut causes = Vec::new();
        let mut add = |cause: &str| {
            if !causes.iter().any(|c: &String| c == cause) {
                causes.push(cause.to_owned());
            }
        };
        for check in failed {
            match (check.id(), check.evidence()) {
                (CheckId::IntegrityManifest, _) => {
                    add(
                        "the manifest was changed or replaced after its digest was pinned, or a wrong digest was pinned; the artifact was not compared with that manifest",
                    );
                }
                (_, Evidence::KindMismatch { .. }) => {
                    add("the path names a different kind of artifact than the reference describes");
                }
                (CheckId::IntegrityDigest | CheckId::IntegritySize | CheckId::IntegrityTree, _) => {
                    add(
                        "the artifact was modified, corrupted or truncated after the reference was made",
                    );
                    add("the reference describes a different artifact, or another version of it");
                    if check.id() == CheckId::IntegrityTree {
                        add(
                            "files in the directory were added, removed or changed, for example by a tool that writes into it",
                        );
                    }
                }
                _ => add("a check found evidence that contradicts a claim"),
            }
        }
        causes
    }

    /// What the report does not establish: every dimension that is not
    /// verified, software security, and the limits of the references used.
    pub fn limitations(&self) -> Vec<String> {
        let mut out = Vec::new();
        for &(dimension, status) in &self.dimensions {
            if status != DimensionStatus::Verified {
                out.push(format!(
                    "{}: {}: {}",
                    dimension.name(),
                    status.label().to_lowercase(),
                    self.dimension_summary(dimension)
                ));
            }
        }
        out.push(
            "software security: not assessed: TrustForge never assesses whether software is safe"
                .to_owned(),
        );
        if self
            .references
            .iter()
            .any(|r| r.origin() == ReferenceOrigin::UnauthenticatedClaim)
        {
            out.push("a manifest without a verified signature is only a claim: whoever can replace the artifact may be able to replace the manifest too".to_owned());
        }
        if self.references.iter().any(|r| r.recipe().is_some()) {
            out.push(
                "a claimed recipe was not rebuilt: this version cannot rebuild artifacts"
                    .to_owned(),
            );
        }
        out
    }
}
