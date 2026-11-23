//! The rules every report must meet, whether it is being produced or read
//! back from a file. Verification applies them to every outcome of every
//! check, and the report reader to every saved report, so that no report
//! TrustForge writes is refused by its own reader, and no report that
//! breaks them is accepted.
//!
//! - [`evidence_agrees`]: a piece of evidence must agree with the artifact and
//!   the reference it is about.
//! - [`required_results`]: every reference has the results its claims call
//!   for, exactly once where a check runs once per reference.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ArtifactSummary, CheckId, CheckResult, ClaimSummary, DigestKind, Dimension, Evidence,
    FailureKind, ReferenceSource, ReferenceSummary, SkipReason, TreeProblem, Unevaluated,
};
use crate::inspect::{ArtifactDigests, ArtifactKind};

fn ok(condition: bool, problem: &'static str) -> Result<(), &'static str> {
    if condition { Ok(()) } else { Err(problem) }
}

/// Whether `evidence`, about the reference at index `reference`, agrees with
/// the artifact and with that reference.
pub(crate) fn evidence_agrees(
    evidence: &Evidence,
    reference: Option<usize>,
    artifact: &ArtifactSummary,
    references: &[ReferenceSummary],
) -> Result<(), &'static str> {
    let summary = match reference {
        Some(i) => Some(references.get(i).ok_or("the result names no reference")?),
        None => None,
    };
    let claimed = summary.and_then(ReferenceSummary::claimed_kind);
    let inspected = artifact.result().ok();
    match evidence {
        Evidence::NoReference => ok(
            reference.is_none() && references.is_empty() && inspected.is_some(),
            "a result without a reference belongs to a report without references",
        ),
        Evidence::NotInspected { unsupported } => ok(
            reference.is_none() == references.is_empty()
                && artifact
                    .result()
                    .err()
                    .is_some_and(|f| (f.kind() == FailureKind::Unsupported) == *unsupported),
            "the artifact's failure is not this one",
        ),
        Evidence::Digests {
            kind,
            expected,
            actual,
        } => {
            let computed = match (inspected, kind, claimed) {
                (Some(a), DigestKind::Content, Some(c)) if c.admits(a.kind()) => {
                    match a.digests() {
                        ArtifactDigests::Content(digests) => digests,
                        ArtifactDigests::Tree(_) => return Err("the digests are not the artifact's"),
                    }
                }
                (Some(a), DigestKind::Tree, Some(c)) if c.admits(a.kind()) => match a.digests() {
                    ArtifactDigests::Tree(digests) => digests,
                    ArtifactDigests::Content(_) => return Err("the digests are not the artifact's"),
                },
                _ => return Err("the digests do not belong to the artifact and the reference"),
            };
            let tree = matches!(claimed, Some(super::ClaimedKind::Directory));
            ok(
                tree == (*kind == DigestKind::Tree)
                    && actual.iter().all(|digest| {
                        computed.get(digest.algorithm()) == Some(digest)
                            && expected.get(digest.algorithm()).is_some()
                    }),
                "the actual digests are not the artifact's",
            )
        }
        Evidence::KindMismatch { expected, actual } => ok(
            claimed == Some(*expected)
                && inspected.is_some_and(|a| a.kind() == *actual)
                && !expected.admits(*actual),
            "the kinds are not the reference's and the artifact's",
        ),
        Evidence::Skipped(SkipReason::PinMismatch) => ok(
            summary.is_some_and(|r| *r.claim() == ClaimSummary::Unusable) && inspected.is_some(),
            "only an unusable reference is skipped for its pin",
        ),
        Evidence::Skipped(SkipReason::NotInspected) => ok(
            claimed.is_some() && inspected.is_none(),
            "the artifact was inspected",
        ),
        Evidence::Skipped(SkipReason::KindMismatch) => ok(
            claimed.is_some_and(|c| inspected.is_some_and(|a| !c.admits(a.kind()))),
            "the artifact is the kind of artifact the reference describes",
        ),
        Evidence::UnsupportedReference => ok(
            summary.is_some_and(|r| matches!(r.claim(), ClaimSummary::Unsupported { .. }))
                && inspected.is_some(),
            "the reference is not one this version cannot evaluate",
        ),
        Evidence::Size { expected, actual } => ok(
            summary.is_some_and(|r| r.claimed_size() == Some(*expected))
                && claimed.is_some_and(|c| {
                    inspected.is_some_and(|a| c.admits(a.kind()) && a.size() == *actual)
                }),
            "the sizes are not the reference's and the artifact's",
        ),
        Evidence::Tree(comparison) => {
            let listed = match summary.map(ReferenceSummary::claim) {
                Some(ClaimSummary::Directory {
                    entries: Some(entries),
                    ..
                }) => *entries,
                _ => return Err("the reference has no listing"),
            };
            let Some(entries) = inspected
                .filter(|a| a.kind() == ArtifactKind::Directory)
                .and_then(|a| a.entries())
            else {
                return Err("the artifact is not a directory that was inspected");
            };
            let unordered = comparison.problem() == Some(&TreeProblem::Unordered);
            let identical = comparison.differences().is_empty() && comparison.omitted() == 0;
            ok(
                comparison.entries() == entries
                    && (!unordered || identical)
                    && (unordered || !identical || listed == entries),
                "the listing comparison does not belong to the artifact and the reference",
            )
        }
        Evidence::Pin { pinned, actual } => ok(
            summary.is_some_and(|r| {
                matches!(
                    r.source(),
                    ReferenceSource::Manifest { sha256, pinned: Some(p), .. }
                        if p == pinned && sha256 == actual
                )
            }),
            "the digests are not the manifest's and its pin",
        ),
        Evidence::NoCheck(Unevaluated::Recipe) => ok(
            summary.is_some_and(|r| r.recipe().is_some()),
            "the reference claims no recipe",
        ),
        Evidence::NoCheck(Unevaluated::Envelope) => ok(
            summary.is_some_and(|r| {
                matches!(r.claim(), ClaimSummary::Unsupported { reason } if reason.is_envelope())
            }),
            "the reference is not a signed envelope",
        ),
        Evidence::DuplicateCheck | Evidence::InvalidEvidence => {
            ok(reference.is_none(), "this result is about no reference")
        }
    }
}

/// Whether a result counts toward the results a reference requires: results
/// of a check that took another's identifier, or that returned evidence it
/// may not, are errors of their own.
fn regular(result: &CheckResult) -> bool {
    !matches!(
        result.evidence(),
        Evidence::DuplicateCheck | Evidence::InvalidEvidence
    )
}

/// The dimensions in which each reference has a result.
pub(crate) fn evaluated(results: &[CheckResult]) -> BTreeSet<(Dimension, usize)> {
    results
        .iter()
        .filter(|r| regular(r))
        .filter_map(|r| r.reference().map(|i| (r.dimension(), i)))
        .collect()
}

/// Whether `checks` hold the results the references call for:
/// - exactly one `integrity.digest` result per reference, or a single one
///   without a reference when there are none;
/// - exactly one `integrity.manifest` result per pinned manifest;
/// - exactly one `integrity.size` result per reference that claims a size;
/// - exactly one `integrity.tree` result per reference with a listing;
/// - a reproducibility result for every claimed recipe, and an authenticity
///   result for every signed envelope.
pub(crate) fn required_results(
    checks: &[CheckResult],
    references: &[ReferenceSummary],
) -> Result<(), &'static str> {
    let mut counts: BTreeMap<(CheckId, Option<usize>), usize> = BTreeMap::new();
    for check in checks.iter().filter(|c| regular(c)) {
        *counts.entry((check.id(), check.reference())).or_default() += 1;
    }
    let count =
        |id: CheckId, reference: Option<usize>| counts.get(&(id, reference)).copied().unwrap_or(0);
    let without = usize::from(references.is_empty());
    if count(CheckId::IntegrityDigest, None) != without {
        return Err(
            "there is one integrity.digest result without a reference exactly when there are no references",
        );
    }
    let evaluated = evaluated(checks);
    for (i, reference) in references.iter().enumerate() {
        if count(CheckId::IntegrityDigest, Some(i)) != 1 {
            return Err("every reference has exactly one integrity.digest result");
        }
        let pinned = matches!(
            reference.source(),
            ReferenceSource::Manifest {
                pinned: Some(_),
                ..
            }
        );
        if count(CheckId::IntegrityManifest, Some(i)) != usize::from(pinned) {
            return Err("every pinned manifest, and only those, has one integrity.manifest result");
        }
        let sized = reference.claimed_size().is_some();
        if count(CheckId::IntegritySize, Some(i)) != usize::from(sized) {
            return Err(
                "every reference that claims a size, and only those, has one integrity.size result",
            );
        }
        let listed = matches!(
            reference.claim(),
            ClaimSummary::Directory {
                entries: Some(_),
                ..
            }
        );
        if count(CheckId::IntegrityTree, Some(i)) != usize::from(listed) {
            return Err(
                "every reference with a listing, and only those, has one integrity.tree result",
            );
        }
        if reference.recipe().is_some() && !evaluated.contains(&(Dimension::Reproducibility, i)) {
            return Err("a claimed recipe has a reproducibility result");
        }
        let envelope = matches!(
            reference.claim(),
            ClaimSummary::Unsupported { reason } if reason.is_envelope()
        );
        if envelope && !evaluated.contains(&(Dimension::Authenticity, i)) {
            return Err("a signed envelope has an authenticity result");
        }
    }
    Ok(())
}
