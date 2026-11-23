//! How statuses are computed (`docs/verification-semantics.md`): a check's
//! from its evidence, a dimension's from its checks, and the overall status
//! from the dimensions and the policy. All three are pure functions, shared
//! by verification and by the report reader.

use std::collections::BTreeSet;

use super::digests::{DigestMatch, match_list};
use super::{
    CheckId, CheckResult, CheckStatus, Dimension, DimensionStatus, Evidence, NotEvaluatedReason,
    OverallStatus, VerificationPolicy,
};
use crate::digest::AlgorithmSet;

/// The status a check's evidence supports.
pub(crate) fn check_status(evidence: &Evidence, accepted: &AlgorithmSet) -> CheckStatus {
    match evidence {
        Evidence::NoReference => CheckStatus::NotProvided,
        Evidence::Digests {
            expected, actual, ..
        } => match match_list(expected, actual, accepted) {
            DigestMatch::Match(_) => CheckStatus::Passed,
            DigestMatch::Mismatch(_) => CheckStatus::Failed,
            DigestMatch::NotComputed(_) => CheckStatus::Error,
            DigestMatch::NothingComparable => CheckStatus::Unsupported,
        },
        Evidence::KindMismatch { .. } => CheckStatus::Failed,
        Evidence::NotInspected { unsupported: true } => CheckStatus::Unsupported,
        Evidence::NotInspected { unsupported: false } => CheckStatus::Error,
        Evidence::Skipped(_) => CheckStatus::Skipped,
        Evidence::UnsupportedReference | Evidence::NoCheck(_) => CheckStatus::Unsupported,
        Evidence::Size { expected, actual } => passed_if(expected == actual),
        Evidence::Pin { pinned, actual } => passed_if(pinned == actual),
        Evidence::Tree(comparison) => comparison.status(),
        Evidence::DuplicateCheck | Evidence::InvalidEvidence => CheckStatus::Error,
    }
}

fn passed_if(equal: bool) -> CheckStatus {
    if equal {
        CheckStatus::Passed
    } else {
        CheckStatus::Failed
    }
}

/// A check result reduced to what statuses depend on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Outcome {
    pub(crate) id: CheckId,
    pub(crate) reference: Option<usize>,
    pub(crate) status: CheckStatus,
}

impl From<&CheckResult> for Outcome {
    fn from(result: &CheckResult) -> Self {
        Self {
            id: result.id(),
            reference: result.reference(),
            status: result.status(),
        }
    }
}

/// The status of `dimension`:
/// 1. any `FAILED` check makes it Failed;
/// 2. otherwise any `ERROR` makes it Error;
/// 3. otherwise it is Verified only if it has results, all of them passed,
///    and the checks that decide the dimension passed;
/// 4. otherwise it is not evaluated, for the most telling reason: unsupported
///    evidence, then a skipped check, then missing evidence.
pub(crate) fn dimension_status(
    dimension: Dimension,
    checks: &[CheckResult],
    reference_count: usize,
) -> DimensionStatus {
    let outcomes: Vec<Outcome> = checks.iter().map(Outcome::from).collect();
    dimension_status_of(dimension, &outcomes, reference_count)
}

pub(crate) fn dimension_status_of(
    dimension: Dimension,
    outcomes: &[Outcome],
    reference_count: usize,
) -> DimensionStatus {
    let mine: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| o.id.dimension() == dimension)
        .collect();
    let any = |status| mine.iter().any(|o| o.status == status);
    if any(CheckStatus::Failed) {
        return DimensionStatus::Failed;
    }
    if any(CheckStatus::Error) {
        return DimensionStatus::Error;
    }
    let all_passed = !mine.is_empty() && mine.iter().all(|o| o.status == CheckStatus::Passed);
    if all_passed && decided(dimension, &mine, reference_count) {
        return DimensionStatus::Verified;
    }
    let reason = if any(CheckStatus::Unsupported) {
        NotEvaluatedReason::Unsupported
    } else if any(CheckStatus::Skipped) {
        NotEvaluatedReason::Skipped
    } else {
        NotEvaluatedReason::NotProvided
    };
    DimensionStatus::NotEvaluated(reason)
}

/// Whether the checks that decide `dimension` passed. Passing checks of
/// other kinds (a pinned manifest, a size) can never verify a dimension on
/// their own.
fn decided(dimension: Dimension, outcomes: &[&Outcome], reference_count: usize) -> bool {
    match dimension {
        // Every reference's digests were compared and matched.
        Dimension::Integrity => {
            let matched: BTreeSet<usize> = outcomes
                .iter()
                .filter(|o| o.id == CheckId::IntegrityDigest && o.status == CheckStatus::Passed)
                .filter_map(|o| o.reference)
                .filter(|&i| i < reference_count)
                .collect();
            reference_count > 0 && matched.len() == reference_count
        }
        // These need references whose signatures were verified under the
        // user's trust policy (origin `authenticated`), which this version
        // cannot produce.
        Dimension::Authenticity | Dimension::Provenance => false,
        // This needs a rebuild performed by this process, which this
        // version cannot do.
        Dimension::Reproducibility => false,
    }
}

/// The overall status, by precedence: MISMATCH if any check failed (in any
/// dimension, required or not), VERIFICATION FAILED if any check could not
/// complete, VERIFIED if every required dimension is verified, PARTIALLY
/// VERIFIED if some dimension is verified, and UNVERIFIED otherwise.
pub(crate) fn overall_status(
    dimensions: &[(Dimension, DimensionStatus)],
    checks: &[CheckResult],
    policy: &VerificationPolicy,
) -> OverallStatus {
    let statuses: Vec<CheckStatus> = checks.iter().map(CheckResult::status).collect();
    overall_status_of(dimensions, &statuses, policy)
}

pub(crate) fn overall_status_of(
    dimensions: &[(Dimension, DimensionStatus)],
    statuses: &[CheckStatus],
    policy: &VerificationPolicy,
) -> OverallStatus {
    let verified = |d: Dimension| {
        dimensions
            .iter()
            .any(|&(dim, status)| dim == d && status == DimensionStatus::Verified)
    };
    if statuses.contains(&CheckStatus::Failed) {
        OverallStatus::Mismatch
    } else if statuses.contains(&CheckStatus::Error) {
        OverallStatus::VerificationFailed
    } else if policy.required().all(verified) {
        OverallStatus::Verified
    } else if Dimension::ALL.into_iter().any(verified) {
        OverallStatus::PartiallyVerified
    } else {
        OverallStatus::Unverified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn outcome(id: CheckId, reference: Option<usize>, status: CheckStatus) -> Outcome {
        Outcome {
            id,
            reference,
            status,
        }
    }

    fn integrity_only() -> VerificationPolicy {
        VerificationPolicy::require([Dimension::Integrity]).unwrap()
    }

    fn all(outcomes: &[Outcome], references: usize) -> Vec<(Dimension, DimensionStatus)> {
        Dimension::ALL
            .into_iter()
            .map(|d| (d, dimension_status_of(d, outcomes, references)))
            .collect()
    }

    fn overall(
        outcomes: &[Outcome],
        references: usize,
        policy: &VerificationPolicy,
    ) -> OverallStatus {
        let statuses: Vec<_> = outcomes.iter().map(|o| o.status).collect();
        overall_status_of(&all(outcomes, references), &statuses, policy)
    }

    use CheckId::*;
    use CheckStatus::*;

    #[test]
    fn a_matching_digest_verifies_integrity_only() {
        let outcomes = [
            outcome(IntegrityDigest, Some(0), Passed),
            outcome(IntegritySize, Some(0), Passed),
        ];
        let dims = all(&outcomes, 1);
        assert_eq!(dims[0], (Dimension::Integrity, DimensionStatus::Verified));
        for (_, status) in &dims[1..] {
            assert_eq!(
                *status,
                DimensionStatus::NotEvaluated(NotEvaluatedReason::NotProvided)
            );
        }
        assert_eq!(
            overall(&outcomes, 1, &integrity_only()),
            OverallStatus::Verified
        );
        assert_eq!(
            overall(&outcomes, 1, &VerificationPolicy::full()),
            OverallStatus::PartiallyVerified
        );
    }

    #[test]
    fn precedence_follows_the_semantics() {
        let failed = [
            outcome(IntegrityDigest, Some(0), Passed),
            outcome(IntegritySize, Some(0), Failed),
            outcome(IntegrityTree, Some(0), Error),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &failed, 1),
            DimensionStatus::Failed
        );
        assert_eq!(
            overall(&failed, 1, &integrity_only()),
            OverallStatus::Mismatch
        );

        let error = [outcome(IntegrityDigest, Some(0), Error)];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &error, 1),
            DimensionStatus::Error
        );
        assert_eq!(
            overall(&error, 1, &integrity_only()),
            OverallStatus::VerificationFailed
        );

        // A failure in a dimension the policy does not require is still a
        // mismatch.
        let elsewhere = [
            outcome(IntegrityDigest, Some(0), Passed),
            outcome(ReproducibilityRebuild, Some(0), Failed),
        ];
        assert_eq!(
            overall(&elsewhere, 1, &integrity_only()),
            OverallStatus::Mismatch
        );
    }

    #[test]
    fn passing_checks_other_than_the_digest_never_verify() {
        // The pin and the size passed, but the digests could not be
        // compared: nothing about the artifact was established.
        let outcomes = [
            outcome(IntegrityManifest, Some(0), Passed),
            outcome(IntegrityDigest, Some(0), Unsupported),
            outcome(IntegritySize, Some(0), Passed),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &outcomes, 1),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
        );
        assert_eq!(
            overall(&outcomes, 1, &integrity_only()),
            OverallStatus::Unverified
        );

        // Every result passed, but one reference has no digest result.
        let incomplete = [
            outcome(IntegrityDigest, Some(0), Passed),
            outcome(IntegritySize, Some(1), Passed),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &incomplete, 2),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::NotProvided)
        );
        assert_eq!(
            overall(&incomplete, 2, &integrity_only()),
            OverallStatus::Unverified
        );
    }

    #[test]
    fn every_reference_must_match() {
        let outcomes = [
            outcome(IntegrityDigest, Some(0), Passed),
            outcome(IntegrityDigest, Some(1), Unsupported),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &outcomes, 2),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
        );
    }

    #[test]
    fn no_reference_means_not_provided() {
        let outcomes = [outcome(IntegrityDigest, None, NotProvided)];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &outcomes, 0),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::NotProvided)
        );
        assert_eq!(
            overall(&outcomes, 0, &integrity_only()),
            OverallStatus::Unverified
        );
    }

    #[test]
    fn the_reason_is_the_most_telling_one() {
        let mixed = [
            outcome(IntegrityDigest, Some(0), Skipped),
            outcome(IntegrityDigest, Some(1), Unsupported),
            outcome(IntegrityDigest, Some(2), NotProvided),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &mixed, 3),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
        );
        let skipped = [
            outcome(IntegrityDigest, Some(0), Skipped),
            outcome(IntegrityDigest, Some(1), Passed),
        ];
        assert_eq!(
            dimension_status_of(Dimension::Integrity, &skipped, 2),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Skipped)
        );
    }

    #[test]
    fn other_dimensions_cannot_be_verified_by_this_version() {
        let outcomes = [
            outcome(AuthenticitySignature, Some(0), Passed),
            outcome(ReproducibilityRebuild, Some(0), Passed),
        ];
        for d in [
            Dimension::Authenticity,
            Dimension::Provenance,
            Dimension::Reproducibility,
        ] {
            assert!(matches!(
                dimension_status_of(d, &outcomes, 1),
                DimensionStatus::NotEvaluated(_)
            ));
        }
    }

    fn arb_outcome() -> impl Strategy<Value = Outcome> {
        let id = prop::sample::select(vec![
            IntegrityManifest,
            IntegrityDigest,
            IntegritySize,
            IntegrityTree,
            AuthenticitySignature,
            ReproducibilityRebuild,
        ]);
        let status = prop::sample::select(vec![
            Passed,
            Failed,
            NotProvided,
            Unsupported,
            Skipped,
            Error,
        ]);
        let reference = prop::option::of(0usize..3);
        (id, reference, status).prop_map(|(id, reference, status)| outcome(id, reference, status))
    }

    fn arb_policy() -> impl Strategy<Value = VerificationPolicy> {
        prop::collection::btree_set(prop::sample::select(Dimension::ALL.to_vec()), 1..=4)
            .prop_map(|dims| VerificationPolicy::require(dims).unwrap())
    }

    proptest! {
        #[test]
        fn statuses_never_overstate(
            outcomes in prop::collection::vec(arb_outcome(), 0..8),
            references in 0usize..3,
            policy in arb_policy(),
        ) {
            let dims = all(&outcomes, references);
            let result = overall(&outcomes, references, &policy);
            let any = |s| outcomes.iter().any(|o| o.status == s);

            // Any contradiction is a mismatch.
            prop_assert_eq!(any(Failed), result == OverallStatus::Mismatch);
            if result == OverallStatus::Verified {
                prop_assert!(!any(Failed) && !any(Error));
                for d in policy.required() {
                    prop_assert!(dims.contains(&(d, DimensionStatus::Verified)));
                }
            }
            if matches!(result, OverallStatus::Verified | OverallStatus::PartiallyVerified) {
                prop_assert!(dims.iter().any(|(_, s)| *s == DimensionStatus::Verified));
            }
            // Integrity is verified only when every reference has a passing
            // digest result, so pins and sizes alone never verify anything.
            if dims[0].1 == DimensionStatus::Verified {
                prop_assert!(references > 0);
                for i in 0..references {
                    prop_assert!(outcomes.iter().any(|o| o.id == IntegrityDigest
                        && o.reference == Some(i)
                        && o.status == Passed));
                }
            }
            // Nothing but integrity can be verified by this version.
            for (d, status) in &dims[1..] {
                prop_assert!(*status != DimensionStatus::Verified, "{:?}", d);
            }
        }
    }
}
