//! The one rule for comparing claimed digests with computed ones, used for an
//! artifact's digests and for every file of a claimed listing.
//!
//! Every claimed algorithm the policy accepts must have been computed and
//! must match (`docs/manifest-spec.md`, "Digest sets"). in-toto allows a
//! match on *any* accepted algorithm; TrustForge is stricter, so anything it
//! accepts, an in-toto verifier also accepts.

use crate::digest::{AlgorithmSet, Digest, DigestAlgorithm, DigestSet};

/// How claimed digests compare with computed ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DigestMatch {
    /// Every claimed algorithm the policy accepts was computed and matches.
    Match(Vec<DigestAlgorithm>),
    /// These compared algorithms differ. A contradiction outranks an
    /// algorithm that was not computed.
    Mismatch(Vec<DigestAlgorithm>),
    /// These claimed, accepted algorithms were not computed: a fault in
    /// TrustForge, never a pass.
    NotComputed(Vec<DigestAlgorithm>),
    /// The claim has no algorithm the policy accepts.
    NothingComparable,
}

/// Compares `claimed` with what `computed` returns for each algorithm.
pub(crate) fn match_digests<'a>(
    claimed: &DigestSet,
    computed: impl Fn(DigestAlgorithm) -> Option<&'a Digest>,
    accepted: &AlgorithmSet,
) -> DigestMatch {
    let (mut matching, mut differing, mut missing) = (Vec::new(), Vec::new(), Vec::new());
    for expected in claimed.iter() {
        let algorithm = expected.algorithm();
        if !accepted.contains(algorithm) {
            continue;
        }
        match computed(algorithm) {
            Some(actual) if actual == expected => matching.push(algorithm),
            Some(_) => differing.push(algorithm),
            None => missing.push(algorithm),
        }
    }
    if !differing.is_empty() {
        DigestMatch::Mismatch(differing)
    } else if !missing.is_empty() {
        DigestMatch::NotComputed(missing)
    } else if matching.is_empty() {
        DigestMatch::NothingComparable
    } else {
        DigestMatch::Match(matching)
    }
}

/// [`match_digests`] against a list of computed digests.
pub(crate) fn match_list(
    claimed: &DigestSet,
    computed: &[Digest],
    accepted: &AlgorithmSet,
) -> DigestMatch {
    match_digests(
        claimed,
        |algorithm| computed.iter().find(|d| d.algorithm() == algorithm),
        accepted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use DigestAlgorithm::{Blake3, Sha256, Sha512};

    fn set(digests: &[Digest]) -> DigestSet {
        DigestSet::new(digests.iter().cloned()).unwrap()
    }

    fn accept(algorithms: &[DigestAlgorithm]) -> AlgorithmSet {
        AlgorithmSet::new(algorithms.iter().copied()).unwrap()
    }

    #[test]
    fn every_accepted_algorithm_must_match() {
        let good = [Digest::of(Sha256, b"a"), Digest::of(Sha512, b"a")];
        let claimed = set(&good);
        assert_eq!(
            match_list(&claimed, &good, &AlgorithmSet::all()),
            DigestMatch::Match(vec![Sha256, Sha512])
        );
        // One wrong algorithm among several is a mismatch, never a pass.
        let one_wrong = [Digest::of(Sha256, b"a"), Digest::of(Sha512, b"b")];
        assert_eq!(
            match_list(&claimed, &one_wrong, &AlgorithmSet::all()),
            DigestMatch::Mismatch(vec![Sha512])
        );
    }

    #[test]
    fn the_policy_decides_which_algorithms_count() {
        let claimed = set(&[Digest::of(Blake3, b"a"), Digest::of(Sha512, b"a")]);
        let computed = [Digest::of(Sha512, b"a")];
        assert_eq!(
            match_list(&claimed, &computed, &accept(&[Sha512])),
            DigestMatch::Match(vec![Sha512])
        );
        // A wrong digest under an algorithm the policy does not accept is
        // not compared at all.
        let claimed = set(&[Digest::of(Blake3, b"x"), Digest::of(Sha512, b"a")]);
        assert_eq!(
            match_list(&claimed, &computed, &accept(&[Sha512])),
            DigestMatch::Match(vec![Sha512])
        );
        assert_eq!(
            match_list(&claimed, &computed, &accept(&[Sha256])),
            DigestMatch::NothingComparable
        );
    }

    #[test]
    fn a_digest_that_was_not_computed_is_never_a_pass() {
        let claimed = set(&[Digest::of(Sha256, b"a"), Digest::of(Blake3, b"a")]);
        let computed = [Digest::of(Sha256, b"a")];
        assert_eq!(
            match_list(&claimed, &computed, &AlgorithmSet::all()),
            DigestMatch::NotComputed(vec![Blake3])
        );
        // A contradiction outranks it.
        let computed = [Digest::of(Sha256, b"b")];
        assert_eq!(
            match_list(&claimed, &computed, &AlgorithmSet::all()),
            DigestMatch::Mismatch(vec![Sha256])
        );
    }
}
