//! Verification policies: which dimensions must be verified for a result to
//! count as VERIFIED, and which digest algorithms comparisons accept.

use std::collections::BTreeSet;

use super::Dimension;
use crate::digest::AlgorithmSet;

/// What a verification must establish to be VERIFIED.
///
/// The default, [`full`](Self::full), requires all four dimensions
/// (`docs/architecture.md`, decision 2), so a matching checksum alone is
/// only PARTIALLY VERIFIED. Narrower policies are requested explicitly, and
/// every report names the policy it was computed under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationPolicy {
    required: BTreeSet<Dimension>,
    accepted_algorithms: AlgorithmSet,
}

/// Why a policy cannot be built.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// A policy must require at least one dimension.
    #[error("a policy must require at least one dimension")]
    NothingRequired,
}

impl VerificationPolicy {
    /// The policy `full`: integrity, authenticity, provenance and
    /// reproducibility are all required.
    pub fn full() -> Self {
        Self {
            required: Dimension::ALL.into_iter().collect(),
            accepted_algorithms: AlgorithmSet::all(),
        }
    }

    /// A policy requiring exactly `dimensions`, which must not be empty.
    pub fn require(dimensions: impl IntoIterator<Item = Dimension>) -> Result<Self, PolicyError> {
        let required: BTreeSet<_> = dimensions.into_iter().collect();
        if required.is_empty() {
            return Err(PolicyError::NothingRequired);
        }
        Ok(Self {
            required,
            accepted_algorithms: AlgorithmSet::all(),
        })
    }

    /// This policy, comparing digests only under `algorithms`. A claimed
    /// digest set with none of them cannot be evaluated (`UNSUPPORTED`).
    pub fn with_accepted_algorithms(mut self, algorithms: AlgorithmSet) -> Self {
        self.accepted_algorithms = algorithms;
        self
    }

    /// `full` when every dimension is required, otherwise the required
    /// dimensions' names joined with commas, in report order, such as
    /// `integrity`.
    pub fn name(&self) -> String {
        if self.required.len() == Dimension::ALL.len() {
            return "full".to_owned();
        }
        self.required
            .iter()
            .map(|d| d.name())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The required dimensions, in report order.
    pub fn required(&self) -> impl Iterator<Item = Dimension> + '_ {
        self.required.iter().copied()
    }

    /// Whether `dimension` is required.
    pub fn requires(&self, dimension: Dimension) -> bool {
        self.required.contains(&dimension)
    }

    /// The digest algorithms comparisons accept.
    pub fn accepted_algorithms(&self) -> &AlgorithmSet {
        &self.accepted_algorithms
    }
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self::full()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_are_named_by_what_they_require() {
        assert_eq!(VerificationPolicy::full().name(), "full");
        assert_eq!(VerificationPolicy::default(), VerificationPolicy::full());
        let integrity = VerificationPolicy::require([Dimension::Integrity]).unwrap();
        assert_eq!(integrity.name(), "integrity");
        let two = VerificationPolicy::require([Dimension::Reproducibility, Dimension::Integrity])
            .unwrap();
        assert_eq!(two.name(), "integrity,reproducibility");
        assert!(two.requires(Dimension::Integrity));
        assert!(!two.requires(Dimension::Authenticity));
        let all = VerificationPolicy::require(Dimension::ALL).unwrap();
        assert_eq!(all, VerificationPolicy::full());
    }

    #[test]
    fn a_policy_requires_something() {
        assert_eq!(
            VerificationPolicy::require([]),
            Err(PolicyError::NothingRequired)
        );
    }
}
