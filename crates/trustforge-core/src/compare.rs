//! Comparing two artifacts (`docs/verification-semantics.md`, "Comparison
//! outcomes").
//!
//! Both sides are inspected with every algorithm (SHA-256, SHA-512 and
//! BLAKE3) and every safeguard of [`crate::inspect`]. The outcome is
//! `MATCH` only when the two are the same kind of artifact (a file and a
//! stream hold the same kind of content), their sizes are equal, all three
//! digests are equal, and, for directories, every entry is equal. No second,
//! byte-by-byte pass is made: equal digests under three independent
//! algorithms identify equal bytes, and a false match would need collisions
//! in all three at once.

use crate::digest::{AlgorithmSet, DigestAlgorithm};
use crate::inspect::{
    ArtifactDigests, ArtifactKind, InspectError, InspectOptions, Inspection, Limits,
};
use crate::json::{self, StrictValue};
use crate::report::{artifact_value, object, text, tree_fields};
use crate::verify::{
    ArtifactSource, ArtifactSummary, DigestKind, FailureKind, TreeComparison, entry_views,
    tree_diff,
};

/// Options for a comparison.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompareOptions {
    /// Resource limits for inspecting each side.
    pub limits: Limits,
}

/// The outcome of a comparison.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComparisonOutcome {
    /// Same kind, same size, and the same digests under every algorithm;
    /// for directories, the same entries. The only kind of match.
    Match,
    /// Both sides were read completely, and they differ.
    Different,
    /// The comparison could not cover everything: a side is missing, a limit
    /// was exceeded, or this platform cannot inspect a side.
    Incomplete,
    /// The comparison could not be performed.
    Failed,
}

impl ComparisonOutcome {
    /// `MATCH`, `DIFFERENT`, `INCOMPLETE` or `FAILED`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Match => "MATCH",
            Self::Different => "DIFFERENT",
            Self::Incomplete => "INCOMPLETE",
            Self::Failed => "FAILED",
        }
    }
}

/// How two artifacts that were both read completely differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Differences {
    kinds: bool,
    size: bool,
    digests: Vec<DigestAlgorithm>,
    tree: Option<TreeComparison>,
}

impl Differences {
    /// Whether one is a directory and the other is not.
    pub fn kinds_differ(&self) -> bool {
        self.kinds
    }

    /// Whether the sizes differ.
    pub fn size_differs(&self) -> bool {
        self.size
    }

    /// The algorithms whose digests differ, when the kinds are the same.
    pub fn digests(&self) -> &[DigestAlgorithm] {
        &self.digests
    }

    /// The entry-by-entry comparison of two directories.
    pub fn tree(&self) -> Option<&TreeComparison> {
        self.tree.as_ref()
    }

    fn none(&self) -> bool {
        !self.kinds
            && !self.size
            && self.digests.is_empty()
            && self
                .tree
                .as_ref()
                .is_none_or(|t| t.differences().is_empty() && t.omitted() == 0)
    }
}

/// The result of comparing two artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    original: ArtifactSummary,
    candidate: ArtifactSummary,
    outcome: ComparisonOutcome,
    differences: Option<Differences>,
}

impl Comparison {
    /// The first artifact.
    pub fn original(&self) -> &ArtifactSummary {
        &self.original
    }

    /// The second artifact.
    pub fn candidate(&self) -> &ArtifactSummary {
        &self.candidate
    }

    /// The outcome.
    pub fn outcome(&self) -> ComparisonOutcome {
        self.outcome
    }

    /// How the two differ, when both were read completely.
    pub fn differences(&self) -> Option<&Differences> {
        self.differences.as_ref()
    }

    /// The comparison as a JSON value, deterministic and safe to display.
    pub fn to_value(&self) -> StrictValue {
        let differences = match &self.differences {
            None => StrictValue::Null,
            Some(d) => {
                let kind = match self.original.result() {
                    Ok(a) if a.kind() == ArtifactKind::Directory => DigestKind::Tree,
                    _ => DigestKind::Content,
                };
                object([
                    (
                        "digests",
                        StrictValue::Array(d.digests.iter().map(|a| text(kind.key(*a))).collect()),
                    ),
                    ("kind", StrictValue::Bool(d.kinds)),
                    ("size", StrictValue::Bool(d.size)),
                    (
                        "tree",
                        d.tree
                            .as_ref()
                            .map_or(StrictValue::Null, |t| object(tree_fields(t))),
                    ),
                ])
            }
        };
        object([
            ("candidate", artifact_value(&self.candidate)),
            ("differences", differences),
            ("original", artifact_value(&self.original)),
            ("outcome", text(self.outcome.code())),
        ])
    }

    /// The deterministic, indented form.
    pub fn to_pretty_json(&self) -> Vec<u8> {
        json::to_pretty(&self.to_value())
    }
}

/// Compares `original` with `candidate`. Never fails: an artifact that
/// cannot be read makes the outcome `INCOMPLETE` or `FAILED`.
pub fn compare(
    original: ArtifactSource<'_>,
    candidate: ArtifactSource<'_>,
    opts: &CompareOptions,
) -> Comparison {
    let inspect = InspectOptions {
        algorithms: AlgorithmSet::all(),
        limits: opts.limits.clone(),
    };
    let (original_name, original_result) = original.inspect(&inspect);
    let (candidate_name, candidate_result) = candidate.inspect(&inspect);
    let (outcome, differences) = match (&original_result, &candidate_result) {
        (Ok(a), Ok(b)) => {
            let differences = differences(a, b);
            let outcome = if differences
                .tree
                .as_ref()
                .is_some_and(|t| t.problem().is_some())
            {
                // Inspections are always ordered and fully hashed; anything
                // else is a fault, never a match.
                ComparisonOutcome::Failed
            } else if differences.none() {
                ComparisonOutcome::Match
            } else {
                ComparisonOutcome::Different
            };
            (outcome, Some(differences))
        }
        (a, b) => (failure_outcome(a.as_ref().err(), b.as_ref().err()), None),
    };
    Comparison {
        original: ArtifactSummary::of(original_name, &original_result),
        candidate: ArtifactSummary::of(candidate_name, &candidate_result),
        outcome,
        differences,
    }
}

/// A directory, or content (a file or a stream).
fn is_directory(kind: ArtifactKind) -> bool {
    kind == ArtifactKind::Directory
}

fn differences(a: &Inspection, b: &Inspection) -> Differences {
    let size = a.size() != b.size();
    let (x, y) = match (a.digests(), b.digests()) {
        (ArtifactDigests::Content(x), ArtifactDigests::Content(y))
        | (ArtifactDigests::Tree(x), ArtifactDigests::Tree(y))
            if is_directory(a.kind()) == is_directory(b.kind()) =>
        {
            (x, y)
        }
        _ => {
            return Differences {
                kinds: true,
                size,
                digests: Vec::new(),
                tree: None,
            };
        }
    };
    let digests = DigestAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| x.get(*algorithm) != y.get(*algorithm))
        .collect();
    let tree = match (a.entries(), b.entries()) {
        (Some(original), Some(candidate)) => Some(tree_diff::compare(
            entry_views(original),
            entry_views(candidate),
            &AlgorithmSet::all(),
        )),
        _ => None,
    };
    Differences {
        kinds: false,
        size,
        digests,
        tree,
    }
}

/// `INCOMPLETE` when what failed is a missing side, an exceeded limit or an
/// unsupported platform; `FAILED` otherwise, and whenever either side
/// failed that way.
fn failure_outcome(a: Option<&InspectError>, b: Option<&InspectError>) -> ComparisonOutcome {
    let incomplete = |err: &InspectError| {
        matches!(
            FailureKind::of(err),
            FailureKind::NotFound | FailureKind::LimitExceeded | FailureKind::Unsupported
        )
    };
    if a.into_iter().chain(b).all(incomplete) {
        ComparisonOutcome::Incomplete
    } else {
        ComparisonOutcome::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::Path;

    fn files(dir: &Path, a: &[u8], b: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let (x, y) = (dir.join("a"), dir.join("b"));
        std::fs::write(&x, a).unwrap();
        std::fs::write(&y, b).unwrap();
        (x, y)
    }

    fn paths(a: &Path, b: &Path) -> Comparison {
        compare(
            ArtifactSource::Path(a),
            ArtifactSource::Path(b),
            &CompareOptions::default(),
        )
    }

    #[test]
    fn identical_files_match() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = files(dir.path(), b"same", b"same");
        let result = paths(&a, &b);
        assert_eq!(result.outcome(), ComparisonOutcome::Match);
        assert!(result.differences().unwrap().digests().is_empty());
    }

    #[test]
    fn different_files_differ_in_every_digest() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = files(dir.path(), b"same", b"sane");
        let result = paths(&a, &b);
        assert_eq!(result.outcome(), ComparisonOutcome::Different);
        let differences = result.differences().unwrap();
        assert!(!differences.size_differs());
        assert_eq!(differences.digests(), DigestAlgorithm::ALL);
    }

    #[test]
    fn a_stream_holds_the_same_kind_of_content_as_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _) = files(dir.path(), b"same", b"");
        let result = compare(
            ArtifactSource::Path(&a),
            ArtifactSource::Reader {
                name: "-",
                reader: Box::new(Cursor::new(b"same".to_vec())),
            },
            &CompareOptions::default(),
        );
        assert_eq!(result.outcome(), ComparisonOutcome::Match);
    }

    #[test]
    fn a_missing_side_is_incomplete_and_a_limit_too() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _) = files(dir.path(), b"same", b"");
        let missing = dir.path().join("missing");
        assert_eq!(paths(&a, &missing).outcome(), ComparisonOutcome::Incomplete);
        assert_eq!(
            paths(&missing, &missing).outcome(),
            ComparisonOutcome::Incomplete
        );
        let mut opts = CompareOptions::default();
        opts.limits.max_bytes = 2;
        let result = compare(ArtifactSource::Path(&a), ArtifactSource::Path(&a), &opts);
        assert_eq!(result.outcome(), ComparisonOutcome::Incomplete);
        assert!(result.differences().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn any_other_failure_makes_it_failed() {
        let dir = tempfile::tempdir().unwrap();
        let (a, _) = files(dir.path(), b"same", b"");
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert_eq!(paths(&a, &fifo).outcome(), ComparisonOutcome::Failed);
        // Failed outranks incomplete.
        let missing = dir.path().join("missing");
        assert_eq!(paths(&missing, &fifo).outcome(), ComparisonOutcome::Failed);
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_compared_entry_by_entry() {
        let dir = tempfile::tempdir().unwrap();
        let make = |name: &str, contents: &[u8]| {
            let root = dir.path().join(name);
            std::fs::create_dir_all(root.join("sub")).unwrap();
            std::fs::write(root.join("sub/file"), contents).unwrap();
            root
        };
        let (a, b, c) = (make("a", b"1"), make("b", b"1"), make("c", b"2"));
        assert_eq!(paths(&a, &b).outcome(), ComparisonOutcome::Match);
        let result = paths(&a, &c);
        assert_eq!(result.outcome(), ComparisonOutcome::Different);
        let tree = result.differences().unwrap().tree().unwrap();
        assert_eq!(tree.differences().len(), 1);
        assert_eq!(tree.differences()[0].path().as_str(), "sub/file");

        // A directory and a file are different kinds, whatever their sizes.
        let file = dir.path().join("file");
        std::fs::write(&file, b"1").unwrap();
        let result = paths(&a, &file);
        assert_eq!(result.outcome(), ComparisonOutcome::Different);
        assert!(result.differences().unwrap().kinds_differ());
    }

    #[test]
    fn output_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = files(dir.path(), b"same", b"sane");
        assert_eq!(
            paths(&a, &b).to_pretty_json(),
            paths(&a, &b).to_pretty_json()
        );
    }
}
