//! Rendering comparisons as text: both sides, how they differ, and the
//! outcome last.

use std::fmt::Write as _;

use trustforge_core::compare::{Comparison, ComparisonOutcome};
use trustforge_core::inspect::ArtifactKind;

use crate::render_report::{artifact_lines, describe};

/// At most this many listing differences are shown.
const SHOWN_DIFFERENCES: usize = 20;

const CLOSING: &str = "A match shows that both sides hold the same bytes. It does not show who produced them or whether they are safe.";

/// The comparison as text.
pub fn text(comparison: &Comparison) -> String {
    let mut out = String::new();
    artifact_lines(&mut out, "Original", comparison.original());
    artifact_lines(&mut out, "Candidate", comparison.candidate());
    let directories = comparison
        .original()
        .result()
        .is_ok_and(|a| a.kind() == ArtifactKind::Directory);
    if let Some(differences) = comparison.differences()
        && comparison.outcome() != ComparisonOutcome::Match
    {
        out.push_str("\nDifferences\n");
        if differences.kinds_differ() {
            out.push_str("  one is a directory and the other is not\n");
        }
        if differences.size_differs() {
            out.push_str("  the sizes differ\n");
        }
        if !differences.digests().is_empty() {
            let names: Vec<&str> = differences
                .digests()
                .iter()
                .map(|a| if directories { a.tree_name() } else { a.name() })
                .collect();
            let _ = writeln!(out, "  digests differ: {}", names.join(", "));
        }
        if let Some(tree) = differences.tree() {
            for difference in tree.differences().iter().take(SHOWN_DIFFERENCES) {
                let _ = writeln!(out, "  {}", describe(difference));
            }
            let shown = tree.differences().len().min(SHOWN_DIFFERENCES) as u64;
            let more = tree.differences().len() as u64 + tree.omitted() - shown;
            if more > 0 {
                let _ = writeln!(out, "  … and {more} more");
            }
        }
    }
    let explanation = match comparison.outcome() {
        ComparisonOutcome::Match if directories => {
            "the same entries, and the same SHA-256, SHA-512 and BLAKE3 tree digests"
        }
        ComparisonOutcome::Match => {
            "the same size and the same SHA-256, SHA-512 and BLAKE3 digests"
        }
        ComparisonOutcome::Different => "both sides were read completely, and they differ",
        ComparisonOutcome::Incomplete => {
            "a side is missing, a limit was exceeded, or this platform cannot inspect a side"
        }
        _ => "the comparison could not be performed",
    };
    if comparison.outcome() == ComparisonOutcome::Match {
        let _ = writeln!(out, "\n{CLOSING}");
    }
    let _ = writeln!(
        out,
        "\nOutcome: {} ({explanation})",
        comparison.outcome().code()
    );
    out
}
