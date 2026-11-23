//! Comparing two directory listings entry by entry.
//!
//! Both listings must be in tree order (depth-first, siblings in ascending
//! byte order: `a`, `a/b`, `a-b`), which lets one merge-join pass find every
//! missing, unexpected and changed entry. A listing that is not strictly in
//! that order cannot be compared reliably, so it is an error rather than a
//! comparison that silently misses entries.
//!
//! The differences kept are capped by number and by size, so that a report
//! stays bounded however much two trees differ; the rest are counted.

use std::cmp::Ordering;
use std::iter::Peekable;

use super::CheckStatus;
use super::digests::{DigestMatch, match_digests};
use crate::digest::{AlgorithmSet, DigestAlgorithm, DigestSet};
use crate::manifest::{EntryClaimKind, TreeEntryClaim};
use crate::name::RelPath;

/// At most this many differences are kept.
pub(crate) const MAX_DIFFERENCES: usize = 1000;

/// At most about this many bytes of differences are kept: paths can be tens
/// of kilobytes long, so a count alone would not bound a report.
pub(crate) const MAX_DIFFERENCE_BYTES: usize = 1 << 20;

/// The type of a directory entry.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
}

impl EntryType {
    /// `file`, `directory` or `symlink`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        [Self::File, Self::Directory, Self::Symlink]
            .into_iter()
            .find(|t| t.code() == code)
    }
}

/// How one entry differs. "Expected" is the reference's listing (or, when
/// comparing two artifacts, the original); "actual" is the artifact's (or
/// the candidate's).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Expected, but absent.
    Missing(EntryType),
    /// Present, but not expected.
    Unexpected(EntryType),
    /// A different type of entry.
    Type {
        /// The expected type.
        expected: EntryType,
        /// The actual type.
        actual: EntryType,
    },
    /// A different owner-execute bit.
    Executable {
        /// Expected.
        expected: bool,
        /// Actual.
        actual: bool,
    },
    /// A different size.
    Size {
        /// Expected, in bytes.
        expected: u64,
        /// Actual, in bytes.
        actual: u64,
    },
    /// Different contents: the compared algorithms whose digests differ.
    Digest(Vec<DigestAlgorithm>),
    /// A different symlink target.
    Target {
        /// The expected target text.
        expected: String,
        /// The actual target text.
        actual: String,
    },
}

impl Change {
    /// The kind of change: `missing`, `unexpected`, `type`, `executable`,
    /// `size`, `digest` or `target`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::Unexpected(_) => "unexpected",
            Self::Type { .. } => "type",
            Self::Executable { .. } => "executable",
            Self::Size { .. } => "size",
            Self::Digest(_) => "digest",
            Self::Target { .. } => "target",
        }
    }

    fn text_len(&self) -> usize {
        match self {
            Self::Target { expected, actual } => expected.len() + actual.len(),
            _ => 0,
        }
    }
}

/// One differing entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    path: RelPath,
    change: Change,
}

impl Difference {
    pub(crate) fn new(path: RelPath, change: Change) -> Self {
        Self { path, change }
    }

    /// The entry's path.
    pub fn path(&self) -> &RelPath {
        &self.path
    }

    /// How it differs.
    pub fn change(&self) -> &Change {
        &self.change
    }
}

/// Why a listing comparison could not be completed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeProblem {
    /// A listing is not in strictly increasing tree order, so it cannot be
    /// compared reliably.
    Unordered,
    /// A file's digest under a compared algorithm was not computed.
    NotComputed {
        /// The file.
        path: RelPath,
    },
    /// A file's claimed digests use no algorithm the policy accepts.
    NotComparable {
        /// The file.
        path: RelPath,
    },
}

impl TreeProblem {
    /// `unordered`, `not-computed` or `not-comparable`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unordered => "unordered",
            Self::NotComputed { .. } => "not-computed",
            Self::NotComparable { .. } => "not-comparable",
        }
    }

    /// The entry involved, if any.
    pub fn path(&self) -> Option<&RelPath> {
        match self {
            Self::Unordered => None,
            Self::NotComputed { path } | Self::NotComparable { path } => Some(path),
        }
    }
}

/// The result of comparing two listings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeComparison {
    entries: u64,
    differences: Vec<Difference>,
    omitted: u64,
    problem: Option<TreeProblem>,
}

impl TreeComparison {
    pub(crate) fn new(
        entries: u64,
        differences: Vec<Difference>,
        omitted: u64,
        problem: Option<TreeProblem>,
    ) -> Self {
        Self {
            entries,
            differences,
            omitted,
            problem,
        }
    }

    /// The number of entries in the actual listing.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// The differences kept, in tree order.
    pub fn differences(&self) -> &[Difference] {
        &self.differences
    }

    /// How many further differences were found but not kept.
    pub fn omitted(&self) -> u64 {
        self.omitted
    }

    /// Why the comparison could not be completed, if it could not.
    pub fn problem(&self) -> Option<&TreeProblem> {
        self.problem.as_ref()
    }

    /// `ERROR` for unordered listings; otherwise `FAILED` if anything
    /// differs; otherwise `ERROR` for a digest that was not computed,
    /// `UNSUPPORTED` for a file that cannot be compared, or `PASSED`.
    pub(crate) fn status(&self) -> CheckStatus {
        match &self.problem {
            Some(TreeProblem::Unordered) => CheckStatus::Error,
            _ if !self.differences.is_empty() || self.omitted > 0 => CheckStatus::Failed,
            Some(TreeProblem::NotComputed { .. }) => CheckStatus::Error,
            Some(TreeProblem::NotComparable { .. }) => CheckStatus::Unsupported,
            None => CheckStatus::Passed,
        }
    }
}

/// One entry of either listing.
pub(crate) struct View<'a> {
    pub(crate) path: &'a RelPath,
    pub(crate) kind: ViewKind<'a>,
}

pub(crate) enum ViewKind<'a> {
    File {
        executable: bool,
        size: u64,
        digest: &'a DigestSet,
    },
    Directory,
    Symlink {
        target: &'a str,
    },
}

impl ViewKind<'_> {
    fn entry_type(&self) -> EntryType {
        match self {
            Self::File { .. } => EntryType::File,
            Self::Directory => EntryType::Directory,
            Self::Symlink { .. } => EntryType::Symlink,
        }
    }
}

/// The views of a claimed listing.
pub(crate) fn claim_views(entries: &[TreeEntryClaim]) -> impl Iterator<Item = View<'_>> {
    entries.iter().map(|entry| View {
        path: entry.path(),
        kind: match entry.kind() {
            EntryClaimKind::File {
                executable,
                size,
                digest,
            } => ViewKind::File {
                executable: *executable,
                size: *size,
                digest,
            },
            EntryClaimKind::Directory => ViewKind::Directory,
            EntryClaimKind::Symlink { target } => ViewKind::Symlink { target },
        },
    })
}

/// Compares `expected` with `actual`. File contents are compared with
/// [`match_digests`] under `accepted`.
pub(crate) fn compare<'e, 'a>(
    expected: impl IntoIterator<Item = View<'e>>,
    actual: impl IntoIterator<Item = View<'a>>,
    accepted: &AlgorithmSet,
) -> TreeComparison {
    let mut expected = Ordered::new(expected.into_iter());
    let mut actual = Ordered::new(actual.into_iter());
    let mut out = Collector::default();
    loop {
        let order = match (expected.peek_path(), actual.peek_path()) {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(e), Some(a)) => e.tree_cmp(a),
        };
        match order {
            Ordering::Less => {
                if let Some(e) = expected.take() {
                    out.push(e.path, Change::Missing(e.kind.entry_type()));
                }
            }
            Ordering::Greater => {
                if let Some(a) = actual.take() {
                    out.push(a.path, Change::Unexpected(a.kind.entry_type()));
                }
            }
            Ordering::Equal => {
                if let (Some(e), Some(a)) = (expected.take(), actual.take()) {
                    compare_entries(&e, &a, accepted, &mut out);
                }
            }
        }
        if expected.unordered || actual.unordered {
            let entries = actual.count.saturating_add(actual.inner.count() as u64);
            return TreeComparison::new(entries, Vec::new(), 0, Some(TreeProblem::Unordered));
        }
    }
    TreeComparison::new(actual.count, out.differences, out.omitted, out.problem)
}

fn compare_entries(e: &View<'_>, a: &View<'_>, accepted: &AlgorithmSet, out: &mut Collector) {
    let path = e.path;
    match (&e.kind, &a.kind) {
        (
            ViewKind::File {
                executable: expected_executable,
                size: expected_size,
                digest: expected_digest,
            },
            ViewKind::File {
                executable: actual_executable,
                size: actual_size,
                digest: actual_digest,
            },
        ) => {
            if expected_executable != actual_executable {
                out.push(
                    path,
                    Change::Executable {
                        expected: *expected_executable,
                        actual: *actual_executable,
                    },
                );
            }
            if expected_size != actual_size {
                out.push(
                    path,
                    Change::Size {
                        expected: *expected_size,
                        actual: *actual_size,
                    },
                );
            }
            let actual_digest: &DigestSet = actual_digest;
            match match_digests(expected_digest, |alg| actual_digest.get(alg), accepted) {
                DigestMatch::Match(_) => {}
                DigestMatch::Mismatch(algorithms) => out.push(path, Change::Digest(algorithms)),
                DigestMatch::NotComputed(_) => {
                    out.problem(TreeProblem::NotComputed { path: path.clone() })
                }
                DigestMatch::NothingComparable => {
                    out.problem(TreeProblem::NotComparable { path: path.clone() })
                }
            }
        }
        (ViewKind::Directory, ViewKind::Directory) => {}
        (ViewKind::Symlink { target: expected }, ViewKind::Symlink { target: actual }) => {
            if expected != actual {
                out.push(
                    path,
                    Change::Target {
                        expected: (*expected).to_owned(),
                        actual: (*actual).to_owned(),
                    },
                );
            }
        }
        (expected, actual) => out.push(
            path,
            Change::Type {
                expected: expected.entry_type(),
                actual: actual.entry_type(),
            },
        ),
    }
}

/// A listing read in order, noting whether it ever fails to increase.
struct Ordered<'p, I: Iterator<Item = View<'p>>> {
    inner: Peekable<I>,
    last: Option<&'p RelPath>,
    unordered: bool,
    count: u64,
}

impl<'p, I: Iterator<Item = View<'p>>> Ordered<'p, I> {
    fn new(inner: I) -> Self {
        Self {
            inner: inner.peekable(),
            last: None,
            unordered: false,
            count: 0,
        }
    }

    fn peek_path(&mut self) -> Option<&'p RelPath> {
        self.inner.peek().map(|view| view.path)
    }

    fn take(&mut self) -> Option<View<'p>> {
        let view = self.inner.next()?;
        if self
            .last
            .is_some_and(|last| last.tree_cmp(view.path) != Ordering::Less)
        {
            self.unordered = true;
        }
        self.last = Some(view.path);
        self.count = self.count.saturating_add(1);
        Some(view)
    }
}

#[derive(Default)]
struct Collector {
    differences: Vec<Difference>,
    bytes: usize,
    omitted: u64,
    problem: Option<TreeProblem>,
}

impl Collector {
    fn push(&mut self, path: &RelPath, change: Change) {
        // Generous: JSON escaping can double a string.
        let cost = 2 * (path.as_str().len() + change.text_len()) + 64;
        if self.differences.len() < MAX_DIFFERENCES && self.bytes + cost <= MAX_DIFFERENCE_BYTES {
            self.bytes += cost;
            self.differences.push(Difference::new(path.clone(), change));
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    /// Keeps the first problem, except that a digest that was not computed
    /// (a fault) outranks a file that cannot be compared.
    fn problem(&mut self, problem: TreeProblem) {
        let replace = matches!(
            (&self.problem, &problem),
            (None, _)
                | (
                    Some(TreeProblem::NotComparable { .. }),
                    TreeProblem::NotComputed { .. }
                )
        );
        if replace {
            self.problem = Some(problem);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use proptest::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Kind {
        File(bool, u64, DigestSet),
        Directory,
        Symlink(String),
    }

    type Listing = Vec<(RelPath, Kind)>;

    fn file(content: &[u8]) -> Kind {
        Kind::File(
            false,
            content.len() as u64,
            DigestSet::new([Digest::of(DigestAlgorithm::Sha256, content)]).unwrap(),
        )
    }

    fn listing(entries: &[(&str, Kind)]) -> Listing {
        entries
            .iter()
            .map(|(p, k)| (RelPath::parse(p).unwrap(), k.clone()))
            .collect()
    }

    fn views(listing: &Listing) -> impl Iterator<Item = View<'_>> {
        listing.iter().map(|(path, kind)| View {
            path,
            kind: match kind {
                Kind::File(executable, size, digest) => ViewKind::File {
                    executable: *executable,
                    size: *size,
                    digest,
                },
                Kind::Directory => ViewKind::Directory,
                Kind::Symlink(target) => ViewKind::Symlink { target },
            },
        })
    }

    fn diff(expected: &Listing, actual: &Listing) -> TreeComparison {
        compare(views(expected), views(actual), &AlgorithmSet::all())
    }

    fn changes(comparison: &TreeComparison) -> Vec<(&str, &Change)> {
        comparison
            .differences()
            .iter()
            .map(|d| (d.path().as_str(), d.change()))
            .collect()
    }

    #[test]
    fn identical_listings_pass() {
        let tree = listing(&[
            ("a", Kind::Directory),
            ("a/b", file(b"x")),
            ("a-b", Kind::Symlink("a/b".into())),
        ]);
        let result = diff(&tree, &tree);
        assert_eq!(result.status(), CheckStatus::Passed);
        assert_eq!(result.entries(), 3);
        assert!(result.differences().is_empty());
    }

    #[test]
    fn every_kind_of_change_is_found() {
        let expected = listing(&[
            ("bin", Kind::Directory),
            ("bin/app", file(b"v1")),
            ("bin/tool", file(b"t")),
            ("doc", Kind::Directory),
            ("link", Kind::Symlink("bin/app".into())),
            ("readme", file(b"r")),
            ("same", file(b"s")),
        ]);
        let mut exec = file(b"t");
        if let Kind::File(executable, ..) = &mut exec {
            *executable = true;
        }
        let actual = listing(&[
            ("bin", Kind::Directory),
            ("bin/app", file(b"v2!")),
            ("bin/tool", exec),
            ("doc", file(b"not a directory")),
            ("extra", file(b"e")),
            ("link", Kind::Symlink("bin/tool".into())),
            ("same", file(b"s")),
        ]);
        let result = diff(&expected, &actual);
        assert_eq!(result.status(), CheckStatus::Failed);
        assert_eq!(
            changes(&result),
            vec![
                (
                    "bin/app",
                    &Change::Size {
                        expected: 2,
                        actual: 3
                    }
                ),
                ("bin/app", &Change::Digest(vec![DigestAlgorithm::Sha256])),
                (
                    "bin/tool",
                    &Change::Executable {
                        expected: false,
                        actual: true
                    }
                ),
                (
                    "doc",
                    &Change::Type {
                        expected: EntryType::Directory,
                        actual: EntryType::File
                    }
                ),
                ("extra", &Change::Unexpected(EntryType::File)),
                (
                    "link",
                    &Change::Target {
                        expected: "bin/app".into(),
                        actual: "bin/tool".into()
                    }
                ),
                ("readme", &Change::Missing(EntryType::File)),
            ]
        );
    }

    #[test]
    fn tree_order_is_not_string_order() {
        // In string order "a-b" sorts before "a/b"; in tree order after it.
        let expected = listing(&[
            ("a", Kind::Directory),
            ("a/b", file(b"1")),
            ("a-b", file(b"2")),
        ]);
        let result = diff(&expected, &expected);
        assert_eq!(result.status(), CheckStatus::Passed);
        let missing_child = listing(&[("a", Kind::Directory), ("a-b", file(b"2"))]);
        assert_eq!(
            changes(&diff(&expected, &missing_child)),
            vec![("a/b", &Change::Missing(EntryType::File))]
        );
    }

    #[test]
    fn unordered_listings_are_an_error_not_a_silent_pass() {
        let ordered = listing(&[("a", file(b"1")), ("b", file(b"2"))]);
        let reordered = listing(&[("b", file(b"2")), ("a", file(b"1"))]);
        let duplicated = listing(&[("a", file(b"1")), ("a", file(b"1"))]);
        for (expected, actual) in [
            (&ordered, &reordered),
            (&reordered, &ordered),
            (&duplicated, &duplicated),
        ] {
            let result = diff(expected, actual);
            assert_eq!(result.problem(), Some(&TreeProblem::Unordered));
            assert_eq!(result.status(), CheckStatus::Error);
            assert!(result.differences().is_empty());
        }
    }

    #[test]
    fn files_without_a_comparable_digest_are_not_passed() {
        let tree = listing(&[("a", file(b"1"))]);
        let only_blake3 = AlgorithmSet::new([DigestAlgorithm::Blake3]).unwrap();
        let result = compare(views(&tree), views(&tree), &only_blake3);
        assert_eq!(
            result.problem(),
            Some(&TreeProblem::NotComparable {
                path: RelPath::parse("a").unwrap()
            })
        );
        assert_eq!(result.status(), CheckStatus::Unsupported);

        let claimed = listing(&[(
            "a",
            Kind::File(
                false,
                1,
                DigestSet::new([
                    Digest::of(DigestAlgorithm::Sha256, b"1"),
                    Digest::of(DigestAlgorithm::Blake3, b"1"),
                ])
                .unwrap(),
            ),
        )]);
        let result = compare(views(&claimed), views(&tree), &AlgorithmSet::all());
        assert_eq!(
            result.problem().map(TreeProblem::code),
            Some("not-computed")
        );
        assert_eq!(result.status(), CheckStatus::Error);
    }

    #[test]
    fn differences_are_capped_by_number_and_by_size() {
        let many: Listing = (0..MAX_DIFFERENCES + 5)
            .map(|i| (RelPath::parse(&format!("f{i:05}")).unwrap(), file(b"x")))
            .collect();
        let result = diff(&many, &Vec::new());
        assert_eq!(result.differences().len(), MAX_DIFFERENCES);
        assert_eq!(result.omitted(), 5);
        assert_eq!(result.status(), CheckStatus::Failed);

        let long_name = "n".repeat(255);
        let deep = |i: usize| {
            let path = vec![long_name.as_str(); 60].join("/");
            RelPath::parse(&format!("{path}/{i:04}")).unwrap()
        };
        let long: Listing = (0..100).map(|i| (deep(i), file(b"x"))).collect();
        let result = diff(&long, &Vec::new());
        assert!(result.differences().len() < 100);
        assert_eq!(
            result.differences().len() as u64 + result.omitted(),
            100,
            "everything is either kept or counted"
        );
    }

    fn arb_listing() -> impl Strategy<Value = Listing> {
        let component = prop::sample::select(vec!["a", "b", "a-b", "a.b", "B", "z"]);
        let path = prop::collection::vec(component, 1..4);
        let kind = prop_oneof![
            (any::<bool>(), 0u8..3).prop_map(|(executable, content)| {
                let bytes = [content];
                Kind::File(
                    executable,
                    1,
                    DigestSet::new([Digest::of(DigestAlgorithm::Sha256, &bytes)]).unwrap(),
                )
            }),
            Just(Kind::Directory),
            prop::sample::select(vec!["x", "../y"]).prop_map(|t| Kind::Symlink(t.into())),
        ];
        prop::collection::btree_map(path, kind, 0..12).prop_map(|map| {
            // Component-wise order of the paths is tree order.
            map.into_iter()
                .map(|(components, kind)| (RelPath::parse(&components.join("/")).unwrap(), kind))
                .collect()
        })
    }

    proptest! {
        #[test]
        fn a_listing_equals_itself(tree in arb_listing()) {
            let result = diff(&tree, &tree);
            prop_assert_eq!(result.status(), CheckStatus::Passed);
            prop_assert_eq!(result.entries(), tree.len() as u64);
        }

        #[test]
        fn listings_differ_exactly_when_they_are_different(a in arb_listing(), b in arb_listing()) {
            let result = diff(&a, &b);
            prop_assert_eq!(result.problem(), None);
            prop_assert_eq!(result.differences().is_empty(), a == b);
        }
    }
}
