//! Benchmarks for comparisons and reports:
//! `cargo bench -p trustforge-core --bench compare`.
//!
//! Inputs are generated before timing starts, in a temporary directory, so
//! file benchmarks measure whatever file system backs it (often tmpfs).

// Setup failures should abort a benchmark run loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use divan::counter::{BytesCount, ItemsCount};
use divan::{AllocProfiler, Bencher, black_box};
use trustforge_core::compare::{CompareOptions, compare};
use trustforge_core::inspect::inspect_path;
use trustforge_core::json::JsonLimits;
use trustforge_core::manifest::{Manifest, ParseOptions};
use trustforge_core::report::read_report;
use trustforge_core::verify::{
    ArtifactSource, Dimension, Reference, VerificationPolicy, VerificationReport,
    VerificationRequest, verify,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

const MIB: usize = 1 << 20;
const DATA_LEN: usize = 256 * MIB;
const TREE_DIRS: usize = 100;
const FILES_PER_DIR: usize = 1000;
/// More differing files than a report keeps, so that the report is at its
/// cap.
const CHANGED_FILES: usize = 1500;

struct Fixture {
    _dir: tempfile::TempDir,
    files: [PathBuf; 2],
    trees: [PathBuf; 2],
}

fn write_tree(root: &Path) {
    for d in 0..TREE_DIRS {
        let sub = root.join(format!("dir{d:03}"));
        fs::create_dir_all(&sub).unwrap();
        for f in 0..FILES_PER_DIR {
            fs::write(
                sub.join(format!("file{f:04}")),
                format!("contents of {d}/{f}\n"),
            )
            .unwrap();
        }
    }
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..DATA_LEN).map(|i| (i % 251) as u8).collect();
    let files = [dir.path().join("a.bin"), dir.path().join("b.bin")];
    for file in &files {
        fs::write(file, &data).unwrap();
    }
    let trees = [dir.path().join("a"), dir.path().join("b")];
    for tree in &trees {
        write_tree(tree);
    }
    Fixture {
        _dir: dir,
        files,
        trees,
    }
});

/// A report whose listing comparison holds as many differences as a report
/// keeps.
static REPORT: LazyLock<VerificationReport> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("tree");
    fs::create_dir_all(&root).unwrap();
    for f in 0..CHANGED_FILES {
        fs::write(root.join(format!("file{f:05}")), b"original").unwrap();
    }
    let inspection = inspect_path(&root, &Default::default()).unwrap();
    let manifest = Manifest::from_inspection(&inspection, None)
        .unwrap()
        .to_pretty_json();
    for f in 0..CHANGED_FILES {
        fs::write(root.join(format!("file{f:05}")), b"changed!").unwrap();
    }
    let reference =
        Reference::from_manifest(&manifest, "tree.json", None, &ParseOptions::default()).unwrap();
    verify(VerificationRequest::new(
        ArtifactSource::Path(&root),
        vec![reference],
        VerificationPolicy::require([Dimension::Integrity]).unwrap(),
    ))
});

/// Comparing two identical 256 MiB files: both are read and hashed with all
/// three algorithms.
#[divan::bench(sample_count = 10, sample_size = 1)]
fn compare_256_mib_files(bencher: Bencher) {
    let fixture = &*FIXTURE;
    let opts = CompareOptions::default();
    bencher.counter(BytesCount::new(2 * DATA_LEN)).bench(|| {
        black_box(compare(
            ArtifactSource::Path(&fixture.files[0]),
            ArtifactSource::Path(&fixture.files[1]),
            &opts,
        ))
    });
}

/// Comparing two identical trees of 100,000 files: both are walked, and their
/// listings compared entry by entry.
#[divan::bench(sample_count = 5, sample_size = 1)]
fn compare_100k_file_trees(bencher: Bencher) {
    let fixture = &*FIXTURE;
    let opts = CompareOptions::default();
    bencher
        .counter(ItemsCount::new(2 * TREE_DIRS * FILES_PER_DIR))
        .bench(|| {
            black_box(compare(
                ArtifactSource::Path(&fixture.trees[0]),
                ArtifactSource::Path(&fixture.trees[1]),
                &opts,
            ))
        });
}

/// Writing a report with as many differences as a report keeps.
#[divan::bench]
fn write_report_at_its_cap(bencher: Bencher) {
    let report = &*REPORT;
    bencher.bench(|| black_box(report.to_pretty_json()));
}

/// Reading back and checking a report with as many differences as a report
/// keeps.
#[divan::bench]
fn read_report_at_its_cap(bencher: Bencher) {
    let bytes = REPORT.to_pretty_json();
    bencher
        .counter(BytesCount::of_slice(&bytes))
        .bench(|| black_box(read_report(&bytes, &JsonLimits::default()).unwrap()));
}
