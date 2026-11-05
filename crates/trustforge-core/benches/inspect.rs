//! Benchmarks for hashing and inspection: `cargo bench -p trustforge-core`.
//!
//! Inputs are generated before timing starts, in a temporary directory, so
//! file benchmarks measure whatever file system backs it (often tmpfs).
//! Divan's allocation profiler reports the memory each operation allocates,
//! which backs the claim that hashing memory does not grow with input size.

// Setup failures should abort a benchmark run loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::sync::LazyLock;

use divan::counter::{BytesCount, ItemsCount};
use divan::{AllocProfiler, Bencher, black_box};
use trustforge_core::digest::{AlgorithmSet, DigestAlgorithm, MultiHasher};
use trustforge_core::inspect::{InspectOptions, inspect_path};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

const MIB: usize = 1 << 20;
const DATA_LEN: usize = 256 * MIB;
const TREE_DIRS: usize = 100;
const FILES_PER_DIR: usize = 1000;

static DATA: LazyLock<Vec<u8>> = LazyLock::new(|| (0..DATA_LEN).map(|i| (i % 251) as u8).collect());

struct Fixture {
    _dir: tempfile::TempDir,
    file: PathBuf,
    tree: PathBuf,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.bin");
    fs::write(&file, &*DATA).unwrap();
    let tree = dir.path().join("tree");
    for d in 0..TREE_DIRS {
        let sub = tree.join(format!("dir{d:03}"));
        fs::create_dir_all(&sub).unwrap();
        for f in 0..FILES_PER_DIR {
            fs::write(
                sub.join(format!("file{f:04}")),
                format!("contents of {d}/{f}\n"),
            )
            .unwrap();
        }
    }
    Fixture {
        _dir: dir,
        file,
        tree,
    }
});

fn algorithms(name: &str) -> AlgorithmSet {
    match name {
        "all" => AlgorithmSet::all(),
        name => AlgorithmSet::new([name.parse::<DigestAlgorithm>().unwrap()]).unwrap(),
    }
}

/// In-memory hashing throughput, per algorithm and with all three in one pass.
#[divan::bench(args = ["blake3", "sha256", "sha512", "all"], sample_count = 10, sample_size = 1)]
fn hash_256_mib_in_memory(bencher: Bencher, name: &str) {
    let set = algorithms(name);
    let data = &*DATA;
    bencher.counter(BytesCount::of_slice(data)).bench(|| {
        let mut hasher = MultiHasher::new(&set);
        hasher.update(data);
        black_box(hasher.finalize())
    });
}

/// Inspecting a 256 MiB file: streaming through the read buffer, all three
/// algorithms, format detection and modification checks.
#[divan::bench(sample_count = 10, sample_size = 1)]
fn inspect_256_mib_file(bencher: Bencher) {
    let fixture = &*FIXTURE;
    let opts = InspectOptions::default();
    bencher
        .counter(BytesCount::new(DATA_LEN))
        .bench(|| black_box(inspect_path(&fixture.file, &opts).unwrap()));
}

/// Inspecting a tree of 100,000 small files in 100 directories.
#[divan::bench(sample_count = 5, sample_size = 1)]
fn inspect_100k_file_tree(bencher: Bencher) {
    let fixture = &*FIXTURE;
    let opts = InspectOptions::default();
    bencher
        .counter(ItemsCount::new(TREE_DIRS * FILES_PER_DIR))
        .bench(|| black_box(inspect_path(&fixture.tree, &opts).unwrap()));
}
