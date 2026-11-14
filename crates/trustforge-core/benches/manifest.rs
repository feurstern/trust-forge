//! Benchmarks for manifests: `cargo bench -p trustforge-core --bench manifest`.
//!
//! The input is a valid directory manifest just under the default 4 MiB
//! limit, generated in memory before timing starts.

// Setup failures should abort a benchmark run loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::LazyLock;

use divan::counter::BytesCount;
use divan::{AllocProfiler, Bencher, black_box};
use trustforge_core::digest::{Digest, DigestAlgorithm};
use trustforge_core::manifest::{ParseOptions, parse_manifest};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

/// A directory manifest with as many files as fit in 4 MiB.
static MANIFEST: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let limit = ParseOptions::default().limits.max_bytes;
    let mut files = 0;
    let mut best = Vec::new();
    loop {
        let candidate = directory_manifest(files + 1000);
        if candidate.len() > limit {
            return best;
        }
        best = candidate;
        files += 1000;
    }
});

fn directory_manifest(files: usize) -> Vec<u8> {
    let mut subjects = Vec::with_capacity(files);
    let mut tree = vec![r#"{"path":"data","type":"directory"}"#.to_owned()];
    for i in 0..files {
        let path = format!("data/file{i:06}.bin");
        let sha256 = Digest::of(DigestAlgorithm::Sha256, path.as_bytes()).to_hex();
        let digest = format!(r#"{{"sha256":"{sha256}"}}"#);
        subjects.push(format!(r#"{{"digest":{digest},"name":"{path}"}}"#));
        tree.push(format!(
            r#"{{"digest":{digest},"executable":false,"path":"{path}","size":1,"type":"file"}}"#
        ));
    }
    let nar = Digest::of(DigestAlgorithm::Sha256, b"tree").to_hex();
    format!(
        r#"{{"_type":"https://in-toto.io/Statement/v1","predicate":{{"artifact":{{"kind":"directory","size":{files},"tree":[{}],"treeDigest":{{"narSha256":"{nar}"}}}}}},"predicateType":"https://feurstern.github.io/trust-forge/manifest/v0","subject":[{}]}}"#,
        tree.join(","),
        subjects.join(","),
    )
    .into_bytes()
}

/// Strict parsing and full validation of a 4 MiB manifest.
#[divan::bench(sample_count = 20, sample_size = 1)]
fn parse_4_mib_manifest(bencher: Bencher) {
    let bytes = &*MANIFEST;
    let opts = ParseOptions::default();
    bencher
        .counter(BytesCount::of_slice(bytes))
        .bench(|| black_box(parse_manifest(bytes, &opts).unwrap()));
}

/// Writing the same manifest in the RFC 8785 canonical form.
#[divan::bench(sample_count = 20, sample_size = 1)]
fn write_canonical_4_mib_manifest(bencher: Bencher) {
    let manifest = parse_manifest(&MANIFEST, &ParseOptions::default())
        .unwrap()
        .manifest;
    bencher
        .counter(BytesCount::of_slice(&*MANIFEST))
        .bench(|| black_box(manifest.to_canonical_json()));
}
