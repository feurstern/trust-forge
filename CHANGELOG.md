# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, breaking changes may happen in any release and are always listed here.

## [Unreleased]

### Added

- Milestone 3: `trustforge verify <file|directory|->` compares an artifact with a manifest (`--manifest`, optionally pinned with `--manifest-digest sha256:…`) and with digests given directly (`--expect`), and reports integrity, authenticity, provenance and reproducibility separately, under a policy (`--require`, default `full`). This version establishes integrity only; the other three are always NOT EVALUATED, so under the default policy a match is PARTIALLY VERIFIED (exit code 3). Text or JSON output (`--format json`), with no timestamp unless `--timestamp` is given. Exit codes: 0 verified, 1 mismatch, 2 usage error or invalid manifest, 3 policy not satisfied, 4 verification failed.
- `trustforge compare <original> <candidate>`: MATCH, DIFFERENT, INCOMPLETE or FAILED, from sizes and SHA-256, SHA-512 and BLAKE3 digests, and for directories every entry (exit codes 0, 1, 4, 4).
- `trustforge report <file|->` shows a saved JSON report again, under the banner "loaded from file: not re-verified; reports are unsigned". It refuses reports whose recorded statuses do not follow from their own evidence, or that lack a result their references call for, and regenerates every explanation instead of showing the file's. Values from documents are only ever shown quoted.
- `manifest validate` quotes unsupported statement and predicate types with `"` and `\` escaped, so a value cannot end its quotation.
- `trustforge-core`: the `verify` module (the `Check` trait; built-in checks `integrity.digest`, `integrity.size`, `integrity.tree` and `integrity.manifest`; references with their origins; policies; status computation; explicit `UNSUPPORTED` results for claimed recipes and signed envelopes), the `report` module (the `report/v0` JSON format and its strict reader) and the `compare` module.
- The report format `https://feurstern.github.io/trust-forge/report/v0`, with saved-report fixtures (`fixtures/reports/v0`, written by `scripts/report-fixtures.sh`) and forged copies that must be refused.
- Golden files pinning the output of `verify`, `compare` and `report` (`crates/trustforge-cli/tests/golden/`).
- A fuzz target for the report reader, run weekly in CI; benchmarks for comparisons and reports (`cargo bench -p trustforge-core --bench compare`).
- A desk evaluation of Rust Sigstore libraries, ahead of Milestone 5 (`docs/research/sigstore-libraries.md`).
- Milestone 2: `trustforge manifest create <file|directory|->` writes a manifest (an in-toto Statement v1 with the predicate type `https://feurstern.github.io/trust-forge/manifest/v0`) for an artifact, optionally with a Rust/Cargo recipe (`--build-definition`), in the indented or the RFC 8785 canonical form (`--canonical`), to standard output or atomically to a file (`--output`). `trustforge manifest validate` checks a manifest strictly, with text or JSON output and a `--strict` mode.
- `trustforge-core`: the `json` module (strict I-JSON parsing with JSON Pointer error locations; RFC 8785 and indented writers) and the `manifest` module (typed manifests with every v0 rule, creation from an inspection, the `cargo/v0` build type). `Digest::from_hex`, `Digest::of`, `DigestSet::new` and `RelPath::parse`.
- Manifest fixtures (`fixtures/manifests/v0`): valid manifests in several styles, invalid ones, pinned outputs of `manifest create`, and reference serializations from ECMAScript (`scripts/json-reference.mjs`).
- A JSON Schema for manifests (`docs/schemas/manifest-v0.schema.json`, not normative), checked against the fixtures with ajv (`scripts/check-schema.sh`).
- Coverage-guided fuzz targets (`fuzz/`) for strict JSON, manifests, format detection and names, run weekly in CI (`.github/workflows/fuzz.yml`).
- Milestone 1: `trustforge inspect <file|directory|->`, with text and JSON (`--format json`) output, digest selection (`--algorithm`) and limits (`--max-bytes`, `--max-entries`, `--max-depth`). It inspects and hashes; it verifies nothing.
- `trustforge-core` library API: `digest` (SHA-256, SHA-512 and BLAKE3 computed in one streaming pass), `format` (header-based detection of ELF, Mach-O, PE, WebAssembly, archives and compressed data), `name` (name validation and safe display), and `inspect` (files, streams, and Unix directory trees with NAR tree digests).
- Directory traversal through descriptor-relative system calls that never follow symlinks below the root, never open special files, and reject artifacts modified during inspection (best-effort detection).
- Tests: FIPS 180-4 and official BLAKE3 known-answer vectors; reference NAR files produced by Nix 2.35.4 (`fixtures/nar`, `scripts/nar-reference.sh`); property tests; deterministic concurrent-modification tests; hostile-name, special-file and limit regression tests.
- Benchmarks (`cargo bench -p trustforge-core`).
- Documentation: getting started, CLI reference; architecture decision 10 (traversal with `rustix`, directory inspection unsupported on Windows).
- Milestone 0: Cargo workspace with `trustforge-core` (library, no API yet) and `trustforge-cli` (binary `trustforge`, `--help` and `--version` only).
- Pinned toolchain (Rust 1.99.1), MSRV 1.88, workspace lints (`unsafe_code` forbidden; `todo!`/`unimplemented!`/`dbg!` denied), rustfmt, clippy and cargo-deny configuration.
- CI workflow (fmt, clippy, tests on Linux/macOS/Windows, MSRV, rustdoc, cargo-deny) and Dependabot configuration.
- Architecture, threat model, verification semantics, draft manifest specification (v0), standards status, known limitations and roadmap documents.

### Changed

- Verification semantics, as implemented: PARTIALLY VERIFIED means that at least one *dimension* is verified, and UNVERIFIED that none is (previously "at least one check passed"), so a passing side check such as a pinned manifest never counts as partial verification. Integrity is verified only when every reference's digests were compared and matched. A dimension's reason for not being evaluated is unsupported, then skipped, then not provided.
- A comparison's MATCH is defined by equal sizes and equal SHA-256, SHA-512 and BLAKE3 digests (all computed in the same run), rather than by a byte-by-byte pass.
- `inspect`'s limit options (`--max-bytes`, `--max-entries`, `--max-depth`) are shared by `manifest create`, `verify` and `compare`.
- `insta` is no longer planned: golden files pin command-line output. `tracing` is deferred to Milestone 4.
- `trustforge-core`: `ManifestError::Unsupported` carries a structured `manifest::Unsupported` value (statement type, predicate type, or no accepted algorithm) instead of a string, so the value from the document is never mixed with the explanation. Its message is unchanged, except that `"` and `\` in the quoted value are escaped.
- The manifest specification is implemented as v0: the namespace is `https://feurstern.github.io/trust-forge`; unknown fields in `internalParameters` are rejected, like those in `externalParameters`; the Cargo character rules, exact toolchains, full refs, repository URLs and resolved-dependency rules are stated precisely; a subject list must match a directory's tree.
- The manifest size limit stays at 4 MiB by default and is configurable (`--max-manifest-size`).
- CI runs on pushes to `master`, the repository's default branch, and runs clippy on Linux, macOS and Windows.
- The dependency plan: `cap-std` is replaced by `rustix` (decision 10). `tracing`, `anyhow` and `insta` are deferred until needed.

TrustForge establishes integrity only: signatures, provenance and rebuilds are not verified yet, and are always reported as not evaluated.
