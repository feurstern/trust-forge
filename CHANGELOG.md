# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, breaking changes may happen in any release and are always listed here.

## [Unreleased]

### Added

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

- CI runs on pushes to `master`, the repository's default branch, and runs clippy on Linux, macOS and Windows.
- The dependency plan: `cap-std` is replaced by `rustix` (decision 10). `tracing`, `anyhow` and `insta` are deferred until needed.

No verification functionality exists yet: Milestone 1 inspects and hashes artifacts but compares them with nothing.
