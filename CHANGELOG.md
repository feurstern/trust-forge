# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, breaking changes may happen in any release and are always listed here.

## [Unreleased]

### Added

- Milestone 0: Cargo workspace with `trustforge-core` (library, no API yet) and `trustforge-cli` (binary `trustforge`, `--help` and `--version` only).
- Pinned toolchain (Rust 1.99.1), MSRV 1.88, workspace lints (`unsafe_code` forbidden; `todo!`/`unimplemented!`/`dbg!` denied), rustfmt, clippy and cargo-deny configuration.
- CI workflow (fmt, clippy, tests on Linux/macOS/Windows, MSRV, rustdoc, cargo-deny) and Dependabot configuration.
- Architecture, threat model, verification semantics, draft manifest specification (v0), standards status, known limitations and roadmap documents.

No verification functionality exists yet.
