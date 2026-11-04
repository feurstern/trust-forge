//! Core library of TrustForge, a reproducible build verification engine.
//!
//! # Status
//!
//! Pre-alpha: this crate has no public API yet. Milestone 0 only sets up the
//! workspace. Artifact inspection and hashing arrive in Milestone 1, together
//! with their tests. Nothing in this crate verifies anything today.
//!
//! The planned modules (`digest`, `inspect`, `manifest`, `compare`, `verify`
//! and `report`) are described in `docs/architecture.md`. The guarantees
//! TrustForge keeps apart (integrity, authenticity, provenance and
//! reproducibility) are defined in `docs/verification-semantics.md`.
