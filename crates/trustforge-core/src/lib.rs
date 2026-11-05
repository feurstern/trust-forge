//! Core library of TrustForge, a reproducible build verification engine.
//!
//! # Status
//!
//! Pre-alpha. Milestone 1 provides artifact inspection and hashing:
//! [`inspect::inspect_path`] and [`inspect::inspect_reader`] describe a file,
//! a directory tree or a stream, with SHA-256, SHA-512 and BLAKE3 digests
//! computed in one streaming pass ([`digest`]), the format detected from
//! header bytes ([`format`](mod@format)), and, for directories, tree digests
//! over the tree's NAR serialization.
//!
//! **Nothing in this crate verifies anything yet.** A digest identifies
//! bytes; it does not show who produced them or whether they are safe.
//! Verification against references arrives in later milestones (see
//! `docs/roadmap.md`). The guarantees TrustForge keeps apart (integrity,
//! authenticity, provenance and reproducibility) are defined in
//! `docs/verification-semantics.md`, and the design in
//! `docs/architecture.md`.
//!
//! This crate never spawns processes and never opens network connections.

#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod digest;
pub mod format;
pub mod inspect;
pub mod name;
// Only directory traversal, which is Unix-only, writes NAR.
#[cfg_attr(not(unix), allow(dead_code))]
mod nar;
