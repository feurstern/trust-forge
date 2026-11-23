//! Core library of TrustForge, a reproducible build verification engine.
//!
//! # Status
//!
//! Pre-alpha. What exists so far:
//! - inspection and hashing (Milestone 1): [`inspect::inspect_path`] and
//!   [`inspect::inspect_reader`] describe a file, a directory tree or a
//!   stream, with SHA-256, SHA-512 and BLAKE3 digests computed in one
//!   streaming pass ([`digest`]), the format detected from header bytes
//!   ([`format`](mod@format)), and, for directories, tree digests over the
//!   tree's NAR serialization;
//! - manifests (Milestone 2): strict JSON ([`json`]) and in-toto Statements
//!   that claim an artifact's digests and recipe ([`manifest`]);
//! - verification (Milestone 3): [`verify::verify`] compares an artifact with
//!   references and reports each guarantee separately, [`report`] writes and
//!   strictly reads reports, and [`compare::compare`] compares two artifacts.
//!
//! **This version can establish integrity only**: that an artifact's bytes
//! are the ones a reference describes. Authenticity, provenance and
//! reproducibility are always reported as not evaluated, and a digest does
//! not show who produced the bytes or whether they are safe. What results
//! mean is defined in `docs/verification-semantics.md`, and the design in
//! `docs/architecture.md`.
//!
//! This crate never spawns processes and never opens network connections.

#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod compare;
pub mod digest;
pub mod format;
pub mod inspect;
pub mod json;
pub mod manifest;
pub mod name;
pub mod report;
pub mod verify;
// Only directory traversal, which is Unix-only, writes NAR.
#[cfg_attr(not(unix), allow(dead_code))]
mod nar;
