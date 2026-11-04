# Roadmap

Development proceeds in milestones. Each milestone is planned and approved before implementation starts. It is complete only when its quality gates pass.

## Quality gates (every milestone)

- All relevant tests pass, and the actual results are reported.
- `cargo fmt --check` passes, and clippy passes with `-D warnings`.
- `cargo deny check` passes.
- Documentation is updated, including the [threat model](threat-model.md) for security-relevant changes and the [standards status](standards.md).
- Public APIs are reviewed.
- No known regression remains. Limitations are written down in [limitations.md](limitations.md).

## Milestones

### M0: Research and architecture (current)

Architecture, threat model, draft manifest specification and verification semantics, standards survey, dependency selection, workspace, lints, CI and Dependabot configuration. No verification functionality.

### M1: Artifact inspection and hashing

- A spike evaluating `cap-std` traversal semantics on Linux, macOS and Windows.
- The `digest` module, with known-answer and property tests.
- Streaming multi-algorithm hashing (SHA-256, SHA-512, BLAKE3).
- File and stdin inspection, with executable and archive format detection.
- Directory traversal with NAR tree digests and resource limits.
- `trustforge inspect` with text and JSON output.
- Security regression tests and benchmarks.
- Installation guide, quick start, and CLI reference for `inspect`.

### M2: Manifest

- A strict JSON parsing layer.
- The typed in-toto Statement and TrustForge predicate (v0), with validation rules.
- Deterministic and RFC 8785 serialization.
- `trustforge manifest create` and `manifest validate`.
- Golden fixtures, a JSON Schema document and a fuzz target.

### M3: Verification engine

- The `Check` trait, and integrity checks for digest, size and tree.
- Policies, dimension and overall status computation.
- JSON report (v0) and a sanitized terminal renderer.
- `trustforge verify`, `compare` and `report`, with stable exit codes and snapshot tests.
- The Sigstore library spike starts in parallel.

### M4: Rust reproducible build MVP

- The `trustforge-rebuild` crate:
  - plan and approval;
  - hardened source acquisition with reachability checks;
  - the container runtime driver;
  - the two-phase fetch and build;
  - limits, logs, collection, comparison, diagnostics and rebuild records.
- `trustforge rebuild` and `verify --rebuild`.
- Deterministic, nondeterministic and path-sensitive fixture projects.
- An opt-in container CI job.
- The reproducible build guide.

### M5: Provenance and signatures

- The `trustforge-provenance` crate:
  - DSSE and in-toto parsing;
  - SLSA Provenance v1 validation;
  - Sigstore bundle verification (certificate chain, transparency log, trusted time, TUF root);
  - the trust policy file, with cryptographic validity and policy acceptance as separate checks.
- Interoperability with GitHub artifact attestations, verification of signed manifests, and rebuild records as SLSA provenance.
- Negative security tests, plus the sigstore-conformance suite.

### M6: Release preparation

- A CLI review and freeze, and complete documentation.
- A release workflow with reproducible builds, checksums and GitHub artifact attestations, and crates.io Trusted Publishing.
- `cargo-semver-checks`.
- A dogfood job in which TrustForge rebuilds and verifies its own release.
- The manifest v1 freeze, then `v0.1.0-rc.1`.
- Replace the cargo-deny CI action, which downloads cargo-deny without checksum verification, with a digest-pinned installation.

## Open questions

| # | Question | Needed by |
|---|---|---|
| a | What URI namespace should TrustForge's types use (`<ns>`)? A domain the project controls, or a GitHub organization? | M2 |
| b | Keep the name "TrustForge"? An unrelated project, `kodydennon/trustforge`, uses the same name. | M2, at the latest before the first publish |
| c | What security contact should SECURITY.md list? | M6 |
| d | Is it acceptable for directory tree digests to be unsupported on Windows in v0? | M1 |
| e | Should there be a publisher-side `trustforge build` that produces release artifacts with the same recipe verifiers rerun? | M4 |
| f | Should contributions require a DCO sign-off, a CLA, or neither? | M6 |

Questions settled by spikes:
- host `git` versus `gix` versus `git` in a container (M4);
- which Rust Sigstore library to use (M5);
- the trust policy file format and identity-matching rules (M5).

## Hardening backlog (after the MVP)

- An egress allowlist proxy for the rebuild fetch phase.
- Running parsers in a restricted child process (Landlock or seccomp).
- First-class rootless Podman and Docker support, and a bubblewrap backend.
- Verifying vendored crates against crates.io.
- Verification Summary Attestation (VSA) export.
- Consuming SBOMs (SPDX, CycloneDX) as component claims.
