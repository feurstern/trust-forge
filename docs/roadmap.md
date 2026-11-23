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

### M0: Research and architecture (done)

Architecture, threat model, draft manifest specification and verification semantics, standards survey, dependency selection, workspace, lints, CI and Dependabot configuration. No verification functionality.

### M1: Artifact inspection and hashing (done)

- An evaluation of directory traversal approaches. Decided: `rustix` descriptor-relative system calls on Unix, with directory inspection unsupported on Windows ([architecture](architecture.md#key-decisions), decision 10).
- The `digest` module, with known-answer and property tests.
- Streaming multi-algorithm hashing (SHA-256, SHA-512, BLAKE3).
- File and stdin inspection, with executable and archive format detection.
- Directory traversal with NAR tree digests and resource limits, checked against reference serializations produced by Nix.
- `trustforge inspect` with text and JSON output.
- Security regression tests and benchmarks.
- [Getting started](getting-started.md) (installation and quick start) and the [CLI reference](cli-reference.md) for `inspect`.

### M2: Manifest (done)

- A strict JSON parsing layer (`trustforge_core::json`).
- The typed in-toto Statement and TrustForge predicate (v0), with validation rules.
- Deterministic and RFC 8785 serialization, checked against ECMAScript's own JSON serialization.
- `trustforge manifest create` and `manifest validate`.
- Golden fixtures (`fixtures/manifests/v0`), a non-normative [JSON Schema](schemas/manifest-v0.schema.json) checked against them with ajv, and coverage-guided fuzz targets for the manifest parser and the M1 format detector, run weekly in CI.
- The manifest size limit for large directory artifacts: decided to stay at 4 MiB by default and be configurable (see [manifest-spec.md](manifest-spec.md#parsing-and-validation)); a more compact form for very large trees is an open item before v1.

### M3: Verification engine (current)

- The `Check` trait, and integrity checks for digest, size, tree and pinned manifests (`trustforge_core::verify`). Built-in checks always run; a result's status is computed from its evidence.
- Policies (`full` by default, or `--require` a list of dimensions), and dimension and overall status computation, property-tested against the rules of [verification-semantics.md](verification-semantics.md).
- The JSON report (`report/v0`) and its strict reader, which recomputes every status and refuses inconsistent reports; a sanitized terminal renderer.
- `trustforge verify`, `compare` and `report`, with stable exit codes; their output is pinned by golden files, and saved reports by fixtures (`fixtures/reports/v0`). A fuzz target for the report reader joins the weekly job.
- The Sigstore library spike started as a desk evaluation, [research/sigstore-libraries.md](research/sigstore-libraries.md); the hands-on spike and the decision belong to M5.

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
| b | Keep the name "TrustForge"? An unrelated project, `kodydennon/trustforge`, uses the same name. | M2, at the latest before the first publish |
| c | What security contact should SECURITY.md list? | M6 |
| e | Should there be a publisher-side `trustforge build` that produces release artifacts with the same recipe verifiers rerun? | M4 |
| f | Should contributions require a DCO sign-off, a CLA, or neither? | M6 |

Settled:
- (a) TrustForge's type URIs live under `https://feurstern.github.io/trust-forge` (decided for Milestone 2).
- (d) Directory tree digests are unsupported on Windows in v0 (decided for Milestone 1).

Questions that spikes will settle:
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
