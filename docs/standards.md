# Supported Standards

TrustForge integrates with established standards and does not invent its own. This page records, for each standard, **what TrustForge does with it and which guarantee that provides**.

| Status | Meaning |
|---|---|
| **Supported** | Implemented **and** covered by tests |
| **Partial** | Implemented with documented gaps |
| **Planned** | Not implemented. Nothing on this page should be read as available unless it says Supported. |

> As of Milestone 1, the digest algorithms and NAR tree digests are **Supported**. Every other row is Planned.

| Standard (version referenced) | Role in TrustForge | Milestone | Guarantee provided | Not provided | Status |
|---|---|---|---|---|---|
| SHA-256, SHA-512 (FIPS 180-4); BLAKE3 | Artifact digests, computed by `trustforge inspect`; tested against the FIPS 180-4 examples and the official BLAKE3 test vectors | M1 | Identifies exact bytes. Integrity relative to a reference once references are compared (M3). | Anything about where the reference came from | Supported |
| NAR serialization (Nix Archive) | Directory tree digests; tested against reference serializations produced by Nix 2.35.4 | M1 | Exact identity of a file tree (contents, owner-execute bits, symlinks, empty directories) | Timestamps, ownership, permission bits other than owner-execute (including setuid and capabilities); unsupported on Windows | Supported |
| RFC 7493 (I-JSON), RFC 8785 (JCS) | Strict parsing, deterministic and canonical output | M2 | Unambiguous parsing | Authenticity | Planned |
| in-toto Attestation Framework v1 (Statement, ResourceDescriptor, DigestSet) | Manifest envelope (M2); attestation parsing (M5) | M2, M5 | A well-defined structure for claims | Authenticity until signed | Planned |
| SLSA v1.2: Build Track, Provenance v1, Verification Summary (VSA) v1 | Recipe structure in manifests (M2); provenance verification and rebuild provenance output (M5); VSA export (after M6) | M2–M6 | Provenance *as attested by a builder the user's policy trusts* | That the builder was not compromised | Planned |
| DSSE v1 | Envelope for signed attestations | M5 | Authenticity of the exact signed bytes | Meaning of the payload | Planned |
| Sigstore: bundle v0.3, Fulcio certificates, Rekor v1 and v2, TUF trusted root | Keyless signature verification under an explicit identity policy | M5 | Authenticity and transparency-log inclusion | Anything beyond what the identity policy pins | Planned |
| GitHub Artifact Attestations | Consumed as Sigstore bundles carrying SLSA provenance | M5 | As for Sigstore and SLSA | As for Sigstore and SLSA | Planned |
| OSS Rebuild attestations | Optional third-party rebuild evidence for crates.io source packages | M5+ | A third-party claim, accepted only under policy | Independent verification by TrustForge | Planned |
| Reproducible Builds: `SOURCE_DATE_EPOCH`; diffoscope | Rebuild environment; optional deep diff diagnostics | M4 | Diagnostics only | — | Planned |
| OCI image digests; Package URL (purl) | Pinning build images; identifying resources | M2, M4 | Content identity of the build environment | Trustworthiness of the image | Planned |
| cargo-auditable (embedded dependency list) | Reading the dependency list embedded in Rust binaries | M4+ | An unauthenticated claim | Verification of that list | Planned |
| SPDX 3.0.1, CycloneDX 1.7 | Consuming SBOMs as component claims | After M6 | Inventory | Verification | Planned |

## Deliberate deviations

- **in-toto digest matching.** in-toto considers two digest sets matching if *any* accepted algorithm matches. TrustForge requires *every* accepted algorithm present to match. This is stricter, so anything TrustForge accepts, an in-toto verifier also accepts.
- **BLAKE3 in digest sets.** in-toto does not predefine `blake3`. TrustForge uses the key `blake3` with the lowercase hex encoding of the 32-byte default output, documented in [manifest-spec.md](manifest-spec.md#digest-sets) as in-toto requires for new algorithm names.
- **Unknown build parameters.** Following SLSA's verifier guidance, unknown fields in `externalParameters` are rejected rather than ignored.

## Not planned

TrustForge does not aim to replace or operate a package registry, CI system, signing authority (it uses Sigstore), provenance framework (it uses SLSA and in-toto), malware scanner, or any blockchain-based trust system.

## Versions referenced (November 2026)

- SLSA v1.2, released November 2025 (adds the Source Track; backward compatible with v1.1).
- in-toto Attestation Framework v1.
- Sigstore bundle format v0.3; Rekor v2, generally available since October 2025.
- CycloneDX 1.7 (October 2025); SPDX 3.0.1.
