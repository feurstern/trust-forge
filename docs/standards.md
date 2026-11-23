# Supported Standards

TrustForge integrates with established standards and does not invent its own. This page records, for each standard, **what TrustForge does with it and which guarantee that provides**.

| Status | Meaning |
|---|---|
| **Supported** | Implemented **and** covered by tests |
| **Partial** | Implemented with documented gaps |
| **Planned** | Not implemented. Nothing on this page should be read as available unless it says Supported. |

> As of Milestone 3, the digest algorithms, NAR tree digests, strict JSON parsing and canonical serialization are **Supported**, and `trustforge verify` uses them to establish integrity against references; the in-toto Statement, SLSA build definition and package URL rows are **Partial**. Every other row is Planned.

| Standard (version referenced) | Role in TrustForge | Milestone | Guarantee provided | Not provided | Status |
|---|---|---|---|---|---|
| SHA-256, SHA-512 (FIPS 180-4); BLAKE3 | Artifact digests, computed by `trustforge inspect`, compared with references by `trustforge verify` and between artifacts by `trustforge compare`; tested against the FIPS 180-4 examples and the official BLAKE3 test vectors | M1, M3 | Identifies exact bytes; integrity relative to a reference | Anything about where the reference came from | Supported |
| NAR serialization (Nix Archive) | Directory tree digests; tested against reference serializations produced by Nix 2.35.4 | M1 | Exact identity of a file tree (contents, owner-execute bits, symlinks, empty directories) | Timestamps, ownership, permission bits other than owner-execute (including setuid and capabilities); unsupported on Windows | Supported |
| RFC 7493 (I-JSON), RFC 8785 (JCS) | Strict parsing of manifests and recipe files; deterministic and canonical (JCS) output, tested byte for byte against ECMAScript's own JSON serialization | M2 | Unambiguous parsing: every document has one meaning | Authenticity | Supported |
| in-toto Attestation Framework v1 (Statement, ResourceDescriptor, DigestSet) | TrustForge manifests are written and read as Statements (M2), and artifacts are verified against their digest sets with a stricter matching rule (M3); attestations with other predicates, and DSSE envelopes, are parsed from M5 (until then a DSSE envelope is reported as unsupported) | M2, M3, M5 | A well-defined structure for claims | Authenticity until signed | Partial |
| SLSA v1.2: Build Track, Provenance v1, Verification Summary (VSA) v1 | A manifest's recipe uses the shape of Provenance v1's `BuildDefinition` (M2); provenance verification and rebuild provenance output (M5); VSA export (after M6) | M2–M6 | Provenance *as attested by a builder the user's policy trusts* | That the builder was not compromised | Partial |
| DSSE v1 | Envelope for signed attestations | M5 | Authenticity of the exact signed bytes | Meaning of the payload | Planned |
| Sigstore: bundle v0.3, Fulcio certificates, Rekor v1 and v2, TUF trusted root | Keyless signature verification under an explicit identity policy | M5 | Authenticity and transparency-log inclusion | Anything beyond what the identity policy pins | Planned |
| GitHub Artifact Attestations | Consumed as Sigstore bundles carrying SLSA provenance | M5 | As for Sigstore and SLSA | As for Sigstore and SLSA | Planned |
| OSS Rebuild attestations | Optional third-party rebuild evidence for crates.io source packages | M5+ | A third-party claim, accepted only under policy | Independent verification by TrustForge | Planned |
| Reproducible Builds: `SOURCE_DATE_EPOCH`; diffoscope | Rebuild environment; optional deep diff diagnostics | M4 | Diagnostics only | — | Planned |
| OCI image digests; Package URL (purl) | A recipe's build image must be a `pkg:docker/` package URL with a SHA-256 image manifest digest (M2); the package URL is not otherwise parsed; pinning the image for rebuilds (M4) | M2, M4 | Content identity of the build environment | Trustworthiness of the image | Partial |
| cargo-auditable (embedded dependency list) | Reading the dependency list embedded in Rust binaries | M4+ | An unauthenticated claim | Verification of that list | Planned |
| SPDX 3.0.1, CycloneDX 1.7 | Consuming SBOMs as component claims | After M6 | Inventory | Verification | Planned |

## Deliberate deviations

- **in-toto digest matching.** in-toto considers two digest sets matching if *any* accepted algorithm matches. TrustForge requires *every* accepted algorithm present to match (enforced by `trustforge verify` since Milestone 3). This is stricter, so anything TrustForge accepts, an in-toto verifier also accepts. Subject names are not compared, as in in-toto: subjects match by digest.
- **BLAKE3 in digest sets.** in-toto does not predefine `blake3`. TrustForge uses the key `blake3` with the lowercase hex encoding of the 32-byte default output, documented in [manifest-spec.md](manifest-spec.md#digest-sets) as in-toto requires for new algorithm names.
- **Unknown build parameters.** Following SLSA's verifier guidance, unknown fields in `externalParameters` are rejected rather than ignored.

## Not planned

TrustForge does not aim to replace or operate a package registry, CI system, signing authority (it uses Sigstore), provenance framework (it uses SLSA and in-toto), malware scanner, or any blockchain-based trust system.

## Versions referenced (November 2026)

- SLSA v1.2, released November 2025 (adds the Source Track; backward compatible with v1.1).
- in-toto Attestation Framework v1.
- Sigstore bundle format v0.3; Rekor v2, generally available since October 2025.
- CycloneDX 1.7 (October 2025); SPDX 3.0.1.
