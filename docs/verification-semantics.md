# Verification Semantics

> **Status:** implemented in Milestone 3 for **integrity**: `trustforge verify`, `compare` and `report` follow this document, and so does the library (`trustforge_core::verify`, `report`, `compare`). Authenticity, provenance and reproducibility are always NOT EVALUATED in this version; their checks arrive in Milestones 4 and 5. Once 1.0 is released, the statuses, check identifiers, report fields and exit codes defined here are a stable contract. Until then, every change is listed in the [CHANGELOG](../CHANGELOG.md).

This document defines what TrustForge's results mean. It aims to make it impossible to read a result as more than its evidence supports.

## Dimensions

TrustForge evaluates four **dimensions**, each answering a different question:

| Dimension | Question |
|---|---|
| **Integrity** | Are these exactly the bytes the reference describes? |
| **Authenticity** | Did an identity accepted by the trust policy vouch for these bytes? |
| **Provenance** | Was the artifact built the way an accepted builder attests (source, revision, build process)? |
| **Reproducibility** | Did *this* TrustForge run rebuild the claimed source into identical bytes? |

**Software security is not a dimension.** TrustForge never assesses whether software is safe, and every report says "software security: not assessed".

## Evidence and references

- **Evidence** is what the running TrustForge process observed itself (digests it computed, a rebuild it performed) or verified cryptographically. Imported results, such as saved reports or rebuild records produced elsewhere, are **never** evidence.
- **References** are expected values. Every reference records its origin:

| Origin | Meaning |
|---|---|
| `user-supplied` | Given directly by the user, e.g. `--expect sha256:…` |
| `user-pinned` | A manifest whose SHA-256 the user pinned with `--manifest-digest` |
| `unauthenticated-claim` | Taken from a document whose signature was not verified, such as an unsigned manifest |
| `authenticated` | Taken from a document whose signature was verified and whose signer the trust policy accepts (Milestone 5; this version never produces it, and refuses saved reports that claim it) |

Integrity can be VERIFIED against any reference, but the reference's origin is always printed next to it, including in the overall line. Authenticity and provenance can be VERIFIED only from `authenticated` references.

A verification can use several references, such as a manifest and digests given on the command line. Each is compared separately, and **every one must match**. The artifact's name is never compared with a reference's subject name: as in in-toto, subjects match by digest, so a renamed download still verifies.

A pinned manifest is used only if the SHA-256 of its exact bytes is the pinned digest. Its size is checked first, then its digest, and only then is it parsed: a swapped manifest is never parsed at all.

## Check results

Each check has a **stable identifier** (for example `integrity.digest`), which fixes its dimension. Each result has a status, a one-line explanation, typed evidence, and the reference it is about. **A result's status is computed from its evidence**, by the same function when a report is produced and when a saved report is read.

| Status | Meaning |
|---|---|
| `PASSED` | The evidence supports the claim. |
| `FAILED` | The evidence **contradicts** the claim: digest mismatch, rebuild DIFFERENT, invalid signature, identity rejected by policy. |
| `NOT_PROVIDED` | The evidence the check needs was not supplied. |
| `UNSUPPORTED` | Evidence was supplied, but this version of TrustForge cannot evaluate it, for example an unknown predicate type or a signed envelope. |
| `SKIPPED` | Not run: a prerequisite failed, the user declined approval, or the policy excluded it. |
| `ERROR` | The check started but could not complete: I/O error, timeout, build failure, runtime unavailable. |

JSON reports spell statuses as shown; text output replaces underscores with spaces (`NOT PROVIDED`).

Cryptographic validity and policy acceptance are **separate checks**. A valid signature from an identity the policy does not accept is `authenticity.signature PASSED` together with `authenticity.trust-policy FAILED`.

### Check identifiers

| Check | Dimension | In this version |
|---|---|---|
| `integrity.manifest` | Integrity | Implemented: a pinned manifest's SHA-256 is the pinned digest |
| `integrity.digest` | Integrity | Implemented |
| `integrity.size` | Integrity | Implemented |
| `integrity.tree` | Integrity | Implemented |
| `authenticity.signature` | Authenticity | Only `UNSUPPORTED`, for a signed envelope (DSSE, Sigstore bundle) given as a manifest |
| `authenticity.trust-policy` | Authenticity | Planned (M5) |
| `provenance.subject` | Provenance | Planned (M5) |
| `provenance.builder-policy` | Provenance | Planned (M5) |
| `provenance.source` | Provenance | Planned (M5) |
| `source.reachability` | Reproducibility | Planned (M4) |
| `reproducibility.rebuild` | Reproducibility | Only `UNSUPPORTED`, for a manifest that claims a recipe |
| `reproducibility.compare` | Reproducibility | Planned (M4) |

Evidence that no available check can evaluate always gets an explicit `UNSUPPORTED` result rather than being passed over ([architecture](architecture.md), decision 7).

### Integrity checks

The integrity checks always run; a library caller can add checks, never remove or replace them. Every outcome of every check is held to the rules a saved report must meet (see [Saved reports](#saved-reports)): an outcome whose evidence its check may not report, or that disagrees with the artifact or the reference it names, becomes an `ERROR` result.

- **`integrity.digest`**: exactly one result for each reference (or one `NOT_PROVIDED` result when there is none).
  - The reference's digests are filtered by the algorithms the policy accepts (by default SHA-256, SHA-512 and BLAKE3). **Every remaining algorithm must match**: one wrong digest among several is `FAILED`. If no claimed algorithm is accepted, the result is `UNSUPPORTED`.
  - Content digests (`sha256`, …) are compared only with files and streams, and tree digests (`narSha256`, …) only with directories. Any other pairing is `FAILED`: the reference describes a different kind of artifact. A stream holds the same kind of content as a file.
  - An artifact that cannot be read is `ERROR` for every reference, whatever the reference is (`UNSUPPORTED` when this platform cannot inspect it, such as a directory on Windows), so verification fails rather than reporting the policy as merely unsatisfied. Otherwise, a reference this version cannot evaluate (another manifest version, a signed envelope) is `UNSUPPORTED`, and a manifest that does not match its pin is `SKIPPED`.
  - The explanation names any claimed algorithm the policy does not accept, such as "blake3 matches; sha256 not compared: the policy does not accept it".
- **`integrity.size`**: for references that claim a size. `SKIPPED` when the artifact could not be read or is not the kind of artifact the reference describes.
- **`integrity.tree`**: for directory references with a listing (a manifest's `artifact.tree`): an exact entry-by-entry comparison. Missing, unexpected and retyped entries, a changed owner-execute bit, size, content digest or symlink target are all differences, and any difference is `FAILED`. A listing that is not in tree order is `ERROR`; a file whose claimed digests use no accepted algorithm is `UNSUPPORTED`. At most 1,000 differences (and about 1 MiB of them) are kept in a report; the rest are counted.
- **`integrity.manifest`**: for pinned manifests. `FAILED` if the manifest's SHA-256 is not the pinned digest; the manifest's claims are then not used, and its `integrity.digest` result is `SKIPPED`.

## Dimension status

A dimension's status is computed from its checks' results, in this order:

1. **FAILED** if any check failed.
2. **ERROR** if any check could not complete.
3. **VERIFIED** only if it has at least one result, every result passed, and the checks that decide the dimension passed:
   - integrity: every reference has a passing `integrity.digest` result. Passing pin or size checks alone never verify integrity;
   - authenticity and provenance: additionally, their references are `authenticated` under the trust policy (impossible in this version);
   - reproducibility: a rebuild performed by this process (impossible in this version).
4. **NOT EVALUATED** otherwise, with the most telling reason: unsupported evidence, then a skipped check, then missing evidence (not provided). A dimension without any result is not evaluated because its evidence was not provided: "no signature supplied", "no provenance supplied", "no rebuild performed".

## Overall status

The overall status is computed by this precedence. The first matching rule wins:

| # | Overall status | When |
|---|---|---|
| 1 | **MISMATCH** | Any check `FAILED`, in any dimension, required by the policy or not: some evidence contradicts a claim. |
| 2 | **VERIFICATION FAILED** | Any check hit `ERROR`. TrustForge fails closed. |
| 3 | **VERIFIED** | Every dimension the policy requires is VERIFIED. |
| 4 | **PARTIALLY VERIFIED** | At least one dimension is VERIFIED, but the policy is not satisfied. |
| 5 | **UNVERIFIED** | No dimension is VERIFIED. |

Rules 4 and 5 count verified *dimensions*, not passing checks, so that a run in which only a side check passed (a pinned manifest, a size) is never called "partially verified".

A MISMATCH is **not** a finding of malice. Non-reproducible builds, for example, usually come from embedded timestamps, paths or toolchain differences. Reports list *possible* causes without claiming a root cause.

### Policies

- The default policy, **`full`**, requires integrity, authenticity, provenance and reproducibility. Until signature, provenance and rebuild support exists, a matching checksum therefore yields **PARTIALLY VERIFIED** (exit code 3).
- Narrower policies must be requested explicitly, for example `--require integrity`, or `--require integrity,reproducibility`. The overall line then names the policy and every reference's origin: `VERIFIED (policy "integrity" is satisfied; reference 1: user-supplied)`.
- A policy also lists the digest algorithms comparisons accept (all three by default). The accepted set comes from the policy, never from the reference. The command line does not change it in this version; the library can. The text output always shows the policy's required dimensions and accepted algorithms on its own line.
- The `limitations` section of every report lists every dimension that was not verified, "software security: not assessed", and what the references themselves cannot establish.

## Exit codes

| Code | `verify` | `compare` | `report` | Other commands |
|---|---|---|---|---|
| 0 | VERIFIED under the policy | MATCH | Report shown, whatever it says | Success |
| 1 | MISMATCH | DIFFERENT | — | — |
| 2 | Usage error or invalid input document (bad arguments, malformed or oversized manifest) | Usage error | Usage error, or an invalid or inconsistent report | Same |
| 3 | Policy not satisfied (PARTIALLY VERIFIED or UNVERIFIED) | — | — | — |
| 4 | VERIFICATION FAILED (could not complete) | INCOMPLETE or FAILED | The file could not be read | Operation failed |
| 101 | Internal error (a panic). Please report it. | Same | Same | Same |

A non-zero exit code never means success, and a panic can never produce exit code 0. Any status a later version adds maps to exit code 4 in this version, never to 0.

## Comparison outcomes

`trustforge compare` inspects both sides with SHA-256, SHA-512 and BLAKE3:

| Outcome | Meaning |
|---|---|
| `MATCH` | Both are the same kind of artifact (a file and a stream count as the same kind), their sizes are equal, and their SHA-256, SHA-512 and BLAKE3 digests, all computed in this run, are equal; for directories, every entry is equal too. This is the only kind of match. Any future "normalized" comparison will have a separate, weaker status. |
| `DIFFERENT` | Both sides were read completely and differ. |
| `INCOMPLETE` | The comparison could not cover everything: a side is missing, a limit was exceeded, or this platform cannot inspect a side. |
| `FAILED` | The comparison could not be performed (any other error, such as a permission error, a special file, or a change while reading). When both sides fail, FAILED wins over INCOMPLETE. |

No separate byte-by-byte pass is made: equal digests under three independent algorithms identify equal bytes, and a false MATCH would need collisions in SHA-256, SHA-512 and BLAKE3 at once. Byte-range diagnostics of differences arrive with rebuilds (Milestone 4).

## Reports

### JSON report (`report/v0`)

`verify --format json` writes one JSON document of type `https://feurstern.github.io/trust-forge/report/v0` (see [manifest-spec.md](manifest-spec.md#namespace)).

- It is **deterministic**: keys in RFC 8785 order, two-space indentation, and no wall-clock time unless `--timestamp` is given. The same inputs give byte-identical reports.
- Every string is written in **display form**: characters unsafe for a terminal (control characters, bidi controls, line separators, noncharacters) are escaped as `\u{…}` text. A report is therefore safe to print, and always passes TrustForge's own strict parsing. A name in display form is unambiguous to read, but two different names can have the same display form, because `\` is not escaped.
- Its size is bounded: differences and manifest warnings are capped by number and by size, so every report TrustForge writes fits the default reading limit of 4 MiB.

| Field | Meaning |
|---|---|
| `_type` | `https://feurstern.github.io/trust-forge/report/v0` |
| `tool` | `name` (`trustforge`) and `version` |
| `artifact` | `name` (display form), and `kind`, `size`, `entries` (for a directory, its number of entries; otherwise `null`) and `digest` or `treeDigest` as computed; or `error` with `kind` (such as `not-found`) and `message` |
| `references[]` | `origin`; `source` (`{"type": "expected"}` or `{"type": "manifest", "path", "sha256", "pinned"}`); `claim` (`file` with its claimed `size`; `directory` with its claimed `size` and its listing's number of `entries`; `unsupported` with a `reason` (`statement-type`, `predicate-type`, `no-accepted-algorithm`, `dsse-envelope`, `sigstore-bundle`) and the document's `value` or `pointer` where there is one; or `unusable`); `recipe` (the build type a manifest claims); `warnings` and `warningsOmitted` |
| `checks[]` | `id`, `dimension`, `reference` (an index into `references`, or `null`), `status`, `evidence` (typed by its `type`: `digests`, `size`, `tree`, `pin`, `kind-mismatch`, `not-inspected`, `skipped`, `unsupported-reference`, `no-check` with the `claim` no check evaluated, `no-reference`, `duplicate-check`, `invalid-evidence`), and `summary` |
| `dimensions` | For each dimension: `status`, `reason` (`not-provided`, `unsupported` or `skipped` when not evaluated, otherwise `null`) and `summary` |
| `policy` | `name`, `require` (the required dimensions) and `acceptedAlgorithms` |
| `overall` | `status`, `summary` and `possibleCauses` |
| `limitations[]` | What the report does not establish |
| `generatedAt` | Only with `--timestamp`: an RFC 3339 UTC time |

`summary`, `possibleCauses` and `limitations` are explanations derived from the structured fields, for readers of the JSON. They are not part of what a report claims: `trustforge report` regenerates them.

### Terminal output

The artifact and its digests come first, then the references with their origins, one line per dimension, the checks (with expected and actual values for a mismatch, and up to 20 listing differences), the possible causes of a mismatch, and the limitations. **The overall status is printed last.** All untrusted text is escaped.

### Example (default policy, unsigned manifest)

```text
Integrity          VERIFIED        the artifact matches the reference
Authenticity       NOT EVALUATED   no signature supplied
Provenance         NOT EVALUATED   no provenance supplied
Reproducibility    NOT EVALUATED   no rebuild performed
Software security  NOT ASSESSED    out of scope for TrustForge

Checks
  integrity.digest  PASSED       reference 1: blake3, sha256, sha512 match
  integrity.size    PASSED       reference 1: 13 bytes

Overall: PARTIALLY VERIFIED (policy "full" also requires authenticity, provenance and reproducibility, which are not verified; reference 1: unauthenticated claim (no signature was verified))
```

### Saved reports

`trustforge report <file>` shows a saved report again under the banner *"Loaded from file: not re-verified; reports are unsigned."*, marks every dimension line "recorded", and ends with "Overall (as recorded, not re-verified)". It exits 0 when the report is shown, whatever the report says, so a stored report can never be mistaken for a fresh verification.

A saved report is untrusted input, never evidence. It is read strictly and fails closed:

- anything this version does not define is refused: unknown fields, statuses, evidence types, check identifiers, reference origins (including `authenticated`), tools and report versions;
- every check's status is recomputed from its evidence, every dimension's from the checks, the policy's name from its requirements, and the overall status from those; a recorded value that differs makes the report inconsistent, and it is refused (exit code 2);
- every piece of evidence must agree with what it refers to: the digests, size and number of entries computed for the artifact, the reference's kind, claimed size and listing, a manifest's pinned and actual digests, and each check identifier's fixed dimension;
- every reference must have the results its claims call for: exactly one `integrity.digest` result; one `integrity.manifest` result if it is pinned; one `integrity.size` result if it claims a size; one `integrity.tree` result if it has a listing; a reproducibility result if it claims a recipe; an authenticity result if it is a signed envelope. Deleting a result that told against the artifact is therefore detected;
- explanations are never taken from the file: everything shown is regenerated from the structured data. Values that come from a document or an artifact (a predicate or build type, a JSON Pointer, a path, a symlink target) are shown only in double quotes, with `"` and `\` escaped, and never as part of TrustForge's own sentences. Only inherently free values are shown as stored, on their own labelled lines: names, paths, error messages and the tool version.

What this cannot detect is a report forged consistently throughout: one invented as a whole reads exactly like a genuine one. Reports are unsigned. Verify again to know.
