# Verification Semantics

> **Status:** draft. Implemented from Milestone 3; until then, nothing here is available. Once 1.0 is released, the statuses, check identifiers and exit codes defined here are a stable contract, and changes before then are listed in the [CHANGELOG](../CHANGELOG.md).

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
| `unauthenticated-claim` | Taken from an unsigned document, such as an unsigned manifest |
| `authenticated` | Taken from a document whose signature was verified and whose signer the trust policy accepts (M5) |

Integrity can be VERIFIED against any reference, but the reference's origin is always printed next to it, including in the overall line. Authenticity and provenance can be VERIFIED only from `authenticated` references.

## Check results

Each check has a **stable identifier** (for example `integrity.digest`), a dimension, a status, a one-line explanation, typed evidence, the reference origin, and failure details where relevant.

| Status | Meaning |
|---|---|
| `PASSED` | The evidence supports the claim. |
| `FAILED` | The evidence **contradicts** the claim: digest mismatch, rebuild DIFFERENT, invalid signature, identity rejected by policy. |
| `NOT_PROVIDED` | The evidence the check needs was not supplied. |
| `UNSUPPORTED` | Evidence was supplied, but this version of TrustForge cannot evaluate it, for example an unknown predicate type. |
| `SKIPPED` | Not run: a prerequisite failed, the user declined approval, or the policy excluded it. |
| `ERROR` | The check started but could not complete: I/O error, timeout, build failure, runtime unavailable. |

Cryptographic validity and policy acceptance are **separate checks**. A valid signature from an identity the policy does not accept is `authenticity.signature PASSED` together with `authenticity.trust-policy FAILED`.

Planned check identifiers include:

| Check | Dimension |
|---|---|
| `integrity.digest` | Integrity |
| `integrity.size` | Integrity |
| `integrity.tree` | Integrity |
| `authenticity.signature` | Authenticity |
| `authenticity.trust-policy` | Authenticity |
| `provenance.subject` | Provenance |
| `provenance.builder-policy` | Provenance |
| `provenance.source` | Provenance |
| `source.reachability` | Reproducibility |
| `reproducibility.rebuild` | Reproducibility |
| `reproducibility.compare` | Reproducibility |

## Dimension status

A dimension is **VERIFIED** only if all of the following hold:

- every one of its checks passed, and at least one ran;
- its evidence was produced or cryptographically verified by this process;
- for authenticity and provenance, its references are `authenticated` under the trust policy.

Otherwise it is **FAILED** (some check failed), **ERROR** (some check could not complete), or **NOT EVALUATED**, with the reason (not provided, unsupported or skipped).

## Overall status

The overall status is computed by this precedence. The first matching rule wins:

| # | Overall status | When |
|---|---|---|
| 1 | **MISMATCH** | Any check `FAILED`: some evidence contradicts a claim. |
| 2 | **VERIFICATION FAILED** | Any check hit `ERROR`. TrustForge fails closed. |
| 3 | **VERIFIED** | Every dimension the policy requires is VERIFIED. |
| 4 | **PARTIALLY VERIFIED** | At least one check passed, but the policy is not satisfied. |
| 5 | **UNVERIFIED** | Nothing passed. |

A MISMATCH is **not** a finding of malice. Non-reproducible builds, for example, usually come from embedded timestamps, paths or toolchain differences. Reports list *possible* causes without claiming a root cause.

### Policies

- The default policy, **`full`**, requires integrity, authenticity, provenance and reproducibility. Until signature and provenance support exists (M5), a matching checksum therefore yields **PARTIALLY VERIFIED**.
- Narrower policies must be requested explicitly, for example `--require integrity`. The overall line then names the policy and the reference origin: `VERIFIED (policy: integrity; reference: user-supplied)`.
- The `limitations` section of every report lists every dimension that was not evaluated, plus "software security: not assessed".

## Exit codes

| Code | `verify` | `compare` | Other commands |
|---|---|---|---|
| 0 | VERIFIED under the policy | Identical | Success |
| 1 | MISMATCH | Different | — |
| 2 | Usage error or invalid input document (bad arguments, malformed or oversized manifest) | Same | Same |
| 3 | Policy not satisfied (PARTIALLY VERIFIED or UNVERIFIED) | — | — |
| 4 | VERIFICATION FAILED (could not complete) | I/O failure | Operation failed |
| 101 | Internal error (a panic). Please report it. | Same | Same |

A non-zero exit code never means success, and a panic can never produce exit code 0.

## Comparison outcomes

| Outcome | Meaning |
|---|---|
| `MATCH` | Every digest, the size, and every byte are identical. This is the only kind of match. Any future "normalized" comparison will have a separate, weaker status. |
| `DIFFERENT` | Both sides were read completely and differ. |
| `INCOMPLETE` | The comparison could not cover everything, for example a missing side or an exceeded limit. |
| `FAILED` | The comparison could not be performed (I/O error). |

## Reports

- **JSON reports** have a versioned type (`<ns>/report/v0`; see [manifest-spec.md](manifest-spec.md#namespace)). They are deterministic: no wall-clock timestamp unless `--timestamp` is given, and stable ordering. With `--format json`, stdout contains exactly one JSON document, and logs go to stderr.
- **Terminal reports** show one line per dimension, the evidence and its origin, the limitations, and the overall status **last**. All untrusted text is escaped.
- **`trustforge report <file>`** re-renders a saved report under the banner *"loaded from file: not re-verified; reports are unsigned"*. It exits 0 when rendering succeeds, whatever the report says, so a stored report can never be mistaken for a fresh verification.

### Example (planned terminal output, default policy, unsigned manifest)

```text
Integrity          VERIFIED        sha256 matches trustforge.json
                                   reference: unauthenticated claim (manifest is not signed)
Authenticity       NOT EVALUATED   no signature supplied
Provenance         NOT EVALUATED   no provenance supplied
Reproducibility    NOT EVALUATED   no rebuild performed
Software security  NOT ASSESSED    out of scope for TrustForge

Overall: PARTIALLY VERIFIED (policy "full" requires all four dimensions)
```
