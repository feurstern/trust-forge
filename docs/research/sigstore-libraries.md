# Sigstore Libraries for Rust: Desk Evaluation

> **Status:** desk research done during Milestone 3, on 2026-11-23, ahead of Milestone 5. It uses public sources only: no code was built, run or added. **Nothing here is a decision.** The library is chosen in Milestone 5, after a hands-on spike judged on conformance results ([roadmap](../roadmap.md#open-questions)). The facts below can change quickly: re-check them when the spike starts.

## What Milestone 5 needs

`trustforge-provenance` must verify Sigstore bundles ([threat model](../threat-model.md#signatures-and-provenance-m5)):
- Fulcio certificate chains, under an explicit identity policy;
- transparency-log inclusion, for Rekor v1 and Rekor v2;
- a trusted time, from a Rekor inclusion or an RFC 3161 timestamp, with no fallback to the current time;
- DSSE envelopes carrying in-toto statements, such as GitHub artifact attestations with SLSA provenance;
- a trusted root distributed through TUF, and verification **offline** given a trusted root.

The library must also fit TrustForge's constraints:
- synchronous APIs, with no async runtime ([architecture](../architecture.md#key-decisions), decision 3);
- MSRV 1.88;
- licences on the cargo-deny allow-list (`deny.toml`);
- a small, auditable dependency tree, preferring pure-Rust dependencies ([threat model](../threat-model.md#trustforge-itself)).

## Candidates

| | `sigstore-verify` ([sigstore/sigstore-rust]) | `sigstore` ([sigstore/sigstore-rs]) |
|---|---|---|
| Newest version | 0.17.0, 2026-11-22 [1] | 0.15.1, 2026-11-22 [2] |
| Licence | Apache-2.0. Versions 0.2.0–0.6.3 were BSD-3-Clause [1] | Apache-2.0 [2] |
| MSRV | 1.86; CI checks it on the locked dependency set [1][3] | none declared [2] |
| Maintenance | First published 2025-11-27. Six breaking minor releases (0.12 to 0.17) since 2026-09-23 [1][4] | Active. Its README calls it "experimental". The Sigstore documentation still lists version 0.10.0 [5][6] |
| Bundle format v0.3 | yes (documented) [7] | not yet: issue #432 is open [8] |
| Rekor v2 | yes (in code) [9] | not found |
| RFC 3161 timestamps | yes (in code). A token must verify against a timestamp authority of the trusted root. At least one verified time is required, with no fallback to the current time [10] | not found |
| DSSE | yes. Accepted log entry kinds: dsse 0.0.1, intoto 0.0.2, hashedrekord 0.0.2; none for dsse 0.0.2 [11] | yes, with exactly one signature (dsse 0.0.1). The inclusion-proof and signed-entry-timestamp checks of its bundle verifier are marked as to-do [12] |
| Synchronous API | yes: `verify` and `verify_reader`. The default features include no HTTP client and no Tokio runtime [7][13] | no. `Verifier` is async, and `blocking::Verifier` starts a Tokio runtime internally; Tokio is a mandatory dependency [12][14] |
| Trusted root | From JSON, synchronously, or from roots embedded in the crate (documented as possibly stale, but usable offline). Through TUF with `sigstore-tuf` (async, behind a feature) [15][16] | Through TUF with `tough` (async), or from JSON "unchecked": its documentation says that path performs no validation [17] |
| Cryptography | aws-lc-rs (C, through `aws-lc-sys`) as the built-in provider. The provider is pluggable, and the repository tests a BoringSSL one [7][18] | OpenSSL by default (`native-tls`). aws-lc-rs with `rustls-tls` and through `tough` [14] |
| Conformance suite | **140 of 140 tests pass**, with no expected failures, at commit 6ce3f74, from which 0.17.0 was published [19][1] | not in the report. A conformance workflow exists but runs only by hand, and had not run [20] |
| Advisories | none found. An Ed25519 key and signature validation fix was released on 2026-11-22 without an advisory [21][22] | none found [23] |

Other crates:
- **`attestation-verify` 0.1.0** (MIT OR Apache-2.0, MSRV 1.88). It verifies only GitHub SLSA provenance bundles (v0.3) from public repositories, rejects Rekor v2 entries, has no RFC 3161 support, and its README says it has not been independently audited [24].
- **`sigstore-verification`** was archived on 2026-05-18 [25].

TUF clients:
- **`tough`** (MIT OR Apache-2.0; 0.24.0, 2026-07-10): async only, with Tokio, aws-lc-rs and rustls as mandatory dependencies. GitHub lists 11 security advisories, three of them published on 2026-04-24 (for example CVE-2026-6968, fixed in 0.22.0) [26][27].
- **`tuf`** (rust-tuf): no stable release since 0.2.0 in 2017. Its newest version is 0.3.0-beta14 (2025-10-20), and its README warns that it is beta software [28].
- **`sigstore-tuf`** 0.17.0 (Apache-2.0, part of sigstore-rust): an async updater, plus a store for offline use. Its CI passes the TUF conformance suite (tuf-conformance v2.5.0) with no expected failures [29][30].

Both Sigstore libraries, and `tough`, depend on **`aws-lc-sys`**, which builds the AWS-LC C library. It received five RustSec advisories on 2026-03-20 (for example RUSTSEC-2026-0047, fixed in 0.38.0). Its licence expression is reported to include MIT-0, which `deny.toml` does not allow today [31][32].

## Conformance suite

The [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) report of 2026-11-23 lists seven clients: cosign, sigstore-go, sigstore-java, sigstore-js, sigstore-python, sigstore-ruby and sigstore-rust [19].
- sigstore-rust passes all 140 tests, with Rekor v2, "DSSE as hashedrekord" and user-managed keys all supported.
- sigstore-rs is not in the report.
- The bundle-verification tests (70 cases, including 26 for Rekor v2, 7 for DSSE and 7 for in-toto, plus timestamp-authority cases) give the client its trusted root as a file. That is the offline model TrustForge needs [33].
- sigstore-rust's CI pins suite v0.0.29, the newest tagged release, and also runs interoperability tests against cosign and sigstore-python, including a Rekor v2 log [3][34].

## Shortlist for the Milestone 5 spike

1. **`sigstore-verify`**, with `sigstore-trust-root`, and `sigstore-tuf` only if TUF must run inside TrustForge. It is the only Rust client in the conformance report. It covers Rekor v1 and v2, RFC 3161 and DSSE, and verifies synchronously, and its MSRV is below TrustForge's.
2. **`attestation-verify`**, as reference code only.

Not shortlisted:
- `sigstore`: its bundle verifier lacks the inclusion-proof and signed-entry-timestamp checks, RFC 3161 and Rekor v2.
- `tough`: async only, with a history of advisories.
- `tuf`: beta releases only.
- `sigstore-verification`: archived.

## Questions for the spike

1. **Dependency tree.** With `default-features = false` and only the needed features, does `cargo tree` show no Tokio and no HTTP client? Does it build on Rust 1.88 with TrustForge's lockfile?
2. **Licences.** What does `cargo deny check` report, in particular for `aws-lc-sys` (MIT-0 is not allowed today)? Any addition to the allow-list needs a justification.
3. **C code.** `aws-lc-sys` builds a C library, which goes against the preference for pure-Rust dependencies and complicates builds on some targets. Is that acceptable for `trustforge-provenance`, or is a pure-Rust crypto provider realistic? Writing one would itself be security-critical code.
4. **TUF from synchronous code.** Can `sigstore-tuf` run under a minimal executor against a local repository, or should the trusted root be fetched separately and loaded from JSON? How stale do the embedded roots get, and how would TrustForge report their age?
5. **Real attestations, end to end:**
   - GitHub attestations from a public repository (Rekor v1).
   - GitHub attestations from a private repository, which have no transparency-log entry and need the library's `skip_tlog_unsafe`. TrustForge would need an explicit, visible policy opt-in for this.
   - Subjects with digests other than SHA-256.
   - Identity policies over the Fulcio certificate extensions.
6. **DSSE entries in Rekor v2.** The library does not accept dsse 0.0.2 entries, and the conformance suite dropped those tests in v0.0.28 [34]. Is it confirmed that production logs never produce them?
7. **Churn and reporting.** How would TrustForge absorb frequent breaking releases before 1.0? Is the verification result detailed enough for TrustForge's per-check evidence?
8. **Security process.** How does the project handle vulnerabilities? The Ed25519 fix of 2026-11-22 came without an advisory.

## Sources

All accessed on 2026-11-23. The versions, licences, MSRVs and conformance results were checked a second time directly against [1], [2], [19] and the repository page.

[sigstore/sigstore-rust]: https://github.com/sigstore/sigstore-rust
[sigstore/sigstore-rs]: https://github.com/sigstore/sigstore-rs

1. https://crates.io/api/v1/crates/sigstore-verify
2. https://crates.io/api/v1/crates/sigstore
3. https://github.com/sigstore/sigstore-rust/blob/main/.github/workflows/ci.yml
4. https://github.com/sigstore/sigstore-rust/releases
5. https://github.com/sigstore/sigstore-rs
6. https://docs.sigstore.dev/language_clients/rust/
7. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-verify/README.md
8. https://github.com/sigstore/sigstore-rs/issues/432
9. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-verify/src/verify_impl/tlog.rs
10. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-verify/src/verify_impl/helpers.rs
11. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-verify/src/verify_impl/rekor.rs
12. https://github.com/sigstore/sigstore-rs/blob/main/src/bundle/verify/verifier.rs
13. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-verify/Cargo.toml
14. https://github.com/sigstore/sigstore-rs/blob/main/Cargo.toml
15. https://docs.rs/sigstore-trust-root/latest/sigstore_trust_root/
16. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-trust-root/Cargo.toml
17. https://docs.rs/sigstore/latest/sigstore/trust/sigstore/struct.SigstoreTrustRoot.html
18. https://github.com/sigstore/sigstore-rust/blob/main/crates/sigstore-crypto/Cargo.toml
19. https://sigstore.github.io/sigstore-conformance
20. https://github.com/sigstore/sigstore-rs/blob/main/.github/workflows/conformance.yml
21. https://github.com/sigstore/sigstore-rust/security/advisories
22. https://github.com/sigstore/sigstore-rust/commits/main
23. https://github.com/sigstore/sigstore-rs/security/advisories
24. https://github.com/combinatrix-ai/attestation-verify
25. https://github.com/jdx/sigstore-verification
26. https://crates.io/api/v1/crates/tough
27. https://github.com/awslabs/tough/security/advisories
28. https://github.com/theupdateframework/rust-tuf
29. https://docs.rs/sigstore-tuf/latest/sigstore_tuf/
30. https://github.com/sigstore/sigstore-rust/blob/main/.github/workflows/tuf-conformance.yml
31. https://rustsec.org/packages/aws-lc-sys.html
32. https://rustsec.org/advisories/RUSTSEC-2026-0047.html
33. https://github.com/sigstore/sigstore-conformance/tree/main/test/assets/bundle-verify
34. https://github.com/sigstore/sigstore-conformance/releases
