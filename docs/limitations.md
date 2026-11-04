# Known Limitations

## Current state

- **TrustForge does not verify anything yet.** Milestone 0 provides architecture, documentation and a workspace whose CLI only supports `--help` and `--version`. See the [roadmap](roadmap.md).

## Inherent limitations

These follow from what verification can and cannot establish. They will not be "fixed".

- **A matching checksum is not trust.** It establishes integrity relative to a reference. If the reference comes from the same place as the artifact, an attacker can replace both.
- **Reproducibility is not security.** A byte-identical rebuild shows the publisher added nothing beyond the declared inputs. It says nothing about whether the source, its dependencies or the toolchain are benign. Backdoors committed to the source reproduce perfectly.
- **Trusting trust.** If the build image's toolchain is compromised, the original build and the rebuild can be compromised identically.
- **Signatures are only as good as the policy.** A valid signature from an identity you did not mean to trust proves nothing useful. TrustForge never trusts a signer by default.
- **Containers are not virtual machines.** Rebuild isolation relies on a container runtime. Containers share the host kernel, and access to a rootful Docker daemon is equivalent to root. Use a rootless runtime, gVisor or a disposable VM when stronger isolation is needed.
- **Verify-then-use gap.** A file can be replaced after it was verified. Verify immediately before use, or verify an immutable copy.
- **Software security is never assessed.**

## Planned scope limitations

These are limitations of the planned initial releases.

- **Rebuilds:** Linux hosts only. Rust/Cargo projects only. One binary target and one target triple per manifest. Packaged archives (for example a tarball containing a binary plus scripts) are not rebuilt.
- **Build images:** by default only official `docker.io/library/rust` images pinned by digest are accepted. Others need explicit approval.
- **Fetch phase:** dependency downloads run with unrestricted network egress in the first rebuild release. No credentials are present, and no repository-configured code is expected to run.
- **Git:** most repositories identify commits with SHA-1. TrustForge additionally records a SHA-256 digest of the checked-out tree.
- **Registries:** alternate Cargo registries are not supported in the first rebuild release.
- **Path remapping:** Cargo's `trim-paths` is still unstable. Reproducibility across different build paths needs identical paths or `--remap-path-prefix`.
- **Directories:**
  - directory tree digests are unsupported on Windows, which has no executable bit;
  - file names must be valid UTF-8 without control characters, bidi controls or backslash;
  - FIFOs, sockets and device nodes are rejected;
  - names are compared byte for byte, with no Unicode normalization, so trees copied between file systems that normalize names differently will not match.
- **Concurrent modification** of an artifact during inspection is detected and reported as an error, not prevented.
- **Signatures and provenance** depend on the maturity of the Rust Sigstore libraries. The library choice is made in Milestone 5, based on conformance results.
