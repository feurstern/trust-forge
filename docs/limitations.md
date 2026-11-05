# Known Limitations

## Current state

- **TrustForge does not verify anything yet.** Milestone 1 provides `trustforge inspect`, which describes an artifact and computes its digests. It compares them with nothing, so it establishes which bytes were read, not that they are genuine. See the [roadmap](roadmap.md).
- **Format detection reads header bytes only.** It reports what a file's first bytes claim, without validating the file. A file can be valid in several formats at once (a polyglot). PE headers that start beyond the first 4 KiB are not recognized.
- **Concurrent modification is detected on a best-effort basis, never prevented.** These can go unnoticed:
  - changes within the file system's timestamp granularity that keep the size;
  - writes through already-dirty shared memory maps;
  - a change that is undone before the check (A-B-A);
  - network or FUSE file systems that report false metadata.

  On Windows, a single file's length and modification time are the only checks, and the given path is opened (with no access rights) to determine its type, so a device or named-pipe path is opened before it is rejected. Inspect an immutable copy when this matters.
- **Memory for directory listings** grows with the number of entries, at about 0.7 KB per entry with all three algorithms. At the default limit of 1,000,000 entries, that is about 0.7 GB.
- **Limits** (defaults; the first three are adjustable on the command line):

  | Limit | Default |
  |---|---|
  | Content bytes read | 64 GiB |
  | Directory entries | 1,000,000 |
  | Directory depth | 128 path components |
  | Total length of entry paths | 256 MiB |
  | Symlink target length | 4,096 bytes |
- **`Mode` and `Modified`** in the text output are file-system metadata of the given path, not covered by any digest.

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
  - directory inspection is unsupported on Windows, which has no executable bit;
  - names and symlink targets must be valid UTF-8 without control characters, bidi controls, line or paragraph separators, or backslash (the exact list is in the [architecture](architecture.md#directory-traversal-rules));
  - FIFOs, sockets and device nodes are rejected;
  - mount points inside a tree are rejected, including btrfs subvolumes, which have their own device numbers;
  - nothing is excluded: `.git`, `.DS_Store` and similar files are part of the tree digest;
  - names are compared byte for byte, with no Unicode normalization, so trees copied between file systems that normalize names differently will not match;
  - only the owner-execute permission bit is covered. **`cp -a`, `rsync -a` or `tar -p` of a verified tree can carry permission bits (setuid, setgid, file capabilities) that no digest covered;**
  - on macOS, reading an iCloud "dataless" placeholder file makes the operating system download it.
- **Signatures and provenance** depend on the maturity of the Rust Sigstore libraries. The library choice is made in Milestone 5, based on conformance results.
