# Threat Model and Security Model

> **Status:** Milestone 1. The artifact inspection mitigations below are implemented and covered by tests. All other mitigations are planned for the milestone named next to each component. Behavior that a test has not demonstrated must not be described as a guarantee. Update this document with every security-relevant change.

## Security model

TrustForge's output is used to make trust decisions, so its most important property is that **it never reports more than its evidence supports.** Everything below follows from these principles:

1. **Fail closed.** Anything that cannot be completed is an error or "not evaluated", never a pass.
2. **No implicit trust.** There is no default trusted signer, builder or image. Trust comes only from explicit user policy.
3. **Evidence is distinguished from claims.** TrustForge counts as evidence only what it observed or cryptographically verified in the current run. Every expected value carries its origin, and imported results (saved reports, rebuild records) are claims.
4. **All external input is hostile.** This covers artifacts, manifests, provenance, saved reports, repositories, dependencies, container images and build outputs.
5. **Least privilege.** Untrusted code runs only in a container, after explicit approval, with no network during the build and no access to user files or credentials.
6. **Explicit, inspectable actions.** A rebuild shows its exact plan before anything executes, and approval is bound to that plan.

## Assets

1. **The correctness of verdicts.** A false VERIFIED, PASSED or MATCH is the worst possible failure.
2. The host running TrustForge and its secrets: user files, SSH keys, tokens, the container runtime socket.
3. Availability of the tool in CI pipelines.
4. The integrity of TrustForge's own releases.

## Adversaries

- A **malicious or compromised publisher**, who controls the artifact, the manifest, the source repository, build scripts and dependency declarations.
- A **network or mirror attacker** who can substitute downloads.
- A **malicious dependency author**, whose `build.rs` or procedural macros run during a rebuild.
- A **local unprivileged user** racing on shared filesystem paths.
- A **compromised build platform** that issues signed provenance (relevant from M5).

## Trust boundaries

| # | Boundary | Untrusted input | Controlled by |
|---|---|---|---|
| TB1 | artifact → inspector | Bytes, tree structure, names, symlinks, special files, concurrent modification | The publisher, or anyone with write access to the path |
| TB2 | documents → parsers | Manifests, provenance, DSSE envelopes, Sigstore bundles, saved reports | The publisher, network attackers |
| TB3 | source and dependencies → build sandbox | Repository content, build scripts, procedural macros, Cargo and rustup configuration, vendored crates | Repository owners, dependency authors |
| TB4 | sandbox → host | Output files, logs, exit status, leftover files | Build code |
| TB5 | network | Git remotes, crates.io, container registries, Sigstore/TUF services | Network attackers, service operators |
| TB6 | trust anchors and policy (**trusted**) | Trust policy, image policy, trusted root, pinned digests, approval decisions | The TrustForge user |
| TB7 | TrustForge → people and CI | Terminal output, JSON reports, exit codes | Must not be steerable from TB1–TB5 |
| TB8 | TrustForge's own supply chain | Dependencies, CI actions, release pipeline | Upstream maintainers, CI |

## Threats and mitigations

### Artifact inspection (M1, implemented)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Symlink escape | Below the root, nothing is resolved by path. Each entry is examined with `fstatat(AT_SYMLINK_NOFOLLOW)` and opened by its single name relative to its parent's descriptor with `O_NOFOLLOW`. Symlinks are recorded with their target text and never followed. A root symlink is followed once and reported. | — |
| Special files (FIFO, device, socket) causing hangs or device reads | The type comes from `stat`/`fstatat` before anything is opened; special files are errors and are never opened. Opens use `O_NONBLOCK`, so an object swapped in meanwhile cannot block, and `fstat` rejects it before any read. | — |
| Concurrent modification (TOCTOU) | Opened objects must have the device and inode that `fstatat` reported. A file is read for exactly its reported size, with an end-of-file probe. Afterwards its device, inode, permissions, link count, size, modification time and status-change time must be unchanged, and its name must still refer to it. Directories are re-checked after listing and after their subtree, including that their name still refers to them. After the walk, a final pass re-examines every entry, so the result describes the tree at one moment rather than a mix of states (for example, a file moved from a finished directory into one not yet listed). The root path must still lead to the inspected object at the end. | **Best-effort detection, not prevention.** Changes within timestamp granularity that keep the size, writes through already-dirty shared memory maps, A-B-A restores, and network or FUSE file systems reporting false metadata can go unnoticed. On Windows, a single file's length and modification time are the only checks. |
| A shrinking file re-framing the archive | The NAR writer is a state machine: a file accepts exactly its declared length, and entry names must strictly increase. Without this, bytes after a truncated file could be read back as its content, and the stream could equal the valid serialization of a different tree. | — |
| Size reports that lie (procfs, sysfs, FUSE) | The exact-length read and end-of-file probe reject any file whose content does not match its reported size. | — |
| Crash on truncation | Files are never memory-mapped. | — |
| Name tricks: lossy conversion, control or bidi characters, normalization | A fixed list of forbidden code points; invalid UTF-8 is rejected, never converted lossily; byte-exact comparison; duplicates rejected. Error messages escape the offending bytes. | Visually confusable names (homoglyphs) are not detected. |
| Terminal injection through artifact names or targets | One sanitizer escapes control characters (including ESC, so no ANSI or OSC sequence passes), bidi controls and line separators in all text output. JSON output spells the same characters as `\uXXXX` escapes, so it is safe to print and its values are unchanged. | Programs that decode the JSON and display its strings must escape them themselves. |
| File/tree digest confusion | Separate digest-set keys (`narSha256`, …) and a separate type (`ArtifactDigests::Tree`) for tree digests | — |
| Permission bits that no digest covers | Documented: only the owner-execute bit is covered. | Copying a tree with `cp -a`, `rsync -a` or `tar -p` can carry setuid bits or file capabilities that no digest covered. |
| Crossing into other file systems; bind-mount cycles | A directory on a different device than its parent, or one that is its own ancestor, is an error. | Btrfs subvolumes are rejected as mount points. |
| Running hostile binaries during inspection | Header parsing is in-process, hand-written and bounds-checked, and reads at most the first 4 KiB captured while hashing. `ldd`, `file` and binutils are never invoked, and the core library cannot spawn processes (enforced by clippy). | — |
| Resource exhaustion | Streaming through a fixed buffer. Limits on content bytes (checked against the reported size before reading, so a huge sparse file fails instantly), entries, depth, total path length and symlink-target length. Iterative traversal with at most one descriptor per level. Running out of descriptors is a reported error. | A listing at the default entry limit can use about 0.7 GB of memory (about 0.7 KB per entry). |

### Documents and parsing (M2–M3)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Parser differentials | Strict I-JSON:<br>• UTF-8 only; no BOM, trailing data or lone surrogates<br>• **duplicate keys rejected at every depth, compared after unescaping**<br>• keys that differ from a known field only in case are rejected (some parsers match case-insensitively)<br>• integers only, within ±(2^53−1)<br>• nesting limit<br>• control and bidi characters rejected | Other tools may still interpret documents differently |
| Hash algorithm confusion | Typed digests whose length is bound to the algorithm. md5 and sha1 are never accepted. Every accepted algorithm present must match. The accepted set comes from policy, not from input. | — |
| Malicious manifest values | Size limit before parsing. Strict validation of Cargo names and target triples. **No value may begin with `-`** (argument injection). HTTPS-only URLs without credentials. Environment-variable allowlist. Unknown build parameters rejected. | — |
| Manifest swapped after approval | Read once; its SHA-256 binds the plan and the approval. | — |
| Schema downgrade | Missing evidence that the policy requires leaves the policy unsatisfied; it can never produce VERIFIED. | — |
| Report forgery | Saved reports are never evidence. `trustforge report` re-renders them under a "not re-verified" banner. | — |
| Terminal injection through untrusted strings | One sanitizer for all terminal output: control characters, ANSI/OSC sequences (including OSC 8 links and OSC 52 clipboard writes) and bidi controls are escaped. The verdict is printed last. | JSON consumers must apply their own escaping when rendering |
| Output-path symlink attacks | Temp file plus atomic rename; existing symlinks are never followed. | — |

### Source acquisition (M4)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Malicious repository content exploiting git | Hardened invocation:<br>• HTTPS only (`GIT_ALLOW_PROTOCOL=https`); `ext::`, `fd::`, `file:` and leading `-` rejected; URL passed after `--`<br>• hooks disabled (`core.hooksPath=/dev/null`, empty `init.templateDir`)<br>• `transfer.fsckObjects=true`; no submodules<br>• system and global git config ignored, which disables LFS and filter drivers; `GIT_LFS_SKIP_SMUDGE=1`<br>• minimum git version enforced | Undiscovered git vulnerabilities (the M4 spike evaluates `gix` or git inside a container) |
| Revision confusion | Only full commit SHAs are accepted, and object format is verified. | SHA-1 commit IDs are weaker than SHA-256. TrustForge also records a SHA-256 tree digest of the checkout. |
| **Commits from forks** | GitHub serves objects from any fork through the upstream URL, so the commit must be **reachable from the claimed ref** of the claimed repository. | Rewritten history or moved tags upstream |

### Build execution (M4)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Malicious build scripts and procedural macros | Container only, after approval:<br>• `--network=none` during the build<br>• non-root user; all capabilities dropped (no device nodes, no setuid-root outputs); `no-new-privileges`<br>• read-only root filesystem; size-limited `/tmp`<br>• process, memory, swap, CPU, file-size and time limits<br>• explicit entrypoint and argument vector, never a shell<br>• the Docker socket, home directory and credentials are never mounted | **Containers share the host kernel.** Kernel or runtime vulnerabilities can break isolation, and a rootful Docker daemon is root-equivalent. Rootless runtimes, gVisor or a disposable VM give stronger isolation. The rebuilt binary is never executed. |
| **Repository-controlled code before the build** | Cargo can run repository-configured wrappers even during `cargo fetch`, and rustup toolchain files can point to arbitrary toolchain paths. TrustForge therefore:<br>• fetches from a neutral working directory so repository Cargo configuration is not loaded (confirmed by a canary test)<br>• pins `RUSTUP_TOOLCHAIN` and disables auto-install<br>• empties `RUSTC_WRAPPER`<br>• never runs cargo or rustup on the host | If the working-directory assumption fails, fall back to downloads verified by TrustForge itself |
| Dependency substitution | `--locked` and `--frozen`; Cargo verifies registry checksums against `Cargo.lock`. The approval prompt and report list:<br>• non-registry sources: git, path, alternate registries, vendored directories<br>• `[patch]`, `[replace]` and `paths` overrides<br>• risky configuration keys<br>Vendored checksums are written by the repository itself, so Cargo's check of them is not independent. Comparing vendored crates with crates.io is a planned stretch goal. | Substitutions committed into the declared source reproduce faithfully |
| Malicious or outdated build image | **The image is a trust root governed by the user's image policy, never by the manifest.**<br>• default: `docker.io/library/rust`, pinned by digest; others need explicit approval<br>• platform pinned<br>• image `ENV` and `VOLUME` inspected<br>• toolchain version checked inside the container | A compromised toolchain ("trusting trust") produces identical, compromised output. Pulling and starting an image exercises the container daemon and runtime. |
| Cache poisoning across runs | No shared mutable Cargo or git cache in the MVP. Each run gets a fresh `CARGO_HOME`. | — |
| Environment injection | Containers get only an explicit environment. Host child processes get an allowlisted environment: no `CARGO_*`, `RUSTUP_*`, `GIT_*`, SSH agent, CI tokens, or proxy variables unless opted in. Only local container daemons are accepted. | — |
| Network during builds | The build has no network. The fetch phase has network but no credentials, and runs no repository-configured code. | Fetch-phase egress is unrestricted in the MVP, including cloud metadata endpoints. An egress allowlist proxy is planned hardening. |
| Fake reproducibility: copying a committed binary into the output | The original artifact is never mounted. The source tree is scanned for files matching the artifact digest and for large binary blobs. The output path comes only from the validated recipe. | Obfuscated or generated blobs |
| Output collection races and hostile outputs | Collection only after the container exits; no-follow opens; regular files only; permission bits stripped; hashed while copied to a private file. `docker cp` is never used. | — |
| Approval spoofing | Confirmation is read from the terminal, never stdin. Approval is bound to the plan digest. A manifest can never pre-approve. | Approval fatigue; `--yes` in automation |
| Resource exhaustion | Container limits, a periodic workspace-size watchdog, capped logs, timeouts | Disk limits are best-effort |
| Temporary-file races and leftovers | Private random directories; cleanup on drop, error and SIGINT; containers labeled for `trustforge clean` | Leftovers after SIGKILL |

### Signatures and provenance (M5)

| Threat | Mitigation | Residual risk |
|---|---|---|
| Forged provenance | Checks:<br>• signature and certificate chain to the Fulcio root<br>• a trusted time (a Rekor inclusion proof for this entry, or an RFC 3161 timestamp); without one, the check fails<br>• trusted root distributed via TUF from an embedded initial root; expired metadata fails<br>• subject digest match; buildType allowlist<br>• DSSE: only the verified payload bytes are parsed and `payloadType` is checked<br>Unsigned provenance is only an unauthenticated claim. | A compromised trusted builder |
| Signatures by untrusted identities | **No implicit trust.** Without a policy, authenticity is "not evaluated". The policy pins the issuer (failing on conflicting issuer extensions), the exact subject, the **build signer workflow** (any CI step with an OIDC token can sign) and the source repository and revision. Cryptographic validity and policy acceptance are separate checks. The policy is loaded only from `--policy` or the user configuration directory, never from the current directory. | Misconfigured policies; exact matching is the default |

### TrustForge itself

| Threat | Mitigation | Residual risk |
|---|---|---|
| TrustForge as a stepping stone to root: access to the container daemon is root-equivalent | Parsers in safe Rust, fuzzed, preferring pure-Rust dependencies. `inspect`, `verify` and `compare` never contact the container runtime. | Parser sandboxing in a restricted child process is a possible future hardening |
| Compromised dependencies or CI | `Cargo.lock` committed; `cargo deny` (advisories, licenses, sources); CI actions pinned by commit SHA with read-only permissions and no persisted credentials; planned reproducible, attested releases and crates.io Trusted Publishing | Upstream compromise not yet covered by an advisory |
| Verify-then-use gap | Documented: verify immediately before use, or verify an immutable copy | A file swapped after verification |

## What a byte-identical rebuild proves

A MATCH shows the publisher added nothing beyond the declared inputs: the source at that commit, the dependencies as fetched, the build image, the flags and the environment. It does **not** show:

- that the source or its dependencies are benign (backdoors in the source reproduce perfectly);
- that the toolchain is honest;
- that maintainers endorsed the commit;
- that the binary was built from human-readable source (committed prebuilt blobs);
- that other users received the same bytes;
- that the rebuild was independent, if it ran on the same infrastructure as the original.

TrustForge states this on every reproducibility result. Several independent rebuilders give stronger evidence than one.

## Out of scope

- An attacker with root privileges on the verifying host.
- Kernel vulnerabilities that defeat container isolation (documented, not mitigated).
- A compromised toolchain inside an image that the user's policy allows.
- Deciding whether software is safe. TrustForge never assesses software security.

## Assumptions still to confirm

These come from design review and must be confirmed by a spike or a regression test before anything depends on them:

- Cargo discovers configuration from the working directory, not from `--manifest-path` (M4).
- `cargo fetch` invokes `rustc -vV` through configured wrappers (M4).
- Rekor v2 entries need RFC 3161 timestamps for trusted time (M5).
- Which Rust Sigstore libraries support Sigstore bundle v0.3 and Rekor v2, and how mature they are (M5).
