# Architecture

> **Status:** Milestone 0 design. Nothing described here as "planned" exists yet. Each part is implemented in the milestone named next to it, together with its tests. Signatures shown below are sketches that are finalized when the milestone lands.

TrustForge is a Rust workspace with a reusable library and a command-line tool. This document describes how the workspace is organized, the planned library APIs, the artifact model, the rebuild engine, and the decisions behind them. What results *mean* is defined in [verification-semantics.md](verification-semantics.md), and what TrustForge defends against is in [threat-model.md](threat-model.md).

## Design principles

1. **Never overstate a guarantee.** Integrity, authenticity, provenance, reproducibility and software security are different properties (see the [README](../README.md#the-problem)), and TrustForge reports each one separately. Missing evidence is reported as missing.
2. **Fail closed.** A check that cannot complete is an error or "not evaluated", never a pass. Unimplemented features return an explicit "unsupported" result.
3. **Every input is untrusted.** Artifacts, manifests, provenance, saved reports, repositories, dependencies and build outputs are all parsed defensively, with explicit limits.
4. **Determinism.** The same inputs produce byte-identical machine-readable output.
5. **Bounded resources.** Hashing streams. Every collection read from untrusted input has a documented limit.
6. **Small, safe, synchronous code.** `unsafe` is forbidden, dependencies are few and justified, and there is no async runtime without a measured need.

## Workspace layout

```text
├── Cargo.toml                   workspace: shared package metadata, dependencies, lints
├── rust-toolchain.toml          pinned development/CI/release toolchain
├── crates/
│   ├── trustforge-core/         library: digest, inspect, manifest, compare, verify, report model
│   ├── trustforge-cli/          binary `trustforge`: argument parsing, rendering, exit codes
│   ├── trustforge-rebuild/      (planned, M4) source acquisition, container runtime driver
│   └── trustforge-provenance/   (planned, M5) DSSE, in-toto, SLSA, Sigstore, trust policy
├── fixtures/                    (planned) test inputs, byte-exact on every platform
└── docs/
```

Dependency direction: `cli → {core, rebuild, provenance}`, `rebuild → core`, `provenance → core`. `core` depends on no other workspace crate.

**`trustforge-core` never spawns processes and never opens network connections.** From Milestone 1 this is enforced mechanically: a crate-level `clippy.toml` disallows `std::process::Command::new`, and the crate denies `clippy::print_stdout` and `clippy::print_stderr`. Embedders such as package registries can therefore use the core library without inheriting the rebuild engine's attack surface.

### Why four crates and not more

Crate boundaries sit where the **dependency footprint or the security surface** changes:

| Concern | Location | Reason |
|---|---|---|
| Hashing, manifests, verification engine, report model | modules of `trustforge-core` | Small, tightly related, no heavy dependencies. They can be split out before 1.0 (behind a re-export) if outside consumers need them separately. |
| Terminal rendering, exit codes | `trustforge-cli` | Presentation, not library behavior |
| Build reproduction | `trustforge-rebuild` | Executes untrusted code through a container runtime, a very different risk profile, and optional for library users |
| Signatures and provenance | `trustforge-provenance` | Heavy cryptography, X.509 and TUF dependency tree, kept as an isolated audit surface |

## Key decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | The **manifest is an in-toto Statement v1** with a TrustForge predicate. Its build section reuses the shape of SLSA Provenance v1's `BuildDefinition`. | Uses an established envelope instead of inventing one. Manifests can be signed today with existing tools (`cosign attest-blob`, GitHub `actions/attest`) without changing format. Subject matching is shared with SLSA provenance verification. A TrustForge-specific `predicateType` and the absence of builder identity keep it from being mistaken for provenance. See [manifest-spec.md](manifest-spec.md). |
| 2 | The **default verification policy (`full`) requires all four dimensions.** | A checksum match alone yields "partially verified". Narrower policies must be requested explicitly, and the overall status always names the policy and where the reference came from. |
| 3 | **Synchronous APIs, no async runtime.** | The work is disk- and CPU-bound, and process supervision is blocking. If a networked integration ever needs async, it stays confined to `trustforge-provenance`. |
| 4 | **Closed set of digest algorithms** (an enum), with no pluggable hasher trait. | An open extension point would let weak algorithms in. One streaming pass must feed several algorithms anyway. |
| 5 | **Directory tree digests hash the NAR serialization** of the tree (the Nix Archive format). | An existing, documented, injective serialization that covers the executable bit, symlinks and empty directories, so no new format is needed. Values can be cross-checked with `nix hash path`. |
| 6 | **Strict JSON parsing.** Input is parsed into an internal `StrictValue` tree, then converted to typed structures by hand-written code. | Rejects duplicate keys, case variants of known fields and other parser-differential tricks that serde's derived deserializers accept silently. No `serde(flatten)` or `untagged`. |
| 7 | The **engine is composed of `Check` implementations.** | Lets `rebuild` and `provenance` plug checks in without `core` depending on them, and makes "evidence supplied but no check can evaluate it" an explicit `UNSUPPORTED` result. |
| 8 | **Rebuild isolation is delegated to a container runtime through its CLI** (Docker first, Podman best-effort). There is no host-build mode. | TrustForge does not implement its own sandbox. The CLI driver avoids an async Docker-only client library and works with both runtimes. |
| 9 | **Reports contain no wall-clock timestamps unless requested.** | Reports stay deterministic and can be snapshot-tested. |

## Planned library API (`trustforge-core`)

Conventions:
- Public enums and structs that will grow are `#[non_exhaustive]`.
- Each module has one `thiserror` error enum whose errors carry the path or field involved.
- Explicit `Limits` (sizes, entry counts, depth, document size) are passed in, never implicit.
- Validated newtypes are used: `Digest`, `RelPath`, `GitCommit`, `ImageRef` (pinned by digest), `TargetTriple`, `CargoName`.
- Documents (manifests, provenance) are read and size-checked at the edges and then evaluated by pure code.

```rust
// digest (M1)
#[non_exhaustive]
pub enum DigestAlgorithm { Sha256, Sha512, Blake3 }   // "md5"/"sha1" are rejected when parsing
pub struct Digest { /* algorithm + fixed-size bytes; the length always matches the algorithm */ }
pub struct DigestSet(BTreeMap<DigestAlgorithm, Digest>);
pub struct MultiHasher { /* one state per selected algorithm, fed in a single pass */ }
impl std::io::Write for MultiHasher { /* … */ }
pub fn hash_reader(r: impl Read, algorithms: &AlgorithmSet) -> Result<HashOutput, DigestError>;

// inspect (M1)
pub fn inspect_path(path: &Path, opts: &InspectOptions) -> Result<Inspection, InspectError>;
pub fn inspect_reader(name: &str, r: impl Read, opts: &InspectOptions) -> Result<Inspection, InspectError>;

// manifest (M2)
pub fn parse_manifest(bytes: &[u8], limits: &Limits) -> Result<ParsedManifest, ManifestError>;
pub struct ParsedManifest { pub manifest: Manifest, pub file_digest: Digest, pub warnings: Vec<ManifestWarning> }

// compare (M3)
pub fn compare_paths(original: &Path, candidate: &Path, opts: &CompareOptions) -> Result<Comparison, CompareError>;
pub enum ComparisonOutcome { Match, Different, Incomplete, Failed }

// verify (M3)
pub trait Check {
    fn id(&self) -> CheckId;
    fn dimension(&self) -> Dimension;
    fn run(&self, ctx: &CheckContext<'_>) -> CheckResult;   // never panics; failures become Status::Error
}
pub struct VerificationRequest<'a> {
    pub artifact: &'a Path,
    pub references: Vec<Reference>,          // expected values, each tagged with its origin
    pub checks: Vec<Box<dyn Check + 'a>>,
    pub policy: &'a VerificationPolicy,
}
pub fn verify(req: VerificationRequest<'_>) -> VerificationReport;   // always produces a report
```

The engine inspects the artifact itself, so a read failure becomes an `ERROR` check inside a report rather than a missing report. The result model (`CheckResult`, `CheckStatus`, `DimensionStatus`, `OverallStatus`, `VerificationReport`) is specified in [verification-semantics.md](verification-semantics.md).

## Artifact model (M1)

```rust
pub struct Inspection {
    pub name: String,                     // as given by the user; never canonicalized to an absolute path
    pub kind: ArtifactKind,               // File | Directory | Stream (stdin)
    pub size: u64,                        // file length; for directories, the sum of regular files
    pub digests: DigestSet,               // file: content digests; directory: tree digests
    pub format: FileFormat,               // from magic bytes, never from the file extension
    pub platform: Option<BinaryPlatform>, // the artifact's target, read from executable headers
    pub entries: Option<Vec<TreeEntry>>,  // directories only
    pub untrusted: UntrustedMetadata,     // mtime, mode bits: shown for information, never trusted
}
pub enum EntryKind { File { executable: bool }, Symlink { target: String }, Directory }
```

- **Format detection** reads only fixed-offset header fields:
  - ELF identification and machine;
  - Mach-O magic and CPU type, including universal binaries;
  - the PE machine field;
  - archive magic numbers (tar, gzip, xz, zstd, zip).

  The code is hand-written, bounds-checked and fuzzed. External tools (`ldd`, `file`, binutils) are never run, because `ldd` can execute the binary. Deeper parsing (sections, GNU build-id, embedded `cargo auditable` data) arrives in M4.
- **Archives are never extracted to disk.** From M4, entry listings are streamed in memory under limits with pure-Rust decoders, and are used **only for diagnostics**. Verdicts are always computed on the archive's own bytes, so archive-parser ambiguities cannot change one.
- **Hashing** reads each file once through a bounded buffer that feeds every selected algorithm. Memory use does not depend on file size. Memory-mapping is never used, because a concurrently truncated file would crash the process. Parallel hashing is enabled only where benchmarks show a benefit, and output order never depends on completion order.

### Directory traversal rules

1. If the root path the user gave is a symlink, it is resolved once, and the report says so. **Below the root, symlinks are never followed.** They are recorded with their target text, and absolute or escaping targets are flagged.
2. Only regular files, directories and symlinks are accepted. A FIFO, socket or device node is an error naming the path, so traversal can neither block on a FIFO nor read a device.
3. Files are opened relative to their parent directory's handle (planned: `cap-std`), with no-follow and non-blocking flags, and checked with `fstat` after opening. Size, modification time and inode are re-checked after hashing, and a change is reported as an error.
4. Names must be valid UTF-8 without NUL, control characters, bidi controls or backslash, and anything else is an error. Names are never converted lossily, and they are compared byte-for-byte with no Unicode normalization. Empty directories are recorded.
5. Only the entry type, the executable bit, the size, the content digests and the symlink target are recorded. Timestamps, ownership, other permission bits, extended attributes and hard-link identity are deliberately excluded.
6. The **tree digest** is the hash of the tree's NAR serialization. Tree digests use their own digest-set keys (`narSha256`, …), and every comparison checks the artifact kind, so a file whose bytes happen to be a NAR serialization can never satisfy a tree claim.
7. Entry count, depth, total size and symlink-target length are limited by documented defaults. Traversal is iterative, not recursive.
8. On Windows, which has no executable bit, the tree digest is reported as **unsupported** rather than computed differently. Single-file artifacts are fully supported on every platform.

## Rebuild engine (M4, Linux first, Rust/Cargo)

Rebuilding executes code from the claimed source repository and its dependencies, all of it untrusted. The engine runs that code only inside a container, only after the user approves the exact plan, and never on the host. The threat analysis behind every step is in [threat-model.md](threat-model.md).

1. **Plan (host, nothing executes).**
   - Read the manifest once and validate the `cargo/v0` recipe.
   - Check the build image against the user's image policy. By default only `docker.io/library/rust` images pinned by digest are allowed.
   - Hash the original artifact now. It is never mounted into a container.
   - Produce a `RebuildPlan`: image digest, every command line, environment, mounts, limits and network phases. The approval is bound to the plan's digest. `--dry-run` prints the plan as JSON.
   - Confirmation is read from the terminal (`/dev/tty`) or given with `--yes`. Without either, the rebuild is refused.
2. **Workspace.** A fresh, private (0700) directory, mounted at fixed in-container paths (`/build/src`, `/build/cargo-home`). Rust binaries embed source and registry paths, so these paths are part of the recipe.
3. **Source.**
   - Fetch with hardened `git` on the host, or use a local checkout via `--source-dir`.
   - Accept only a full commit SHA, and require it to be reachable from the claimed ref of the claimed repository.
   - Compute the source tree's NAR SHA-256, excluding `.git`.
   - Scan for committed binaries matching the artifact.
   - Read Cargo and rustup configuration files **as data** and list every risky setting in the approval prompt.
4. **Fetch phase** (container, network on, no credentials):
   - Command: `cargo fetch --locked --manifest-path …`, run from a neutral working directory so that repository-level Cargo configuration is not loaded. This assumption is confirmed by a spike and a regression test before it is relied on.
   - Environment: `RUSTUP_TOOLCHAIN` pinned, auto-install off, fresh `CARGO_HOME`.
5. **Build phase** (container, `--network=none`, non-root user, all capabilities dropped, read-only root filesystem, process, memory, CPU, file-size and time limits, explicit entrypoint):
   - Command: `cargo build --frozen` with the declared profile, target, binary and features.
   - Logs go to capped files.
6. **Collect** only after the container has exited. Only the recipe's declared output path is read: no-follow, regular files only. It is hashed while being copied into a private file.
7. **Compare.** The outcome is one of four:
   - `MATCH`: every digest and byte is equal.
   - `DIFFERENT`: the build succeeded but the bytes differ.
   - `INCOMPLETE`: the recipe could not be executed as declared.
   - `FAILED`: a build or runtime error.
8. **Diagnose** differences without claiming a root cause: byte ranges, differing ELF sections, and path- or timestamp-like strings found in them. All are reported as *possible* causes, and `diffoscope` is suggested if installed.
9. **Record and clean up.**
   - Emit a versioned rebuild record, which becomes signable SLSA provenance in M5.
   - Remove the containers and the workspace.
   - SIGINT handling kills labeled containers. `trustforge clean` removes any leftovers.

Runtime access goes through a small `ContainerRuntime` trait (`check`, `pull_by_digest`, `run`, `kill`). Only a local daemon is accepted by default.

Reproducibility evidence counts toward a verified result only when **this** TrustForge process produced it. Imported rebuild records are unauthenticated claims.

## Output discipline (CLI)

- **stdout** carries only the primary output. With `--format json`, it is exactly one JSON document.
- **stderr** carries progress (only on a TTY), logs and warnings. The verdict is printed last.
- Every untrusted string is passed through a single sanitizer before reaching a terminal. It escapes control characters, ANSI and OSC sequences, and bidi controls.
- Output files are written to a temporary file and atomically renamed. An existing symlink at the destination is never followed.
- Child processes get `/dev/null` as stdin and never get a TTY.

## Dependencies

Each dependency is added in the milestone that first needs it, and only after review (maintenance, license, footprint, MSRV, alternatives). `cargo deny check` enforces licenses, advisories and sources.

| Crate | Purpose | Milestone |
|---|---|---|
| `clap` (derive) | Command-line parsing | M0 |
| `assert_cmd` (dev) | CLI integration tests | M0 |
| `sha2`, `blake3` | SHA-256/SHA-512 (RustCrypto) and BLAKE3 (official implementation) | M1 |
| `cap-std`, `cap-fs-ext` | Capability-based traversal that cannot escape the root (evaluated in an M1 spike; the fallback is `rustix` with `openat`) | M1 |
| `serde`, `serde_json` | JSON input/output under TrustForge's own strict parsing layer | M1–M2 |
| `thiserror`, `tracing` | Library errors and diagnostics | M1 |
| `anyhow`, `tracing-subscriber` | CLI error context and logging | M1 |
| `insta`, `proptest`, `divan` (dev) | Snapshot, property and benchmark tests | M1 |
| `tempfile` | Private temporary directories | M1/M4 |
| `toml` | Reading Cargo and rustup configuration *as data* | M4 |
| `object` | Executable section diagnostics | M4 |
| a Sigstore crate, `tough` (TUF) | Signature and provenance verification, selected by spike | M5 |

**Deliberately not used:**
- an async runtime (see decision 3);
- `subtle`: digests of public artifacts are not secret, and TrustForge handles no secret material;
- `bollard`: async and Docker-only;
- the `in-toto` crate: it implements the legacy layout/link format, not the attestation framework;
- `cargo_metadata`: it runs Cargo, which may execute repository-chosen programs;
- a database.

## Performance

Performance claims are made only from measurements. Benchmarks (`divan`, including its allocation profiler) will cover:
- hashing a 1 GiB file per algorithm and combined;
- inspecting a 100,000-entry directory;
- parsing a 4 MiB manifest;
- comparing 1 GiB files;
- rendering reports.

Results are published together with the hardware they ran on.

## Open design questions

- The URI namespace for TrustForge's predicate, build, report and record types (written `<ns>` in the drafts).
- Host `git` versus `gix` versus `git` inside a container for source acquisition (M4 spike).
- Which Rust Sigstore library to use (M5 spike, judged on conformance results).
- The trust policy file format and identity-matching rules (M5).
- Whether to add a publisher-side `trustforge build` that produces release artifacts using the same recipe verifiers will rerun.

The full list, with owners and milestones, is kept in [roadmap.md](roadmap.md#open-questions).
