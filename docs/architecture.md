# Architecture

> **Status:** Milestone 1. Artifact inspection and hashing are implemented (the `digest`, `format`, `name` and `inspect` modules). Everything described as "planned" is not implemented yet; each part arrives in the milestone named next to it, with its tests. Planned signatures are sketches that are finalized when their milestone lands.

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
├── fixtures/nar/                reference NAR files produced by Nix, byte-exact on every platform
├── scripts/nar-reference.sh     generates them, once, in a pinned container
└── docs/
```

Dependency direction: `cli → {core, rebuild, provenance}`, `rebuild → core`, `provenance → core`. `core` depends on no other workspace crate.

**`trustforge-core` never spawns processes and never opens network connections.** This is enforced mechanically: a crate-level `clippy.toml` disallows `std::process::Command::new`, and the crate denies `clippy::print_stdout` and `clippy::print_stderr`. Embedders such as package registries can therefore use the core library without inheriting the rebuild engine's attack surface.

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
| 10 | **Directory traversal uses `rustix` system calls directly, not `cap-std`, and is Unix-only.** | Result of the M1 traversal evaluation. TrustForge never resolves a multi-component path below the root: it opens only single names returned by `readdir`, relative to the parent directory's descriptor, with no-follow flags. The exact POSIX calls it needs (`openat`, `fstatat`, `readlinkat`, `fstat`, `getdents`) are what `rustix` exposes safely, so the semantics the threat model relies on are those of the documented calls. `cap-std`'s sandboxed path resolution, and its Windows support, are not needed: directory inspection is unsupported on Windows (open question d, decided in M1), because tree digests cover the executable bit, which Windows lacks. `cap-std` would also add about eight crates. |

## Library API (`trustforge-core`)

Conventions:
- Public enums and structs that will grow are `#[non_exhaustive]`.
- Each module has one `thiserror` error enum whose errors carry the path or field involved.
- Explicit `Limits` (sizes, entry counts, depth, document size) are passed in, never implicit.
- Validated newtypes are used: `Digest`, `RelPath`, `GitCommit`, `ImageRef` (pinned by digest), `TargetTriple`, `CargoName`.
- Documents (manifests, provenance) are read and size-checked at the edges and then evaluated by pure code.

```rust
// digest (implemented, M1)
#[non_exhaustive]
pub enum DigestAlgorithm { Blake3, Sha256, Sha512 }  // name order; FromStr rejects "md5"/"sha1" as insecure
pub struct AlgorithmSet { /* non-empty */ }
pub struct Digest { /* algorithm + bytes; the length always matches the algorithm */ }
pub struct DigestSet(BTreeMap<DigestAlgorithm, Digest>);   // never empty
pub struct MultiHasher { /* one state per selected algorithm, fed in a single pass */ }
impl std::io::Write for MultiHasher { /* … */ }
pub fn hash_reader(r: impl Read, algorithms: &AlgorithmSet) -> io::Result<HashOutput>;

// format (implemented, M1)
pub fn detect_format(head: &[u8]) -> FileFormat;   // never panics; Unknown when unrecognized

// name (implemented, M1)
pub fn validate_name(bytes: &[u8]) -> Result<&str, NameError>;
pub fn validate_symlink_target(bytes: &[u8]) -> Result<&str, NameError>;
pub struct RelPath;                    // validated, `/`-joined relative path
pub struct EscapedBytes<'a>(pub &'a [u8]);   // safe display of untrusted bytes

// inspect (implemented, M1)
pub struct InspectOptions { pub algorithms: AlgorithmSet, pub limits: Limits }
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
pub struct Inspection {                    // private fields, read through accessors
    name: String,                          // as given by the user; never canonicalized to an absolute path
    kind: ArtifactKind,                    // File | Directory | Stream (stdin)
    size: u64,                             // file length; for directories, the sum of regular files
    digests: ArtifactDigests,              // Content(DigestSet) | Tree(DigestSet): never interchangeable
    format: Option<FileFormat>,            // files and streams: from header bytes, never from the name
    tree: Option<(Vec<TreeEntry>, EntryCounts)>,  // directories: entries in NAR order
    root_symlink_followed: bool,
    untrusted: Option<UntrustedMetadata>,  // mode bits, mtime of the given path: information only
}
pub enum EntryKind {
    File { executable: bool, size: u64, digest: DigestSet },
    Directory,
    Symlink { target: String, target_leaves_tree: bool },
}
```

`Inspection` serializes (JSON output) with only what is derived from the artifact's content and structure, plus its name, so identical artifacts serialize identically. File-system metadata is left out. The JSON format is documented in the [CLI reference](cli-reference.md#json-output).

- **Format detection** reads only fixed-offset header fields, from the first 4 KiB captured during the hashing pass (never a second read):
  - ELF class, byte order, type, machine and OS ABI;
  - Mach-O word size, byte order, CPU type and file type, including universal binaries (told apart from Java class files by the architecture count);
  - the PE machine, optional-header magic and DLL flag;
  - the WebAssembly version and layer;
  - archive and compression magic numbers (tar, zip, ar, 7z, gzip, xz, zstd, bzip2).

  The code is hand-written and bounds-checked, and property tests feed it arbitrary bytes. A coverage-guided fuzz target is added in M2, alongside the manifest parser's. External tools (`ldd`, `file`, binutils) are never run, because `ldd` can execute the binary. Deeper parsing (sections, GNU build-id, embedded `cargo auditable` data) arrives in M4.
- **Archives are never extracted to disk.** From M4, entry listings are streamed in memory under limits with pure-Rust decoders, and are used **only for diagnostics**. Verdicts are always computed on the archive's own bytes, so archive-parser ambiguities cannot change one.
- **Hashing** reads each file once through a 128 KiB buffer that feeds every selected algorithm. Memory use does not depend on file size. Memory-mapping is never used, because a concurrently truncated file would crash the process. Hashing is single-threaded in M1; parallel hashing will be enabled only where benchmarks show a benefit, and output order will never depend on completion order.

### Directory traversal rules

1. **The root.** The path the user gave is resolved by the operating system. If its last component (ignoring trailing slashes) is a symbolic link, it is followed once and the result says so. The resolved object must be a regular file or a directory; anything else is an error, and it is never opened. It is then opened without following a symlink that was not there a moment ago, `fstat` must show the same type, device and inode, and after the inspection the path must still lead to that object. Nothing below the root is ever resolved by path.
2. **Entry types.** Each entry is examined with `fstatat(AT_SYMLINK_NOFOLLOW)` relative to its parent directory's descriptor, before anything is opened. Only regular files, directories and symbolic links are accepted. A FIFO, socket or device node is an error naming the path, and it is never opened. An entry swapped for one of these in between is opened once without blocking, and is never read.
3. **Identity and modification checks.** A regular file is opened by its single name with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`, and `fstat` must report the same type, device and inode. It is read for exactly its reported size; an early end of file, or any data beyond it, is an error. Afterwards its device, inode, permissions, link count, size, modification time and status-change time (with nanoseconds) must be unchanged, and its name must still refer to it. A directory must report unchanged metadata, and a non-zero link count, after it is listed and after its subtree is done, and its name must still refer to it. After the walk, a final pass examines every entry once more, through descriptors opened the same way, and its metadata must still match what was recorded when it was read. Because each entry was unchanged while it was read and is unchanged at the end, the result describes the tree at one moment (between the walk and the final pass) rather than a mix of states: a file moved from a finished directory into one not yet listed, or edited after it was hashed, is detected. Any difference is an error. The status-change time matters because a writer can reset the modification time, but not the status-change time. This detection is best effort: timestamp granularity, writes through shared memory maps, and network or FUSE file systems can hide changes. Digests always describe exactly the bytes read.
4. **Names.** A name must be valid UTF-8, must not be empty, and must not contain U+0000–U+001F, U+007F–U+009F, `/`, `\`, U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+2028 or U+2029. This list is fixed here; it does not follow new Unicode versions. A symlink target follows the same rules, except that `/`, `.` and `..` are allowed. Anything else is an error. Names are never converted lossily and are compared byte for byte with no Unicode normalization. `.` and `..` are skipped. A name listed twice is an error.
5. **What is recorded.** Only the entry type, the **owner-execute bit** (`S_IXUSR`, exactly as in Nix), the size, the content digests and the symlink target are recorded. No digest covers setuid, setgid or sticky bits, group or other permission bits, ACLs, extended attributes (including file capabilities), ownership, timestamps, or hard-link identity. Empty directories are recorded.
6. **Tree digest.** The tree digest is the hash of the tree's NAR serialization, written by a state machine that enforces the format's framing: a file accepts exactly its declared length, and names must strictly increase. Tree digests use their own digest-set keys (`narSha256`, …) and a separate type, so a file whose bytes happen to be a NAR serialization can never satisfy a tree claim. The implementation is checked against NAR files produced by Nix itself (`fixtures/nar`, generated by `scripts/nar-reference.sh`).
7. **Boundaries.** A directory on a different device than its parent (a mount point, including a btrfs subvolume) is an error, and so is a directory that is one of its own ancestors (as a bind mount can make it). Nothing is excluded by default: `.git`, `.DS_Store` and every other entry are hashed.
8. **Limits.** Content bytes (default 64 GiB), entries (1,000,000), depth (128 path components), the total length of all entry paths (256 MiB) and symlink-target length (4,096 bytes) are limited, with checked arithmetic. A file's reported size is charged before it is read. Traversal is iterative, not recursive; at most one directory descriptor per level is open, plus one for the file or listing in progress and one more for the root, kept for the final pass.
9. **Windows.** Windows has no executable bit, so directory inspection is **unsupported** there rather than computed differently. Single-file artifacts are supported on every platform. Without descriptor-relative `stat`, concurrent modification of a single file on Windows is detected from its length and modification time only, and determining the type of the given path opens it (with no access rights), so on Windows a device or named-pipe path is opened before it is rejected.

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
- Every untrusted string is passed through a single sanitizer before reaching a terminal. It escapes control characters, ANSI and OSC sequences, and bidi controls. JSON output spells the same characters as `\uXXXX` escapes, which leave every value unchanged.
- Output files are written to a temporary file and atomically renamed. An existing symlink at the destination is never followed.
- Child processes get `/dev/null` as stdin and never get a TTY.

## Dependencies

Each dependency is added in the milestone that first needs it, and only after review (maintenance, license, footprint, MSRV, alternatives). `cargo deny check` enforces licenses, advisories and sources.

| Crate | Purpose | Milestone |
|---|---|---|
| `clap` (derive) | Command-line parsing | M0 |
| `assert_cmd` (dev) | CLI integration tests | M0 |
| `sha2` (no default features), `blake3` | SHA-256/SHA-512 (RustCrypto, with runtime SHA-NI detection) and BLAKE3 (the official implementation; its build script assembles SIMD code, so building needs a C compiler; the `mmap` and `rayon` features stay off) | M1 |
| `rustix` (`fs`, Unix only) | `openat`, `fstatat`, `readlinkat`, `fstat` and `getdents` relative to directory descriptors (decision 10) | M1 |
| `serde` (derive) | Serializing results; never used to deserialize untrusted input (M2's strict parser does that) | M1 |
| `serde_json` | JSON output (CLI); strict input parsing builds on it in M2 | M1–M2 |
| `thiserror` | Library errors | M1 |
| `tempfile` (dev) | Temporary trees in tests and benchmarks; private temporary directories in M4 | M1/M4 |
| `proptest`, `divan` (dev) | Property tests; benchmarks with an allocation profiler | M1 |
| `insta` (dev) | Snapshot tests of reports | M3 |
| `tracing`, `tracing-subscriber` | Diagnostics and logging, once there is something to log | M3–M4 |
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

Performance claims are made only from measurements. `cargo bench -p trustforge-core` runs the benchmarks (`divan`, including its allocation profiler):
- hashing 256 MiB in memory, per algorithm and with all three in one pass (M1);
- inspecting a 256 MiB file (M1);
- inspecting a directory of 100,000 files (M1);
- parsing a 4 MiB manifest (M2);
- comparing large files (M3);
- rendering reports (M3).

Results are published together with the hardware they ran on.

## Open design questions

- The URI namespace for TrustForge's predicate, build, report and record types (written `<ns>` in the drafts).
- Whether a manifest's 4 MiB size limit should grow for large directory artifacts (M2; see [manifest-spec.md](manifest-spec.md#open-items-before-v1)).
- Host `git` versus `gix` versus `git` inside a container for source acquisition (M4 spike).
- Which Rust Sigstore library to use (M5 spike, judged on conformance results).
- The trust policy file format and identity-matching rules (M5).
- Whether to add a publisher-side `trustforge build` that produces release artifacts using the same recipe verifiers will rerun.

The full list, with owners and milestones, is kept in [roadmap.md](roadmap.md#open-questions).
