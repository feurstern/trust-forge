# TrustForge

**Make software artifacts independently verifiable.**

TrustForge is an open-source Rust library and command-line tool for checking where a compiled artifact came from. It will inspect an artifact, check its digests, evaluate signatures and build provenance when they are supplied, and rebuild it from its claimed source to see whether the result is byte-for-byte identical. It then reports exactly which of these checks were done, what they established, and what they did not.

> **Status: pre-alpha (Milestone 1: inspection and hashing).**
> TrustForge can inspect artifacts and compute their digests, but it does not
> verify anything yet: it compares those digests with nothing. Do not use it
> for security decisions. See the [roadmap](docs/roadmap.md).

## The problem

Developers routinely download and run compiled software. Several mechanisms claim to make that safe, but each answers a **different question**:

| Property | Question it answers | What establishes it | What it does *not* tell you |
|---|---|---|---|
| **Integrity** | Are these exactly the bytes the reference describes? | A digest (checksum) that matches a reference value | Whether the reference itself is genuine |
| **Authenticity** | Did an identity I trust vouch for these bytes? | A valid signature from an identity accepted by an explicit trust policy | Whether the build was correct, or the code benign |
| **Provenance** | How, where and from what source was it built? | Signed provenance (for example [SLSA](https://slsa.dev/)) from a builder your policy trusts | Whether the builder or the source was compromised |
| **Reproducibility** | Does rebuilding the claimed source produce identical bytes? | An independent rebuild under recorded conditions that yields a byte-identical artifact | Whether the source is benign |
| **Software security** | Is the code safe to run? | Review, testing and analysis of the code itself | TrustForge never assesses this |

### Why checksums alone are not enough

A matching SHA-256 shows that you have the same bytes as whoever published the checksum. If the artifact and its checksum come from the same place, for example the same release page, an attacker who can replace one can replace both. A checksum establishes **integrity relative to a reference**. It says nothing about who produced the bytes or how.

### Signatures, provenance and reproducible builds

- A **signature** binds the bytes to an identity. It is only as meaningful as your policy about *which* identities you trust.
- **Provenance** is a signed statement from a build system about how the artifact was built: source repository, revision, build process. You are trusting that build system.
- A **reproducible build** lets *anyone* rebuild the claimed source and compare the result. A byte-identical rebuild shows the publisher added nothing beyond the declared inputs. It does **not** show that those inputs (the source, the dependencies, the toolchain) are benign.

These guarantees complement each other, and TrustForge never reports one as another.

## How TrustForge will work

```text
artifact ──► inspect & hash ──► compare with manifest / expected digests ──┐
                                                                            ├──► report: one status per
signatures & provenance ──► verify under an explicit trust policy ─────────┤    property, with the evidence
                                                                            │    and every limitation
claimed source ──► rebuild in an isolated container ──► byte comparison ───┘
```

1. **Inspect** the artifact (file, executable, archive or directory) and compute SHA-256, SHA-512 or BLAKE3 digests in a single streaming pass.
2. **Compare** against expected digests or a TrustForge **manifest**: an [in-toto](https://in-toto.io/) Statement describing the artifact and its claimed build.
3. **Verify** signatures and provenance (Sigstore bundles, SLSA provenance), always under an explicit trust policy.
4. **Rebuild** Rust/Cargo projects from the claimed source revision inside an isolated container, after you approve the exact plan, and compare the result byte for byte.
5. **Report** a status for each property. Missing evidence is shown as missing, never as passed.

## What TrustForge verifies today

**Nothing.** What exists today is inspection:

```sh
trustforge inspect target/release/myapp      # kind, size, format, SHA-256/SHA-512/BLAKE3
trustforge inspect dist/                     # tree digests over the directory's NAR serialization
trustforge inspect --format json - < app.tar.gz
```

`inspect` reports which bytes an artifact contains: its size, its format (from header bytes), and its digests. For a directory, the tree digest covers every file's contents and executable bit, every symlink's target, and empty directories, and equals the NAR hash Nix computes for the same directory (`nix-hash --type sha256`). Symbolic links are recorded and never followed, and special files are never opened. Comparing digests against references, which is where verification starts, arrives in Milestone 3. See [getting started](docs/getting-started.md).

The [roadmap](docs/roadmap.md) lists when each capability is planned:

| Capability | Planned for |
|---|---|
| Artifact inspection and SHA-256 / SHA-512 / BLAKE3 hashing | Milestone 1 (available) |
| TrustForge manifest (draft v0) | Milestone 2 |
| Verification engine, JSON and terminal reports, stable exit codes | Milestone 3 |
| Reproducible rebuilds of Rust/Cargo projects (Linux, container-isolated) | Milestone 4 |
| Sigstore signatures, in-toto attestations, SLSA provenance | Milestone 5 |
| First release candidate | Milestone 6 |

## What TrustForge will not do

- It will not tell you that software is **safe**. "Software security: not assessed" appears on every report.
- It will not treat a checksum match as trust, or an unsigned document as authenticated.
- It will not trust a signature without an explicit policy saying whose signatures you accept.
- It will not run untrusted build code on your host. Rebuilds run in containers, and only after you approve the exact plan. Containers are **not** a complete security boundary; see the [threat model](docs/threat-model.md).

See [known limitations](docs/limitations.md) for the full list.

## Documentation

- [Getting started](docs/getting-started.md): installation and quick start
- [CLI reference](docs/cli-reference.md): options, output formats, exit codes
- [Architecture](docs/architecture.md): workspace layout, APIs, key decisions
- [Threat model and security model](docs/threat-model.md)
- [Verification semantics](docs/verification-semantics.md): statuses, policies, exit codes
- [Manifest specification (draft v0)](docs/manifest-spec.md)
- [Supported standards](docs/standards.md)
- [Known limitations](docs/limitations.md)
- [Roadmap](docs/roadmap.md)

The reproducible build guide will be written when rebuilds land (Milestone 4).

## Building from source

TrustForge builds with the toolchain pinned in `rust-toolchain.toml`, which rustup installs automatically. The minimum supported Rust version is 1.88. A C compiler is needed too, for BLAKE3's SIMD code.

```sh
cargo install --path crates/trustforge-cli --locked
trustforge inspect --help
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report security issues privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
