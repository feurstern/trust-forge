# Getting Started

> **Status:** pre-alpha. TrustForge can inspect and hash artifacts. **It does not verify anything yet**, so do not use it for security decisions. See the [roadmap](roadmap.md).

## Installation

There are no releases yet. Build TrustForge from source.

**Requirements:**
- [rustup](https://rustup.rs/). The toolchain pinned in `rust-toolchain.toml` is installed automatically on first use. The minimum supported Rust version is 1.88.
- A C compiler (`cc`). The `blake3` crate assembles its SIMD implementations at build time.

```sh
git clone https://github.com/feurstern/trust-forge.git
cd trust-forge
cargo install --path crates/trustforge-cli --locked
trustforge --version
```

`cargo install` places the `trustforge` binary in `~/.cargo/bin`. To try it without installing, use `cargo run -p trustforge-cli -- <arguments>` instead.

## Quick start

Inspect a file:

```sh
trustforge inspect target/release/myapp
```

TrustForge prints:
- the artifact's size;
- its format, detected from its header bytes (for example an ELF executable for x86_64);
- its SHA-256, SHA-512 and BLAKE3 digests.

Only these algorithms are computed:

```sh
trustforge inspect -a sha256 myapp.tar.gz
```

Inspect standard input:

```sh
curl -sL https://example.com/tool.tar.gz | trustforge inspect -
```

Inspect a directory (Linux and macOS):

```sh
trustforge inspect dist/
```

A directory gets **tree digests** (`narSha256`, …), which cover:
- every file's contents;
- each file's owner-execute bit;
- symbolic links, recorded with their target text and never followed;
- empty directories.

Two directories with the same tree digest have identical contents and structure, whatever their timestamps or other permission bits.

Get everything as JSON, including each entry's digests:

```sh
trustforge inspect --format json dist/ > dist.inspection.json
```

## What a digest does and does not tell you

A digest identifies bytes. If you compare it with a digest you obtained from somewhere else, a match shows you have the same bytes as whoever produced that reference. It shows nothing more:
- If the artifact and the reference come from the same place, an attacker who can change one can usually change the other.
- A digest says nothing about who built the artifact, how it was built, or whether it is safe.

TrustForge's later milestones add signature and provenance verification and reproducible rebuilds, and report each guarantee separately. See the [README](../README.md#the-problem).

## Next steps

- [CLI reference](cli-reference.md): every option, both output formats, exit codes.
- [Known limitations](limitations.md).
- [Threat model](threat-model.md).
