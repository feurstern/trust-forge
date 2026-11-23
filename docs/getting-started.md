# Getting Started

> **Status:** pre-alpha. TrustForge can inspect and hash artifacts, write and check manifests, and verify an artifact's **integrity** against a manifest or expected digests. It does not verify signatures, provenance or rebuilds yet, so it cannot tell you who produced an artifact. Do not rely on it for security decisions yet. See the [roadmap](roadmap.md).

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

## Write a manifest

A manifest records an artifact's digests (for a directory, its full tree) as an [in-toto](https://in-toto.io/) Statement, so that others can later check the artifact against it:

```sh
trustforge manifest create target/release/myapp -o myapp.manifest.json
trustforge manifest create dist/ -o dist.manifest.json
```

To claim how the artifact is built, put a `buildDefinition` object in a file (the format is in the [manifest specification](manifest-spec.md#build-type-httpsfeursterngithubiotrust-forgebuildcargov0)) and add `--build-definition recipe.json`. Every value is checked before anything is written; for example, a binary name that starts with `-` is refused.

Check a manifest, yours or someone else's:

```sh
trustforge manifest validate dist.manifest.json
```

Validation reads the document strictly and checks every rule of the specification, then shows the SHA-256 that identifies the manifest's exact bytes. It does not look at the artifact, and it cannot tell who wrote the manifest: a valid manifest is a well-formed claim, not evidence.

## Verify an artifact

Compare an artifact with its manifest:

```sh
trustforge verify target/release/myapp --manifest myapp.manifest.json
```

TrustForge reports each guarantee separately, and the overall result last. This version can establish only **integrity**: that these are the bytes the manifest describes. Authenticity, provenance and reproducibility are reported as not evaluated, so under the default policy, which requires all four, a match is `PARTIALLY VERIFIED` (exit code 3). To require integrity alone:

```sh
trustforge verify target/release/myapp --manifest myapp.manifest.json --require integrity
```

That prints `Overall: VERIFIED` and exits with 0 if the artifact matches, and `Overall: MISMATCH` with exit code 1 if it does not.

An unsigned manifest is only a claim. If you obtained the manifest's SHA-256 through a channel you trust, pin it, and the manifest is used only if it is that exact document:

```sh
trustforge verify myapp --manifest myapp.manifest.json --manifest-digest sha256:… --require integrity
```

Without a manifest, compare with a digest you were given (`narSha256:…` for a directory):

```sh
curl -sL https://example.com/tool.tar.gz | trustforge verify - --expect sha256:… --require integrity
```

Save the report as JSON for later, and show it again (it is not re-verified, and the output says so):

```sh
trustforge verify myapp --manifest myapp.manifest.json --format json > myapp.report.json
trustforge report myapp.report.json
```

Compare two artifacts, such as two builds:

```sh
trustforge compare build-1/myapp build-2/myapp
```

Exit codes and every option are in the [CLI reference](cli-reference.md#trustforge-verify).

## What a digest does and does not tell you

A digest identifies bytes. If you compare it with a digest you obtained from somewhere else, a match shows you have the same bytes as whoever produced that reference. It shows nothing more:
- If the artifact and the reference come from the same place, an attacker who can change one can usually change the other.
- A digest says nothing about who built the artifact, how it was built, or whether it is safe.

That is exactly what `verify` reports as integrity, and why it names where every reference came from. TrustForge's later milestones add signature and provenance verification and reproducible rebuilds, each reported as its own guarantee. See the [README](../README.md#the-problem).

## Next steps

- [CLI reference](cli-reference.md): every option, both output formats, exit codes.
- [Known limitations](limitations.md).
- [Threat model](threat-model.md).
