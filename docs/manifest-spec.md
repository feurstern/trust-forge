# TrustForge Manifest Specification — Draft v0

> **Status: DRAFT, not implemented.** Implementation is planned for Milestone 2. Version `v0` is unstable: it may change incompatibly in any release, and every such change is listed in the [CHANGELOG](../CHANGELOG.md). Documents written against this draft are not interoperable until the [namespace](#namespace) is fixed.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## Purpose

A TrustForge manifest is a **claim document**. It describes an artifact by its digests and, optionally, the recipe that is claimed to build it.

- A manifest **is not evidence.** Verification establishes which of its claims are supported (see [verification-semantics.md](verification-semantics.md)).
- A manifest **is not provenance.** Provenance is attested by a build platform. A manifest is written by whoever publishes it, and its `predicateType` deliberately differs from SLSA provenance so the two cannot be confused.
- An **unsigned** manifest is an `unauthenticated-claim`. Matching it establishes integrity *relative to that claim* only.

## Namespace

TrustForge's type URIs have not been assigned yet. This draft writes the namespace as `<ns>`. The identifiers it defines are:

| Identifier | Used for |
|---|---|
| `<ns>/manifest/v0` | Predicate type of a TrustForge manifest |
| `<ns>/build/cargo/v0` | Build type for Rust/Cargo recipes |
| `<ns>/report/v0` | Verification report documents |
| `<ns>/rebuild-record/v0` | Rebuild record documents |

## Format

A manifest is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) whose predicate is defined below. Using the Statement envelope means a manifest can be signed as an in-toto attestation (a DSSE envelope, for example with `cosign attest-blob` or GitHub's `actions/attest`) without changing its format. TrustForge verifies signed manifests from Milestone 5.

### Example: a single binary

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicate": {
    "artifact": {
      "kind": "file",
      "size": 102400
    },
    "buildDefinition": {
      "buildType": "<ns>/build/cargo/v0",
      "externalParameters": {
        "bin": "application",
        "defaultFeatures": true,
        "features": [],
        "outputPath": "target/x86_64-unknown-linux-gnu/release/application",
        "package": "application",
        "profile": "release",
        "source": {
          "ref": "refs/tags/v1.2.3",
          "repository": "https://github.com/example/project.git"
        },
        "target": "x86_64-unknown-linux-gnu"
      },
      "internalParameters": {
        "cargoHome": "/build/cargo-home",
        "env": {
          "SOURCE_DATE_EPOCH": "1730678400"
        },
        "toolchain": "1.99.1",
        "workdir": "/build/src"
      },
      "resolvedDependencies": [
        {
          "digest": {
            "gitCommit": "<40 or 64 lowercase hex characters>"
          },
          "uri": "git+https://github.com/example/project.git@refs/tags/v1.2.3"
        },
        {
          "digest": {
            "sha256": "<64 lowercase hex characters>"
          },
          "uri": "pkg:docker/library/rust@1.99.1-slim-bookworm?repository_url=docker.io"
        }
      ]
    }
  },
  "predicateType": "<ns>/manifest/v0",
  "subject": [
    {
      "digest": {
        "sha256": "<64 lowercase hex characters>",
        "sha512": "<128 lowercase hex characters>"
      },
      "name": "application"
    }
  ]
}
```

(Keys appear in the sorted order that TrustForge writes; see [Serialization](#serialization).)

## Statement fields

| Field | Required | Rules |
|---|---|---|
| `_type` | MUST | Exactly `https://in-toto.io/Statement/v1` |
| `subject` | MUST | A non-empty array. Each element has a `name`, unique within the manifest, and a `digest` [digest set](#digest-sets). |
| `predicateType` | MUST | `<ns>/manifest/v0`. Any other value makes the manifest `UNSUPPORTED`; it is never interpreted on a best-effort basis. |
| `predicate` | MUST | An object as defined below |

## Predicate

### `artifact` (MUST)

| Field | Required | Rules |
|---|---|---|
| `kind` | MUST | `"file"` or `"directory"` |
| `size` | SHOULD | Integer number of bytes. For a directory, the total size of its regular files. A mismatch is a contradiction, and TrustForge can detect it before hashing. |
| `tree` | MUST for directories | Directory listing (see [Directory artifacts](#directory-artifacts)) |
| `treeDigest` | MUST for directories | A digest set using the [tree digest keys](#tree-digests) |

### `buildDefinition` (MAY)

`buildDefinition` has the shape of the SLSA Provenance v1 [`BuildDefinition`](https://slsa.dev/spec/v1.2/provenance): `buildType`, `externalParameters`, `internalParameters` and `resolvedDependencies`. Here it describes a **claimed recipe**, not an attested build.

If `buildDefinition` is absent, the manifest can still be used to verify integrity, and reproducibility is reported as `NOT_PROVIDED`. Only the build type `<ns>/build/cargo/v0` is defined in v0. Any other build type makes the rebuild `UNSUPPORTED`.

## Build type `<ns>/build/cargo/v0`

Builds one binary target of a Rust/Cargo project for one target triple.

### `externalParameters`

Unknown fields in `externalParameters` **MUST be rejected**, because an unexpected parameter could change what gets built. This follows SLSA's guidance for verifiers.

| Field | Required | Rules |
|---|---|---|
| `source.repository` | MUST | An `https` URL with no user name or password. `file:`, `ssh:` and `ext::` URLs are rejected. |
| `source.ref` | SHOULD | A full ref name, such as `refs/tags/v1.2.3`. Without it, the commit's reachability cannot be checked, and `source.reachability` is `NOT_PROVIDED`. |
| `workspacePath` | MAY | Relative path to the Cargo workspace root. Default `.` |
| `package` | MAY | Cargo package name |
| `bin` | MUST | Binary target name |
| `profile` | MAY | Cargo profile name. Default `release` |
| `target` | MUST | Target triple |
| `features` | MAY | Array of feature names, sorted and unique. Default `[]` |
| `defaultFeatures` | MAY | Boolean. Default `true` |
| `outputPath` | MUST | Path of the produced artifact, relative to the workspace root |

Names (`package`, `bin`, `profile`, feature names) and the target triple MUST match Cargo's character rules, and **no value may begin with `-`**. Paths MUST be relative, `/`-separated, and free of `.`, `..` and empty components.

### `internalParameters`

| Field | Required | Rules |
|---|---|---|
| `toolchain` | MUST | Exact rustup toolchain name, such as `1.99.1`. The rebuild pins it with `RUSTUP_TOOLCHAIN`, overriding any toolchain file in the repository. |
| `workdir` | MAY | Absolute in-container path of the source tree. Default `/build/src` |
| `cargoHome` | MAY | Absolute in-container `CARGO_HOME`. Default `/build/cargo-home` |
| `env` | MAY | Map of extra environment variables. Keys MUST be on the allowlist: `SOURCE_DATE_EPOCH`, `RUSTFLAGS`, `CARGO_PROFILE_*`. Values MUST NOT contain control characters. `SOURCE_DATE_EPOCH` MUST be a decimal integer. |

Rust binaries embed source and registry paths, so `workdir` and `cargoHome` are part of the recipe. The original build must have used the same paths, or remapped them with `--remap-path-prefix` in `RUSTFLAGS`.

### `resolvedDependencies`

These are in-toto ResourceDescriptors. There MUST be exactly one entry of each of these kinds:

- **Source:** `uri` `git+<repository>@<ref>`, with `digest.gitCommit` set to the **full** commit SHA (40 or 64 lowercase hex characters).
- **Build image:** `uri` a package URL (`pkg:docker/…`), with `digest.sha256` set to the image manifest digest.

Additional entries MAY appear. They are listed in reports but do not affect the rebuild.

## Digest sets

A digest set is a JSON object mapping an algorithm name to a lowercase hexadecimal value.

| Key | Value | Notes |
|---|---|---|
| `sha256` | 64 hex characters | SHOULD always be present, for compatibility with other in-toto tools |
| `sha512` | 128 hex characters | |
| `blake3` | 64 hex characters | BLAKE3 default 32-byte output. in-toto does not predefine `blake3`, so this document defines its encoding, as in-toto requires for new algorithm names. |

- Values MUST be lowercase hexadecimal of the exact length.
- Keys TrustForge does not accept are ignored and **reported**. `md5` and `sha1` are flagged as insecure and are never accepted.
- A digest set with no accepted key cannot be evaluated, so the result is `UNSUPPORTED`.
- **Matching rule:** every accepted algorithm present MUST match. The in-toto framework allows a match on *any* accepted algorithm. TrustForge is deliberately stricter, so anything TrustForge accepts, an in-toto verifier also accepts.

### Tree digests

| Key | Value |
|---|---|
| `narSha256` | SHA-256 of the tree's NAR serialization (hex) |
| `narSha512` | SHA-512 of the tree's NAR serialization (hex) |
| `narBlake3` | BLAKE3 of the tree's NAR serialization (hex) |

NAR is the Nix Archive format, a deterministic, injective serialization of a file tree, described in the Nix manual. It records:
- regular files, with their contents and executable bit;
- directories, including empty ones, with entries sorted by the byte value of their names;
- symlinks, with their target text.

It does not record timestamps, ownership or other permissions. Tree digests use separate keys and are compared only against directory artifacts, so a file whose bytes happen to be a NAR serialization can never satisfy a tree digest.

## Directory artifacts

- `subject` lists every regular file, with `name` set to its relative path. This keeps the manifest useful to generic in-toto tools.
- `artifact.tree` lists every entry in NAR traversal order (depth-first, siblings sorted by byte value). Each entry has:
  - `path`
  - `type`: `"file"`, `"directory"` or `"symlink"`
  - for files, `executable`, `size` and `digest`
  - for symlinks, `target`
- Verification requires an **exact** tree match. Extra, missing or retyped entries, a changed executable bit or a changed symlink target are all mismatches.
- File names must be valid UTF-8 without control characters, bidi controls or backslash. Names are compared byte for byte with no Unicode normalization.

## Source identity

Most git repositories identify commits with SHA-1. TrustForge treats `gitCommit` as a **locator**:
- the commit must be given in full;
- it must exist with the expected object format;
- it must be reachable from `source.ref` in `source.repository`. GitHub serves commits pushed to any fork through the upstream URL, so a successful fetch alone does not show that a commit belongs to the repository.

During a rebuild, TrustForge also records a `narSha256` digest of the checked-out source tree (excluding `.git`), which identifies the source with SHA-256.

## Parsing and validation

A manifest MUST be rejected unless all of the following hold:

1. It is at most 4 MiB (the limit is configurable) **before** parsing.
2. It is strict I-JSON (RFC 7493):
   - UTF-8, with no byte-order mark, no data after the top-level value, and no unpaired surrogates;
   - **no duplicate object keys at any depth**, compared after unescaping (`"sha256"` and `"sha256"` are duplicates);
   - **no key that differs from a defined field name only in letter case** (some JSON parsers match field names case-insensitively);
   - no C0, C1 or bidi control characters in any string;
   - nesting depth at most 64;
   - numbers only where this specification allows them, as integers between 0 and 2^53−1.
3. Every rule in the sections above holds.

TrustForge implements these rules in its own strict parsing layer, not by relying on a general-purpose JSON library's defaults.

## Unknown fields

- Fields this specification does not define are **ignored** at the Statement and predicate level, as the in-toto parsing rules require. TrustForge **reports** each ignored field as a warning, and `trustforge manifest validate --strict` rejects them.
- In `externalParameters`, unknown fields are **rejected** (see above).
- An extension field MUST NOT change the meaning of any field defined here.

## Serialization

TrustForge writes manifests **deterministically**:
- object keys in the order defined by RFC 8785 (for the ASCII keys used here, ascending byte order);
- strings and integers encoded as RFC 8785 specifies;
- two-space indentation, LF line endings and a trailing newline.

`--canonical` writes the exact RFC 8785 (JCS) form instead. Keys are sorted explicitly by TrustForge, so the output does not depend on the iteration order of any JSON library.

Signatures (DSSE) cover the **exact bytes** of a document, so verification never depends on re-serialization.

## Manifest identity and integrity

- A manifest is identified by the **SHA-256 of its exact bytes**, which every report shows.
- TrustForge reads a manifest **once**. Every later step, including the rebuild plan and the user's approval, is bound to that digest.
- A user who obtained a manifest's digest through a trusted channel can pin it with `--manifest-digest sha256:…`. The reference origin then becomes `user-pinned`.
- Authenticity of a manifest requires a verified signature under the user's trust policy (Milestone 5).

## Versioning and compatibility

- The major version is part of `predicateType`. `v0` is unstable. `v1` will be frozen before the first release candidate (Milestone 6).
- Minor versions add only optional fields that follow the in-toto *monotonic principle*: ignoring such a field can never turn a rejection into an acceptance. Any other change requires a new major version.
- TrustForge reads the current major version and the previous one for at least 12 months after a new major version is released. Unknown major versions are `UNSUPPORTED`.
- Example manifests for every published version are kept as test fixtures permanently.

## Security considerations

- Every manifest field is attacker-controlled. Values are validated, never interpolated into shell commands, and passed to programs only as separate arguments in `--flag=value` form.
- A manifest can never approve a rebuild. Approval comes only from the user, bound to the displayed plan.
- The build image named in a manifest is used only if the user's image policy allows it. The manifest itself cannot grant trust in an image.

## Open items before v1

- The namespace URI.
- Whether `artifact.size` becomes mandatory.
- Directory tree digests on Windows (currently unsupported, because Windows has no executable bit).
- Build types beyond `cargo/v0`.
- The signing profile for manifests (Milestone 5).
