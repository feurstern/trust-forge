# TrustForge Manifest Specification — v0

> **Status: implemented (Milestone 2), unstable.** `trustforge manifest create` writes manifests and `trustforge manifest validate` checks them against every rule below. `trustforge verify --manifest` compares artifacts with them (Milestone 3). Version `v0` may still change incompatibly in any release, and every such change is listed in the [CHANGELOG](../CHANGELOG.md). Version `v1` will be frozen before the first release candidate.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in RFC 2119.

## Purpose

A TrustForge manifest is a **claim document**. It describes an artifact by its digests and, optionally, the recipe that is claimed to build it.

- A manifest **is not evidence.** Verification establishes which of its claims are supported (see [verification-semantics.md](verification-semantics.md)).
- A manifest **is not provenance.** Provenance is attested by a build platform. A manifest is written by whoever publishes it, and its `predicateType` deliberately differs from SLSA provenance so the two cannot be confused.
- An **unsigned** manifest is an `unauthenticated-claim`. Matching it establishes integrity *relative to that claim* only.

## Namespace

TrustForge's type URIs live under `https://feurstern.github.io/trust-forge` (roadmap open question a, settled in Milestone 2). They are identifiers: they need not resolve, although the project's GitHub Pages site can later publish each specification at its URI.

| Identifier | Used for |
|---|---|
| `https://feurstern.github.io/trust-forge/manifest/v0` | Predicate type of a TrustForge manifest |
| `https://feurstern.github.io/trust-forge/build/cargo/v0` | Build type for Rust/Cargo recipes |
| `https://feurstern.github.io/trust-forge/report/v0` | Verification report documents (Milestone 3) |
| `https://feurstern.github.io/trust-forge/rebuild-record/v0` | Rebuild record documents (Milestone 4) |

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
      "buildType": "https://feurstern.github.io/trust-forge/build/cargo/v0",
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
            "gitCommit": "8c3e1f6b2a9d4e5f60718293a4b5c6d7e8f90a1b"
          },
          "uri": "git+https://github.com/example/project.git@refs/tags/v1.2.3"
        },
        {
          "digest": {
            "sha256": "5d1f3c8e9a2b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
          },
          "uri": "pkg:docker/library/rust@1.99.1-slim-bookworm?repository_url=docker.io"
        }
      ]
    }
  },
  "predicateType": "https://feurstern.github.io/trust-forge/manifest/v0",
  "subject": [
    {
      "digest": {
        "sha256": "d1676dcb0cd0903841cf4953ba161eb34601a821d45ae551049318597b7aa5b9",
        "sha512": "c897ef6cb44a887e024e74a2a6510a144ab6a9b85d4d8b6a6e8622b4d3f8ebab0c42599260ae00f794c908439835645e0a8baa9e65d5fae9f44018d173de4aa3"
      },
      "name": "application"
    }
  ]
}
```

(Keys appear in the sorted order that TrustForge writes; see [Serialization](#serialization). The digests and IDs are examples. This document, with more fields, is the fixture `fixtures/manifests/v0/valid/file-recipe.json`.)

## Statement fields

| Field | Required | Rules |
|---|---|---|
| `_type` | MUST | Exactly `https://in-toto.io/Statement/v1` |
| `subject` | MUST | A non-empty array. Each element has a `name`, unique within the manifest, and a `digest` [digest set](#digest-sets). A name is a relative path under the [name rules](#directory-artifacts). A file artifact has exactly one subject; a directory artifact's subjects are its regular files. |
| `predicateType` | MUST | `https://feurstern.github.io/trust-forge/manifest/v0`. Any other value makes the manifest `UNSUPPORTED`; it is never interpreted on a best-effort basis. The type and version are checked before anything else is read. |
| `predicate` | MUST | An object as defined below |

## Predicate

### `artifact` (MUST)

| Field | Required | Rules |
|---|---|---|
| `kind` | MUST | `"file"` or `"directory"` |
| `size` | SHOULD | Integer number of bytes. For a directory, the total size of its regular files, which MUST equal the sum of the tree's file sizes. A mismatch with the artifact is a contradiction, and TrustForge can detect it before hashing. |
| `tree` | MUST for directories, MUST NOT for files | Directory listing (see [Directory artifacts](#directory-artifacts)) |
| `treeDigest` | MUST for directories, MUST NOT for files | A digest set using the [tree digest keys](#tree-digests) |

### `buildDefinition` (MAY)

`buildDefinition` has the shape of the SLSA Provenance v1 [`BuildDefinition`](https://slsa.dev/spec/v1.2/provenance): `buildType`, `externalParameters`, `internalParameters` and `resolvedDependencies`. Here it describes a **claimed recipe**, not an attested build.

If `buildDefinition` is absent, the manifest can still be used to verify integrity, and reproducibility is reported as not evaluated because no recipe was provided. Only the build type `https://feurstern.github.io/trust-forge/build/cargo/v0` is defined in v0. Any other build type is accepted with a warning and kept as written, but not interpreted: the manifest can still be used for integrity, and the rebuild is `UNSUPPORTED`. Until rebuilds exist (Milestone 4), every claimed recipe, `cargo/v0` included, gets a `reproducibility.rebuild` result of `UNSUPPORTED`. `trustforge manifest create` refuses to embed a recipe of any other build type, so a misspelled build type cannot slip into a new manifest unchecked.

## Build type `https://feurstern.github.io/trust-forge/build/cargo/v0`

Builds one binary target of a Rust/Cargo project for one target triple.

### `externalParameters`

Unknown fields in `externalParameters` **MUST be rejected**, because an unexpected parameter could change what gets built. This follows SLSA's guidance for verifiers.

| Field | Required | Rules |
|---|---|---|
| `source.repository` | MUST | An `https` URL: a host name (letters, digits, `-` and `.`, not starting with `-` or `.`), an optional port and an optional path of printable ASCII segments. No user name, password, query, fragment or percent-encoding (`@ ? # \ %` are rejected in the path), and no empty, `.` or `..` segment (so no trailing `/` either): the URL names exactly the repository it shows. `http:`, `file:`, `ssh:` and `ext::` URLs are rejected. At most 2,048 characters. |
| `source.ref` | SHOULD | A full ref name, such as `refs/tags/v1.2.3`, under git's rules plus one: printable ASCII without `~ ^ : ? * [ \` and without `@`, which git allows outside `@{` but which would make the source URI `git+<repository>@<ref>` ambiguous; no `..`; no empty component, no component starting with `.` or ending with `.lock`; not ending with `/` or `.`; at most 255 characters. Without it, the commit's reachability cannot be checked, and `source.reachability` is `NOT_PROVIDED`. |
| `workspacePath` | MAY | Relative path to the Cargo workspace root. Default `.` |
| `package` | MAY | Cargo package name |
| `bin` | MUST | Binary target name |
| `profile` | MAY | Cargo profile name. Default `release` |
| `target` | MUST | Target triple |
| `features` | MAY | Array of feature names, sorted and unique. Default `[]` |
| `defaultFeatures` | MAY | Boolean. Default `true` |
| `outputPath` | MUST | Path of the produced artifact, relative to the workspace root |

**No value may begin with `-`**, which would turn it into an option:
- `package`, `bin` and `profile`: ASCII letters, digits, `_` and `-`, starting with a letter or `_`, at most 64 characters;
- feature names: ASCII letters, digits, `_`, `-`, `+` and `.`, starting with a letter, digit or `_`, at most 64 characters (`dep:` and `package/feature` forms are not accepted in v0);
- `target`: a target triple name of two to five `-`-separated parts in lowercase ASCII letters, digits, `_` and (after the first part) `.`, at most 64 characters, never a path to a custom target specification (`*.json`);
- `workspacePath` and `outputPath`: relative, `/`-separated paths whose components each start with an ASCII letter, digit or `_` and contain only ASCII letters, digits, `_`, `-`, `+` and `.`, so no component is empty, `.` or `..`, or begins with `-`.

### `internalParameters`

| Field | Required | Rules |
|---|---|---|
| `toolchain` | MUST | An exact toolchain: a version (`1.99.1`) or a dated channel (`nightly-2026-11-13`, `beta-2026-11-13`). Channel names such as `stable` are rejected, because what they name changes over time, and so are paths and host-specific names. The rebuild pins it with `RUSTUP_TOOLCHAIN`, overriding any toolchain file in the repository. |
| `workdir` | MAY | In-container path of the source tree. Default `/build/src` |
| `cargoHome` | MAY | In-container `CARGO_HOME`. Default `/build/cargo-home` |
| `env` | MAY | Map of extra environment variables. Keys MUST be on the allowlist: `SOURCE_DATE_EPOCH`, `RUSTFLAGS`, `CARGO_PROFILE_` followed by uppercase letters, digits and `_`. `SOURCE_DATE_EPOCH` MUST be a decimal integer of at most 19 digits. |

Unknown fields in `internalParameters` are **rejected** too: they are part of how the build runs.

`workdir` and `cargoHome` are absolute paths under `/build/` whose components each start with an ASCII letter, digit or `_` and contain only ASCII letters, digits, `_`, `-` and `.`. That excludes `,`, `:` and `=`, which container runtimes read as syntax in mount options. The two MUST NOT be the same directory or one inside the other, defaults included: Cargo trusts the contents of `CARGO_HOME`, such as its configuration and the registry sources it has already downloaded and extracted, so they must not come from the repository.

Rust binaries embed source and registry paths, so `workdir` and `cargoHome` are part of the recipe. The original build must have used the same paths, or remapped them with `--remap-path-prefix` in `RUSTFLAGS`.

### `resolvedDependencies`

These are in-toto ResourceDescriptors with a `uri`, a `digest` and an optional `name`; other ResourceDescriptor fields are ignored with a warning. There MUST be exactly one entry of each of these kinds:

- **Source** (the only `uri` starting with `git+`, in any letter case): `uri` MUST be exactly `git+<repository>@<ref>`, or `git+<repository>` without a ref, matching `externalParameters.source`. `digest.gitCommit` MUST be the **full** commit ID (40 or 64 lowercase hex characters).
- **Build image** (the only `uri` starting with `pkg:docker/`, in any letter case): the prefix MUST be written in lowercase, and `digest.sha256` MUST be the image manifest digest. The package URL is not otherwise interpreted in v0.

Prefixes are matched in any letter case so that an entry such as `GIT+https://…` counts as a second source, rather than being passed over by TrustForge while another tool reads it as the source.

Additional entries MAY appear. They are listed in reports but do not affect the rebuild. In every entry, `sha256`, `sha512`, `blake3` and `gitCommit` values MUST be well-formed lowercase hex, and other digest values MUST be non-empty strings. A digest key that differs from one of those four only in letter case is an error. `md5` and `sha1` values, in any letter case, are dropped with a warning, as in subjects.

## Digest sets

A digest set is a JSON object mapping an algorithm name to a lowercase hexadecimal value.

| Key | Value | Notes |
|---|---|---|
| `sha256` | 64 hex characters | SHOULD always be present, for compatibility with other in-toto tools |
| `sha512` | 128 hex characters | |
| `blake3` | 64 hex characters | BLAKE3 default 32-byte output. in-toto does not predefine `blake3`, so this document defines its encoding, as in-toto requires for new algorithm names. |

- Values MUST be lowercase hexadecimal of the exact length.
- Keys TrustForge does not accept are ignored and **reported**. `md5` and `sha1` are flagged as insecure and are never accepted.
- A key that differs from an accepted name only in letter case (such as `SHA256`) is an error: another tool might read it as that algorithm.
- An empty digest set is invalid. A digest set whose keys are all ignored cannot be evaluated, so the result is `UNSUPPORTED`.
- **Matching rule:** every accepted algorithm present MUST match. The in-toto framework allows a match on *any* accepted algorithm. TrustForge is deliberately stricter, so anything TrustForge accepts, an in-toto verifier also accepts. Which algorithms are accepted is decided by the verifier's policy, never by the document.
- A subject's `name` is not compared with the name of the artifact being verified: subjects match by digest, as in in-toto, so a renamed download still verifies.

### Tree digests

| Key | Value |
|---|---|
| `narSha256` | SHA-256 of the tree's NAR serialization (hex) |
| `narSha512` | SHA-512 of the tree's NAR serialization (hex) |
| `narBlake3` | BLAKE3 of the tree's NAR serialization (hex) |

NAR is the Nix Archive format, a deterministic, injective serialization of a file tree, as produced by `nix-store --dump`. It records:
- regular files, with their contents and whether they are executable, which means the **owner-execute bit (`S_IXUSR`) only**, exactly as in Nix;
- directories, including empty ones, with entries sorted by the unsigned byte value of their names;
- symlinks, with their target text.

No tree digest covers:
- setuid, setgid or sticky bits;
- group or other permission bits;
- ACLs, extended attributes (including file capabilities) or resource forks;
- ownership, timestamps or hard-link identity.

A tree copied with tools that preserve these (`cp -a`, `rsync -a`, `tar -p`) can carry privileges that no digest covered.

Tree digests use separate keys and are compared only against directory artifacts, so a file whose bytes happen to be a NAR serialization can never satisfy a tree digest. TrustForge's NAR implementation is tested against reference serializations produced by Nix itself.

## Directory artifacts

- `subject` lists every regular file, with `name` set to its relative path, in the same order as `artifact.tree`. This keeps the manifest useful to generic in-toto tools.
- `artifact.tree` lists every entry in NAR traversal order: the root itself is not listed, then depth-first pre-order with siblings in ascending unsigned byte order of their names. This is not full-path order: `a`, `a/b`, `a-b`. Paths are `/`-separated, with no leading `./`. Each entry has:
  - `path`
  - `type`: `"file"`, `"directory"` or `"symlink"`
  - for files, `executable`, `size` and `digest`
  - for symlinks, `target`
- Every entry's parent directory MUST be listed before it, and entries MUST be unique: each path sorts strictly after the previous one in tree order.
- A `file` entry has exactly `executable`, `size` and `digest`; a `symlink` entry has exactly `target`; a `directory` entry has none of them.
- The `subject` list MUST be exactly the tree's regular files, in tree order, with the same digest sets as their tree entries.
- `artifact.size` counts a file with several hard links once per path.
- A directory without regular files cannot be described in v0: in-toto requires at least one subject.
- Verification requires an **exact** tree match. Extra, missing or retyped entries, a changed executable bit or a changed symlink target are all mismatches.
- A name must be valid UTF-8, must not be empty, `.` or `..`, and must not contain U+0000–U+001F, U+007F–U+009F, `/`, `\`, U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+2028, U+2029 or any of the 66 noncharacters (U+FDD0–U+FDEF and the last two code points of every plane: U+FFFE, U+FFFF, U+1FFFE, …, U+10FFFF). This list is fixed; it does not follow new Unicode versions. Symlink targets follow the same rules, except that `/`, `.` and `..` are allowed. Names are compared byte for byte with no Unicode normalization.

## Source identity

Most git repositories identify commits with SHA-1. TrustForge treats `gitCommit` as a **locator**:
- the commit must be given in full;
- it must exist with the expected object format;
- it must be reachable from `source.ref` in `source.repository`. GitHub serves commits pushed to any fork through the upstream URL, so a successful fetch alone does not show that a commit belongs to the repository.

During a rebuild, TrustForge also records a `narSha256` digest of the checked-out source tree (excluding `.git`), which identifies the source with SHA-256.

## Parsing and validation

A manifest MUST be rejected unless all of the following hold:

1. It is at most 4 MiB **before** parsing. The limit is configurable (`--max-manifest-size`), and readers need the same limit as the writer. Listing every file in both `subject` and `artifact.tree` costs roughly 150 bytes or more per file, so a 4 MiB directory manifest holds about 10,000–20,000 files; larger trees need a raised limit. The limit stays at 4 MiB by default because it is what bounds the parser's work on hostile input.
2. It is strict I-JSON (RFC 7493):
   - UTF-8, with no byte-order mark, no data after the top-level value, and no unpaired surrogates;
   - **no duplicate object keys at any depth**, compared after unescaping (`"sha256"` and `"sha\u0032\u0035\u0036"` are duplicates);
   - **no key that differs from a defined field name only in letter case**, compared with Unicode case folding, so `Subject` and `ſubject` (with U+017F) are both rejected: some JSON parsers, such as Go's, match field names case-insensitively;
   - no control characters (U+0000–U+001F, U+007F–U+009F), bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), line and paragraph separators (U+2028, U+2029) or noncharacters (U+FDD0–U+FDEF and the last two code points of every plane, which I-JSON forbids) in any string or key, escaped or not;
   - nesting depth at most 64;
   - numbers only where this specification allows them, as integers between 0 and 2^53−1, with no sign, fraction or exponent (`-0` and `1.0` are rejected).
3. Every rule in the sections above holds.

TrustForge implements these rules in its own strict parsing layer (`trustforge_core::json`), not by relying on a general-purpose JSON library's defaults.

A [JSON Schema](schemas/manifest-v0.schema.json) (draft 2020-12) describes the structure for other tools. It is **not normative**: it cannot express strict parsing, case-variant keys, entry order, subjects matching the tree, sizes, the source URI matching the recipe, or sorted features, so a document that matches it can still be invalid. `scripts/check-schema.sh` checks it against every fixture.

## Unknown fields

- Fields this specification does not define are **ignored** in the Statement, subjects, the predicate, `artifact`, tree entries, `buildDefinition` and resolved dependencies, as the in-toto parsing rules require. TrustForge **reports** each ignored field as a warning. `trustforge manifest validate --strict` turns every warning into an error.
- In `externalParameters`, `externalParameters.source` and `internalParameters`, unknown fields are **rejected** (see above).
- Ignored fields are not kept when TrustForge writes a manifest back.
- An extension field MUST NOT change the meaning of any field defined here.

## Serialization

TrustForge writes manifests **deterministically**:
- object keys in the order defined by RFC 8785 (for the ASCII keys used here, ascending byte order);
- strings and integers encoded as RFC 8785 specifies;
- two-space indentation, LF line endings and a trailing newline.

`--canonical` writes the exact RFC 8785 (JCS) form instead. Keys are sorted explicitly by TrustForge, by UTF-16 code units as RFC 8785 requires, so the output does not depend on the iteration order of any JSON library. Both forms are tested byte for byte against `scripts/json-reference.mjs`, which uses only ECMAScript's own JSON serialization, the reference RFC 8785 is defined on.

Signatures (DSSE) cover the **exact bytes** of a document, so verification never depends on re-serialization.

## Manifest identity and integrity

- A manifest is identified by the **SHA-256 of its exact bytes**, which every report shows.
- TrustForge reads a manifest **once**. Every later step, including the rebuild plan and the user's approval, is bound to that digest.
- A user who obtained a manifest's digest through a trusted channel can pin it with `trustforge verify --manifest-digest sha256:…`. The reference origin then becomes `user-pinned`. A manifest whose digest differs is never parsed and its claims are not used; the result is a mismatch (implemented in Milestone 3).
- Authenticity of a manifest requires a verified signature under the user's trust policy (Milestone 5).

## Versioning and compatibility

- The major version is part of `predicateType`. `v0` is unstable. `v1` will be frozen before the first release candidate (Milestone 6).
- Minor versions add only optional fields that follow the in-toto *monotonic principle*: ignoring such a field can never turn a rejection into an acceptance. Any other change requires a new major version.
- TrustForge reads the current major version and the previous one for at least 12 months after a new major version is released. Unknown major versions are `UNSUPPORTED`.
- Example manifests for every published version are kept as test fixtures permanently (`fixtures/manifests/v0/`): they must keep parsing, with the same warnings.

## Security considerations

- Every manifest field is attacker-controlled. Values are validated, never interpolated into shell commands, and passed to programs only as separate arguments in `--flag=value` form.
- A manifest can never approve a rebuild. Approval comes only from the user, bound to the displayed plan.
- The build image named in a manifest is used only if the user's image policy allows it. The manifest itself cannot grant trust in an image.

## Open items before v1

- Whether `artifact.size` becomes mandatory.
- Directory tree digests on Windows (unsupported in v0, because Windows has no executable bit; decided in Milestone 1).
- A more compact form for very large directory artifacts, which today need a raised size limit.
- Directories without regular files, which cannot have a subject.
- Feature names in `dep:` and `package/feature` form.
- Build types beyond `cargo/v0`.
- The signing profile for manifests (Milestone 5).
