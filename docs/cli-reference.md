# CLI Reference

> **Status:** pre-alpha. `inspect` is the only command. Output formats are version 0 and may change in any release; every change is listed in the [CHANGELOG](../CHANGELOG.md).

## `trustforge inspect`

```text
trustforge inspect [OPTIONS] <PATH>
```

Describes an artifact and computes its digests: its kind, size, format and SHA-256, SHA-512 and BLAKE3 digests. A directory's tree digests are computed over its [NAR serialization](manifest-spec.md#tree-digests).

**`inspect` verifies nothing.** It reports which bytes it read. It does not compare them with anything, and it says nothing about who produced them or whether they are safe. Verification against references arrives in Milestone 3 (see the [roadmap](roadmap.md)).

### Arguments and options

| Option | Default | Meaning |
|---|---|---|
| `<PATH>` | (required) | The file or directory to inspect, or `-` to read standard input. Must be valid UTF-8. To inspect a file named `-`, write `./-`. |
| `--format <text\|json>` | `text` | Output format (see below). |
| `-a`, `--algorithm <ALGORITHM>` | all | `sha256`, `sha512` or `blake3`. Repeat the option or separate names with commas, for example `-a sha256,blake3`. `md5` and `sha1` are never accepted. |
| `--max-bytes <BYTES>` | 68719476736 (64 GiB) | Fail instead of reading more content bytes than this: the file, the stream, or all regular files of a directory together. A file's reported size is checked before it is read, so a huge sparse file fails immediately. |
| `--max-entries <N>` | 1000000 | Fail on a directory with more entries than this, not counting its root. |
| `--max-depth <N>` | 128 | Fail on a directory entry with more path components than this (`a/b/c` has three). |

Two further limits are not exposed as options:
- the total length of all entries' relative paths: 256 MiB, which bounds the memory a listing uses;
- the length of a symlink target: 4,096 bytes.

### What is inspected

- **A regular file** is read once, from start to end, through a fixed-size buffer. Its format is detected from its first 4 KiB, and never from its name.
- **Standard input** (`-`) is treated like a file.
- **A directory**, on Unix only, is traversed depth-first. Siblings are visited in ascending byte order of their names. The traversal rules are in the [architecture](architecture.md#directory-traversal-rules); in short:
  - Symbolic links below the root are recorded with their target text and never followed.
  - FIFOs, sockets and device nodes are errors, and they are never opened.
  - A name or symlink target that is not valid UTF-8, or that contains a control character, a bidi control, a line or paragraph separator or a backslash, is an error.
  - A directory on another file system (a mount point, including a btrfs subvolume) is an error.
  - A directory that is one of its own ancestors is an error.
  - Nothing is excluded: `.git`, `.DS_Store` and every other entry are hashed.
- **On Windows**, directory inspection is unsupported. Windows has no executable bit, which tree digests cover. Single files work on every platform.
- **A path that is a symbolic link** is followed once, and the output says so.

If the artifact changes while it is being inspected, the inspection fails:
- A file must read exactly its reported size and then show unchanged metadata.
- A directory must show unchanged metadata after it is listed and after its entries are done.
- After a directory walk, every entry is checked once more, so the result describes the tree at one moment rather than a mix of states.

This detection is best effort: see [limitations](limitations.md).

### Text output

```text
$ trustforge inspect hello.txt
Artifact   hello.txt
Kind       file
Size       14 bytes
Format     unknown (detected from header bytes only)
blake3     fa5d7675d23c30fda281f74ab6b4bceff968c4364a08bd9e15a13ec298aa0e55
sha256     1ab1a2bb8502820a83881a5b66910b819121bafe336d76374637aa4ea7ba2616
sha512     874b96bad154f354982afd58cda6b63720c37e3c3ba91a5731473e1cf2f23a1b9904b5770152b52e47eaaa3c270242a42f204c2b5a970c7745727edf9d24e35a
Mode       0644 (file-system metadata, not covered by any digest)
Modified   2026-11-05T03:08:45Z (file-system metadata, not covered by any digest)

Digests identify these bytes. They do not show who produced them or whether they are safe.
```

For a directory, the digest lines are the tree digests (`narBlake3`, `narSha256`, `narSha512`). Symbolic links whose targets leave the tree are listed. Per-entry details are only in the JSON output.

`Mode` and `Modified` describe the given path, not its contents. They are not covered by any digest and can differ between copies of the same artifact.

Every string that comes from the artifact, and every error message, is passed through one sanitizer before it reaches the terminal. Control characters (including the ESC that starts terminal escape sequences), bidi controls and line separators are shown as `\u{…}`. Bytes that are not valid UTF-8 are shown as `\xNN`.

### JSON output

`--format json` writes exactly one JSON document to standard output. Object keys are sorted at every level. Control characters, bidi controls and line separators inside strings are written as `\uXXXX` escapes, so the document is safe to print to a terminal and still decodes to the exact values.

The document contains only what is derived from the artifact's content and structure, plus the name it was given, so identical artifacts inspected under the same name produce byte-identical JSON. File-system metadata (`Mode`, `Modified`) is left out.

Example for a directory `dist` containing `README`, an executable `bin/hello` and a symbolic link:

```json
{
  "counts": {
    "directories": 1,
    "files": 2,
    "symlinks": 1
  },
  "entries": [
    {
      "digest": {
        "blake3": "fa5d7675d23c30fda281f74ab6b4bceff968c4364a08bd9e15a13ec298aa0e55",
        "sha256": "1ab1a2bb8502820a83881a5b66910b819121bafe336d76374637aa4ea7ba2616",
        "sha512": "874b96bad154f354982afd58cda6b63720c37e3c3ba91a5731473e1cf2f23a1b9904b5770152b52e47eaaa3c270242a42f204c2b5a970c7745727edf9d24e35a"
      },
      "executable": false,
      "path": "README",
      "size": 14,
      "type": "file"
    },
    {
      "path": "bin",
      "type": "directory"
    },
    {
      "digest": {
        "blake3": "51b972d648f597be6a7867cc3629ec7e067218e0f9d356a80b9e74b2a7a88326",
        "sha256": "bfdeaeb08cffb6a36438bcd12dda25417e3cdd36f1e7e482a2849d539225288b",
        "sha512": "21c8b1b3d6bb72ee5a2025efa2a9eab0e18f79bc346e30f269b474b9865edf2c53cb02538027314d4511bc21ef7f4dd46296c8dd7f885a97afe4420dac62cca4"
      },
      "executable": true,
      "path": "bin/hello",
      "size": 21,
      "type": "file"
    },
    {
      "path": "libexample.so",
      "target": "/usr/lib/libexample.so.1",
      "targetLeavesTree": true,
      "type": "symlink"
    }
  ],
  "kind": "directory",
  "name": "dist",
  "rootSymlinkFollowed": false,
  "size": 35,
  "treeDigest": {
    "narBlake3": "cf0affc27e8e75730bd0cde5c3185356dd64e9b6bfd571a3272f30a2f715aef6",
    "narSha256": "18dec0d94eec3e18bd1f2a9c8d56ed8ad6176421ab95a23219991bdcb821c52d",
    "narSha512": "69a552bc90d1ab491c68da850fcf17f187af7d2fd80a4d07a85af5dfd0f49a7d94f41d3e03ab9641bf45c92b4b095047cb03881831045b728d45ed9641e7b050"
  }
}
```

#### Fields

| Field | Present for | Meaning |
|---|---|---|
| `name` | all | The `PATH` argument as given, never canonicalized; `-` for standard input |
| `kind` | all | `file`, `directory` or `stream` |
| `size` | all | Bytes; for a directory, the total size of its regular files (a file with several hard links counts once per path) |
| `rootSymlinkFollowed` | all | Whether `PATH` was a symbolic link, followed once |
| `digest` | file, stream | Content digests: `blake3`, `sha256`, `sha512` (lowercase hex), for the selected algorithms |
| `format` | file, stream | The format detected from header bytes (see below) |
| `treeDigest` | directory | Digests of the NAR serialization: `narBlake3`, `narSha256`, `narSha512` |
| `counts` | directory | Numbers of `directories` (excluding the root), `files` and `symlinks` |
| `entries` | directory | Every entry, depth-first with siblings in ascending byte order (the NAR order). This is not full-path order: `a`, `a/b`, `a-b`. |
| `entries[].path` | | Path relative to the root, `/`-separated, with no leading `./` |
| `entries[].type` | | `file`, `directory` or `symlink` |
| `entries[].executable` | `file` | Whether the owner-execute bit is set: the only permission bit any digest covers |
| `entries[].size`, `entries[].digest` | `file` | As for a file artifact |
| `entries[].target` | `symlink` | The link's target text, never followed |
| `entries[].targetLeavesTree` | `symlink` | Whether the target is absolute or climbs above the root with `..`. Computed from the text alone; informational. |

#### Formats

`format.type` is one of:
- `elf`, with `bits`, `endianness`, `objectType` and `objectTypeCode`, `machine` and `machineCode`, and `osAbi`;
- `mach-o`, with `bits`, `endianness`, `cpu`, `cpuType`, `fileType` and `fileTypeCode`;
- `mach-o-universal`, with `architectures[]` (`cpu`, `cpuType`);
- `pe`, with `machine`, `machineCode`, `optionalHeader` (`pe32` or `pe32+`) and `dll`;
- `wasm`, with `version` and `layer`;
- `tar`, `zip`, `ar`, `7z`, `gzip`, `xz`, `zstd`, `bzip2`;
- `unknown`.

Machine names follow Rust's `target_arch` values (`x86_64`, `aarch64`, …). They are `null` when unrecognized, and the raw code is always present. An ELF `objectType` of `shared-object` includes position-independent executables.

Format detection reads fixed header fields only. It does not validate the file, and a file can be valid in several formats at once, so the result is informational.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The artifact was inspected. |
| 2 | Usage error: unknown option or algorithm, missing or non-UTF-8 `PATH`. |
| 4 | The artifact could not be inspected. Examples: not found, permission denied, unsupported file type, invalid name, limit exceeded, changed during inspection, unsupported on this platform. The reason is printed on standard error. |
| 101 | Internal error (a panic). Please report it. |

Standard output carries only the result. Errors and hints go to standard error, and nothing is written to standard output when inspection fails.
