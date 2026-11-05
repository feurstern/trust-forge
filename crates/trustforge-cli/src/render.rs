//! Rendering inspections as text and JSON.

use std::fmt::Write as _;

use trustforge_core::format::{Endianness, FileFormat};
use trustforge_core::inspect::{ArtifactDigests, ArtifactKind, EntryKind, Inspection};
use trustforge_core::name::is_unsafe_to_display;

use crate::sanitize::sanitize;

const CLOSING: &str =
    "Digests identify these bytes. They do not show who produced them or whether they are safe.";

const UNVERIFIED_METADATA: &str = "(file-system metadata, not covered by any digest)";

/// One JSON document. Object keys are sorted at every level: the value tree
/// is built with `serde_json`'s ordered map, and a test pins the output.
pub fn json(inspection: &Inspection) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(inspection)?;
    let mut text = escape_for_terminal(&serde_json::to_string_pretty(&value)?);
    text.push('\n');
    Ok(text)
}

/// `serde_json` escapes C0 control characters but writes DEL, C1 controls,
/// bidi controls and the line separators raw, and a terminal would act on
/// them. They can only occur inside JSON strings (everything else in the
/// document is ASCII punctuation, digits, letters, spaces and newlines),
/// where `\uXXXX` is an equivalent spelling: the escaped document has
/// exactly the same values.
fn escape_for_terminal(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c > '\u{1f}' && is_unsafe_to_display(c) {
            // Every such character is in the Basic Multilingual Plane.
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Human-readable text. Every string that comes from the artifact goes
/// through the sanitizer.
pub fn text(inspection: &Inspection) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        let _ = writeln!(out, "{label:<11}{value}");
    };
    let artifact = match inspection.kind() {
        ArtifactKind::Stream => "(standard input)".to_owned(),
        _ => sanitize(inspection.name()),
    };
    line("Artifact", &artifact);
    match (inspection.kind(), inspection.counts()) {
        (ArtifactKind::Directory, Some(counts)) => {
            line(
                "Kind",
                &format!(
                    "directory: {}, {}, {}",
                    plural(counts.files, "file", "files"),
                    plural(counts.directories, "subdirectory", "subdirectories"),
                    plural(counts.symlinks, "symbolic link", "symbolic links"),
                ),
            );
            line(
                "Size",
                &format!(
                    "{} in regular files",
                    plural(inspection.size(), "byte", "bytes")
                ),
            );
        }
        (kind, _) => {
            line("Kind", kind_name(kind));
            line("Size", &plural(inspection.size(), "byte", "bytes"));
        }
    }
    if let Some(format) = inspection.format() {
        line(
            "Format",
            &format!("{} (detected from header bytes only)", describe(format)),
        );
    }
    match inspection.digests() {
        ArtifactDigests::Content(digests) => {
            for digest in digests.iter() {
                line(digest.algorithm().name(), &digest.to_hex());
            }
        }
        ArtifactDigests::Tree(digests) => {
            for digest in digests.iter() {
                line(digest.algorithm().tree_name(), &digest.to_hex());
            }
        }
    }
    if let Some(metadata) = inspection.untrusted_metadata() {
        if let Some(mode) = metadata.mode {
            line("Mode", &format!("{mode:04o} {UNVERIFIED_METADATA}"));
        }
        if let Some(modified) = metadata.modified_rfc3339() {
            line("Modified", &format!("{modified} {UNVERIFIED_METADATA}"));
        }
    }
    if inspection.root_symlink_followed() {
        line("Note", "the path is a symbolic link; it was followed once");
    }

    if let Some(entries) = inspection.entries() {
        let leaving: Vec<String> = entries
            .iter()
            .filter_map(|entry| match entry.kind() {
                EntryKind::Symlink {
                    target,
                    target_leaves_tree: true,
                } => Some(format!(
                    "  {} -> {}",
                    sanitize(entry.path().as_str()),
                    sanitize(target)
                )),
                _ => None,
            })
            .collect();
        if !leaving.is_empty() {
            out.push_str(
                "\nSymbolic links are recorded, never followed. These point outside the tree:\n",
            );
            for link in leaving {
                out.push_str(&link);
                out.push('\n');
            }
        }
        out.push_str("\nPer-entry details: --format json\n");
    } else {
        out.push('\n');
    }
    out.push_str(CLOSING);
    out.push('\n');
    out
}

fn kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::File => "file",
        ArtifactKind::Directory => "directory",
        ArtifactKind::Stream => "stream",
        _ => "other",
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn endian(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little-endian",
        Endianness::Big => "big-endian",
    }
}

fn named(name: Option<&str>, prefix: &str, code: impl std::fmt::LowerHex) -> String {
    name.map_or_else(|| format!("{prefix} 0x{code:x}"), str::to_owned)
}

fn describe(format: &FileFormat) -> String {
    match format {
        FileFormat::Elf(h) => format!(
            "ELF {}-bit {} {}, {}",
            h.bits,
            endian(h.endianness),
            match h.object_type {
                // ET_DYN: shared libraries, and position-independent executables.
                Some("shared-object") =>
                    "shared object or position-independent executable".to_owned(),
                other => named(other, "type", h.object_type_code),
            },
            named(h.machine, "machine", h.machine_code),
        ),
        FileFormat::MachO(h) => format!(
            "Mach-O {}-bit {} {}, {}",
            h.bits,
            endian(h.endianness),
            named(h.file_type, "type", h.file_type_code),
            named(h.cpu, "cpu", h.cpu_type),
        ),
        FileFormat::MachOUniversal(h) => {
            let archs: Vec<String> = h
                .architectures
                .iter()
                .map(|a| named(a.cpu, "cpu", a.cpu_type))
                .collect();
            format!("Mach-O universal binary: {}", archs.join(", "))
        }
        FileFormat::Pe(h) => format!(
            "PE {} {}, {}",
            h.optional_header.unwrap_or("(unknown optional header)"),
            if h.dll { "DLL" } else { "executable" },
            named(h.machine, "machine", h.machine_code),
        ),
        FileFormat::Wasm(h) => format!(
            "WebAssembly {} (version {})",
            if h.layer == 1 { "component" } else { "module" },
            h.version
        ),
        FileFormat::Tar => "tar archive".into(),
        FileFormat::Zip => "zip archive".into(),
        FileFormat::Ar => "ar archive".into(),
        FileFormat::SevenZip => "7z archive".into(),
        FileFormat::Gzip => "gzip-compressed data".into(),
        FileFormat::Xz => "xz-compressed data".into(),
        FileFormat::Zstd => "Zstandard-compressed data".into(),
        FileFormat::Bzip2 => "bzip2-compressed data".into(),
        FileFormat::Unknown => "unknown".into(),
        _ => "other".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustforge_core::format::detect_format;

    #[test]
    fn formats_are_described_for_people() {
        let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
        elf.resize(16, 0);
        elf.extend(3u16.to_le_bytes());
        elf.extend(62u16.to_le_bytes());
        assert_eq!(
            describe(&detect_format(&elf)),
            "ELF 64-bit little-endian shared object or position-independent executable, x86_64"
        );
        assert_eq!(
            describe(&detect_format(b"\x1f\x8b\x08")),
            "gzip-compressed data"
        );
        assert_eq!(
            describe(&detect_format(b"\0asm\x01\0\0\0")),
            "WebAssembly module (version 1)"
        );
    }

    #[test]
    fn json_escapes_what_serde_json_leaves_raw_without_changing_values() {
        let raw = "{\n  \"name\": \"x\u{7f}\u{9b}31m\u{202e}\u{2028}y\\u001b\"\n}";
        let escaped = escape_for_terminal(raw);
        assert_eq!(
            escaped,
            "{\n  \"name\": \"x\\u007f\\u009b31m\\u202e\\u2028y\\u001b\"\n}"
        );
        let before: serde_json::Value = serde_json::from_str(raw).unwrap();
        let after: serde_json::Value = serde_json::from_str(&escaped).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn counts_are_pluralized() {
        assert_eq!(plural(1, "file", "files"), "1 file");
        assert_eq!(plural(0, "file", "files"), "0 files");
        assert_eq!(plural(2, "byte", "bytes"), "2 bytes");
    }
}
