//! File format detection from header bytes.
//!
//! Only fixed-offset header fields are read, from the first [`HEAD_LEN`]
//! bytes captured while the file is hashed; the file is never read a second
//! time. Nothing is executed, and no external tool is run (`ldd` can execute
//! the binary it inspects; `file` and binutils are not used either).
//!
//! The result describes what the header *claims*. It is not validated, and a
//! file can be valid in several formats at once, so it is informational only.

use serde::Serialize;

/// Number of leading bytes examined.
pub const HEAD_LEN: usize = 4096;

/// A detected file format.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum FileFormat {
    /// An ELF object file, executable or shared object.
    Elf(ElfHeader),
    /// A Mach-O object file, executable or library.
    MachO(MachOHeader),
    /// A universal ("fat") Mach-O file containing one binary per architecture.
    MachOUniversal(UniversalHeader),
    /// A PE/COFF executable or DLL.
    Pe(PeHeader),
    /// A WebAssembly binary.
    Wasm(WasmHeader),
    /// A tar archive (POSIX ustar or GNU).
    Tar,
    /// A zip archive (also jar, wheel, apk, …).
    Zip,
    /// A Unix `ar` archive: static libraries, Rust `.rlib` files, Debian packages.
    Ar,
    /// A 7z archive.
    #[serde(rename = "7z")]
    SevenZip,
    /// gzip-compressed data.
    Gzip,
    /// xz-compressed data.
    Xz,
    /// Zstandard-compressed data.
    Zstd,
    /// bzip2-compressed data.
    Bzip2,
    /// None of the formats above.
    Unknown,
}

/// Byte order declared by a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

/// Fields of an ELF identification and header.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfHeader {
    /// 32 or 64.
    pub bits: u8,
    /// Byte order.
    pub endianness: Endianness,
    /// `relocatable`, `executable`, `shared-object` (which includes
    /// position-independent executables) or `core`, if the type is one of these.
    pub object_type: Option<&'static str>,
    /// The raw `e_type` value.
    pub object_type_code: u16,
    /// The architecture, named like Rust's `target_arch`, if known.
    pub machine: Option<&'static str>,
    /// The raw `e_machine` value.
    pub machine_code: u16,
    /// The raw `EI_OSABI` value.
    pub os_abi: u8,
}

/// Fields of a Mach-O header.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachOHeader {
    /// 32 or 64.
    pub bits: u8,
    /// Byte order.
    pub endianness: Endianness,
    /// The architecture, named like Rust's `target_arch`, if known.
    pub cpu: Option<&'static str>,
    /// The raw `cputype` value.
    pub cpu_type: u32,
    /// `object`, `executable`, `core`, `dylib`, `dylinker`, `bundle`, `dsym`
    /// or `kext-bundle`, if the type is one of these.
    pub file_type: Option<&'static str>,
    /// The raw `filetype` value.
    pub file_type_code: u32,
}

/// The architecture list of a universal Mach-O file.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UniversalHeader {
    /// One entry per contained binary, in header order.
    pub architectures: Vec<UniversalArch>,
}

/// One architecture of a universal Mach-O file.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalArch {
    /// The architecture, named like Rust's `target_arch`, if known.
    pub cpu: Option<&'static str>,
    /// The raw `cputype` value.
    pub cpu_type: u32,
}

/// Fields of a PE/COFF header.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeHeader {
    /// The architecture, named like Rust's `target_arch`, if known.
    pub machine: Option<&'static str>,
    /// The raw COFF `Machine` value.
    pub machine_code: u16,
    /// `pe32` or `pe32+`, from the optional header's magic, if recognized.
    pub optional_header: Option<&'static str>,
    /// Whether the COFF characteristics mark the file as a DLL.
    pub dll: bool,
}

/// Fields of a WebAssembly preamble.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WasmHeader {
    /// The binary format version.
    pub version: u16,
    /// 0 for a core module, 1 for a component.
    pub layer: u16,
}

/// Detects the format of a file from its first bytes. Never panics, whatever
/// `head` contains; anything unrecognized or truncated is
/// [`FileFormat::Unknown`].
pub fn detect_format(head: &[u8]) -> FileFormat {
    elf(head)
        .or_else(|| mach_o(head))
        .or_else(|| universal(head))
        .or_else(|| pe(head))
        .or_else(|| wasm(head))
        .or_else(|| magic(head))
        .unwrap_or(FileFormat::Unknown)
}

fn bytes<const N: usize>(head: &[u8], at: usize) -> Option<[u8; N]> {
    head.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u16_at(head: &[u8], at: usize, e: Endianness) -> Option<u16> {
    let b = bytes::<2>(head, at)?;
    Some(match e {
        Endianness::Little => u16::from_le_bytes(b),
        Endianness::Big => u16::from_be_bytes(b),
    })
}

fn u32_at(head: &[u8], at: usize, e: Endianness) -> Option<u32> {
    let b = bytes::<4>(head, at)?;
    Some(match e {
        Endianness::Little => u32::from_le_bytes(b),
        Endianness::Big => u32::from_be_bytes(b),
    })
}

fn elf(head: &[u8]) -> Option<FileFormat> {
    if bytes::<4>(head, 0)? != *b"\x7fELF" {
        return None;
    }
    let bits = match head.get(4)? {
        1 => 32,
        2 => 64,
        _ => return None,
    };
    let endianness = match head.get(5)? {
        1 => Endianness::Little,
        2 => Endianness::Big,
        _ => return None,
    };
    let object_type_code = u16_at(head, 16, endianness)?;
    let machine_code = u16_at(head, 18, endianness)?;
    Some(FileFormat::Elf(ElfHeader {
        bits,
        endianness,
        object_type: match object_type_code {
            1 => Some("relocatable"),
            2 => Some("executable"),
            3 => Some("shared-object"),
            4 => Some("core"),
            _ => None,
        },
        object_type_code,
        machine: elf_machine(machine_code, bits),
        machine_code,
        os_abi: *head.get(7)?,
    }))
}

fn elf_machine(code: u16, bits: u8) -> Option<&'static str> {
    let wide = bits == 64;
    Some(match code {
        2 => "sparc",
        3 => "x86",
        8 if wide => "mips64",
        8 => "mips",
        20 => "powerpc",
        21 => "powerpc64",
        22 if wide => "s390x",
        40 => "arm",
        43 => "sparc64",
        62 => "x86_64",
        183 => "aarch64",
        243 if wide => "riscv64",
        243 => "riscv32",
        247 => "bpf",
        258 if wide => "loongarch64",
        258 => "loongarch32",
        _ => return None,
    })
}

fn mach_o(head: &[u8]) -> Option<FileFormat> {
    let (bits, endianness) = match bytes::<4>(head, 0)? {
        [0xce, 0xfa, 0xed, 0xfe] => (32, Endianness::Little),
        [0xfe, 0xed, 0xfa, 0xce] => (32, Endianness::Big),
        [0xcf, 0xfa, 0xed, 0xfe] => (64, Endianness::Little),
        [0xfe, 0xed, 0xfa, 0xcf] => (64, Endianness::Big),
        _ => return None,
    };
    let cpu_type = u32_at(head, 4, endianness)?;
    let file_type_code = u32_at(head, 12, endianness)?;
    Some(FileFormat::MachO(MachOHeader {
        bits,
        endianness,
        cpu: mach_o_cpu(cpu_type),
        cpu_type,
        file_type: match file_type_code {
            1 => Some("object"),
            2 => Some("executable"),
            4 => Some("core"),
            6 => Some("dylib"),
            7 => Some("dylinker"),
            8 => Some("bundle"),
            10 => Some("dsym"),
            11 => Some("kext-bundle"),
            _ => None,
        },
        file_type_code,
    }))
}

fn mach_o_cpu(cpu_type: u32) -> Option<&'static str> {
    Some(match cpu_type {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "aarch64",
        0x0200_000c => "arm64_32",
        18 => "powerpc",
        0x0100_0012 => "powerpc64",
        _ => return None,
    })
}

/// Universal binaries share the magic `CAFEBABE` with Java class files. As in
/// Apple's tools, an architecture count below 20 means a universal binary: a
/// class file has its version there, and every Java version is at least 45.
const MAX_UNIVERSAL_ARCHS: u32 = 20;

fn universal(head: &[u8]) -> Option<FileFormat> {
    let entry_len = match bytes::<4>(head, 0)? {
        [0xca, 0xfe, 0xba, 0xbe] => 20,
        [0xca, 0xfe, 0xba, 0xbf] => 32,
        _ => return None,
    };
    let count = u32_at(head, 4, Endianness::Big)?;
    if count == 0 || count >= MAX_UNIVERSAL_ARCHS {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    // The whole architecture table must be present.
    head.get(8..count.checked_mul(entry_len)?.checked_add(8)?)?;
    let architectures = (0..count)
        .map(|i| {
            let at = i.checked_mul(entry_len)?.checked_add(8)?;
            let cpu_type = u32_at(head, at, Endianness::Big)?;
            Some(UniversalArch {
                cpu: mach_o_cpu(cpu_type),
                cpu_type,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(FileFormat::MachOUniversal(UniversalHeader {
        architectures,
    }))
}

fn pe(head: &[u8]) -> Option<FileFormat> {
    if bytes::<2>(head, 0)? != *b"MZ" {
        return None;
    }
    let pe_at = usize::try_from(u32_at(head, 0x3c, Endianness::Little)?).ok()?;
    if bytes::<4>(head, pe_at)? != *b"PE\0\0" {
        return None;
    }
    let coff_at = pe_at.checked_add(4)?;
    let machine_code = u16_at(head, coff_at, Endianness::Little)?;
    let characteristics = u16_at(head, coff_at.checked_add(18)?, Endianness::Little)?;
    let optional_magic = u16_at(head, coff_at.checked_add(20)?, Endianness::Little)?;
    Some(FileFormat::Pe(PeHeader {
        machine: match machine_code {
            0x014c => Some("x86"),
            0x8664 => Some("x86_64"),
            0xaa64 => Some("aarch64"),
            0x01c0 | 0x01c4 => Some("arm"),
            0xa641 => Some("arm64ec"),
            0x5032 => Some("riscv32"),
            0x5064 => Some("riscv64"),
            0x6264 => Some("loongarch64"),
            _ => None,
        },
        machine_code,
        optional_header: match optional_magic {
            0x10b => Some("pe32"),
            0x20b => Some("pe32+"),
            _ => None,
        },
        dll: characteristics & 0x2000 != 0,
    }))
}

fn wasm(head: &[u8]) -> Option<FileFormat> {
    if bytes::<4>(head, 0)? != *b"\0asm" {
        return None;
    }
    Some(FileFormat::Wasm(WasmHeader {
        version: u16_at(head, 4, Endianness::Little)?,
        layer: u16_at(head, 6, Endianness::Little)?,
    }))
}

fn magic(head: &[u8]) -> Option<FileFormat> {
    let starts = |m: &[u8]| head.starts_with(m);
    let format = if starts(b"\x1f\x8b") {
        FileFormat::Gzip
    } else if starts(b"\xfd7zXZ\0") {
        FileFormat::Xz
    } else if starts(b"\x28\xb5\x2f\xfd") {
        FileFormat::Zstd
    } else if starts(b"BZh") && head.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        FileFormat::Bzip2
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        FileFormat::Zip
    } else if starts(b"7z\xbc\xaf\x27\x1c") {
        FileFormat::SevenZip
    } else if starts(b"!<arch>\n") {
        FileFormat::Ar
    } else if head.get(257..262) == Some(b"ustar") {
        FileFormat::Tar
    } else {
        return None;
    };
    Some(format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn elf_header(class: u8, data: u8, e_type: u16, machine: u16) -> Vec<u8> {
        let mut h = vec![0x7f, b'E', b'L', b'F', class, data, 1, 3];
        h.resize(16, 0);
        if data == 2 {
            h.extend(e_type.to_be_bytes());
            h.extend(machine.to_be_bytes());
        } else {
            h.extend(e_type.to_le_bytes());
            h.extend(machine.to_le_bytes());
        }
        h.resize(64, 0);
        h
    }

    #[test]
    fn elf_executables_and_libraries() {
        let FileFormat::Elf(h) = detect_format(&elf_header(2, 1, 3, 62)) else {
            panic!("not ELF")
        };
        assert_eq!((h.bits, h.endianness), (64, Endianness::Little));
        assert_eq!(
            (h.object_type, h.machine, h.os_abi),
            (Some("shared-object"), Some("x86_64"), 3)
        );

        let FileFormat::Elf(h) = detect_format(&elf_header(1, 2, 2, 8)) else {
            panic!("not ELF")
        };
        assert_eq!((h.bits, h.endianness), (32, Endianness::Big));
        assert_eq!(
            (h.object_type, h.machine),
            (Some("executable"), Some("mips"))
        );

        let FileFormat::Elf(h) = detect_format(&elf_header(2, 1, 0xfe00, 0x1234)) else {
            panic!("not ELF")
        };
        assert_eq!((h.object_type, h.object_type_code), (None, 0xfe00));
        assert_eq!((h.machine, h.machine_code), (None, 0x1234));
    }

    #[test]
    fn elf_with_invalid_identification_is_unknown() {
        assert_eq!(detect_format(&elf_header(3, 1, 2, 62)), FileFormat::Unknown);
        assert_eq!(detect_format(&elf_header(2, 0, 2, 62)), FileFormat::Unknown);
    }

    #[test]
    fn mach_o_in_both_byte_orders() {
        let mut le = vec![0xcf, 0xfa, 0xed, 0xfe];
        le.extend(0x0100_000c_u32.to_le_bytes());
        le.extend(0_u32.to_le_bytes());
        le.extend(2_u32.to_le_bytes());
        let FileFormat::MachO(h) = detect_format(&le) else {
            panic!("not Mach-O")
        };
        assert_eq!(
            (h.bits, h.endianness, h.cpu, h.file_type),
            (64, Endianness::Little, Some("aarch64"), Some("executable"))
        );

        let mut be = vec![0xfe, 0xed, 0xfa, 0xce];
        be.extend(18_u32.to_be_bytes());
        be.extend(0_u32.to_be_bytes());
        be.extend(6_u32.to_be_bytes());
        let FileFormat::MachO(h) = detect_format(&be) else {
            panic!("not Mach-O")
        };
        assert_eq!(
            (h.bits, h.endianness, h.cpu, h.file_type),
            (32, Endianness::Big, Some("powerpc"), Some("dylib"))
        );
    }

    #[test]
    fn universal_binaries_are_told_apart_from_java_classes() {
        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe];
        fat.extend(2_u32.to_be_bytes());
        for cpu in [0x0100_0007_u32, 0x0100_000c] {
            fat.extend(cpu.to_be_bytes());
            fat.extend([0; 16]);
        }
        let FileFormat::MachOUniversal(h) = detect_format(&fat) else {
            panic!("not universal")
        };
        let cpus: Vec<_> = h.architectures.iter().map(|a| a.cpu).collect();
        assert_eq!(cpus, [Some("x86_64"), Some("aarch64")]);

        // A Java class file: minor version 0, major version 65 (Java 21).
        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65, 0, 0];
        assert_eq!(detect_format(&class), FileFormat::Unknown);
        // A universal header that promises more entries than are present.
        assert_eq!(detect_format(&fat[..fat.len() - 1]), FileFormat::Unknown);
    }

    fn pe_file(pe_at: u32, machine: u16, characteristics: u16, magic: u16) -> Vec<u8> {
        let mut h = vec![0; 0x40];
        h[..2].copy_from_slice(b"MZ");
        h[0x3c..0x40].copy_from_slice(&pe_at.to_le_bytes());
        h.resize(pe_at as usize, 0);
        h.extend(b"PE\0\0");
        h.extend(machine.to_le_bytes());
        h.extend([0; 16]);
        h.extend(characteristics.to_le_bytes());
        h.extend(magic.to_le_bytes());
        h
    }

    #[test]
    fn pe_machine_kind_and_dll_flag() {
        let FileFormat::Pe(h) = detect_format(&pe_file(0x80, 0x8664, 0x0022, 0x20b)) else {
            panic!("not PE")
        };
        assert_eq!(
            (h.machine, h.optional_header, h.dll),
            (Some("x86_64"), Some("pe32+"), false)
        );
        let FileFormat::Pe(h) = detect_format(&pe_file(0x40, 0xaa64, 0x2022, 0x10b)) else {
            panic!("not PE")
        };
        assert_eq!(
            (h.machine, h.optional_header, h.dll),
            (Some("aarch64"), Some("pe32"), true)
        );
    }

    #[test]
    fn pe_offsets_outside_the_header_are_unknown() {
        let mut far = pe_file(0x80, 0x8664, 0, 0x20b);
        far[0x3c..0x40].copy_from_slice(&0xffff_fff0_u32.to_le_bytes());
        assert_eq!(detect_format(&far), FileFormat::Unknown);
        let mut beyond = pe_file(0x80, 0x8664, 0, 0x20b);
        beyond[0x3c..0x40].copy_from_slice(&(HEAD_LEN as u32).to_le_bytes());
        assert_eq!(detect_format(&beyond), FileFormat::Unknown);
        // A DOS executable without a PE header.
        assert_eq!(detect_format(b"MZ\x90\x00"), FileFormat::Unknown);
    }

    #[test]
    fn wasm_modules_and_components() {
        assert_eq!(
            detect_format(b"\0asm\x01\0\0\0"),
            FileFormat::Wasm(WasmHeader {
                version: 1,
                layer: 0
            })
        );
        assert_eq!(
            detect_format(b"\0asm\x0d\0\x01\0"),
            FileFormat::Wasm(WasmHeader {
                version: 13,
                layer: 1
            })
        );
    }

    #[test]
    fn archives_and_compressed_data() {
        let mut tar = vec![0; 512];
        tar[257..263].copy_from_slice(b"ustar\0");
        let cases: [(&[u8], FileFormat); 10] = [
            (b"\x1f\x8b\x08\0", FileFormat::Gzip),
            (b"\xfd7zXZ\0\0", FileFormat::Xz),
            (b"\x28\xb5\x2f\xfd\0", FileFormat::Zstd),
            (b"BZh9\x31", FileFormat::Bzip2),
            (b"PK\x03\x04\x14\0", FileFormat::Zip),
            (b"PK\x05\x06", FileFormat::Zip),
            (b"7z\xbc\xaf\x27\x1c\0\x04", FileFormat::SevenZip),
            (b"!<arch>\ndebian-binary", FileFormat::Ar),
            (&tar, FileFormat::Tar),
            (b"BZh0", FileFormat::Unknown),
        ];
        for (head, expected) in cases {
            assert_eq!(detect_format(head), expected, "{head:x?}");
        }
    }

    #[test]
    fn every_truncation_of_a_valid_header_is_safe() {
        let mut tar = vec![0; 512];
        tar[257..262].copy_from_slice(b"ustar");
        let samples = [
            elf_header(2, 1, 2, 62),
            pe_file(0x80, 0x8664, 0, 0x20b),
            b"\xcf\xfa\xed\xfe\x07\0\0\x01\0\0\0\0\x02\0\0\0".to_vec(),
            tar,
        ];
        for sample in samples {
            for len in 0..=sample.len() {
                let _ = detect_format(&sample[..len]);
            }
        }
    }

    #[test]
    fn format_serializes_with_a_type_tag() {
        let json = serde_json::to_value(detect_format(&elf_header(2, 1, 2, 62))).unwrap();
        assert_eq!(json["type"], "elf");
        assert_eq!(json["machine"], "x86_64");
        assert_eq!(json["objectType"], "executable");
        assert_eq!(
            serde_json::to_value(FileFormat::SevenZip).unwrap()["type"],
            "7z"
        );
        assert_eq!(
            serde_json::to_value(FileFormat::Unknown).unwrap()["type"],
            "unknown"
        );
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(head in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = detect_format(&head);
        }

        /// Arbitrary bytes behind every recognized magic number still never panic.
        #[test]
        fn arbitrary_bytes_after_known_magic_never_panic(
            magic in prop::sample::select(vec![
                &b"\x7fELF"[..], b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe",
                b"\xca\xfe\xba\xbf", b"MZ", b"\0asm",
            ]),
            tail in proptest::collection::vec(any::<u8>(), 0..600),
        ) {
            let mut head = magic.to_vec();
            head.extend(tail);
            let _ = detect_format(&head);
        }
    }
}
