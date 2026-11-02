//! CorOS VFS Module: `mime_registry`
//!
//! Magic-byte file signature inspector & filename extension classifier supporting
//! ELF64 binaries, PE32+/UEFI executables, BMP, PNG, RIFF/WAV audio, POSIX ustar TAR,
//! SVR4 CPIO, GZIP archives, shebang (`#!`) shell scripts, Rust sources, and UTF-8 text.

/// Broad content category used by VFS security and desktop shell handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentCategory {
    ExecutableBinary,
    ArchiveImage,
    RasterGraphics,
    DigitalAudio,
    SourceOrScript,
    PlainText,
    OctetStream,
}

/// Complete MIME classification descriptor returned by `inspect_file_content`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MimeDescriptor {
    pub mime_type: &'static str,
    pub category: ContentCategory,
    pub description: &'static str,
}

pub const MIME_ELF: MimeDescriptor = MimeDescriptor {
    mime_type: "application/x-executable",
    category: ContentCategory::ExecutableBinary,
    description: "ELF 64-bit LSB executable/shared object",
};

pub const MIME_UEFI_PE: MimeDescriptor = MimeDescriptor {
    mime_type: "application/vnd.microsoft.portable-executable",
    category: ContentCategory::ExecutableBinary,
    description: "PE32+ / UEFI application image (MZ)",
};

pub const MIME_PNG: MimeDescriptor = MimeDescriptor {
    mime_type: "image/png",
    category: ContentCategory::RasterGraphics,
    description: "PNG raster image data",
};

pub const MIME_BMP: MimeDescriptor = MimeDescriptor {
    mime_type: "image/bmp",
    category: ContentCategory::RasterGraphics,
    description: "PC bitmap (BMP) raster image",
};

pub const MIME_WAV: MimeDescriptor = MimeDescriptor {
    mime_type: "audio/wav",
    category: ContentCategory::DigitalAudio,
    description: "RIFF WAVE PCM audio stream",
};

pub const MIME_GZIP: MimeDescriptor = MimeDescriptor {
    mime_type: "application/gzip",
    category: ContentCategory::ArchiveImage,
    description: "gzip compressed archive (RFC 1952)",
};

pub const MIME_CPIO: MimeDescriptor = MimeDescriptor {
    mime_type: "application/x-cpio",
    category: ContentCategory::ArchiveImage,
    description: "SVR4 portable CPIO initramfs archive",
};

pub const MIME_TAR: MimeDescriptor = MimeDescriptor {
    mime_type: "application/x-tar",
    category: ContentCategory::ArchiveImage,
    description: "POSIX ustar tape archive",
};

pub const MIME_SHELL: MimeDescriptor = MimeDescriptor {
    mime_type: "text/x-shellscript",
    category: ContentCategory::SourceOrScript,
    description: "POSIX shell script executable",
};

pub const MIME_RUST: MimeDescriptor = MimeDescriptor {
    mime_type: "text/x-rust",
    category: ContentCategory::SourceOrScript,
    description: "Rust source code module",
};

pub const MIME_TOML: MimeDescriptor = MimeDescriptor {
    mime_type: "application/toml",
    category: ContentCategory::PlainText,
    description: "TOML configuration document",
};

pub const MIME_UTF8_TEXT: MimeDescriptor = MimeDescriptor {
    mime_type: "text/plain; charset=utf-8",
    category: ContentCategory::PlainText,
    description: "UTF-8 plain text document",
};

pub const MIME_OCTET_STREAM: MimeDescriptor = MimeDescriptor {
    mime_type: "application/octet-stream",
    category: ContentCategory::OctetStream,
    description: "Raw binary data stream",
};

/// Inspects the leading magic bytes of a file buffer to identify its binary or script signature.
pub fn sniff_magic_bytes(header: &[u8]) -> Option<MimeDescriptor> {
    // 1. ELF (\x7FELF)
    if header.len() >= 4 && header[0..4] == [0x7F, b'E', b'L', b'F'] {
        return Some(MIME_ELF);
    }

    // 2. PNG (\x89PNG\r\n\x1A\n)
    if header.len() >= 8 && header[0..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(MIME_PNG);
    }

    // 3. RIFF....WAVE
    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WAVE" {
        return Some(MIME_WAV);
    }

    // 4. SVR4 CPIO ("070701" or "070702")
    if header.len() >= 6 && (&header[0..6] == b"070701" || &header[0..6] == b"070702") {
        return Some(MIME_CPIO);
    }

    // 5. POSIX ustar TAR ("ustar" at byte offset 257)
    if header.len() >= 262 && &header[257..262] == b"ustar" {
        return Some(MIME_TAR);
    }

    // 6. GZIP (\x1F\x8B\x08)
    if header.len() >= 3 && header[0] == 0x1F && header[1] == 0x8B && header[2] == 0x08 {
        return Some(MIME_GZIP);
    }

    // 7. PE32+ / MZ Dos Header ("MZ")
    if header.len() >= 2 && &header[0..2] == b"MZ" {
        return Some(MIME_UEFI_PE);
    }

    // 8. BMP ("BM")
    if header.len() >= 2 && &header[0..2] == b"BM" {
        return Some(MIME_BMP);
    }

    // 9. Shebang script ("#!")
    if header.len() >= 2 && &header[0..2] == b"#!" {
        return Some(MIME_SHELL);
    }

    None
}

/// Classifies a filename by its case-insensitive extension.
pub fn classify_by_extension(filename: &str) -> Option<MimeDescriptor> {
    let dot_idx = filename.rfind('.')?;
    let ext = &filename[dot_idx + 1..];

    if ext.eq_ignore_ascii_case("elf") || ext.eq_ignore_ascii_case("so") {
        Some(MIME_ELF)
    } else if ext.eq_ignore_ascii_case("efi") || ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll") {
        Some(MIME_UEFI_PE)
    } else if ext.eq_ignore_ascii_case("png") {
        Some(MIME_PNG)
    } else if ext.eq_ignore_ascii_case("bmp") {
        Some(MIME_BMP)
    } else if ext.eq_ignore_ascii_case("wav") {
        Some(MIME_WAV)
    } else if ext.eq_ignore_ascii_case("gz") || ext.eq_ignore_ascii_case("tgz") {
        Some(MIME_GZIP)
    } else if ext.eq_ignore_ascii_case("cpio") {
        Some(MIME_CPIO)
    } else if ext.eq_ignore_ascii_case("tar") {
        Some(MIME_TAR)
    } else if ext.eq_ignore_ascii_case("sh") {
        Some(MIME_SHELL)
    } else if ext.eq_ignore_ascii_case("rs") {
        Some(MIME_RUST)
    } else if ext.eq_ignore_ascii_case("toml") {
        Some(MIME_TOML)
    } else if ext.eq_ignore_ascii_case("txt") || ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("conf") {
        Some(MIME_UTF8_TEXT)
    } else {
        None
    }
}

/// Returns true if `sample` is valid printable UTF-8 text without binary control bytes (NUL, etc.).
pub fn is_printable_utf8_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }
    if sample.iter().any(|&b| b == 0x00 || (b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')) {
        return false;
    }
    core::str::from_utf8(sample).is_ok()
}

/// Combined MIME inspector: prioritizes magic-byte signatures, then filename extensions, then UTF-8 text heuristics.
pub fn inspect_file_content(filename: &str, sample: &[u8]) -> MimeDescriptor {
    if let Some(magic_desc) = sniff_magic_bytes(sample) {
        return magic_desc;
    }
    if let Some(ext_desc) = classify_by_extension(filename) {
        return ext_desc;
    }
    if is_printable_utf8_text(sample) {
        MIME_UTF8_TEXT
    } else {
        MIME_OCTET_STREAM
    }
}

/// Self-test suite for `mime_registry`.
pub fn verify_vfs_mime_registry() -> u32 {
    let mut passed = 0u32;

    if inspect_file_content("unknown.bin", b"\x7FELF\x02\x01\x01\x00") == MIME_ELF {
        passed += 1;
    }

    if inspect_file_content("BOOTX64.EFI", b"MZ\x90\x00\x03\x00") == MIME_UEFI_PE {
        passed += 1;
    }

    if inspect_file_content("splash.img", b"\x89PNG\r\n\x1A\n\x00\x00") == MIME_PNG {
        passed += 1;
    }

    if inspect_file_content("boot_chime.bin", b"RIFF\x24\x80\x00\x00WAVEfmt ") == MIME_WAV {
        passed += 1;
    }

    if inspect_file_content("lib.rs", b"#![no_std]\npub fn init() {}\n") == MIME_RUST {
        passed += 1;
    }

    if inspect_file_content("README", b"CorOS Virtual File System Documentation\n") == MIME_UTF8_TEXT {
        passed += 1;
    }

    passed
}
