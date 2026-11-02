//! CorOS VFS Module: `initramfs_cpio`
//!
//! Real SVR4/newc (`"070701"` / `"070702"`) CPIO initial RAM filesystem archive parser
//! (`CpioNewcHeader`, 8-digit ASCII hexadecimal field decoder, 4-byte pathname and
//! file payload padding alignment calculator, `"TRAILER!!!"` sentinel handler, and
//! archive builder/extractor).

use alloc::vec::Vec;

/// SVR4 portable CPIO magic without CRC (`"070701"`).
pub const CPIO_MAGIC_NEWC: &[u8; 6] = b"070701";
/// SVR4 portable CPIO magic with CRC (`"070702"`).
pub const CPIO_MAGIC_CRC: &[u8; 6] = b"070702";
/// End-of-archive sentinel filename (`"TRAILER!!!"`).
pub const CPIO_TRAILER_NAME: &str = "TRAILER!!!";
/// Fixed byte size of the SVR4 ASCII CPIO header.
pub const CPIO_HEADER_SIZE: usize = 110;

/// Parsed 110-byte SVR4 `newc` CPIO header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpioNewcHeader {
    pub has_crc: bool,
    pub ino: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub filesize: u32,
    pub devmajor: u32,
    pub devminor: u32,
    pub rdevmajor: u32,
    pub rdevminor: u32,
    pub namesize: u32,
    pub check: u32,
}

/// Extracted entry from an `initramfs` CPIO archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpioArchiveEntry<'a> {
    pub header: CpioNewcHeader,
    pub path: &'a str,
    pub data: &'a [u8],
}

/// Errors returned while decoding a CPIO archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpioError {
    TruncatedHeader,
    InvalidMagic,
    InvalidHexField,
    InvalidPathEncoding,
    TruncatedEntryData,
}

/// Decodes an 8-byte ASCII hexadecimal field (e.g. `b"000081A4"`) into a `u32`.
pub fn parse_hex_u32(bytes8: &[u8]) -> Result<u32, CpioError> {
    if bytes8.len() != 8 {
        return Err(CpioError::InvalidHexField);
    }
    let mut val = 0u32;
    for &b in bytes8 {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return Err(CpioError::InvalidHexField),
        };
        val = (val << 4) | digit;
    }
    Ok(val)
}

/// Aligns an offset upward to the next 4-byte boundary as required by SVR4 `newc` CPIO.
#[inline]
pub const fn align4_up(offset: usize) -> usize {
    (offset + 3) & !3
}

impl CpioNewcHeader {
    /// Parses a 110-byte SVR4 `newc` header slice.
    pub fn decode(raw: &[u8]) -> Result<Self, CpioError> {
        if raw.len() < CPIO_HEADER_SIZE {
            return Err(CpioError::TruncatedHeader);
        }

        let magic = &raw[0..6];
        let has_crc = if magic == CPIO_MAGIC_NEWC {
            false
        } else if magic == CPIO_MAGIC_CRC {
            true
        } else {
            return Err(CpioError::InvalidMagic);
        };

        Ok(Self {
            has_crc,
            ino: parse_hex_u32(&raw[6..14])?,
            mode: parse_hex_u32(&raw[14..22])?,
            uid: parse_hex_u32(&raw[22..30])?,
            gid: parse_hex_u32(&raw[30..38])?,
            nlink: parse_hex_u32(&raw[38..46])?,
            mtime: parse_hex_u32(&raw[46..54])?,
            filesize: parse_hex_u32(&raw[54..62])?,
            devmajor: parse_hex_u32(&raw[62..70])?,
            devminor: parse_hex_u32(&raw[70..78])?,
            rdevmajor: parse_hex_u32(&raw[78..86])?,
            rdevminor: parse_hex_u32(&raw[86..94])?,
            namesize: parse_hex_u32(&raw[94..102])?,
            check: parse_hex_u32(&raw[102..110])?,
        })
    }
}

/// Parses an entire SVR4 `newc` CPIO archive buffer into a vector of entries, stopping at `"TRAILER!!!"`.
pub fn parse_cpio_archive<'a>(archive: &'a [u8]) -> Result<Vec<CpioArchiveEntry<'a>>, CpioError> {
    let mut entries = Vec::new();
    let mut cursor = 0usize;

    while cursor + CPIO_HEADER_SIZE <= archive.len() {
        let header = CpioNewcHeader::decode(&archive[cursor..cursor + CPIO_HEADER_SIZE])?;
        let name_start = cursor + CPIO_HEADER_SIZE;
        let namesize = header.namesize as usize;
        if namesize == 0 || name_start + namesize > archive.len() {
            return Err(CpioError::TruncatedEntryData);
        }

        // Strip trailing NUL byte(s) from pathname
        let raw_name = &archive[name_start..name_start + namesize];
        let clean_len = raw_name.iter().position(|&b| b == 0).unwrap_or(raw_name.len());
        let path = core::str::from_utf8(&raw_name[..clean_len]).map_err(|_| CpioError::InvalidPathEncoding)?;

        // Data begins at 4-byte aligned boundary after (110 + namesize)
        let data_start = align4_up(name_start + namesize);
        let filesize = header.filesize as usize;
        if data_start + filesize > archive.len() {
            return Err(CpioError::TruncatedEntryData);
        }

        if path == CPIO_TRAILER_NAME {
            break;
        }

        let data = &archive[data_start..data_start + filesize];
        entries.push(CpioArchiveEntry { header, path, data });

        // Next header begins at 4-byte aligned boundary after data payload
        cursor = align4_up(data_start + filesize);
    }

    Ok(entries)
}

/// Helper to append an 8-digit uppercase ASCII hex number to a byte vector.
fn push_hex8(out: &mut Vec<u8>, mut val: u32) {
    let mut digits = [b'0'; 8];
    for i in (0..8).rev() {
        let nib = (val & 0xF) as u8;
        digits[i] = if nib < 10 { b'0' + nib } else { b'A' + (nib - 10) };
        val >>= 4;
    }
    out.extend_from_slice(&digits);
}

/// Appends a single SVR4 `070701` record (with 4-byte name and data alignment) to `archive_buf`.
pub fn append_cpio_record(archive_buf: &mut Vec<u8>, ino: u32, mode: u32, path: &str, data: &[u8]) {
    archive_buf.extend_from_slice(CPIO_MAGIC_NEWC);
    push_hex8(archive_buf, ino);
    push_hex8(archive_buf, mode);
    push_hex8(archive_buf, 0); // uid
    push_hex8(archive_buf, 0); // gid
    push_hex8(archive_buf, 1); // nlink
    push_hex8(archive_buf, 0x6900_0000); // mtime
    push_hex8(archive_buf, data.len() as u32); // filesize
    push_hex8(archive_buf, 0); // devmajor
    push_hex8(archive_buf, 1); // devminor
    push_hex8(archive_buf, 0); // rdevmajor
    push_hex8(archive_buf, 0); // rdevminor
    let namesize = (path.len() + 1) as u32;
    push_hex8(archive_buf, namesize);
    push_hex8(archive_buf, 0); // check

    archive_buf.extend_from_slice(path.as_bytes());
    archive_buf.push(0); // NUL terminator
    while archive_buf.len() % 4 != 0 {
        archive_buf.push(0);
    }

    archive_buf.extend_from_slice(data);
    while archive_buf.len() % 4 != 0 {
        archive_buf.push(0);
    }
}

/// Looks up and extracts a single file by path from an SVR4 CPIO archive.
pub fn extract_cpio_file<'a>(archive: &'a [u8], target_path: &str) -> Result<Option<&'a [u8]>, CpioError> {
    let want = target_path.trim_start_matches('/');
    let entries = parse_cpio_archive(archive)?;
    for entry in entries {
        if entry.path.trim_start_matches('/') == want {
            return Ok(Some(entry.data));
        }
    }
    Ok(None)
}

/// Self-test suite for `initramfs_cpio`.
pub fn verify_vfs_initramfs_cpio() -> u32 {
    let mut passed = 0u32;

    if parse_hex_u32(b"000081A4") == Ok(0o100644) && align4_up(110 + 11) == 124 {
        passed += 1;
    }

    let mut archive = Vec::new();
    append_cpio_record(&mut archive, 1, 0o040755, "sbin", b"");
    append_cpio_record(&mut archive, 2, 0o100755, "sbin/init", b"\x7FELF_COROS_INIT");
    append_cpio_record(&mut archive, 3, 0o100644, "etc/hostname", b"coros-node\n");
    append_cpio_record(&mut archive, 0, 0, CPIO_TRAILER_NAME, b"");

    if let Ok(entries) = parse_cpio_archive(&archive) {
        if entries.len() == 3 && entries[1].path == "sbin/init" && entries[1].header.mode == 0o100755 {
            passed += 1;
        }
    }

    if extract_cpio_file(&archive, "/etc/hostname") == Ok(Some(&b"coros-node\n"[..])) {
        passed += 1;
    }

    if extract_cpio_file(&archive, "/nonexistent") == Ok(None) {
        passed += 1;
    }

    passed
}
