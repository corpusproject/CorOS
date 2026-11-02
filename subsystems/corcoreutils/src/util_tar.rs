//! CorOS Userland Coreutil: `tar`
//! Real POSIX.1-1988 USTAR 512-byte header builder & parser (`UstarHeader`),
//! octal ASCII encoder/decoder, header checksum calculator, archive creator & extractor.

use alloc::string::String;
use alloc::vec::Vec;

pub const USTAR_BLOCK_SIZE: usize = 512;

/// Exact 512-byte POSIX.1-1988 USTAR archive header block.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UstarHeader {
    pub name: [u8; 100],
    pub mode: [u8; 8],
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    pub size: [u8; 12],
    pub mtime: [u8; 12],
    pub chksum: [u8; 8],
    pub typeflag: u8,
    pub linkname: [u8; 100],
    pub magic: [u8; 6],
    pub version: [u8; 2],
    pub uname: [u8; 32],
    pub gname: [u8; 32],
    pub devmajor: [u8; 8],
    pub devminor: [u8; 8],
    pub prefix: [u8; 155],
    pub padding: [u8; 12],
}

///Encodes a numeric value as a NUL-terminated fixed-width ASCII octal field.
pub fn encode_octal_field(mut value: u64, dest: &mut [u8]) {
    let len = dest.len();
    if len == 0 {
        return;
    }
    dest[len - 1] = 0;
    for idx in (0..len - 1).rev() {
        dest[idx] = b'0' + ((value & 0o7) as u8);
        value >>= 3;
    }
}

/// Decodes a NUL- or space-terminated ASCII octal field.
pub fn decode_octal_field(src: &[u8]) -> Option<u64> {
    let mut val = 0u64;
    let mut seen_digit = false;
    for &b in src {
        if b == 0 || b == b' ' {
            if seen_digit {
                break;
            }
            continue;
        }
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        seen_digit = true;
        val = (val << 3) | ((b - b'0') as u64);
    }
    if seen_digit {
        Some(val)
    } else {
        Some(0)
    }
}

fn copy_cstr_bytes(src: &str, dest: &mut [u8]) {
    dest.fill(0);
    let bytes = src.as_bytes();
    let count = bytes.len().min(dest.len());
    dest[..count].copy_from_slice(&bytes[..count]);
}

fn read_cstr_bytes(src: &[u8]) -> String {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    String::from(core::str::from_utf8(&src[..end]).unwrap_or(""))
}

impl UstarHeader {
    pub const fn zeroed() -> Self {
        Self {
            name: [0; 100],
            mode: [0; 8],
            uid: [0; 8],
            gid: [0; 8],
            size: [0; 12],
            mtime: [0; 12],
            chksum: [0; 8],
            typeflag: b'0',
            linkname: [0; 100],
            magic: *b"ustar\0",
            version: *b"00",
            uname: [0; 32],
            gname: [0; 32],
            devmajor: [0; 8],
            devminor: [0; 8],
            prefix: [0; 155],
            padding: [0; 12],
        }
    }

    pub fn as_bytes(&self) -> &[u8; USTAR_BLOCK_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; USTAR_BLOCK_SIZE]) }
    }

    pub fn from_bytes(block: &[u8; USTAR_BLOCK_SIZE]) -> Self {
        unsafe { core::ptr::read(block.as_ptr() as *const Self) }
    }

    /// Computes the unsigned byte sum of the 512-byte header treating the 8-byte `chksum` field as ASCII spaces (`0x20`).
    pub fn compute_checksum(&self) -> u32 {
        let mut copy = *self;
        copy.chksum = [b' '; 8];
        let raw = copy.as_bytes();
        let mut sum = 0u32;
        for &b in raw.iter() {
            sum = sum.wrapping_add(b as u32);
        }
        sum
    }

    /// Populates a valid USTAR regular-file or directory header and finalizes its checksum.
    pub fn build(
        path: &str,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        mtime: u64,
        typeflag: u8,
        uname: &str,
        gname: &str,
    ) -> Self {
        let mut hdr = Self::zeroed();
        copy_cstr_bytes(path, &mut hdr.name);
        encode_octal_field(mode as u64, &mut hdr.mode);
        encode_octal_field(uid as u64, &mut hdr.uid);
        encode_octal_field(gid as u64, &mut hdr.gid);
        encode_octal_field(size, &mut hdr.size);
        encode_octal_field(mtime, &mut hdr.mtime);
        hdr.typeflag = typeflag;
        hdr.magic = *b"ustar\0";
        hdr.version = *b"00";
        copy_cstr_bytes(uname, &mut hdr.uname);
        copy_cstr_bytes(gname, &mut hdr.gname);
        encode_octal_field(0, &mut hdr.devmajor);
        encode_octal_field(0, &mut hdr.devminor);

        let sum = hdr.compute_checksum();
        // Standard tar checksum format: 6 octal digits, NUL, space
        encode_octal_field(sum as u64, &mut hdr.chksum[..7]);
        hdr.chksum[7] = b' ';
        hdr
    }

    pub fn is_zero_block(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }

    pub fn verify_magic_and_checksum(&self) -> bool {
        if &self.magic[..5] != b"ustar" {
            return false;
        }
        let recorded = match decode_octal_field(&self.chksum) {
            Some(v) => v as u32,
            None => return false,
        };
        recorded == self.compute_checksum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarArchiveEntry {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub typeflag: u8,
    pub data: Vec<u8>,
}

/// Builds a complete POSIX USTAR `.tar` byte stream from in-memory entries, padded with two 512-byte zero blocks.
pub fn create_ustar_archive(entries: &[TarArchiveEntry]) -> Vec<u8> {
    let mut archive = Vec::new();
    for entry in entries {
        let hdr = UstarHeader::build(
            &entry.path,
            entry.mode,
            entry.uid,
            entry.gid,
            entry.data.len() as u64,
            entry.mtime,
            entry.typeflag,
            "root",
            "wheel",
        );
        archive.extend_from_slice(hdr.as_bytes());
        archive.extend_from_slice(&entry.data);
        let rem = entry.data.len() % USTAR_BLOCK_SIZE;
        if rem != 0 {
            let pad = USTAR_BLOCK_SIZE - rem;
            archive.resize(archive.len() + pad, 0);
        }
    }
    // End-of-archive marker: two 512-byte zero blocks
    archive.resize(archive.len() + USTAR_BLOCK_SIZE * 2, 0);
    archive
}

/// Parses and extracts all valid entries from a POSIX USTAR `.tar` archive byte slice.
pub fn extract_ustar_archive(archive: &[u8]) -> Result<Vec<TarArchiveEntry>, &'static str> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + USTAR_BLOCK_SIZE <= archive.len() {
        let mut block = [0u8; USTAR_BLOCK_SIZE];
        block.copy_from_slice(&archive[offset..offset + USTAR_BLOCK_SIZE]);
        let hdr = UstarHeader::from_bytes(&block);
        offset += USTAR_BLOCK_SIZE;

        if hdr.is_zero_block() {
            break;
        }
        if !hdr.verify_magic_and_checksum() {
            return Err("Invalid USTAR header magic or checksum");
        }

        let size = decode_octal_field(&hdr.size).ok_or("Invalid octal size")? as usize;
        let mode = decode_octal_field(&hdr.mode).unwrap_or(0o644) as u32;
        let uid = decode_octal_field(&hdr.uid).unwrap_or(0) as u32;
        let gid = decode_octal_field(&hdr.gid).unwrap_or(0) as u32;
        let mtime = decode_octal_field(&hdr.mtime).unwrap_or(0);

        if offset + size > archive.len() {
            return Err("Truncated USTAR entry payload");
        }

        let data = archive[offset..offset + size].to_vec();
        let padded_size = (size + USTAR_BLOCK_SIZE - 1) & !(USTAR_BLOCK_SIZE - 1);
        offset += padded_size;

        entries.push(TarArchiveEntry {
            path: read_cstr_bytes(&hdr.name),
            mode,
            uid,
            gid,
            mtime,
            typeflag: hdr.typeflag,
            data,
        });
    }

    Ok(entries)
}

pub fn verify_util_tar() -> u32 {
    let mut passed = 0u32;

    if core::mem::size_of::<UstarHeader>() == USTAR_BLOCK_SIZE {
        passed += 1;
    }

    let mut oct = [0u8; 8];
    encode_octal_field(0o755, &mut oct);
    if decode_octal_field(&oct) == Some(0o755) {
        passed += 1;
    }

    let sample_entries = [
        TarArchiveEntry {
            path: String::from("etc/hostname"),
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 1700000000,
            typeflag: b'0',
            data: b"coros-workstation\n".to_vec(),
        },
        TarArchiveEntry {
            path: String::from("bin/hello.sh"),
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime: 1700000123,
            typeflag: b'0',
            data: b"#!/bin/sh\necho CorOS\n".to_vec(),
        },
    ];

    let archive = create_ustar_archive(&sample_entries);
    if archive.len() == USTAR_BLOCK_SIZE * 6 {
        passed += 1;
    }

    if let Ok(extracted) = extract_ustar_archive(&archive) {
        if extracted.as_slice() == sample_entries.as_slice() {
            passed += 1;
        }
    }

    passed
}
