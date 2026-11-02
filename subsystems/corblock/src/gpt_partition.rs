//! `gpt_partition.rs` — GUID Partition Table (`GPT`) parser and validator for CorOS.
//! Implements IEEE 802.3 CRC32 verification, protective MBR validation,
//! header parsing, and partition entry array extraction.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Standard IEEE 802.3 32-bit CRC calculation without external dependencies.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = !((crc & 1).wrapping_sub(1));
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Errors occurring during GPT and MBR parsing/verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GptError {
    DiskTooSmall,
    InvalidMbrSignature,
    NoProtectivePartition,
    InvalidGptSignature,
    InvalidGptRevision,
    InvalidHeaderSize,
    HeaderCrcMismatch { expected: u32, calculated: u32 },
    PartitionArrayCrcMismatch { expected: u32, calculated: u32 },
    InvalidLbaRanges,
    BufferTooShort,
}

/// 128-bit Globally Unique Identifier (GUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const ZERO: Self = Self([0; 16]);

    pub const EFI_SYSTEM: Self = Self([
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
    ]);

    pub const LINUX_FS: Self = Self([
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
    ]);

    pub const COROS_ROOT: Self = Self([
        0x20, 0x64, 0x98, 0xA1, 0x88, 0x99, 0x22, 0x44, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    ]);

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Formats the GUID as a canonical 36-character hyphenated hexadecimal string.
    pub fn to_string(&self) -> String {
        let b = &self.0;
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        let mut s = String::with_capacity(36);

        use core::fmt::Write;
        let _ = write!(
            s,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        );
        s
    }
}

/// GPT Partition Header (92 bytes, standard EFI PART).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Guid,
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_array_crc32: u32,
}

impl GptHeader {
    pub const SIGNATURE: &'static [u8; 8] = b"EFI PART";
    pub const REVISION_1_0: u32 = 0x0001_0000;
    pub const HEADER_SIZE: u32 = 92;

    pub fn parse(bytes: &[u8]) -> Result<Self, GptError> {
        if bytes.len() < 92 {
            return Err(GptError::BufferTooShort);
        }

        let mut sig = [0u8; 8];
        sig.copy_from_slice(&bytes[0..8]);
        if &sig != Self::SIGNATURE {
            return Err(GptError::InvalidGptSignature);
        }

        let revision = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if revision != Self::REVISION_1_0 {
            return Err(GptError::InvalidGptRevision);
        }

        let header_size = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        if header_size < 92 || header_size as usize > bytes.len() {
            return Err(GptError::InvalidHeaderSize);
        }

        let header_crc32 = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let reserved = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let current_lba = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let backup_lba = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let first_usable_lba = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let last_usable_lba = u64::from_le_bytes(bytes[48..56].try_into().unwrap());

        if first_usable_lba > last_usable_lba {
            return Err(GptError::InvalidLbaRanges);
        }

        let mut disk_guid = [0u8; 16];
        disk_guid.copy_from_slice(&bytes[56..72]);

        let partition_entry_lba = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
        let num_partition_entries = u32::from_le_bytes(bytes[80..84].try_into().unwrap());
        let partition_entry_size = u32::from_le_bytes(bytes[84..88].try_into().unwrap());
        let partition_array_crc32 = u32::from_le_bytes(bytes[88..92].try_into().unwrap());

        // Validate Header CRC32 with CRC field set to 0
        let mut header_copy = bytes[..header_size as usize].to_vec();
        header_copy[16..20].copy_from_slice(&[0, 0, 0, 0]);
        let calculated_crc = crc32(&header_copy);

        if calculated_crc != header_crc32 {
            return Err(GptError::HeaderCrcMismatch {
                expected: header_crc32,
                calculated: calculated_crc,
            });
        }

        Ok(Self {
            signature: sig,
            revision,
            header_size,
            header_crc32,
            reserved,
            current_lba,
            backup_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid: Guid(disk_guid),
            partition_entry_lba,
            num_partition_entries,
            partition_entry_size,
            partition_array_crc32,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.header_size as usize];
        out[0..8].copy_from_slice(&self.signature);
        out[8..12].copy_from_slice(&self.revision.to_le_bytes());
        out[12..16].copy_from_slice(&self.header_size.to_le_bytes());
        out[16..20].copy_from_slice(&0u32.to_le_bytes()); // placeholder
        out[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        out[24..32].copy_from_slice(&self.current_lba.to_le_bytes());
        out[32..40].copy_from_slice(&self.backup_lba.to_le_bytes());
        out[40..48].copy_from_slice(&self.first_usable_lba.to_le_bytes());
        out[48..56].copy_from_slice(&self.last_usable_lba.to_le_bytes());
        out[56..72].copy_from_slice(&self.disk_guid.0);
        out[72..80].copy_from_slice(&self.partition_entry_lba.to_le_bytes());
        out[80..84].copy_from_slice(&self.num_partition_entries.to_le_bytes());
        out[84..88].copy_from_slice(&self.partition_entry_size.to_le_bytes());
        out[88..92].copy_from_slice(&self.partition_array_crc32.to_le_bytes());

        let calculated_crc = crc32(&out);
        out[16..20].copy_from_slice(&calculated_crc.to_le_bytes());
        out
    }
}

/// GPT Partition Entry (128 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartitionEntry {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub name: [u16; 36],
}

impl GptPartitionEntry {
    pub const ATTR_SYSTEM_PARTITION: u64 = 1 << 0;
    pub const ATTR_READ_ONLY: u64 = 1 << 60;
    pub const ATTR_HIDDEN: u64 = 1 << 62;
    pub const ATTR_NO_AUTOMOUNT: u64 = 1 << 63;

    pub fn parse(bytes: &[u8]) -> Result<Self, GptError> {
        if bytes.len() < 128 {
            return Err(GptError::BufferTooShort);
        }

        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&bytes[0..16]);

        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&bytes[16..32]);

        let starting_lba = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let ending_lba = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let attributes = u64::from_le_bytes(bytes[48..56].try_into().unwrap());

        let mut name = [0u16; 36];
        for i in 0..36 {
            let offset = 56 + (i * 2);
            name[i] = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        }

        Ok(Self {
            type_guid: Guid(type_guid),
            unique_guid: Guid(unique_guid),
            starting_lba,
            ending_lba,
            attributes,
            name,
        })
    }

    pub fn is_used(&self) -> bool {
        !self.type_guid.is_zero() && self.ending_lba >= self.starting_lba
    }

    pub fn sector_count(&self) -> u64 {
        if self.ending_lba >= self.starting_lba {
            (self.ending_lba - self.starting_lba) + 1
        } else {
            0
        }
    }

    pub fn is_system_partition(&self) -> bool {
        (self.attributes & Self::ATTR_SYSTEM_PARTITION) != 0
    }

    pub fn is_read_only(&self) -> bool {
        (self.attributes & Self::ATTR_READ_ONLY) != 0
    }

    pub fn is_hidden(&self) -> bool {
        (self.attributes & Self::ATTR_HIDDEN) != 0
    }

    pub fn name_as_string(&self) -> String {
        let mut s = String::new();
        for &ch in &self.name {
            if ch == 0 {
                break;
            }
            if let Some(c) = char::from_u32(ch as u32) {
                s.push(c);
            }
        }
        s
    }

    pub fn serialize(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..16].copy_from_slice(&self.type_guid.0);
        out[16..32].copy_from_slice(&self.unique_guid.0);
        out[32..40].copy_from_slice(&self.starting_lba.to_le_bytes());
        out[40..48].copy_from_slice(&self.ending_lba.to_le_bytes());
        out[48..56].copy_from_slice(&self.attributes.to_le_bytes());
        for (i, &ch) in self.name.iter().enumerate() {
            let offset = 56 + (i * 2);
            let b = ch.to_le_bytes();
            out[offset] = b[0];
            out[offset + 1] = b[1];
        }
        out
    }
}

/// Parsed GPT Partition Table Disk structure.
#[derive(Debug, Clone)]
pub struct GptDisk {
    pub header: GptHeader,
    pub partitions: Vec<GptPartitionEntry>,
}

impl GptDisk {
    /// Validates protective MBR at sector 0.
    pub fn validate_protective_mbr(lba0: &[u8]) -> Result<(), GptError> {
        if lba0.len() < 512 {
            return Err(GptError::BufferTooShort);
        }
        if lba0[510] != 0x55 || lba0[511] != 0xAA {
            return Err(GptError::InvalidMbrSignature);
        }

        // MBR partition record 1 starts at offset 446 (0x1BE)
        let part1_type = lba0[446 + 4];
        if part1_type != 0xEE {
            return Err(GptError::NoProtectivePartition);
        }

        Ok(())
    }

    /// Parses a complete GPT disk image from raw sector bytes.
    pub fn parse(disk_bytes: &[u8], sector_size: usize) -> Result<Self, GptError> {
        if disk_bytes.len() < sector_size * 34 {
            return Err(GptError::DiskTooSmall);
        }

        Self::validate_protective_mbr(&disk_bytes[0..sector_size])?;

        let header_bytes = &disk_bytes[sector_size..sector_size * 2];
        let header = GptHeader::parse(header_bytes)?;

        let entries_offset = (header.partition_entry_lba as usize) * sector_size;
        let total_entries_size = (header.num_partition_entries as usize) * (header.partition_entry_size as usize);

        if entries_offset + total_entries_size > disk_bytes.len() {
            return Err(GptError::BufferTooShort);
        }

        let entries_bytes = &disk_bytes[entries_offset..entries_offset + total_entries_size];
        let calculated_entries_crc = crc32(entries_bytes);

        if calculated_entries_crc != header.partition_array_crc32 {
            return Err(GptError::PartitionArrayCrcMismatch {
                expected: header.partition_array_crc32,
                calculated: calculated_entries_crc,
            });
        }

        let mut partitions = Vec::new();
        for i in 0..header.num_partition_entries as usize {
            let offset = entries_offset + (i * header.partition_entry_size as usize);
            let entry = GptPartitionEntry::parse(&disk_bytes[offset..offset + header.partition_entry_size as usize])?;
            if entry.is_used() {
                partitions.push(entry);
            }
        }

        Ok(Self { header, partitions })
    }

    pub fn find_partition_by_name(&self, name: &str) -> Option<&GptPartitionEntry> {
        self.partitions.iter().find(|p| p.name_as_string() == name)
    }

    pub fn find_partition_by_type(&self, type_guid: &Guid) -> Option<&GptPartitionEntry> {
        self.partitions.iter().find(|p| &p.type_guid == type_guid)
    }
}
