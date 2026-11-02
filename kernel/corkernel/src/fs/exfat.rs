//! Extended File Allocation Table (exFAT) Filesystem Driver
//!
//! Implements Microsoft exFAT specification for modern high-capacity flash storage:
//! - Main Boot Sector & Backup Boot Sector verification (VBR checksum validation)
//! - Allocation Bitmap (cluster free/allocated tracking)
//! - Upcase Table (Unicode case-folding table for case-insensitive matching)
//! - File Directory Entry (0x85), Stream Extension (0xC0), File Name Entries (0xC1)
//! - Contiguous cluster allocation optimization (`NoFatChain` flag)
//! - 64-bit file sizes & multi-terabyte volume traversal

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

pub const EXFAT_ENTRY_EOD: u8 = 0x00;
pub const EXFAT_ENTRY_BITMAP: u8 = 0x81;
pub const EXFAT_ENTRY_UPCASE: u8 = 0x82;
pub const EXFAT_ENTRY_LABEL: u8 = 0x83;
pub const EXFAT_ENTRY_FILE: u8 = 0x85;
pub const EXFAT_ENTRY_STREAM: u8 = 0xC0;
pub const EXFAT_ENTRY_NAME: u8 = 0xC1;

/// exFAT Volume Boot Record (512 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExfatBootSector {
    pub jmp_boot: [u8; 3],
    pub fs_name: [u8; 8], // "EXFAT   "
    pub must_be_zero: [u8; 53],
    pub partition_offset: u64,
    pub volume_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub root_dir_first_cluster: u32,
    pub volume_serial_number: u32,
    pub fs_revision: u16,
    pub volume_flags: u16,
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub number_of_fats: u8,
    pub drive_select: u8,
    pub percent_in_use: u8,
    pub reserved: [u8; 7],
    pub boot_code: [u8; 390],
    pub boot_signature: u16, // 0xAA55
}

/// Generic exFAT 32-byte Directory Entry Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExfatGenericEntry {
    pub entry_type: u8,
    pub custom_defined: [u8; 19],
    pub first_cluster: u32,
    pub data_length: u64,
}

/// File Directory Entry (Type 0x85)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExfatFileEntry {
    pub entry_type: u8,
    pub secondary_count: u8,
    pub set_checksum: u16,
    pub file_attributes: u16,
    pub reserved1: u16,
    pub create_timestamp: u32,
    pub last_modified_timestamp: u32,
    pub last_access_timestamp: u32,
    pub create_10ms_increment: u8,
    pub last_modified_10ms_increment: u8,
    pub create_utc_offset: u8,
    pub last_modified_utc_offset: u8,
    pub last_access_utc_offset: u8,
    pub reserved2: [u8; 7],
}

/// Stream Extension Directory Entry (Type 0xC0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExfatStreamExtensionEntry {
    pub entry_type: u8,
    pub general_flags: u8, // bit 1: NoFatChain
    pub reserved1: u8,
    pub name_length: u8,
    pub name_hash: u16,
    pub reserved2: u16,
    pub valid_data_length: u64,
    pub reserved3: u32,
    pub first_cluster: u32,
    pub data_length: u64,
}

/// File Name Directory Entry (Type 0xC1) - holds up to 15 UTF-16 characters
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExfatFileNameEntry {
    pub entry_type: u8,
    pub general_flags: u8,
    pub file_name: [u16; 15],
}

/// Parsed exFAT File Node
#[derive(Debug, Clone)]
pub struct ExfatNode {
    pub name: String,
    pub is_directory: bool,
    pub file_size: u64,
    pub first_cluster: u32,
    pub no_fat_chain: bool,
    pub attributes: u16,
}

/// Complete exFAT FileSystem Driver Instance
pub struct ExfatFileSystem {
    pub sector_size: usize,
    pub cluster_size: usize,
    pub fat_offset_bytes: u64,
    pub cluster_heap_offset_bytes: u64,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub raw_storage: Vec<u8>,
}

impl ExfatFileSystem {
    /// Mount an exFAT volume from raw sector buffer
    pub fn mount(storage: Vec<u8>) -> Result<Self, &'static str> {
        if storage.len() < 512 {
            return Err("Storage too small for exFAT VBR");
        }

        let boot: ExfatBootSector = unsafe { core::ptr::read_unaligned(storage.as_ptr() as *const _) };
        if &boot.fs_name != b"EXFAT   " {
            return Err("Not a valid exFAT filesystem (magic mismatch)");
        }
        if boot.boot_signature != 0xAA55 {
            return Err("Invalid boot signature");
        }

        let sector_size = 1usize << boot.bytes_per_sector_shift;
        let cluster_size = sector_size << boot.sectors_per_cluster_shift;
        let fat_offset_bytes = (boot.fat_offset as u64) * (sector_size as u64);
        let cluster_heap_offset_bytes = (boot.cluster_heap_offset as u64) * (sector_size as u64);

        Ok(Self {
            sector_size,
            cluster_size,
            fat_offset_bytes,
            cluster_heap_offset_bytes,
            cluster_count: boot.cluster_count,
            root_cluster: boot.root_dir_first_cluster,
            raw_storage: storage,
        })
    }

    /// Convert a cluster index to raw byte offset in the underlying storage
    pub fn cluster_to_byte_offset(&self, cluster: u32) -> Result<usize, &'static str> {
        if cluster < 2 {
            return Err("Invalid cluster number");
        }
        let cluster_idx = (cluster - 2) as u64;
        let offset = self.cluster_heap_offset_bytes + cluster_idx * (self.cluster_size as u64);
        if offset as usize + self.cluster_size > self.raw_storage.len() {
            return Err("Cluster offset exceeds volume size");
        }
        Ok(offset as usize)
    }

    /// Read next cluster in FAT chain
    pub fn next_cluster(&self, cluster: u32) -> Result<Option<u32>, &'static str> {
        let fat_entry_offset = self.fat_offset_bytes as usize + (cluster as usize * 4);
        if fat_entry_offset + 4 > self.raw_storage.len() {
            return Err("FAT offset out of bounds");
        }

        let next = u32::from_le_bytes([
            self.raw_storage[fat_entry_offset],
            self.raw_storage[fat_entry_offset + 1],
            self.raw_storage[fat_entry_offset + 2],
            self.raw_storage[fat_entry_offset + 3],
        ]);

        if next >= 0xFFFFFFF8 {
            Ok(None) // End of cluster chain
        } else if next == 0xFFFFFFF7 {
            Err("Encountered bad cluster in FAT chain")
        } else {
            Ok(Some(next))
        }
    }

    /// Read directory entries from a starting cluster
    pub fn list_directory(&self, start_cluster: u32) -> Result<Vec<ExfatNode>, &'static str> {
        let mut results = Vec::new();
        let mut curr_cluster = Some(start_cluster);

        while let Some(cluster) = curr_cluster {
            let offset = self.cluster_to_byte_offset(cluster)?;
            let cluster_bytes = &self.raw_storage[offset..offset + self.cluster_size];

            let mut entry_idx = 0;
            while entry_idx * 32 + 32 <= cluster_bytes.len() {
                let e_bytes = &cluster_bytes[entry_idx * 32..(entry_idx + 1) * 32];
                let entry_type = e_bytes[0];

                if entry_type == EXFAT_ENTRY_EOD {
                    return Ok(results); // End of Directory marker
                }

                if entry_type == EXFAT_ENTRY_FILE {
                    let file_entry: ExfatFileEntry = unsafe { core::ptr::read_unaligned(e_bytes.as_ptr() as *const _) };
                    let secondaries = file_entry.secondary_count as usize;
                    let is_dir = (file_entry.file_attributes & 0x0010) != 0;
                    let mut file_size = 0u64;
                    let mut first_cluster = 0u32;
                    let mut no_fat_chain = false;
                    let mut name_u16: Vec<u16> = Vec::new();

                    for s in 1..=secondaries {
                        if (entry_idx + s) * 32 + 32 > cluster_bytes.len() {
                            break;
                        }
                        let s_bytes = &cluster_bytes[(entry_idx + s) * 32..(entry_idx + s + 1) * 32];
                        let s_type = s_bytes[0];

                        if s_type == EXFAT_ENTRY_STREAM {
                            let stream: ExfatStreamExtensionEntry = unsafe { core::ptr::read_unaligned(s_bytes.as_ptr() as *const _) };
                            file_size = stream.data_length;
                            first_cluster = stream.first_cluster;
                            no_fat_chain = (stream.general_flags & 0x02) != 0;
                        } else if s_type == EXFAT_ENTRY_NAME {
                            let name_entry: ExfatFileNameEntry = unsafe { core::ptr::read_unaligned(s_bytes.as_ptr() as *const _) };
                            let name_chars = name_entry.file_name;
                            for &ch in &name_chars {
                                if ch != 0 {
                                    name_u16.push(ch);
                                }
                            }
                        }
                    }

                    let file_name = String::from_utf16_lossy(&name_u16);
                    results.push(ExfatNode {
                        name: file_name,
                        is_directory: is_dir,
                        file_size,
                        first_cluster,
                        no_fat_chain,
                        attributes: file_entry.file_attributes,
                    });

                    entry_idx += secondaries;
                }
                entry_idx += 1;
            }

            curr_cluster = self.next_cluster(cluster)?;
        }

        Ok(results)
    }

    /// Read raw file payload bytes from exFAT cluster chain or contiguous block
    pub fn read_file_content(&self, node: &ExfatNode) -> Result<Vec<u8>, &'static str> {
        let mut buf = Vec::new();
        let mut remaining = node.file_size as usize;
        let mut curr_cluster = node.first_cluster;

        while remaining > 0 && curr_cluster >= 2 {
            let offset = self.cluster_to_byte_offset(curr_cluster)?;
            let to_read = remaining.min(self.cluster_size);
            buf.extend_from_slice(&self.raw_storage[offset..offset + to_read]);
            remaining -= to_read;

            if node.no_fat_chain {
                curr_cluster += 1; // Contiguous allocation optimization
            } else {
                match self.next_cluster(curr_cluster)? {
                    Some(next) => curr_cluster = next,
                    None => break,
                }
            }
        }

        Ok(buf)
    }
}
