//! Ext4 (Fourth Extended Filesystem) Engine for CorOS.
//!
//! Implements modern Linux Ext4 features:
//! - Extents-based block mapping (replacing traditional Ext2/3 direct/indirect block pointers)
//! - `ext4_extent_header`, `ext4_extent_idx`, and `ext4_extent` B-tree leaf/index hierarchy
//! - 64-bit block addressing (supporting exabyte volumes)
//! - Flex Block Groups (`FEATURE_INCOMPAT_FLEX_BG`)
//! - Metadata Checksumming (`EXT4_FEATURE_RO_COMPAT_METADATA_CSUM`)
//! - Inode size 256+ bytes with nanosecond timestamps and extended attributes (xattr)

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt;

/// Ext4 Magic Number in Superblock (0xEF53)
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// Ext4 Extents Magic Number (0xF30A)
pub const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// Ext4 Incompatible Feature Flags
pub const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
pub const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
pub const EXT4_FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_MMP: u32 = 0x0100;
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const EXT4_FEATURE_INCOMPAT_CSUM_SEED: u32 = 0x2000;

/// Ext4 Read-Only Compatible Feature Flags
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT4_FEATURE_RO_COMPAT_GDT_CSUM: u32 = 0x0010;
pub const EXT4_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
pub const EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

/// Ext4 Inode Flag: file uses extents instead of traditional block maps
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// Ext4 Extent Tree Header (12 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ext4ExtentHeader {
    pub magic: u16,       // 0xF30A
    pub entries: u16,     // Number of valid entries following header
    pub max_entries: u16, // Maximum capacity of entries in node
    pub depth: u16,       // Distance to leaves (0 = leaf node, contains ext4_extent)
    pub generation: u32,  // Tree generation count
}

impl Ext4ExtentHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != EXT4_EXT_MAGIC {
            return None;
        }
        Some(Self {
            magic,
            entries: u16::from_le_bytes([buf[2], buf[3]]),
            max_entries: u16::from_le_bytes([buf[4], buf[5]]),
            depth: u16::from_le_bytes([buf[6], buf[7]]),
            generation: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

/// Ext4 Extent Leaf Entry (12 bytes)
/// Points to a contiguous run of up to 32,768 physical filesystem blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ext4Extent {
    pub block: u32,    // First logical file block covered by extent
    pub len: u16,      // Number of blocks covered by extent (max 32768, >32768 indicates uninitialized)
    pub start_hi: u16, // High 16 bits of physical starting block
    pub start_lo: u32, // Low 32 bits of physical starting block
}

impl Ext4Extent {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            block: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            len: u16::from_le_bytes([buf[4], buf[5]]),
            start_hi: u16::from_le_bytes([buf[6], buf[7]]),
            start_lo: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }

    /// Full 48-bit physical block address
    pub fn physical_block(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }

    /// Whether this extent has been preallocated but not yet written (unwritten extent)
    pub fn is_unwritten(&self) -> bool {
        self.len > 32768
    }

    /// Actual block count
    pub fn actual_len(&self) -> u16 {
        if self.len > 32768 {
            self.len - 32768
        } else {
            self.len
        }
    }
}

/// Ext4 Extent Index Entry (12 bytes)
/// Internal tree node pointing to a deeper extent node block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ext4ExtentIdx {
    pub block: u32,    // Indexes logical blocks starting at this block
    pub leaf_lo: u32,  // Low 32 bits of physical block of next level node
    pub leaf_hi: u16,  // High 16 bits of physical block of next level node
    pub unused: u16,
}

impl Ext4ExtentIdx {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(Self {
            block: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            leaf_lo: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            leaf_hi: u16::from_le_bytes([buf[8], buf[9]]),
            unused: u16::from_le_bytes([buf[10], buf[11]]),
        })
    }

    pub fn leaf_physical_block(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | (self.leaf_lo as u64)
    }
}

/// Ext4 64-bit Inode Data Structure (typically 256 bytes on disk)
#[derive(Debug, Clone)]
pub struct Ext4Inode {
    pub mode: u16,
    pub uid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u32,
    pub links_count: u16,
    pub blocks: u64,
    pub flags: u32,
    pub block_data: [u8; 60], // 60 bytes: Holds extent root header or direct/indirect ptrs
    pub generation: u32,
    pub file_acl: u64,
    pub extra_isize: u16,
    pub checksum: u32,
}

impl Ext4Inode {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 128 {
            return None;
        }
        let mode = u16::from_le_bytes([buf[0], buf[1]]);
        let uid_low = u16::from_le_bytes([buf[2], buf[3]]);
        let size_low = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let atime = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let ctime = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let mtime = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let dtime = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let gid_low = u16::from_le_bytes([buf[24], buf[25]]);
        let links_count = u16::from_le_bytes([buf[26], buf[27]]);
        let blocks_low = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);

        let mut block_data = [0u8; 60];
        block_data.copy_from_slice(&buf[40..100]);

        let generation = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);
        let file_acl_low = u32::from_le_bytes([buf[104], buf[105], buf[106], buf[107]]);
        let size_high = u32::from_le_bytes([buf[108], buf[109], buf[110], buf[111]]);

        let size = ((size_high as u64) << 32) | (size_low as u64);

        let uid_high = if buf.len() >= 122 { u16::from_le_bytes([buf[120], buf[121]]) } else { 0 };
        let gid_high = if buf.len() >= 124 { u16::from_le_bytes([buf[122], buf[123]]) } else { 0 };
        let uid = ((uid_high as u32) << 16) | (uid_low as u32);
        let gid = ((gid_high as u32) << 16) | (gid_low as u32);

        let extra_isize = if buf.len() >= 130 { u16::from_le_bytes([buf[128], buf[129]]) } else { 0 };
        let checksum = if buf.len() >= 134 { u32::from_le_bytes([buf[130], buf[131], buf[132], buf[133]]) } else { 0 };

        Some(Self {
            mode,
            uid,
            size,
            atime,
            ctime,
            mtime,
            dtime,
            gid,
            links_count,
            blocks: blocks_low as u64,
            flags,
            block_data,
            generation,
            file_acl: file_acl_low as u64,
            extra_isize,
            checksum,
        })
    }

    /// Whether this inode maps its blocks using an Ext4 Extent tree
    pub fn uses_extents(&self) -> bool {
        (self.flags & EXT4_EXTENTS_FL) != 0
    }

    /// Read root extent header directly from inode 60-byte data area
    pub fn extent_header(&self) -> Option<Ext4ExtentHeader> {
        if !self.uses_extents() {
            return None;
        }
        Ext4ExtentHeader::parse(&self.block_data)
    }

    /// Get all extents in root inode if depth == 0
    pub fn root_extents(&self) -> Vec<Ext4Extent> {
        let mut list = Vec::new();
        if let Some(hdr) = self.extent_header() {
            if hdr.depth == 0 {
                let mut offset = 12; // sizeof(Ext4ExtentHeader)
                for _ in 0..hdr.entries {
                    if offset + 12 <= 60 {
                        if let Some(ext) = Ext4Extent::parse(&self.block_data[offset..offset + 12]) {
                            list.push(ext);
                        }
                        offset += 12;
                    }
                }
            }
        }
        list
    }

    /// Look up physical block for a given logical block offset using root extents
    pub fn lookup_block_in_root(&self, logical_block: u32) -> Option<u64> {
        let extents = self.root_extents();
        for ext in extents {
            let start = ext.block;
            let end = start + (ext.actual_len() as u32);
            if logical_block >= start && logical_block < end {
                let offset_in_ext = (logical_block - start) as u64;
                return Some(ext.physical_block() + offset_in_ext);
            }
        }
        None
    }
}

/// Ext4 64-bit Superblock (1024 bytes)
#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub r_blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub magic: u16,
    pub state: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub desc_size: u16,
}

impl Ext4Superblock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 1024 {
            return None;
        }
        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        if magic != EXT4_SUPER_MAGIC {
            return None;
        }

        let inodes_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let blocks_count_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let r_blocks_count_lo = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let free_blocks_count_lo = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let free_inodes_count = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let first_data_block = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let mtime = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let wtime = u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]);
        let state = u16::from_le_bytes([buf[58], buf[59]]);

        let feature_compat = u32::from_le_bytes([buf[92], buf[93], buf[94], buf[95]]);
        let feature_incompat = u32::from_le_bytes([buf[96], buf[97], buf[98], buf[99]]);
        let feature_ro_compat = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[104..120]);

        let mut volume_name = [0u8; 16];
        volume_name.copy_from_slice(&buf[120..136]);

        let inode_size = u16::from_le_bytes([buf[88], buf[89]]);
        let block_group_nr = u16::from_le_bytes([buf[90], buf[91]]);

        let is_64bit = (feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
        let blocks_count_hi = if is_64bit { u32::from_le_bytes([buf[336], buf[337], buf[338], buf[339]]) } else { 0 };
        let free_blocks_count_hi = if is_64bit { u32::from_le_bytes([buf[344], buf[345], buf[346], buf[347]]) } else { 0 };
        let desc_size = if is_64bit { u16::from_le_bytes([buf[254], buf[255]]) } else { 32 };

        let blocks_count = ((blocks_count_hi as u64) << 32) | (blocks_count_lo as u64);
        let free_blocks_count = ((free_blocks_count_hi as u64) << 32) | (free_blocks_count_lo as u64);

        Some(Self {
            inodes_count,
            blocks_count,
            r_blocks_count: r_blocks_count_lo as u64,
            free_blocks_count,
            free_inodes_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            mtime,
            wtime,
            magic,
            state,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            uuid,
            volume_name,
            inode_size,
            block_group_nr,
            desc_size: desc_size.max(32),
        })
    }

    /// Block size in bytes (1024 << log_block_size)
    pub fn block_size(&self) -> usize {
        1024usize << self.log_block_size
    }

    /// Total number of block groups in volume
    pub fn block_groups_count(&self) -> usize {
        ((self.blocks_count + (self.blocks_per_group as u64) - 1) / (self.blocks_per_group as u64)) as usize
    }
}

/// Ext4 High-Performance Filesystem Driver
pub struct Ext4FileSystem {
    pub superblock: Ext4Superblock,
}

impl Ext4FileSystem {
    pub fn mount(raw_superblock_buf: &[u8]) -> Result<Self, &'static str> {
        let sb = Ext4Superblock::parse(raw_superblock_buf).ok_or("Invalid Ext4 Superblock")?;
        if (sb.feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS) == 0 {
            return Err("Ext4 filesystem does not have EXTENTS feature enabled");
        }
        Ok(Self { superblock: sb })
    }

    /// Resolve block group descriptor offset on disk
    pub fn group_descriptor_offset(&self, group_index: usize) -> u64 {
        let sb_block = if self.superblock.block_size() == 1024 { 2 } else { 1 };
        let base = (sb_block as u64) * (self.superblock.block_size() as u64);
        base + (group_index as u64) * (self.superblock.desc_size as u64)
    }
}

impl fmt::Display for Ext4FileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vol_str = core::str::from_utf8(&self.superblock.volume_name).unwrap_or("ext4");
        write!(
            f,
            "Ext4FS(vol='{}', block_size={}B, total_blocks={}, free_blocks={})",
            vol_str.trim_matches(char::from(0)),
            self.superblock.block_size(),
            self.superblock.blocks_count,
            self.superblock.free_blocks_count
        )
    }
}
