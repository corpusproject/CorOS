//! `f2fs_layout` — Samsung Flash-Friendly File System (F2FS) On-Disk Layout.
//! Standard F2FS 4096-byte superblock, checkpoint packet, and SIT/NAT structures.

pub const F2FS_SUPER_MAGIC: u32 = 0xF2F52010;
pub const F2FS_BLKSIZE: usize = 4096;

pub const F2FS_MAX_EXTENSION: usize = 64;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsSuperblock {
    pub magic: u32,
    pub major_ver: u16,
    pub minor_ver: u16,
    pub log_sectorsize: u32,
    pub log_sectors_per_block: u32,
    pub log_blocksize: u32,
    pub log_blocks_per_seg: u32,
    pub segs_per_sec: u32,
    pub secs_per_zone: u32,
    pub checksum_offset: u32,
    pub block_count: u64,
    pub section_count: u32,
    pub total_node_count: u32,
    pub node_ino: u32,
    pub meta_ino: u32,
    pub root_ino: u32,
    pub active_logs: u32,
    pub cp_payload: u32,
    pub sit_nat_version_bitmap: [u8; 64],
    pub extension_count: u32,
    pub extension_list: [[u8; 8]; F2FS_MAX_EXTENSION],
}

impl F2fsSuperblock {
    pub const fn is_valid(&self) -> bool {
        self.magic == F2FS_SUPER_MAGIC
    }

    pub const fn block_size(&self) -> u32 {
        1 << self.log_blocksize
    }

    pub const fn sector_size(&self) -> u32 {
        1 << self.log_sectorsize
    }
}

pub const F2FS_CP_FLAG_ERROR: u32 = 0x00000008;
pub const F2FS_CP_FLAG_COMPACT_SUM: u32 = 0x00000010;
pub const F2FS_CP_FLAG_ORPHAN_PRESENT: u32 = 0x00000020;
pub const F2FS_CP_FLAG_TRIMMED: u32 = 0x00000100;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsCheckpoint {
    pub checkpoint_ver: u64,
    pub user_block_count: u64,
    pub valid_block_count: u64,
    pub rsvd_segment_count: u32,
    pub overprov_segment_count: u32,
    pub free_segment_count: u32,
    pub cur_node_segno: [u32; 3],
    pub cur_node_blkoff: [u16; 3],
    pub cur_data_segno: [u32; 3],
    pub cur_data_blkoff: [u16; 3],
    pub ckpt_flags: u32,
    pub cp_pack_total_block_count: u32,
    pub cp_pack_start_sum: u32,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub next_free_nid: u32,
    pub sit_ver_bitmap_bytesize: u32,
    pub nat_ver_bitmap_bytesize: u32,
    pub checksum_offset: u32,
    pub elapsed_time: u64,
    pub alloc_type: [u8; 6],
}

impl F2fsCheckpoint {
    pub const fn has_orphans(&self) -> bool {
        (self.ckpt_flags & F2FS_CP_FLAG_ORPHAN_PRESENT) != 0
    }

    pub const fn is_trimmed(&self) -> bool {
        (self.ckpt_flags & F2FS_CP_FLAG_TRIMMED) != 0
    }
}

pub const F2FS_NAT_ENTRIES_PER_BLOCK: usize = 455;
pub const F2FS_DENTRIES_PER_BLOCK: usize = 214;

/// F2FS 9-byte NAT Entry.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsNatEntry {
    pub version: u8,
    pub ino: u32,
    pub block_addr: u32,
}

/// F2FS 11-byte Directory Entry.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsDirEntry {
    pub hash_code: u32,
    pub ino: u32,
    pub name_len: u16,
    pub file_type: u8,
}

/// F2FS 4096-byte Dentry Block packing 214 directory entries.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsDentryBlock {
    pub dentry_bitmap: [u8; 27],
    pub reserved: [u8; 3],
    pub dentry: [F2fsDirEntry; F2FS_DENTRIES_PER_BLOCK],
    pub filename: [[u8; 8]; F2FS_DENTRIES_PER_BLOCK],
}

/// F2FS 24-byte Node Footer.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct F2fsNodeFooter {
    pub nid: u32,
    pub ino: u32,
    pub cp_ver: u64,
    pub next_blkaddr: u32,
}
