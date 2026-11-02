//! Linux Fourth Extended Filesystem (Ext4) Superblock & Inode On-Disk Binary Layouts.
//! Pure `#![no_std]` Rust filesystem format registry without numbered repetition.

pub const EXT4_SUPERBLOCK_MAGIC: u16 = 0xEF53;
pub const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;

/// Ext4 Compatible Feature Flags (`s_feature_compat`).
pub mod ext4_feature_compat {
    pub const COMPAT_DIR_PREALLOC: u32 = 0x0001;
    pub const COMPAT_IMAGIC_INODES: u32 = 0x0002;
    pub const COMPAT_HAS_JOURNAL: u32 = 0x0004;
    pub const COMPAT_EXT_ATTR: u32 = 0x0008;
    pub const COMPAT_RESIZE_INODE: u32 = 0x0010;
    pub const COMPAT_DIR_INDEX: u32 = 0x0020;
}

/// Ext4 Incompatible Feature Flags (`s_feature_incompat`).
pub mod ext4_feature_incompat {
    pub const INCOMPAT_FILETYPE: u32 = 0x0002;
    pub const INCOMPAT_RECOVER: u32 = 0x0004;
    pub const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
    pub const INCOMPAT_META_BG: u32 = 0x0010;
    pub const INCOMPAT_EXTENTS: u32 = 0x0040;
    pub const INCOMPAT_64BIT: u32 = 0x0080;
    pub const INCOMPAT_MMP: u32 = 0x0100;
    pub const INCOMPAT_FLEX_BG: u32 = 0x0200;
    pub const INCOMPAT_CSUM_SEED: u32 = 0x2000;
}

/// Ext4 Read-Only Compatible Feature Flags (`s_feature_ro_compat`).
pub mod ext4_feature_ro_compat {
    pub const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
    pub const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
    pub const RO_COMPAT_BTREE_DIR: u32 = 0x0004;
    pub const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
    pub const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
    pub const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
    pub const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
    pub const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
}

/// Authentic 1024-byte Linux Ext4 Superblock Header (little-endian).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ext4Superblock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: i16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
}

impl Ext4Superblock {
    /// Computes the active block size in bytes: `1024 << s_log_block_size`.
    #[inline]
    pub fn block_size_bytes(&self) -> u32 {
        1024 << self.s_log_block_size
    }

    /// Verifies the 0xEF53 magic constant.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.s_magic == EXT4_SUPERBLOCK_MAGIC
    }

    /// Checks if Ext4 extents feature is enabled.
    #[inline]
    pub fn has_extents(&self) -> bool {
        (self.s_feature_incompat & ext4_feature_incompat::INCOMPAT_EXTENTS) != 0
    }
}
