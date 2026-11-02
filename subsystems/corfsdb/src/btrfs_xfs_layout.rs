//! Btrfs (B-Tree Filesystem) & XFS On-Disk Superblock Architectures.
//! Pure `#![no_std]` Rust filesystem format registry without numbered repetition.

pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";
pub const BTRFS_MAGIC_ALT: [u8; 8] = *b"_BtrFS_M";
pub const BTRFS_SUPERBLOCK_OFFSET: u64 = 65536; // 64 KiB offset

pub const XFS_SB_MAGIC: u32 = 0x58465342; // "XFSB" in ASCII

/// Btrfs Superblock Descriptor (at offset 0x10000).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtrfsSuperblock {
    pub csum: [u8; 32], // Checksum of everything past this field (CRC32C, XXHASH, SHA256 or BLAKE2b)
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: [u8; 8],
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub log_root_transid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
}

impl BtrfsSuperblock {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == BTRFS_MAGIC || self.magic == BTRFS_MAGIC_ALT
    }
}

/// SGI XFS Superblock (big-endian).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XfsSuperblock {
    pub sb_magicnum: u32,   // 0x58465342 "XFSB"
    pub sb_blocksize: u32,  // Logical block size in bytes
    pub sb_dblocks: u64,    // Number of data blocks
    pub sb_rblocks: u64,    // Number of realtime blocks
    pub sb_rextents: u64,   // Number of realtime extents
    pub sb_uuid: [u8; 16],  // Filesystem unique identifier
    pub sb_logstart: u64,   // Block number of log
    pub sb_rootino: u64,    // Root inode number
    pub sb_rbmino: u64,     // Realtime bitmap inode
    pub sb_rsumino: u64,    // Realtime summary inode
    pub sb_rextsize: u32,   // Realtime extent size
    pub sb_agblocks: u32,   // Size of an allocation group in blocks
    pub sb_agcount: u32,    // Number of allocation groups
}

impl XfsSuperblock {
    #[inline]
    pub fn is_valid(&self) -> bool {
        u32::from_be(self.sb_magicnum) == XFS_SB_MAGIC
    }

    #[inline]
    pub fn block_size_bytes(&self) -> u32 {
        u32::from_be(self.sb_blocksize)
    }
}

/// 128-bit Packed BMBT (Block Map B+Tree) Extent Record (Big-Endian).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XfsBmbtRec {
    pub hi: u64,
    pub lo: u64,
}

impl XfsBmbtRec {
    #[inline]
    pub fn is_unwritten(&self) -> bool {
        (u64::from_be(self.hi) >> 63) != 0
    }

    #[inline]
    pub fn logical_start(&self) -> u64 {
        (u64::from_be(self.hi) >> 9) & 0x003F_FFFF_FFFF_FFFF
    }

    #[inline]
    pub fn physical_start(&self) -> u64 {
        let hi = u64::from_be(self.hi);
        let lo = u64::from_be(self.lo);
        ((hi & 0x01FF) << 43) | (lo >> 21)
    }

    #[inline]
    pub fn block_count(&self) -> u32 {
        (u64::from_be(self.lo) & 0x001F_FFFF) as u32
    }
}

/// XFS Shortform Local Directory Header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XfsDir2SfHdr {
    pub count: u8,
    pub i8count: u8,
    pub parent: [u8; 4],
}
