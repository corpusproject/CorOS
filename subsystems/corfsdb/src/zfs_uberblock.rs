//! `zfs_uberblock` — OpenZFS On-Disk Vdev Label & Uberblock Formats.
//! Structures representing ZFS storage pool vdev labels, transaction groups and uberblocks.

pub const UBERBLOCK_MAGIC: u64 = 0x00bab10c;
pub const VDEV_UBERBLOCK_COUNT: usize = 128;
pub const VDEV_LABEL_SIZE: usize = 256 * 1024; // 256 KiB

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ZfsDva {
    pub vdev: u64,
    pub offset: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ZfsBlkPtr {
    pub dva: [ZfsDva; 3],
    pub prop: u64,
    pub pad: [u64; 2],
    pub birth_txg: u64,
    pub fill_count: u64,
    pub checksum: [u64; 4],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ZfsUberblock {
    pub ub_magic: u64,
    pub ub_version: u64,
    pub ub_txg: u64,
    pub ub_guid_sum: u64,
    pub ub_timestamp: u64,
    pub ub_rootbp: ZfsBlkPtr,
    pub ub_software_version: u64,
    pub ub_mmp_magic: u64,
    pub ub_mmp_delay: u64,
    pub ub_mmp_seq: u64,
    pub ub_checkpoint_txg: u64,
}

impl ZfsUberblock {
    pub const fn is_valid(&self) -> bool {
        self.ub_magic == UBERBLOCK_MAGIC || self.ub_magic == UBERBLOCK_MAGIC.swap_bytes()
    }

    pub const fn is_big_endian(&self) -> bool {
        self.ub_magic == UBERBLOCK_MAGIC.swap_bytes()
    }

    pub fn txg(&self) -> u64 {
        if self.is_big_endian() {
            self.ub_txg.swap_bytes()
        } else {
            self.ub_txg
        }
    }
}

pub struct ZfsVdevLabelHeader {
    pub blank_boot_blocks: [u8; 8192],
    pub nvlist_header_bytes: usize,
    pub label_index: u8,
}

impl ZfsVdevLabelHeader {
    pub const fn offset_for_label(disk_bytes: u64, label_idx: u8) -> u64 {
        match label_idx {
            0 => 0,
            1 => VDEV_LABEL_SIZE as u64,
            2 => disk_bytes - (2 * VDEV_LABEL_SIZE as u64),
            3 => disk_bytes - (VDEV_LABEL_SIZE as u64),
            _ => 0,
        }
    }
}

/// ZFS Micro-ZAP Header Magic (0x5A5102C0).
pub const ZAP_MICRO_MAGIC: u64 = 0x5A5102C0;

/// Micro-ZAP Header Block (64 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct MicroZapHeader {
    pub mz_block_type: u64, // ZAP_MICRO_MAGIC
    pub mz_salt: u64,
    pub mz_normflags: u64,
    pub mz_pad: [u64; 5],
}

/// Micro-ZAP Entry (64 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct MicroZapEntry {
    pub mze_value: u64, // Target object ID
    pub mze_cd: u32,
    pub mze_pad: u32,
    pub mze_name: [u8; 48],
}
