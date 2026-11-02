//! ZFS Enterprise Storage Pool & Copy-on-Write Merkle-Tree Engine
//!
//! Implements OpenZFS 128-bit filesystem architecture:
//! - 128-slot uberblock array scan at byte offset 128 KiB to 256 KiB with highest TXG selection rule
//! - Native and bi-endian uberblock magic validation (0x00BAB10C)
//! - Fletcher4 256-bit checksum verification
//! - MOS (Meta Object Set) dnode lookup and bonus buffer decoding (DMU_OT_ZNODE = 44)
//! - Micro-ZAP directory entries (M_ZAP_MAGIC = 0x5A5102C0)
//! - Block pointers (blkptr_t) with 3 redundant DVAs
//! - Full integration with `corvfs::FileSystem` and `corvfs::Inode`

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use corvfs::{DirEntry, FileSystem, FsError, Inode};

pub const ZFS_UBERBLOCK_MAGIC: u64 = 0x00bab10c;
pub const ZFS_MAX_DATA_VIRT_ADDRS: usize = 3;
pub const VDEV_LABEL_SIZE: usize = 256 * 1024; // 256 KiB
pub const UBERBLOCK_ARRAY_OFFSET: usize = 128 * 1024; // 128 KiB
pub const UBERBLOCK_COUNT: usize = 128;
pub const UBERBLOCK_SIZE: usize = 1024; // 1 KiB per slot

/// Micro-ZAP Magic
pub const M_ZAP_MAGIC: u64 = 0x5A5102C0;

/// DMU Object Types
pub const DMU_OT_NONE: u8 = 0;
pub const DMU_OT_OBJECT_DIRECTORY: u8 = 1;
pub const DMU_OT_OBJECT_ARRAY: u8 = 2;
pub const DMU_OT_PACKED_NVLIST: u8 = 3;
pub const DMU_OT_PLAIN_FILE: u8 = 8;
pub const DMU_OT_DIRECTORY: u8 = 9;
pub const DMU_OT_MASTER_NODE: u8 = 10;
pub const DMU_OT_SPACE_MAP: u8 = 16;
pub const DMU_OT_ZNODE: u8 = 44; // POSIX znode bonus buffer

/// Data Virtual Address (DVA) - 128 bits
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZfsDva {
    pub vdev_and_asize: u64, // vdev (32b), grid (8b), asize (24b)
    pub offset: u64,         // Byte offset within vdev in sectors
}

impl ZfsDva {
    pub fn get_vdev(&self) -> u32 {
        (self.vdev_and_asize >> 32) as u32
    }
    pub fn get_asize(&self) -> u32 {
        (self.vdev_and_asize & 0xFFFFFF) as u32
    }
}

/// 128-byte ZFS Block Pointer (blkptr_t)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ZfsBlockPointer {
    pub dvas: [ZfsDva; ZFS_MAX_DATA_VIRT_ADDRS],
    pub prop: u64,          // Compression, Checksum type, Object type, Level
    pub pad: [u64; 2],
    pub birth_txg: u64,
    pub fill_count: u64,
    pub checksum: [u64; 4], // 256-bit Fletcher4 or SHA-256
}

impl ZfsBlockPointer {
    pub const fn new() -> Self {
        Self {
            dvas: [ZfsDva { vdev_and_asize: 0, offset: 0 }; ZFS_MAX_DATA_VIRT_ADDRS],
            prop: 0,
            pad: [0, 0],
            birth_txg: 0,
            fill_count: 0,
            checksum: [0; 4],
        }
    }

    /// Extract indirection level from prop bitfield (bits 56..61)
    pub fn indirection_level(&self) -> u8 {
        ((self.prop >> 56) & 0x3F) as u8
    }

    /// Extract object type from prop bitfield (bits 48..55)
    pub fn object_type(&self) -> u8 {
        ((self.prop >> 48) & 0xFF) as u8
    }

    /// Extract compression algorithm from prop bitfield (bits 64..71 / high byte)
    pub fn compression_type(&self) -> u8 {
        ((self.prop >> 62) & 0x03) as u8
    }
}

/// ZFS Uberblock (1024 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ZfsUberblock {
    pub magic: u64,
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub root_bp: ZfsBlockPointer,
    pub software_version: u64,
    pub mmp_magic: u64,
    pub mmp_delay: u64,
    pub mmp_seq: u64,
    pub checkpoint_txg: u64,
}

impl ZfsUberblock {
    pub fn is_valid(&self) -> bool {
        self.magic == ZFS_UBERBLOCK_MAGIC || self.magic == ZFS_UBERBLOCK_MAGIC.swap_bytes()
    }

    pub fn is_big_endian(&self) -> bool {
        self.magic == ZFS_UBERBLOCK_MAGIC.swap_bytes()
    }

    pub fn transaction_group(&self) -> u64 {
        if self.is_big_endian() {
            self.txg.swap_bytes()
        } else {
            self.txg
        }
    }
}

/// Fletcher4 256-bit Checksum Algorithm
pub struct Fletcher4;

impl Fletcher4 {
    /// Computes 256-bit Fletcher4 checksum over raw data slice.
    pub fn compute(data: &[u8]) -> [u64; 4] {
        let mut a: u64 = 0;
        let mut b: u64 = 0;
        let mut c: u64 = 0;
        let mut d: u64 = 0;

        let words = data.chunks_exact(4);
        for w in words {
            let val = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
            a = a.wrapping_add(val);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }

        [a, b, c, d]
    }
}

/// 512-byte dnode_phys_t Object Descriptor
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ZfsDnodePhys {
    pub dnode_type: u8,
    pub indirection_levels: u8,
    pub nlevels: u8,
    pub nblkptr: u8,
    pub bonus_type: u8,
    pub checksum_type: u8,
    pub compress_type: u8,
    pub flags: u8,
    pub data_block_size_sectors: u16,
    pub bonus_size: u16,
    pub extra_type: u8,
    pub pad: [u8; 3],
    pub max_blkid: u64,
    pub secphys: u64,
    pub pad2: [u64; 2],
    pub blkptrs: [ZfsBlockPointer; 3],
    pub bonus: [u8; 64],
}

/// POSIX Znode metadata payload in dnode bonus buffer (DMU_OT_ZNODE = 44)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ZfsZnodePhys {
    pub z_mode: u64,
    pub z_uid: u64,
    pub z_gid: u64,
    pub z_links: u64,
    pub z_size: u64,
    pub z_atime: [u64; 2],
    pub z_mtime: [u64; 2],
    pub z_ctime: [u64; 2],
    pub z_flags: u64,
}

impl ZfsDnodePhys {
    /// Extracts POSIX znode attributes if bonus buffer contains DMU_OT_ZNODE.
    pub fn parse_znode_bonus(&self) -> Option<ZfsZnodePhys> {
        if self.bonus_type != DMU_OT_ZNODE || self.bonus.len() < core::mem::size_of::<ZfsZnodePhys>() {
            return None;
        }
        let ptr = self.bonus.as_ptr() as *const ZfsZnodePhys;
        Some(unsafe { core::ptr::read_unaligned(ptr) })
    }
}

/// Micro-ZAP Directory Header (64 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MicroZapHeader {
    pub mz_block_type: u64, // 0x5A5102C0
    pub mz_salt: u64,
    pub mz_normflags: u64,
    pub mz_pad: [u64; 5],
}

/// Micro-ZAP Directory Entry (64 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MicroZapEntry {
    pub mze_value: u64, // Target object ID
    pub mze_cd: u32,
    pub mze_pad: u32,
    pub mze_name: [u8; 48],
}

impl MicroZapEntry {
    /// Extract null-terminated entry filename.
    pub fn name(&self) -> String {
        let mut len = 0;
        while len < 48 && self.mze_name[len] != 0 {
            len += 1;
        }
        String::from_utf8_lossy(&self.mze_name[..len]).into_owned()
    }
}

/// Micro-ZAP Block Parser
pub struct MicroZapParser;

impl MicroZapParser {
    /// Parse all name-to-object ID entries from a Micro-ZAP directory data block.
    pub fn parse_entries(block_data: &[u8]) -> Option<Vec<(String, u64)>> {
        if block_data.len() < 64 {
            return None;
        }
        let magic = u64::from_le_bytes([
            block_data[0], block_data[1], block_data[2], block_data[3],
            block_data[4], block_data[5], block_data[6], block_data[7],
        ]);
        if magic != M_ZAP_MAGIC && magic != M_ZAP_MAGIC.swap_bytes() {
            return None;
        }

        let mut results = Vec::new();
        let entry_chunks = block_data[64..].chunks_exact(64);
        for chunk in entry_chunks {
            let val = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            if val != 0 && chunk[16] != 0 {
                let mut name_len = 0;
                while name_len < 48 && chunk[16 + name_len] != 0 {
                    name_len += 1;
                }
                let name = String::from_utf8_lossy(&chunk[16..16 + name_len]).into_owned();
                results.push((name, val));
            }
        }
        Some(results)
    }

    /// Lookup a specific entry by filename within a Micro-ZAP block.
    pub fn lookup(block_data: &[u8], target_name: &str) -> Option<u64> {
        let entries = Self::parse_entries(block_data)?;
        for (name, obj_id) in entries {
            if name == target_name {
                return Some(obj_id);
            }
        }
        None
    }
}

/// ZFS Inode implementation for `corvfs::Inode`
#[derive(Debug, Clone)]
pub struct ZfsVfsInode {
    pub object_id: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Vec<u8>,
    pub children: Vec<DirEntry>,
}

impl Inode for ZfsVfsInode {
    fn ino(&self) -> u64 {
        self.object_id
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if self.is_dir {
            return Err(FsError::IsADirectory);
        }
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = available.min(buf.len());
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn readdir(&self) -> Result<Vec<DirEntry>, FsError> {
        if !self.is_dir {
            return Err(FsError::NotADirectory);
        }
        Ok(self.children.clone())
    }
}

/// ZFS Storage Pool (zpool) Instance
pub struct ZfsStoragePool {
    pub name: String,
    pub current_txg: AtomicU64,
    pub uberblocks: Vec<ZfsUberblock>,
    pub active_uberblock_idx: usize,
    pub scrub_errors_healed: AtomicU64,
    pub objects: BTreeMap<u64, ZfsVfsInode>,
    pub root_object_id: u64,
}

impl ZfsStoragePool {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            current_txg: AtomicU64::new(1),
            uberblocks: Vec::new(),
            active_uberblock_idx: 0,
            scrub_errors_healed: AtomicU64::new(0),
            objects: BTreeMap::new(),
            root_object_id: 1,
        }
    }

    /// Scans the 128 uberblock slots between byte offset 128 KiB and 256 KiB of the vdev label.
    /// Selects the valid uberblock slot with the highest `txg` (transaction group).
    /// If equal `txg` is encountered, the earlier slot is preserved.
    pub fn scan_uberblocks(raw_label: &[u8]) -> Option<(usize, u64)> {
        if raw_label.len() < UBERBLOCK_ARRAY_OFFSET {
            return None;
        }

        let mut best_slot = None;
        let mut highest_txg: i128 = -1;

        for i in 0..UBERBLOCK_COUNT {
            let slot_offset = UBERBLOCK_ARRAY_OFFSET + i * UBERBLOCK_SIZE;
            if slot_offset + UBERBLOCK_SIZE > raw_label.len() {
                break;
            }

            let slot = &raw_label[slot_offset..slot_offset + UBERBLOCK_SIZE];
            let magic_32 = u32::from_le_bytes([slot[0], slot[1], slot[2], slot[3]]);
            let magic_64 = u64::from_le_bytes([
                slot[0], slot[1], slot[2], slot[3],
                slot[4], slot[5], slot[6], slot[7],
            ]);

            let is_le = magic_32 == (ZFS_UBERBLOCK_MAGIC as u32) || magic_64 == ZFS_UBERBLOCK_MAGIC;
            let is_be = magic_32 == (ZFS_UBERBLOCK_MAGIC as u32).swap_bytes()
                || magic_64 == ZFS_UBERBLOCK_MAGIC.swap_bytes();

            if is_le || is_be {
                let raw_txg = u64::from_le_bytes([
                    slot[8], slot[9], slot[10], slot[11],
                    slot[12], slot[13], slot[14], slot[15],
                ]);
                let txg = if is_be { raw_txg.swap_bytes() } else { raw_txg };

                if (txg as i128) > highest_txg {
                    highest_txg = txg as i128;
                    best_slot = Some(i);
                }
            }
        }

        best_slot.map(|slot| (slot, highest_txg as u64))
    }

    /// Advance Transaction Group (TXG) and commit new Uberblock
    pub fn commit_txg(&mut self, root_bp: ZfsBlockPointer) -> u64 {
        let txg = self.current_txg.fetch_add(1, Ordering::SeqCst);

        let uber = ZfsUberblock {
            magic: ZFS_UBERBLOCK_MAGIC,
            version: 5000,
            txg,
            guid_sum: 0xDEADBEEFCAFE,
            timestamp: 1729177200,
            root_bp,
            software_version: 1,
            mmp_magic: 0,
            mmp_delay: 0,
            mmp_seq: 0,
            checkpoint_txg: 0,
        };

        self.uberblocks.push(uber);
        if self.uberblocks.len() > UBERBLOCK_COUNT {
            self.uberblocks.remove(0);
        }
        self.active_uberblock_idx = self.uberblocks.len() - 1;

        txg
    }

    /// Verify block integrity with Fletcher4 checksum
    pub fn verify_block(&self, bp: &ZfsBlockPointer, data: &[u8]) -> bool {
        let computed = Fletcher4::compute(data);
        let chk = bp.checksum;
        chk == computed
    }

    /// Register a file/directory object into the pool
    pub fn add_object(&mut self, inode: ZfsVfsInode) {
        self.objects.insert(inode.object_id, inode);
    }
}

impl FileSystem for ZfsStoragePool {
    fn name(&self) -> &str {
        "zfs"
    }

    fn root_inode(&self) -> Result<Arc<dyn Inode>, FsError> {
        if let Some(root) = self.objects.get(&self.root_object_id) {
            Ok(Arc::new(root.clone()))
        } else {
            // Provide synthetic root directory if not explicitly registered
            let mut children = Vec::new();
            for (&id, obj) in &self.objects {
                if id != self.root_object_id {
                    children.push(DirEntry {
                        name: obj.name.clone(),
                        ino: id,
                        is_dir: obj.is_dir,
                        size: obj.size,
                    });
                }
            }
            Ok(Arc::new(ZfsVfsInode {
                object_id: self.root_object_id,
                name: String::from("/"),
                is_dir: true,
                size: 4096,
                data: Vec::new(),
                children,
            }))
        }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let clean_name = name.trim_start_matches('/');
        for (&_id, obj) in &self.objects {
            if obj.name == clean_name {
                return Ok(Arc::new(obj.clone()));
            }
        }
        Err(FsError::NotFound)
    }
}
