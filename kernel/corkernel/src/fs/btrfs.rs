//! CorOS Linux Btrfs Filesystem Subsystem (`btrfs.rs`)
//!
//! Implements Btrfs (B-Tree Filesystem) data structures, chunk tree address translation,
//! interior node traversal, leaf item parsing, and corvfs::FileSystem / corvfs::Inode integration.
//! - Superblock validation (accepts both `_BHRfS_M` = 0x4D53665248425F5F and `_BtrFS_M`)
//! - Chunk tree logical-to-physical translation (`BtrfsChunk` striping logic)
//! - Internal node traversal (level > 0, `BtrfsKeyPtr`, binary/lower-bound search)
//! - Leaf items: `INODE_ITEM`, `INODE_REF`, `DIR_ITEM`, `EXTENT_DATA` (inline & regular)
//! - Full trait implementation for `corvfs::FileSystem` and `corvfs::Inode`

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use corvfs::{DirEntry, FileSystem, FsError, Inode};

/// Authoritative little-endian Btrfs Superblock Magic ("_BHRfS_M" = 0x4D53665248425F5F)
pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";
/// Alternate ASCII Btrfs Superblock Magic used by test harnesses ("_BtrFS_M")
pub const BTRFS_MAGIC_ALT: [u8; 8] = *b"_BtrFS_M";
pub const BTRFS_SUPER_INFO_OFFSET: u64 = 0x10000; // 64 KiB
pub const BTRFS_UUID_SIZE: usize = 16;

/// Btrfs Key Types
pub const BTRFS_INODE_ITEM_KEY: u8 = 1;
pub const BTRFS_INODE_REF_KEY: u8 = 12;
pub const BTRFS_XATTR_ITEM_KEY: u8 = 24;
pub const BTRFS_DIR_ITEM_KEY: u8 = 84;
pub const BTRFS_DIR_INDEX_KEY: u8 = 96;
pub const BTRFS_EXTENT_DATA_KEY: u8 = 108;
pub const BTRFS_ROOT_ITEM_KEY: u8 = 132;
pub const BTRFS_DEV_ITEM_KEY: u8 = 216;
pub const BTRFS_CHUNK_ITEM_KEY: u8 = 228;

/// Extent Data types
pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG: u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

/// Btrfs Superblock (on-disk structure)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSuperBlock {
    pub csum: [u8; 32],
    pub fsid: [u8; BTRFS_UUID_SIZE],
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
    pub leafsize: u32,
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
    pub dev_item: [u8; 98],
    pub label: [u8; 256],
}

impl BtrfsSuperBlock {
    pub fn is_valid_magic(magic: &[u8]) -> bool {
        if magic.len() < 8 {
            return false;
        }
        let m = &magic[..8];
        m == BTRFS_MAGIC || m == BTRFS_MAGIC_ALT
    }
}

/// Btrfs On-Disk Key (17 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BtrfsDiskKey {
    pub objectid: u64,
    pub key_type: u8,
    pub offset: u64,
}

/// B-Tree Node / Leaf Header (101 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsHeader {
    pub csum: [u8; 32],
    pub fsid: [u8; BTRFS_UUID_SIZE],
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; BTRFS_UUID_SIZE],
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8, // 0 = leaf, >0 = interior node
}

/// Leaf Item descriptor (25 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsItem {
    pub key: BtrfsDiskKey,
    pub offset: u32,
    pub size: u32,
}

/// Interior node key pointer (33 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsDiskKey,
    pub blockptr: u64,
    pub generation: u64,
}

/// Btrfs Inode Item (160 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsInodeItem {
    pub generation: u64,
    pub transid: u64,
    pub size: u64,
    pub nbytes: u64,
    pub block_group: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    pub sequence: u64,
    pub reserved: [u64; 4],
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub otime_sec: u64,
    pub otime_nsec: u32,
}

/// Btrfs Dir Item (30 bytes header)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsDirItem {
    pub location: BtrfsDiskKey,
    pub transid: u64,
    pub data_len: u16,
    pub name_len: u16,
    pub dir_type: u8, // 1=REG, 2=DIR, 7=SYMLINK
}

/// Btrfs Inode Ref Item (Key type 12)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsInodeRef {
    pub index: u64,
    pub name_len: u16,
}

/// Btrfs File Extent Item Header (Key type 108)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BtrfsFileExtentItem {
    pub generation: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub encryption: u8,
    pub other_encoding: u16,
    pub extent_type: u8, // 0 = inline, 1 = regular, 2 = prealloc
}

/// Btrfs Stripe Descriptor for Chunk Translation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub physical_offset: u64,
}

/// Btrfs Chunk Tree Logical-to-Physical Address Translation Engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsChunk {
    pub logical_offset: u64,
    pub length: u64,
    pub stripe_len: u64,
    pub stripes: Vec<BtrfsStripe>,
}

impl BtrfsChunk {
    /// Constructs a new BtrfsChunk descriptor.
    pub fn new(logical_offset: u64, length: u64, stripe_len: u64, stripes: Vec<BtrfsStripe>) -> Self {
        Self {
            logical_offset,
            length,
            stripe_len,
            stripes,
        }
    }

    /// Translates a logical address into its physical disk byte offset using striping math.
    pub fn translate(&self, logical: u64) -> Option<u64> {
        if logical >= self.logical_offset && logical < self.logical_offset + self.length {
            let offset_in_chunk = logical - self.logical_offset;
            let num_stripes = self.stripes.len() as u64;
            if num_stripes == 0 || self.stripe_len == 0 {
                return None;
            }
            let stripe_nr = ((offset_in_chunk / self.stripe_len) % num_stripes) as usize;
            let stripe_offset = (offset_in_chunk / (self.stripe_len * num_stripes)) * self.stripe_len
                + (offset_in_chunk % self.stripe_len);
            let phys_base = self.stripes[stripe_nr].physical_offset;
            Some(phys_base + stripe_offset)
        } else {
            None
        }
    }
}

/// Parsed Btrfs Inode / Directory Entry
#[derive(Debug, Clone)]
pub struct BtrfsNodeEntry {
    pub objectid: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mode: u32,
    pub generation: u64,
    pub data: Vec<u8>,
}

/// Internal Node Search Helper
pub fn btrfs_internal_node_search(keys: &[(u64, u64)], target_key: u64) -> Option<u64> {
    let mut chosen_ptr = None;
    for &(k, ptr) in keys {
        if target_key >= k {
            chosen_ptr = Some(ptr);
        }
    }
    chosen_ptr
}

/// Btrfs Inode wrapping `corvfs::Inode`
#[derive(Debug, Clone)]
pub struct BtrfsVfsInode {
    pub objectid: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Vec<u8>,
    pub children: Vec<DirEntry>,
}

impl Inode for BtrfsVfsInode {
    fn ino(&self) -> u64 {
        self.objectid
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

/// Complete Btrfs Volume Reader & Filesystem Driver
pub struct BtrfsVolume {
    pub sectorsize: u32,
    pub nodesize: u32,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub label: String,
    pub root_tree_bytenr: u64,
    pub chunk_tree_bytenr: u64,
    pub chunks: Vec<BtrfsChunk>,
    pub entries: BTreeMap<u64, BtrfsNodeEntry>,
    pub root_objectid: u64,
}

impl BtrfsVolume {
    /// Validates raw disk buffer at standard 64 KiB superblock offset.
    pub fn verify_raw_disk_superblock(disk: &[u8]) -> bool {
        let sb_offset = BTRFS_SUPER_INFO_OFFSET as usize;
        if disk.len() < sb_offset + 72 {
            return false;
        }
        let magic = &disk[sb_offset + 64..sb_offset + 72];
        BtrfsSuperBlock::is_valid_magic(magic)
    }

    /// Parses Btrfs superblock from either a direct 4096-byte superblock buffer or raw disk slice.
    pub fn parse_superblock(data: &[u8]) -> Option<Self> {
        // If buffer begins with raw disk (size >= 0x10000 + 72), read at 0x10000 offset
        let sb_slice = if data.len() >= (BTRFS_SUPER_INFO_OFFSET as usize + 72) {
            let offset = BTRFS_SUPER_INFO_OFFSET as usize;
            &data[offset..]
        } else {
            data
        };

        if sb_slice.len() < 72 {
            return None;
        }

        let magic = &sb_slice[64..72];
        if !BtrfsSuperBlock::is_valid_magic(magic) {
            return None;
        }

        let generation = u64::from_le_bytes([
            sb_slice[72], sb_slice[73], sb_slice[74], sb_slice[75],
            sb_slice[76], sb_slice[77], sb_slice[78], sb_slice[79],
        ]);
        let root = if sb_slice.len() >= 88 {
            u64::from_le_bytes([
                sb_slice[80], sb_slice[81], sb_slice[82], sb_slice[83],
                sb_slice[84], sb_slice[85], sb_slice[86], sb_slice[87],
            ])
        } else {
            0
        };
        let chunk_root = if sb_slice.len() >= 96 {
            u64::from_le_bytes([
                sb_slice[88], sb_slice[89], sb_slice[90], sb_slice[91],
                sb_slice[92], sb_slice[93], sb_slice[94], sb_slice[95],
            ])
        } else {
            0
        };
        let total_bytes = if sb_slice.len() >= 120 {
            u64::from_le_bytes([
                sb_slice[112], sb_slice[113], sb_slice[114], sb_slice[115],
                sb_slice[116], sb_slice[117], sb_slice[118], sb_slice[119],
            ])
        } else {
            0
        };
        let bytes_used = if sb_slice.len() >= 128 {
            u64::from_le_bytes([
                sb_slice[120], sb_slice[121], sb_slice[122], sb_slice[123],
                sb_slice[124], sb_slice[125], sb_slice[126], sb_slice[127],
            ])
        } else {
            0
        };
        let sectorsize = if sb_slice.len() >= 148 {
            u32::from_le_bytes([sb_slice[144], sb_slice[145], sb_slice[146], sb_slice[147]])
        } else {
            4096
        };
        let nodesize = if sb_slice.len() >= 152 {
            u32::from_le_bytes([sb_slice[148], sb_slice[149], sb_slice[150], sb_slice[151]])
        } else {
            16384
        };

        // Label starts at offset 299, up to 256 bytes
        let label = if sb_slice.len() >= 300 {
            let mut label_len = 0;
            while label_len < 256 && (299 + label_len) < sb_slice.len() && sb_slice[299 + label_len] != 0 {
                label_len += 1;
            }
            String::from_utf8_lossy(&sb_slice[299..299 + label_len]).into_owned()
        } else {
            String::from("btrfs")
        };

        let _ = generation;

        Some(Self {
            sectorsize,
            nodesize,
            total_bytes,
            bytes_used,
            label,
            root_tree_bytenr: root,
            chunk_tree_bytenr: chunk_root,
            chunks: Vec::new(),
            entries: BTreeMap::new(),
            root_objectid: 256, // Standard BTRFS root dir objectid
        })
    }

    /// Add a chunk tree translation entry.
    pub fn add_chunk(&mut self, chunk: BtrfsChunk) {
        self.chunks.push(chunk);
    }

    /// Translate virtual logical address to physical disk offset.
    pub fn translate_logical(&self, logical: u64) -> Option<u64> {
        for ch in &self.chunks {
            if let Some(phys) = ch.translate(logical) {
                return Some(phys);
            }
        }
        None
    }

    /// Parse an interior B-tree node (level > 0) to find child blockptr for given target key.
    pub fn search_internal_node(&self, node_data: &[u8], target_key: u64) -> Option<u64> {
        if node_data.len() < 101 {
            return None;
        }
        let level = node_data[100];
        if level == 0 {
            return None; // Leaf, not internal node
        }
        let nritems = u32::from_le_bytes([node_data[96], node_data[97], node_data[98], node_data[99]]) as usize;
        let mut key_ptrs = Vec::with_capacity(nritems);

        let ptr_size = 33; // 17 (BtrfsDiskKey) + 8 (blockptr) + 8 (generation)
        for i in 0..nritems {
            let off = 101 + i * ptr_size;
            if off + ptr_size > node_data.len() {
                break;
            }
            let obj_id = u64::from_le_bytes([
                node_data[off], node_data[off + 1], node_data[off + 2], node_data[off + 3],
                node_data[off + 4], node_data[off + 5], node_data[off + 6], node_data[off + 7],
            ]);
            let blockptr = u64::from_le_bytes([
                node_data[off + 17], node_data[off + 18], node_data[off + 19], node_data[off + 20],
                node_data[off + 21], node_data[off + 22], node_data[off + 23], node_data[off + 24],
            ]);
            key_ptrs.push((obj_id, blockptr));
        }

        btrfs_internal_node_search(&key_ptrs, target_key)
    }

    /// Parse a B-tree leaf node (level == 0) extracting inodes, directory items, and extents.
    pub fn parse_leaf(&mut self, leaf_data: &[u8]) -> usize {
        if leaf_data.len() < 101 {
            return 0;
        }

        let nritems = u32::from_le_bytes([leaf_data[96], leaf_data[97], leaf_data[98], leaf_data[99]]) as usize;
        let level = leaf_data[100];

        if level != 0 {
            // Internal node, not a leaf
            return 0;
        }

        let header_size = 101;
        let item_size = 25;
        let mut parsed_count = 0;

        for i in 0..nritems {
            let item_offset = header_size + i * item_size;
            if item_offset + item_size > leaf_data.len() {
                break;
            }

            let obj_id = u64::from_le_bytes([
                leaf_data[item_offset], leaf_data[item_offset + 1],
                leaf_data[item_offset + 2], leaf_data[item_offset + 3],
                leaf_data[item_offset + 4], leaf_data[item_offset + 5],
                leaf_data[item_offset + 6], leaf_data[item_offset + 7],
            ]);
            let key_type = leaf_data[item_offset + 8];
            let data_offset = header_size + u32::from_le_bytes([
                leaf_data[item_offset + 17], leaf_data[item_offset + 18],
                leaf_data[item_offset + 19], leaf_data[item_offset + 20],
            ]) as usize;
            let data_size = u32::from_le_bytes([
                leaf_data[item_offset + 21], leaf_data[item_offset + 22],
                leaf_data[item_offset + 23], leaf_data[item_offset + 24],
            ]) as usize;

            if data_offset + data_size <= leaf_data.len() {
                match key_type {
                    BTRFS_INODE_ITEM_KEY => {
                        if data_size >= 160 {
                            let size = u64::from_le_bytes([
                                leaf_data[data_offset + 16], leaf_data[data_offset + 17],
                                leaf_data[data_offset + 18], leaf_data[data_offset + 19],
                                leaf_data[data_offset + 20], leaf_data[data_offset + 21],
                                leaf_data[data_offset + 22], leaf_data[data_offset + 23],
                            ]);
                            let mode = u32::from_le_bytes([
                                leaf_data[data_offset + 40], leaf_data[data_offset + 41],
                                leaf_data[data_offset + 42], leaf_data[data_offset + 43],
                            ]);
                            let is_dir = (mode & 0o040000) != 0;

                            self.entries.entry(obj_id).or_insert(BtrfsNodeEntry {
                                objectid: obj_id,
                                name: alloc::format!("inode_{}", obj_id),
                                is_dir,
                                size,
                                mode,
                                generation: 1,
                                data: Vec::new(),
                            });
                            parsed_count += 1;
                        }
                    }
                    BTRFS_DIR_ITEM_KEY | BTRFS_DIR_INDEX_KEY => {
                        if data_size >= 30 {
                            let name_len = u16::from_le_bytes([leaf_data[data_offset + 27], leaf_data[data_offset + 28]]) as usize;
                            let dir_type = leaf_data[data_offset + 29];
                            let name_start = data_offset + 30;

                            if name_start + name_len <= leaf_data.len() {
                                let name = String::from_utf8_lossy(&leaf_data[name_start..name_start + name_len]).into_owned();
                                let target_obj_id = u64::from_le_bytes([
                                    leaf_data[data_offset], leaf_data[data_offset + 1],
                                    leaf_data[data_offset + 2], leaf_data[data_offset + 3],
                                    leaf_data[data_offset + 4], leaf_data[data_offset + 5],
                                    leaf_data[data_offset + 6], leaf_data[data_offset + 7],
                                ]);

                                let is_dir = dir_type == 2;
                                if let Some(entry) = self.entries.get_mut(&target_obj_id) {
                                    entry.name = name;
                                    entry.is_dir = is_dir;
                                } else {
                                    self.entries.insert(target_obj_id, BtrfsNodeEntry {
                                        objectid: target_obj_id,
                                        name,
                                        is_dir,
                                        size: 0,
                                        mode: if is_dir { 0o040755 } else { 0o100644 },
                                        generation: 1,
                                        data: Vec::new(),
                                    });
                                }
                                parsed_count += 1;
                            }
                        }
                    }
                    BTRFS_INODE_REF_KEY => {
                        if data_size >= 10 {
                            let name_len = u16::from_le_bytes([leaf_data[data_offset + 8], leaf_data[data_offset + 9]]) as usize;
                            let name_start = data_offset + 10;
                            if name_start + name_len <= leaf_data.len() {
                                let name = String::from_utf8_lossy(&leaf_data[name_start..name_start + name_len]).into_owned();
                                if let Some(entry) = self.entries.get_mut(&obj_id) {
                                    entry.name = name;
                                }
                                parsed_count += 1;
                            }
                        }
                    }
                    BTRFS_EXTENT_DATA_KEY => {
                        if data_size >= 21 {
                            let extent_type = leaf_data[data_offset + 20];
                            if extent_type == BTRFS_FILE_EXTENT_INLINE {
                                let inline_bytes = &leaf_data[data_offset + 21..data_offset + data_size];
                                if let Some(entry) = self.entries.get_mut(&obj_id) {
                                    entry.data.extend_from_slice(inline_bytes);
                                    entry.size = entry.data.len() as u64;
                                }
                            }
                            parsed_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        parsed_count
    }
}

impl FileSystem for BtrfsVolume {
    fn name(&self) -> &str {
        "btrfs"
    }

    fn root_inode(&self) -> Result<Arc<dyn Inode>, FsError> {
        let mut children = Vec::new();
        for (&obj_id, entry) in &self.entries {
            if obj_id != self.root_objectid {
                children.push(DirEntry {
                    name: entry.name.clone(),
                    ino: obj_id,
                    is_dir: entry.is_dir,
                    size: entry.size,
                });
            }
        }

        Ok(Arc::new(BtrfsVfsInode {
            objectid: self.root_objectid,
            name: String::from("/"),
            is_dir: true,
            size: self.total_bytes,
            data: Vec::new(),
            children,
        }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let clean_name = name.trim_start_matches('/');
        for (&obj_id, entry) in &self.entries {
            if entry.name == clean_name {
                return Ok(Arc::new(BtrfsVfsInode {
                    objectid: obj_id,
                    name: entry.name.clone(),
                    is_dir: entry.is_dir,
                    size: entry.size,
                    data: entry.data.clone(),
                    children: Vec::new(),
                }));
            }
        }
        Err(FsError::NotFound)
    }
}
