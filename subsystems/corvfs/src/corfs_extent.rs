//! CorOS VFS Module: `corfs_extent`
//!
//! Original CorOS extent-based journaled block filesystem (`CorFsSuperblock`,
//! `CorFsExtent`, `CorFsExtentHeader`, `CorFsInode`, binary-searched extent mapping
//! with contiguous coalescing, and bitmap-backed contiguous physical block allocator).

use alloc::vec::Vec;

/// Magic signature `"CORFSv1\0"` (`0x00317653_46524F43` in little-endian).
pub const CORFS_SUPER_MAGIC: u64 = 0x0031_7653_4652_4F43;
/// Magic signature for an inode's extent tree header (`0xC0EF`).
pub const CORFS_EXTENT_MAGIC: u16 = 0xC0EF;
/// Standard CorFS block size (4096 bytes).
pub const CORFS_BLOCK_SIZE: u64 = 4096;

/// On-disk superblock descriptor for a CorFS volume.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorFsSuperblock {
    pub magic: u64,
    pub version_major: u16,
    pub version_minor: u16,
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub journal_start_block: u64,
    pub journal_block_count: u32,
    pub root_inode_num: u64,
    pub volume_uuid: [u8; 16],
    pub volume_label: [u8; 16],
}

impl CorFsSuperblock {
    /// Initializes a formatted CorFS superblock for a volume with `total_blocks` 4 KiB blocks.
    pub fn format_new(total_blocks: u64, total_inodes: u64, label: &[u8]) -> Option<Self> {
        if total_blocks < 128 || total_inodes < 16 {
            return None;
        }
        let mut volume_label = [0u8; 16];
        let copy_len = label.len().min(16);
        volume_label[..copy_len].copy_from_slice(&label[..copy_len]);

        // Reserve block 0 (superblock), blocks 1..=32 (journal), block 33..=40 (inode & block bitmaps)
        let reserved_blocks = 41u64;
        Some(Self {
            magic: CORFS_SUPER_MAGIC,
            version_major: 1,
            version_minor: 0,
            block_size: CORFS_BLOCK_SIZE as u32,
            total_blocks,
            free_blocks: total_blocks - reserved_blocks,
            total_inodes,
            free_inodes: total_inodes - 2, // Inodes 1 (journal) & 2 (root dir) pre-allocated
            journal_start_block: 1,
            journal_block_count: 32,
            root_inode_num: 2,
            volume_uuid: [
                0xC0, 0x20, 0x56, 0x46, 0x53, 0x01, 0x4E, 0x7A,
                0x9B, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ],
            volume_label,
        })
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.magic == CORFS_SUPER_MAGIC
            && self.block_size == (CORFS_BLOCK_SIZE as u32)
            && self.free_blocks <= self.total_blocks
            && self.root_inode_num >= 2
    }
}

/// Header preceding an array of `CorFsExtent` descriptors inside an inode or indirect extent block.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorFsExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max_entries: u16,
    pub depth: u16,
    pub generation: u32,
}

impl CorFsExtentHeader {
    pub const fn new_leaf(max_entries: u16) -> Self {
        Self {
            magic: CORFS_EXTENT_MAGIC,
            entries: 0,
            max_entries,
            depth: 0,
            generation: 1,
        }
    }
}

/// Contiguous mapping of `[logical_block .. logical_block + block_count)` to `[physical_block ..]`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorFsExtent {
    pub logical_block: u32,
    pub block_count: u16,
    pub flags: u16,
    pub physical_block: u64,
}

impl CorFsExtent {
    pub const FLAG_UNWRITTEN_PREALLOC: u16 = 1 << 0;

    #[inline]
    pub const fn end_logical_block(&self) -> u32 {
        self.logical_block.saturating_add(self.block_count as u32)
    }

    #[inline]
    pub const fn end_physical_block(&self) -> u64 {
        self.physical_block.saturating_add(self.block_count as u64)
    }

    #[inline]
    pub const fn contains_logical(&self, lblock: u32) -> bool {
        lblock >= self.logical_block && lblock < self.end_logical_block()
    }
}

/// CorFS Inode structure with inline sorted extent tree for O(log N) block translation.
#[derive(Clone, Debug)]
pub struct CorFsInode {
    pub ino: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size_bytes: u64,
    pub nlink: u32,
    pub flags: u32,
    pub extent_header: CorFsExtentHeader,
    pub extents: Vec<CorFsExtent>,
}

impl CorFsInode {
    pub const MAX_INLINE_EXTENTS: u16 = 64;

    pub fn new(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            mode,
            uid,
            gid,
            size_bytes: 0,
            nlink: 1,
            flags: 0,
            extent_header: CorFsExtentHeader::new_leaf(Self::MAX_INLINE_EXTENTS),
            extents: Vec::new(),
        }
    }

    /// Inserts or merges a contiguous extent into the sorted extent list.
    pub fn insert_extent(&mut self, new_ext: CorFsExtent) -> Result<(), &'static str> {
        if new_ext.block_count == 0 {
            return Err("Extent block_count must be non-zero");
        }

        // Binary search for insertion point by logical_block
        let pos = match self
            .extents
            .binary_search_by_key(&new_ext.logical_block, |e| e.logical_block)
        {
            Ok(_) => return Err("Overlapping logical block extent"),
            Err(idx) => idx,
        };

        // Check overlap with predecessor
        if pos > 0 && self.extents[pos - 1].end_logical_block() > new_ext.logical_block {
            return Err("Extent overlaps with preceding extent");
        }
        // Check overlap with successor
        if pos < self.extents.len() && new_ext.end_logical_block() > self.extents[pos].logical_block {
            return Err("Extent overlaps with succeeding extent");
        }

        // Coalesce with preceding extent if logically and physically contiguous and flags match
        if pos > 0 {
            let prev = &mut self.extents[pos - 1];
            let combined_len = (prev.block_count as u32) + (new_ext.block_count as u32);
            if prev.end_logical_block() == new_ext.logical_block
                && prev.end_physical_block() == new_ext.physical_block
                && prev.flags == new_ext.flags
                && combined_len <= (u16::MAX as u32)
            {
                prev.block_count = combined_len as u16;
                self.extent_header.generation = self.extent_header.generation.wrapping_add(1);
                return Ok(());
            }
        }

        if (self.extents.len() as u16) >= self.extent_header.max_entries {
            return Err("Extent tree node capacity exhausted");
        }

        self.extents.insert(pos, new_ext);
        self.extent_header.entries = self.extents.len() as u16;
        self.extent_header.generation = self.extent_header.generation.wrapping_add(1);
        Ok(())
    }

    /// Translates a file byte offset into `(physical_block_lba, byte_offset_within_block)` using O(log N) binary search.
    pub fn map_byte_offset(&self, file_offset: u64) -> Option<(u64, usize)> {
        let logical_block = (file_offset / CORFS_BLOCK_SIZE) as u32;
        let in_block_offset = (file_offset % CORFS_BLOCK_SIZE) as usize;

        let idx = match self
            .extents
            .binary_search_by_key(&logical_block, |e| e.logical_block)
        {
            Ok(exact) => exact,
            Err(0) => return None,
            Err(ins) => ins - 1,
        };

        let ext = &self.extents[idx];
        if ext.contains_logical(logical_block) {
            let delta = (logical_block - ext.logical_block) as u64;
            Some((ext.physical_block + delta, in_block_offset))
        } else {
            None // Sparse hole or beyond allocated blocks
        }
    }

    /// Total physical 4 KiB blocks allocated to this inode across all extents.
    pub fn total_allocated_blocks(&self) -> u64 {
        self.extents.iter().map(|e| e.block_count as u64).sum()
    }
}

/// Bitmap-backed physical block allocator preferring contiguous multi-block extents.
pub struct CorFsBlockAllocator {
    bitmap: Vec<u64>,
    total_blocks: u64,
    free_blocks: u64,
}

impl CorFsBlockAllocator {
    pub fn new(total_blocks: u64, reserved_prefix_blocks: u64) -> Self {
        let words = ((total_blocks + 63) / 64) as usize;
        let mut bitmap = Vec::with_capacity(words);
        for _ in 0..words {
            bitmap.push(0u64);
        }

        let mut alloc = Self {
            bitmap,
            total_blocks,
            free_blocks: total_blocks,
        };

        for b in 0..reserved_prefix_blocks.min(total_blocks) {
            alloc.set_bit(b);
        }
        alloc
    }

    #[inline]
    fn is_set(&self, block: u64) -> bool {
        let word = (block / 64) as usize;
        let bit = block % 64;
        (self.bitmap[word] & (1u64 << bit)) != 0
    }

    #[inline]
    fn set_bit(&mut self, block: u64) {
        let word = (block / 64) as usize;
        let bit = block % 64;
        if (self.bitmap[word] & (1u64 << bit)) == 0 {
            self.bitmap[word] |= 1u64 << bit;
            self.free_blocks = self.free_blocks.saturating_sub(1);
        }
    }

    #[inline]
    fn clear_bit(&mut self, block: u64) {
        let word = (block / 64) as usize;
        let bit = block % 64;
        if (self.bitmap[word] & (1u64 << bit)) != 0 {
            self.bitmap[word] &= !(1u64 << bit);
            self.free_blocks = self.free_blocks.saturating_add(1);
        }
    }

    /// Allocates up to `requested_count` contiguous blocks, returning `(physical_start_block, allocated_count)`.
    pub fn allocate_extent(&mut self, requested_count: u16) -> Option<(u64, u16)> {
        if requested_count == 0 || self.free_blocks == 0 {
            return None;
        }

        let mut run_start = 0u64;
        let mut run_len = 0u16;
        let mut best_start = 0u64;
        let mut best_len = 0u16;

        for blk in 0..self.total_blocks {
            if !self.is_set(blk) {
                if run_len == 0 {
                    run_start = blk;
                }
                run_len += 1;
                if run_len == requested_count {
                    for b in run_start..run_start + (run_len as u64) {
                        self.set_bit(b);
                    }
                    return Some((run_start, run_len));
                }
                if run_len > best_len {
                    best_start = run_start;
                    best_len = run_len;
                }
            } else {
                run_len = 0;
            }
        }

        if best_len > 0 {
            for b in best_start..best_start + (best_len as u64) {
                self.set_bit(b);
            }
            Some((best_start, best_len))
        } else {
            None
        }
    }

    /// Frees a contiguous physical block range back to the bitmap.
    pub fn free_extent(&mut self, physical_start: u64, count: u16) {
        let end = (physical_start + (count as u64)).min(self.total_blocks);
        for b in physical_start..end {
            self.clear_bit(b);
        }
    }

    #[inline]
    pub const fn free_blocks(&self) -> u64 {
        self.free_blocks
    }
}

/// Self-test suite for `corfs_extent`.
pub fn verify_vfs_corfs_extent() -> u32 {
    let mut passed = 0u32;

    if let Some(sb) = CorFsSuperblock::format_new(4096, 1024, b"COROS_ROOT") {
        if sb.is_valid() && sb.free_blocks == 4096 - 41 {
            passed += 1;
        }
    }

    let mut allocator = CorFsBlockAllocator::new(512, 41);
    let mut inode = CorFsInode::new(10, 0o644, 0, 0);

    // Allocate two contiguous 8-block runs and verify automatic extent coalescing
    if let (Some((p1, c1)), Some((p2, c2))) = (allocator.allocate_extent(8), allocator.allocate_extent(8)) {
        let _ = inode.insert_extent(CorFsExtent {
            logical_block: 0,
            block_count: c1,
            flags: 0,
            physical_block: p1,
        });
        let _ = inode.insert_extent(CorFsExtent {
            logical_block: 8,
            block_count: c2,
            flags: 0,
            physical_block: p2,
        });

        // Because p1 == 41..49 and p2 == 49..57 are physically & logically contiguous, they coalesce into 1 extent of 16 blocks!
        if inode.extents.len() == 1 && inode.total_allocated_blocks() == 16 {
            passed += 1;
        }
    }

    // Add a non-contiguous sparse extent at logical block 32 (leaving logical blocks 16..32 as a sparse hole)
    if let Some((p3, c3)) = allocator.allocate_extent(4) {
        let _ = inode.insert_extent(CorFsExtent {
            logical_block: 32,
            block_count: c3,
            flags: 0,
            physical_block: p3,
        });
        // Byte offset inside logical block 10 (10 * 4096 + 512) -> physical block 41 + 10 = 51, offset 512
        if inode.map_byte_offset(10 * 4096 + 512) == Some((51, 512))
            && inode.map_byte_offset(20 * 4096).is_none()
            && inode.map_byte_offset(33 * 4096 + 128) == Some((p3 + 1, 128))
        {
            passed += 1;
        }
    }

    allocator.free_extent(41, 16);
    if allocator.free_blocks() == 512 - 41 - 4 {
        passed += 1;
    }

    passed
}
