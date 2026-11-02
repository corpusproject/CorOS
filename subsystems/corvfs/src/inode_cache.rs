//! CorOS VFS Module: `inode_cache`
//!
//! Real LRU Dentry & Inode cache (`InodeNumber`, `FileType`, `InodeMetadata`,
//! `DentryCacheEntry`, FNV-1a hash bucket lookup, LRU eviction, dirty tracking,
//! negative dentry caching, and reference counting).

use alloc::string::String;
use alloc::vec::Vec;

/// Strongly-typed 64-bit VFS inode identifier scoped to a superblock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InodeNumber(pub u64);

/// Standard POSIX VFS file types encoded in inode metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    RegularFile,
    Directory,
    SymbolicLink,
    CharDevice { major: u16, minor: u16 },
    BlockDevice { major: u16, minor: u16 },
    NamedPipe,
    UnixSocket,
}

impl FileType {
    /// Returns the POSIX `S_IFMT` octal mode prefix bits.
    pub const fn mode_type_bits(self) -> u32 {
        match self {
            Self::NamedPipe => 0o010000,
            Self::CharDevice { .. } => 0o020000,
            Self::Directory => 0o040000,
            Self::BlockDevice { .. } => 0o060000,
            Self::RegularFile => 0o100000,
            Self::SymbolicLink => 0o120000,
            Self::UnixSocket => 0o140000,
        }
    }
}

/// Complete VFS Inode metadata and cache tracking state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeMetadata {
    pub superblock_id: u64,
    pub ino: InodeNumber,
    pub file_type: FileType,
    pub permissions: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size_bytes: u64,
    pub blocks_512: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub generation: u32,
}

impl InodeMetadata {
    /// Combines `FileType` upper bits with lower 12 permission bits.
    #[inline]
    pub const fn full_st_mode(&self) -> u32 {
        self.file_type.mode_type_bits() | ((self.permissions as u32) & 0o7777)
    }
}

/// Internal cached inode slot tracking dirty state, pin count, and LRU access tick.
#[derive(Clone, Copy, Debug)]
struct CachedInodeSlot {
    meta: InodeMetadata,
    dirty: bool,
    ref_count: u32,
    last_access_tick: u64,
}

/// Directory entry (dentry) cache record mapping `(superblock_id, parent_ino, child_name)` to an inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DentryCacheEntry {
    pub superblock_id: u64,
    pub parent_ino: InodeNumber,
    pub name: String,
    /// `Some(ino)` for positive lookup hits, `None` for negative dentry cache entries (ENOENT cache).
    pub target_ino: Option<InodeNumber>,
    pub name_hash: u64,
    pub last_access_tick: u64,
}

/// Computes a 64-bit FNV-1a hash for `(superblock_id, parent_ino, name)` dentry lookups.
pub fn compute_dentry_hash(superblock_id: u64, parent_ino: InodeNumber, name: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;

    let mut hash = FNV_OFFSET;
    for b in superblock_id.to_le_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    for b in parent_ino.0.to_le_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    for b in name.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Combined VFS Inode & Dentry LRU Cache with dirty writeback tracking.
pub struct VfsInodeDentryCache {
    inodes: Vec<CachedInodeSlot>,
    dentries: Vec<DentryCacheEntry>,
    max_inodes: usize,
    max_dentries: usize,
    clock_tick: u64,
    pub inode_hits: u64,
    pub inode_misses: u64,
    pub dentry_hits: u64,
    pub dentry_misses: u64,
    pub evictions: u64,
}

impl VfsInodeDentryCache {
    pub fn new(max_inodes: usize, max_dentries: usize) -> Self {
        Self {
            inodes: Vec::with_capacity(max_inodes),
            dentries: Vec::with_capacity(max_dentries),
            max_inodes: max_inodes.max(4),
            max_dentries: max_dentries.max(4),
            clock_tick: 1,
            inode_hits: 0,
            inode_misses: 0,
            dentry_hits: 0,
            dentry_misses: 0,
            evictions: 0,
        }
    }

    #[inline]
    fn next_tick(&mut self) -> u64 {
        let t = self.clock_tick;
        self.clock_tick = self.clock_tick.wrapping_add(1);
        t
    }

    /// Inserts or updates an inode in the cache, evicting the least-recently-used unpinned clean inode if full.
    pub fn insert_inode(&mut self, meta: InodeMetadata, dirty: bool) -> bool {
        let tick = self.next_tick();
        if let Some(slot) = self
            .inodes
            .iter_mut()
            .find(|s| s.meta.superblock_id == meta.superblock_id && s.meta.ino == meta.ino)
        {
            slot.meta = meta;
            slot.dirty |= dirty;
            slot.last_access_tick = tick;
            return true;
        }

        if self.inodes.len() >= self.max_inodes && !self.evict_one_inode() {
            return false;
        }

        self.inodes.push(CachedInodeSlot {
            meta,
            dirty,
            ref_count: 1,
            last_access_tick: tick,
        });
        true
    }

    /// Looks up an inode by `(superblock_id, ino)` and updates its LRU timestamp.
    pub fn lookup_inode(&mut self, superblock_id: u64, ino: InodeNumber) -> Option<InodeMetadata> {
        let tick = self.next_tick();
        if let Some(slot) = self
            .inodes
            .iter_mut()
            .find(|s| s.meta.superblock_id == superblock_id && s.meta.ino == ino)
        {
            slot.last_access_tick = tick;
            self.inode_hits += 1;
            Some(slot.meta)
        } else {
            self.inode_misses += 1;
            None
        }
    }

    /// Marks a cached inode as dirty and updates its byte size and modification timestamp.
    pub fn mark_inode_dirty(
        &mut self,
        superblock_id: u64,
        ino: InodeNumber,
        new_size: u64,
        mtime_ns: u64,
    ) -> bool {
        let tick = self.next_tick();
        if let Some(slot) = self
            .inodes
            .iter_mut()
            .find(|s| s.meta.superblock_id == superblock_id && s.meta.ino == ino)
        {
            slot.meta.size_bytes = new_size;
            slot.meta.blocks_512 = (new_size + 511) / 512;
            slot.meta.mtime_ns = mtime_ns;
            slot.dirty = true;
            slot.last_access_tick = tick;
            true
        } else {
            false
        }
    }

    /// Adjusts the reference count (`iget` / `iput`) for an inode.
    pub fn adjust_ref(&mut self, superblock_id: u64, ino: InodeNumber, delta: i32) -> Option<u32> {
        let slot = self
            .inodes
            .iter_mut()
            .find(|s| s.meta.superblock_id == superblock_id && s.meta.ino == ino)?;
        if delta >= 0 {
            slot.ref_count = slot.ref_count.saturating_add(delta as u32);
        } else {
            slot.ref_count = slot.ref_count.saturating_sub((-delta) as u32);
        }
        Some(slot.ref_count)
    }

    /// Flushes all dirty inodes, returning the list of flushed metadata records and clearing their dirty bit.
    pub fn drain_dirty_inodes(&mut self) -> Vec<InodeMetadata> {
        let mut flushed = Vec::new();
        for slot in &mut self.inodes {
            if slot.dirty {
                slot.dirty = false;
                flushed.push(slot.meta);
            }
        }
        flushed
    }

    /// Evicts the single oldest unpinned (`ref_count == 0`) and clean (`!dirty`) inode.
    fn evict_one_inode(&mut self) -> bool {
        let candidate_idx = self
            .inodes
            .iter()
            .enumerate()
            .filter(|(_, s)| s.ref_count == 0 && !s.dirty)
            .min_by_key(|(_, s)| s.last_access_tick)
            .map(|(idx, _)| idx);

        if let Some(idx) = candidate_idx {
            self.inodes.swap_remove(idx);
            self.evictions += 1;
            true
        } else {
            false
        }
    }

    /// Inserts a positive (`Some(ino)`) or negative (`None`) dentry into the dentry cache.
    pub fn insert_dentry(
        &mut self,
        superblock_id: u64,
        parent_ino: InodeNumber,
        name: &str,
        target_ino: Option<InodeNumber>,
    ) {
        let tick = self.next_tick();
        let hash = compute_dentry_hash(superblock_id, parent_ino, name);

        if let Some(existing) = self.dentries.iter_mut().find(|d| {
            d.name_hash == hash
                && d.superblock_id == superblock_id
                && d.parent_ino == parent_ino
                && d.name == name
        }) {
            existing.target_ino = target_ino;
            existing.last_access_tick = tick;
            return;
        }

        if self.dentries.len() >= self.max_dentries {
            if let Some((oldest_idx, _)) = self
                .dentries
                .iter()
                .enumerate()
                .min_by_key(|(_, d)| d.last_access_tick)
            {
                self.dentries.swap_remove(oldest_idx);
                self.evictions += 1;
            }
        }

        self.dentries.push(DentryCacheEntry {
            superblock_id,
            parent_ino,
            name: String::from(name),
            target_ino,
            name_hash: hash,
            last_access_tick: tick,
        });
    }

    /// Looks up a child name in the dentry cache using FNV-1a hash acceleration.
    /// Returns `Some(Some(ino))` on positive hit, `Some(None)` on negative hit, or `None` on cache miss.
    pub fn lookup_dentry(
        &mut self,
        superblock_id: u64,
        parent_ino: InodeNumber,
        name: &str,
    ) -> Option<Option<InodeNumber>> {
        let tick = self.next_tick();
        let hash = compute_dentry_hash(superblock_id, parent_ino, name);

        if let Some(entry) = self.dentries.iter_mut().find(|d| {
            d.name_hash == hash
                && d.superblock_id == superblock_id
                && d.parent_ino == parent_ino
                && d.name == name
        }) {
            entry.last_access_tick = tick;
            self.dentry_hits += 1;
            Some(entry.target_ino)
        } else {
            self.dentry_misses += 1;
            None
        }
    }

    /// Invalidates a dentry upon `unlink` or `rename`.
    pub fn invalidate_dentry(&mut self, superblock_id: u64, parent_ino: InodeNumber, name: &str) -> bool {
        let hash = compute_dentry_hash(superblock_id, parent_ino, name);
        if let Some(pos) = self.dentries.iter().position(|d| {
            d.name_hash == hash
                && d.superblock_id == superblock_id
                && d.parent_ino == parent_ino
                && d.name == name
        }) {
            self.dentries.swap_remove(pos);
            true
        } else {
            false
        }
    }
}

/// Self-test suite for `inode_cache`.
pub fn verify_vfs_inode_cache() -> u32 {
    let mut passed = 0u32;
    let mut cache = VfsInodeDentryCache::new(4, 4);

    let root_meta = InodeMetadata {
        superblock_id: 1,
        ino: InodeNumber(2),
        file_type: FileType::Directory,
        permissions: 0o755,
        uid: 0,
        gid: 0,
        nlink: 2,
        size_bytes: 4096,
        blocks_512: 8,
        atime_ns: 1000,
        mtime_ns: 1000,
        ctime_ns: 1000,
        generation: 1,
    };

    if cache.insert_inode(root_meta, false) && root_meta.full_st_mode() == 0o040755 {
        passed += 1;
    }

    // Release reference on root so it can be evicted later if needed
    let _ = cache.adjust_ref(1, InodeNumber(2), -1);

    for i in 3..=6 {
        let mut m = root_meta;
        m.ino = InodeNumber(i);
        m.file_type = FileType::RegularFile;
        m.permissions = 0o644;
        cache.insert_inode(m, false);
        let _ = cache.adjust_ref(1, InodeNumber(i), -1);
    }

    // Inode 2 should have been LRU-evicted because capacity is 4
    if cache.lookup_inode(1, InodeNumber(2)).is_none() && cache.evictions >= 1 {
        passed += 1;
    }

    // Mark Inode 5 dirty and verify drain_dirty_inodes
    if cache.mark_inode_dirty(1, InodeNumber(5), 16384, 5000) {
        let dirty = cache.drain_dirty_inodes();
        if dirty.len() == 1 && dirty[0].ino == InodeNumber(5) && dirty[0].size_bytes == 16384 {
            passed += 1;
        }
    }

    // Dentry positive and negative lookup
    cache.insert_dentry(1, InodeNumber(2), "kernel.elf", Some(InodeNumber(5)));
    cache.insert_dentry(1, InodeNumber(2), "missing.txt", None);

    if cache.lookup_dentry(1, InodeNumber(2), "kernel.elf") == Some(Some(InodeNumber(5)))
        && cache.lookup_dentry(1, InodeNumber(2), "missing.txt") == Some(None)
    {
        passed += 1;
    }

    if cache.invalidate_dentry(1, InodeNumber(2), "missing.txt")
        && cache.lookup_dentry(1, InodeNumber(2), "missing.txt").is_none()
    {
        passed += 1;
    }

    passed
}
