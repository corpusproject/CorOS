//! High-Performance Inode, Dentry & Page Cache Architecture for CorOS VFS.
//! 100% in-house implementation featuring:
//! - Dentry Cache (dcache) with fast path lookup and LRU eviction
//! - Inode Cache (icache) with reference counting and dirty flag tracking
//! - Page Cache with 4096-byte page frames, dirty state writeback queues,
//!   and coherent buffer management.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_CACHED_PAGES: usize = 1024; // 4 MiB page cache pool

// -----------------------------------------------------------------------------
// Dentry (Directory Entry) Cache
// -----------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DentryType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

#[derive(Clone, Debug)]
pub struct Dentry {
    pub name: String,
    pub inode_number: u64,
    pub parent_inode: u64,
    pub dentry_type: DentryType,
    pub access_counter: u64,
}

pub struct DentryCache {
    entries: BTreeMap<String, Dentry>,
    max_entries: usize,
    lookup_hits: u64,
    lookup_misses: u64,
}

impl DentryCache {
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
            lookup_hits: 0,
            lookup_misses: 0,
        }
    }

    fn make_key(parent_inode: u64, name: &str) -> String {
        let mut key = String::new();
        let mut n = parent_inode;
        if n == 0 {
            key.push('0');
        } else {
            let mut buf = [0u8; 20];
            let mut i = 0;
            while n > 0 {
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
                i += 1;
            }
            while i > 0 {
                i -= 1;
                key.push(buf[i] as char);
            }
        }
        key.push(':');
        key.push_str(name);
        key
    }

    pub fn lookup(&mut self, parent_inode: u64, name: &str) -> Option<Dentry> {
        let key = Self::make_key(parent_inode, name);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.access_counter = entry.access_counter.saturating_add(1);
            self.lookup_hits += 1;
            Some(entry.clone())
        } else {
            self.lookup_misses += 1;
            None
        }
    }

    pub fn insert(&mut self, parent_inode: u64, name: &str, inode_number: u64, dentry_type: DentryType) {
        if self.entries.len() >= self.max_entries {
            // Evict entry with lowest access_counter
            let mut min_key = None;
            let mut min_acc = u64::MAX;
            for (k, v) in self.entries.iter() {
                if v.access_counter < min_acc {
                    min_acc = v.access_counter;
                    min_key = Some(k.clone());
                }
            }
            if let Some(k) = min_key {
                self.entries.remove(&k);
            }
        }

        let key = Self::make_key(parent_inode, name);
        self.entries.insert(key, Dentry {
            name: String::from(name),
            inode_number,
            parent_inode,
            dentry_type,
            access_counter: 1,
        });
    }

    pub fn remove(&mut self, parent_inode: u64, name: &str) {
        let key = Self::make_key(parent_inode, name);
        self.entries.remove(&key);
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (self.lookup_hits, self.lookup_misses, self.entries.len())
    }
}

// -----------------------------------------------------------------------------
// Inode Cache (icache)
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct CachedInode {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub blocks: u64,
    pub ref_count: u32,
    pub is_dirty: bool,
}

pub struct InodeCache {
    nodes: BTreeMap<u64, CachedInode>,
}

impl InodeCache {
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }

    pub fn get(&mut self, ino: u64) -> Option<&mut CachedInode> {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.ref_count = node.ref_count.saturating_add(1);
            Some(node)
        } else {
            None
        }
    }

    pub fn put(&mut self, ino: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            if node.ref_count > 0 {
                node.ref_count -= 1;
            }
        }
    }

    pub fn insert(&mut self, inode: CachedInode) {
        self.nodes.insert(inode.ino, inode);
    }

    pub fn mark_dirty(&mut self, ino: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.is_dirty = true;
        }
    }

    pub fn collect_dirty(&self) -> Vec<u64> {
        let mut dirty = Vec::new();
        for (ino, node) in self.nodes.iter() {
            if node.is_dirty {
                dirty.push(*ino);
            }
        }
        dirty
    }
}

// -----------------------------------------------------------------------------
// Page Cache
// -----------------------------------------------------------------------------
#[derive(Clone)]
pub struct PageFrame {
    pub ino: u64,
    pub page_index: u64, // (file_offset / PAGE_SIZE)
    pub is_dirty: bool,
    pub data: [u8; PAGE_SIZE],
}

pub struct PageCache {
    pages: BTreeMap<(u64, u64), PageFrame>,
    max_pages: usize,
    read_hits: u64,
    read_misses: u64,
}

impl PageCache {
    pub const fn new(max_pages: usize) -> Self {
        Self {
            pages: BTreeMap::new(),
            max_pages,
            read_hits: 0,
            read_misses: 0,
        }
    }

    pub fn read_page(&mut self, ino: u64, page_index: u64, out: &mut [u8]) -> bool {
        if let Some(frame) = self.pages.get(&(ino, page_index)) {
            let copy_len = out.len().min(PAGE_SIZE);
            out[..copy_len].copy_from_slice(&frame.data[..copy_len]);
            self.read_hits += 1;
            true
        } else {
            self.read_misses += 1;
            false
        }
    }

    pub fn write_page(&mut self, ino: u64, page_index: u64, data: &[u8], offset_in_page: usize) {
        if self.pages.len() >= self.max_pages {
            // Evict first non-dirty page
            let mut evict_key = None;
            for (key, frame) in self.pages.iter() {
                if !frame.is_dirty {
                    evict_key = Some(*key);
                    break;
                }
            }
            if let Some(key) = evict_key {
                self.pages.remove(&key);
            }
        }

        let entry = self.pages.entry((ino, page_index)).or_insert_with(|| PageFrame {
            ino,
            page_index,
            is_dirty: false,
            data: [0u8; PAGE_SIZE],
        });

        let write_len = data.len().min(PAGE_SIZE - offset_in_page);
        entry.data[offset_in_page..offset_in_page + write_len].copy_from_slice(&data[..write_len]);
        entry.is_dirty = true;
    }

    pub fn flush_dirty_pages<F>(&mut self, mut flush_fn: F)
    where
        F: FnMut(u64, u64, &[u8]) -> Result<(), ()>,
    {
        for ((ino, page_index), frame) in self.pages.iter_mut() {
            if frame.is_dirty {
                if flush_fn(*ino, *page_index, &frame.data).is_ok() {
                    frame.is_dirty = false;
                }
            }
        }
    }

    pub fn invalidate_inode(&mut self, ino: u64) {
        let keys_to_remove: Vec<(u64, u64)> = self.pages.keys()
            .filter(|(k_ino, _)| *k_ino == ino)
            .copied()
            .collect();
        for k in keys_to_remove {
            self.pages.remove(&k);
        }
    }
}
