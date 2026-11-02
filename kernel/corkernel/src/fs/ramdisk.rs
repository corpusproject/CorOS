//! CorOS Memory-Backed RAMDisk & RamFS Subsystem (`ramdisk.rs`)
//!
//! Provides ultra-high-speed memory block devices and file systems:
//! - RamDisk: Fixed-size block storage allocated in kernel memory (512-byte / 4096-byte sectors)
//! - Direct block read/write with boundary checking
//! - In-memory directory tree with fast path lookup and file modification
//! - RamFs: Lightweight POSIX-like in-memory filesystem with permissions and timestamps

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const RAMDISK_SECTOR_SIZE: usize = 512;
pub const DEFAULT_RAMDISK_SECTORS: usize = 2048; // 1 MiB default

/// Error types for RAMDisk operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamDiskError {
    SectorOutOfBounds,
    BufferTooSmall,
    WriteProtected,
    OutOfMemory,
    FileNotFound,
    FileAlreadyExists,
    NotADirectory,
    IsADirectory,
}

/// In-Memory Block Storage Device
pub struct RamDiskDevice {
    pub name: String,
    pub sector_size: usize,
    pub sector_count: usize,
    pub read_only: bool,
    data: Vec<u8>,
}

impl RamDiskDevice {
    pub fn new(name: &str, sectors: usize, sector_size: usize) -> Self {
        let total_bytes = sectors * sector_size;
        let mut data = Vec::with_capacity(total_bytes);
        data.resize(total_bytes, 0);

        Self {
            name: String::from(name),
            sector_size,
            sector_count: sectors,
            read_only: false,
            data,
        }
    }

    /// Read raw sector
    pub fn read_sector(&self, lba: usize, buf: &mut [u8]) -> Result<(), RamDiskError> {
        if lba >= self.sector_count {
            return Err(RamDiskError::SectorOutOfBounds);
        }
        if buf.len() < self.sector_size {
            return Err(RamDiskError::BufferTooSmall);
        }

        let offset = lba * self.sector_size;
        buf[..self.sector_size].copy_from_slice(&self.data[offset..offset + self.sector_size]);
        Ok(())
    }

    /// Write raw sector
    pub fn write_sector(&mut self, lba: usize, buf: &[u8]) -> Result<(), RamDiskError> {
        if self.read_only {
            return Err(RamDiskError::WriteProtected);
        }
        if lba >= self.sector_count {
            return Err(RamDiskError::SectorOutOfBounds);
        }
        if buf.len() < self.sector_size {
            return Err(RamDiskError::BufferTooSmall);
        }

        let offset = lba * self.sector_size;
        self.data[offset..offset + self.sector_size].copy_from_slice(&buf[..self.sector_size]);
        Ok(())
    }

    pub fn total_bytes(&self) -> usize {
        self.data.len()
    }
}

/// An Inode inside the RamFs
#[derive(Debug, Clone)]
pub struct RamFsInode {
    pub id: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: usize,
    pub mode: u32,
    pub created_at: u64,
    pub modified_at: u64,
    pub content: Vec<u8>,
    pub children: BTreeMap<String, u64>,
    pub parent_id: u64,
}

/// High-speed in-memory filesystem (RamFs)
pub struct RamFs {
    inodes: BTreeMap<u64, RamFsInode>,
    next_inode_id: u64,
    root_id: u64,
}

impl RamFs {
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        let root = RamFsInode {
            id: 1,
            name: String::from("/"),
            is_dir: true,
            size: 0,
            mode: 0o040755,
            created_at: 0,
            modified_at: 0,
            content: Vec::new(),
            children: BTreeMap::new(),
            parent_id: 1,
        };
        inodes.insert(1, root);

        Self {
            inodes,
            next_inode_id: 2,
            root_id: 1,
        }
    }

    /// Canonical path split
    fn split_path<'a>(path: &'a str) -> Vec<&'a str> {
        path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect()
    }

    /// Traverse path to find inode ID
    pub fn lookup(&self, path: &str) -> Option<u64> {
        if path == "/" || path.is_empty() {
            return Some(self.root_id);
        }

        let parts = Self::split_path(path);
        let mut cur_id = self.root_id;

        for part in parts {
            let inode = self.inodes.get(&cur_id)?;
            if !inode.is_dir {
                return None;
            }
            cur_id = *inode.children.get(part)?;
        }

        Some(cur_id)
    }

    /// Create file or directory
    pub fn create_file(&mut self, path: &str, content: &[u8], is_dir: bool, now: u64) -> Result<u64, RamDiskError> {
        let parts = Self::split_path(path);
        if parts.is_empty() {
            return Err(RamDiskError::FileAlreadyExists);
        }

        let filename = parts[parts.len() - 1];
        let parent_parts = &parts[..parts.len() - 1];

        // Resolve parent inode
        let mut parent_id = self.root_id;
        for &p in parent_parts {
            let cur_node = self.inodes.get(&parent_id).ok_or(RamDiskError::FileNotFound)?;
            if !cur_node.is_dir {
                return Err(RamDiskError::NotADirectory);
            }
            parent_id = *cur_node.children.get(p).ok_or(RamDiskError::FileNotFound)?;
        }

        // Check if file already exists in parent
        {
            let parent_node = self.inodes.get(&parent_id).unwrap();
            if parent_node.children.contains_key(filename) {
                return Err(RamDiskError::FileAlreadyExists);
            }
        }

        let new_id = self.next_inode_id;
        self.next_inode_id += 1;

        let new_inode = RamFsInode {
            id: new_id,
            name: String::from(filename),
            is_dir,
            size: content.len(),
            mode: if is_dir { 0o040755 } else { 0o100644 },
            created_at: now,
            modified_at: now,
            content: content.to_vec(),
            children: BTreeMap::new(),
            parent_id,
        };

        self.inodes.insert(new_id, new_inode);

        // Add to parent's children
        if let Some(parent_node) = self.inodes.get_mut(&parent_id) {
            parent_node.children.insert(String::from(filename), new_id);
            parent_node.modified_at = now;
        }

        Ok(new_id)
    }

    /// Read file content
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, RamDiskError> {
        let id = self.lookup(path).ok_or(RamDiskError::FileNotFound)?;
        let inode = self.inodes.get(&id).unwrap();
        if inode.is_dir {
            return Err(RamDiskError::IsADirectory);
        }
        Ok(inode.content.clone())
    }

    /// Write file content
    pub fn write_file(&mut self, path: &str, data: &[u8], now: u64) -> Result<(), RamDiskError> {
        let id = self.lookup(path).ok_or(RamDiskError::FileNotFound)?;
        let inode = self.inodes.get_mut(&id).unwrap();
        if inode.is_dir {
            return Err(RamDiskError::IsADirectory);
        }
        inode.content = data.to_vec();
        inode.size = data.len();
        inode.modified_at = now;
        Ok(())
    }

    /// List directory entries
    pub fn list_directory(&self, path: &str) -> Result<Vec<(String, bool, usize)>, RamDiskError> {
        let id = self.lookup(path).ok_or(RamDiskError::FileNotFound)?;
        let inode = self.inodes.get(&id).unwrap();
        if !inode.is_dir {
            return Err(RamDiskError::NotADirectory);
        }

        let mut list = Vec::new();
        for (name, &child_id) in &inode.children {
            if let Some(child) = self.inodes.get(&child_id) {
                list.push((name.clone(), child.is_dir, child.size));
            }
        }
        Ok(list)
    }
}
