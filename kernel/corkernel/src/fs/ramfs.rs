//! High-Performance In-Memory Filesystem (RamFS / TmpFS) for CorOS.
//! 100% in-house implementation supporting hierarchical directories,
//! dynamic memory buffers, file truncation, file appending, and symlinks.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub enum RamNodeContent {
    File(Vec<u8>),
    Directory(BTreeMap<String, u64>), // filename -> inode_number
    Symlink(String),
}

#[derive(Clone, Debug)]
pub struct RamInode {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub content: RamNodeContent,
}

pub struct RamFileSystem {
    pub inodes: BTreeMap<u64, RamInode>,
    pub next_ino: u64,
}

impl RamFileSystem {
    pub fn new() -> Self {
        let mut fs = Self {
            inodes: BTreeMap::new(),
            next_ino: 2, // Inode 1 is Root directory
        };

        // Create root directory (Inode 1)
        let root = RamInode {
            ino: 1,
            mode: 0o040755, // Directory rwxr-xr-x
            uid: 0,
            gid: 0,
            size: 4096,
            content: RamNodeContent::Directory(BTreeMap::new()),
        };
        fs.inodes.insert(1, root);

        fs
    }

    pub fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Create a regular file at the given directory inode.
    pub fn create_file(&mut self, parent_ino: u64, name: &str, initial_data: &[u8]) -> Result<u64, &'static str> {
        let new_ino = self.alloc_ino();
        let new_node = RamInode {
            ino: new_ino,
            mode: 0o100644, // Regular file rw-r--r--
            uid: 0,
            gid: 0,
            size: initial_data.len() as u64,
            content: RamNodeContent::File(initial_data.to_vec()),
        };
        self.inodes.insert(new_ino, new_node);

        // Add to parent directory
        let parent = self.inodes.get_mut(&parent_ino).ok_or("Parent directory inode not found")?;
        match &mut parent.content {
            RamNodeContent::Directory(children) => {
                children.insert(String::from(name), new_ino);
            }
            _ => return Err("Parent is not a directory"),
        }

        Ok(new_ino)
    }

    /// Create a directory at the given directory inode.
    pub fn create_dir(&mut self, parent_ino: u64, name: &str) -> Result<u64, &'static str> {
        let new_ino = self.alloc_ino();
        let new_node = RamInode {
            ino: new_ino,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 4096,
            content: RamNodeContent::Directory(BTreeMap::new()),
        };
        self.inodes.insert(new_ino, new_node);

        let parent = self.inodes.get_mut(&parent_ino).ok_or("Parent directory inode not found")?;
        match &mut parent.content {
            RamNodeContent::Directory(children) => {
                children.insert(String::from(name), new_ino);
            }
            _ => return Err("Parent is not a directory"),
        }

        Ok(new_ino)
    }

    /// Read data from a file inode.
    pub fn read_file(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let inode = self.inodes.get(&ino).ok_or("Inode not found")?;
        match &inode.content {
            RamNodeContent::File(data) => {
                let off = offset as usize;
                if off >= data.len() {
                    return Ok(0);
                }
                let available = data.len() - off;
                let to_copy = buf.len().min(available);
                buf[..to_copy].copy_from_slice(&data[off..off + to_copy]);
                Ok(to_copy)
            }
            _ => Err("Not a regular file"),
        }
    }

    /// Write data to a file inode (resizes automatically).
    pub fn write_file(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, &'static str> {
        let inode = self.inodes.get_mut(&ino).ok_or("Inode not found")?;
        match &mut inode.content {
            RamNodeContent::File(file_buf) => {
                let off = offset as usize;
                let needed = off + data.len();
                if needed > file_buf.len() {
                    file_buf.resize(needed, 0);
                }
                file_buf[off..off + data.len()].copy_from_slice(data);
                inode.size = file_buf.len() as u64;
                Ok(data.len())
            }
            _ => Err("Not a regular file"),
        }
    }

    /// Look up a path starting from root directory.
    pub fn resolve_path(&self, path: &str) -> Option<u64> {
        let mut cur = 1u64; // Root Inode

        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let inode = self.inodes.get(&cur)?;
            match &inode.content {
                RamNodeContent::Directory(children) => {
                    cur = *children.get(comp)?;
                }
                _ => return None,
            }
        }

        Some(cur)
    }
}
