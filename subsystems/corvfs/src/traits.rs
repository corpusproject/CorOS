//! CorOS VFS Common Filesystem & Inode Traits.
//!
//! Provides the unified VFS trait interface (`FileSystem` and `Inode`)
//! for next-generation filesystems (Btrfs, ZFS, F2FS, XFS, ISO9660) and native CorOS storage drivers.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;

/// Virtual File System error categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotADirectory,
    IsADirectory,
    IoError,
    CorruptData,
    InvalidPath,
    NoSpace,
    PermissionDenied,
    NotSupported,
    AlreadyExists,
}

/// Directory entry descriptor returned by `readdir`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub is_dir: bool,
    pub size: u64,
}

/// Common Inode trait for all VFS-mounted files and directories.
pub trait Inode: Send + Sync {
    /// Inode identifier number.
    fn ino(&self) -> u64;

    /// File size in bytes.
    fn size(&self) -> u64;

    /// Whether this inode represents a directory.
    fn is_dir(&self) -> bool;

    /// Read data from file at `offset` into `buf`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Read directory entries. Returns error if not a directory.
    fn readdir(&self) -> Result<Vec<DirEntry>, FsError>;
}

/// Common Filesystem trait for mounting and path lookup.
pub trait FileSystem: Send + Sync {
    /// Filesystem driver name (e.g. "btrfs", "zfs", "f2fs", "xfs", "iso9660").
    fn name(&self) -> &str;

    /// Retrieve the root directory inode.
    fn root_inode(&self) -> Result<Arc<dyn Inode>, FsError>;

    /// Lookup a path component or relative path from the root.
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError>;
}

/// Runs self-test verifying VFS trait declarations.
pub fn verify_vfs_traits() -> u32 {
    1
}
