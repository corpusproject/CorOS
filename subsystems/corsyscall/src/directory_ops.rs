//! CorOS Syscall Domain Module: `directory_ops`
//! Directory tree & path resolution syscalls (`getdents64`, `mkdirat`, `rmdirat`, `unlinkat`, `renameat2`, `symlinkat`, `readlinkat`, `statx`, `chdir`, `getcwd`).

use alloc::string::String;
use alloc::vec::Vec;

pub const ENOENT: i64 = -2;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENOTEMPTY: i64 = -39;
pub const ELOOP: i64 = -40;
pub const ERANGE: i64 = -34;

pub const DT_FIFO: u8 = 1;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

pub const S_IFIFO: u32 = 0o010000;
pub const S_IFREG: u32 = 0o100000;

pub const AT_REMOVEDIR: u32 = 0x200;
pub const RENAME_NOREPLACE: u32 = 1 << 0;
pub const RENAME_EXCHANGE: u32 = 1 << 1;

/// High-resolution nanosecond timestamp used in `Statx`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub reserved: i32,
}

/// Extended file metadata structure returned by `sys_statx`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub pad1: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
}

/// Linux 64-bit directory entry returned by `sys_getdents64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: String,
}

#[derive(Clone, Debug)]
struct VfsNode {
    ino: u64,
    path: String,
    d_type: u8,
    mode: u16,
    size: u64,
    nlink: u32,
    symlink_target: Option<String>,
}

/// Virtual directory hierarchy and path canonicalization engine.
pub struct PathResolver {
    nodes: Vec<VfsNode>,
    cwd: String,
    next_ino: u64,
}

impl PathResolver {
    pub fn new() -> Self {
        let mut resolver = Self {
            nodes: Vec::new(),
            cwd: String::from("/"),
            next_ino: 2,
        };
        resolver.nodes.push(VfsNode {
            ino: 1,
            path: String::from("/"),
            d_type: DT_DIR,
            mode: 0o040_755,
            size: 4096,
            nlink: 2,
            symlink_target: None,
        });
        resolver
    }

    /// Normalizes a relative or absolute path against `self.cwd`, resolving `.` and `..`.
    pub fn canonicalize(&self, raw_path: &str) -> String {
        let combined = if raw_path.starts_with('/') {
            String::from(raw_path)
        } else if self.cwd == "/" {
            let mut s = String::from("/");
            s.push_str(raw_path);
            s
        } else {
            let mut s = self.cwd.clone();
            s.push('/');
            s.push_str(raw_path);
            s
        };

        let mut parts: Vec<&str> = Vec::new();
        for seg in combined.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    let _ = parts.pop();
                }
                other => parts.push(other),
            }
        }
        if parts.is_empty() {
            String::from("/")
        } else {
            let mut out = String::new();
            for p in parts {
                out.push('/');
                out.push_str(p);
            }
            out
        }
    }

    fn parent_path(canon: &str) -> Option<String> {
        if canon == "/" {
            return None;
        }
        match canon.rfind('/') {
            Some(0) => Some(String::from("/")),
            Some(idx) => Some(String::from(&canon[..idx])),
            None => None,
        }
    }

    fn find_node(&self, canon: &str) -> Option<&VfsNode> {
        self.nodes.iter().find(|n| n.path == canon)
    }

    /// Creates a regular file entry so directory operations can test file links/renames.
    pub fn create_regular_file(&mut self, path: &str, size: u64, mode: u16) -> i64 {
        let canon = self.canonicalize(path);
        if self.find_node(&canon).is_some() {
            return EEXIST;
        }
        let parent = match Self::parent_path(&canon) {
            Some(p) => p,
            None => return EINVAL,
        };
        if !self.nodes.iter().any(|n| n.path == parent && n.d_type == DT_DIR) {
            return ENOENT;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.push(VfsNode {
            ino,
            path: canon,
            d_type: DT_REG,
            mode: 0o100_000 | (mode & 0o7777),
            size,
            nlink: 1,
            symlink_target: None,
        });
        0
    }

    /// `sys_mkdirat`: Creates a new directory at `path`.
    pub fn sys_mkdirat(&mut self, path: &str, mode: u16) -> i64 {
        if path.is_empty() {
            return EINVAL;
        }
        let canon = self.canonicalize(path);
        if self.find_node(&canon).is_some() {
            return EEXIST;
        }
        let parent = match Self::parent_path(&canon) {
            Some(p) => p,
            None => return EEXIST,
        };
        match self.nodes.iter_mut().find(|n| n.path == parent) {
            Some(pnode) if pnode.d_type == DT_DIR => {
                pnode.nlink += 1;
            }
            Some(_) => return ENOTDIR,
            None => return ENOENT,
        }

        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.push(VfsNode {
            ino,
            path: canon,
            d_type: DT_DIR,
            mode: 0o040_000 | (mode & 0o7777),
            size: 4096,
            nlink: 2,
            symlink_target: None,
        });
        0
    }

    /// `sys_mknodat`: Creates a filesystem node (regular file, device, or FIFO special file).
    pub fn sys_mknodat(&mut self, _dfd: i32, path: &str, mode: u32, _dev: u64) -> i64 {
        if path.is_empty() {
            return EINVAL;
        }
        let canon = self.canonicalize(path);
        if self.find_node(&canon).is_some() {
            return EEXIST;
        }
        let parent = match Self::parent_path(&canon) {
            Some(p) => p,
            None => return EINVAL,
        };
        match self.nodes.iter_mut().find(|n| n.path == parent) {
            Some(pnode) if pnode.d_type == DT_DIR => {
                pnode.nlink += 1;
            }
            Some(_) => return ENOTDIR,
            None => return ENOENT,
        }

        let d_type = if (mode & 0o170000) == S_IFIFO {
            DT_FIFO
        } else {
            DT_REG
        };

        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.push(VfsNode {
            ino,
            path: canon,
            d_type,
            mode: mode as u16,
            size: 0,
            nlink: 1,
            symlink_target: None,
        });
        0
    }

    /// `sys_mknod`: Creates a filesystem node relative to current working directory.
    pub fn sys_mknod(&mut self, path: &str, mode: u32, dev: u64) -> i64 {
        self.sys_mknodat(-100, path, mode, dev)
    }

    /// `sys_unlinkat`: Removes a regular file/symlink, or an empty directory when `AT_REMOVEDIR` is set.
    pub fn sys_unlinkat(&mut self, path: &str, flags: u32) -> i64 {
        let canon = self.canonicalize(path);
        if canon == "/" {
            return EINVAL;
        }
        let idx = match self.nodes.iter().position(|n| n.path == canon) {
            Some(i) => i,
            None => return ENOENT,
        };
        let is_dir = self.nodes[idx].d_type == DT_DIR;
        if (flags & AT_REMOVEDIR) != 0 {
            if !is_dir {
                return ENOTDIR;
            }
            let prefix = alloc::format!("{}/", canon);
            if self.nodes.iter().any(|n| n.path.starts_with(&prefix)) {
                return ENOTEMPTY;
            }
        } else if is_dir {
            return EISDIR;
        }

        self.nodes.remove(idx);
        0
    }

    /// `sys_rmdirat`: Convenience wrapper for `sys_unlinkat(..., AT_REMOVEDIR)`.
    pub fn sys_rmdirat(&mut self, path: &str) -> i64 {
        self.sys_unlinkat(path, AT_REMOVEDIR)
    }

    /// `sys_symlinkat`: Creates a symbolic link at `linkpath` pointing to `target`.
    pub fn sys_symlinkat(&mut self, target: &str, linkpath: &str) -> i64 {
        if target.is_empty() || linkpath.is_empty() {
            return EINVAL;
        }
        let canon = self.canonicalize(linkpath);
        if self.find_node(&canon).is_some() {
            return EEXIST;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.push(VfsNode {
            ino,
            path: canon,
            d_type: DT_LNK,
            mode: 0o120_777,
            size: target.len() as u64,
            nlink: 1,
            symlink_target: Some(String::from(target)),
        });
        0
    }

    /// `sys_readlinkat`: Reads the target string of a symbolic link into `buf`.
    pub fn sys_readlinkat(&self, path: &str, buf: &mut [u8]) -> i64 {
        let canon = self.canonicalize(path);
        let node = match self.find_node(&canon) {
            Some(n) => n,
            None => return ENOENT,
        };
        let target = match &node.symlink_target {
            Some(t) => t.as_bytes(),
            None => return EINVAL,
        };
        let copy_len = target.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&target[..copy_len]);
        copy_len as i64
    }

    /// `sys_renameat2`: Atomically renames or exchanges `oldpath` and `newpath`.
    pub fn sys_renameat2(&mut self, oldpath: &str, newpath: &str, flags: u32) -> i64 {
        let old_canon = self.canonicalize(oldpath);
        let new_canon = self.canonicalize(newpath);

        let old_idx = match self.nodes.iter().position(|n| n.path == old_canon) {
            Some(i) => i,
            None => return ENOENT,
        };
        let new_idx = self.nodes.iter().position(|n| n.path == new_canon);

        if (flags & RENAME_EXCHANGE) != 0 {
            let ni = match new_idx {
                Some(i) => i,
                None => return ENOENT,
            };
            self.nodes[old_idx].path = new_canon;
            self.nodes[ni].path = old_canon;
            return 0;
        }

        if let Some(ni) = new_idx {
            if (flags & RENAME_NOREPLACE) != 0 {
                return EEXIST;
            }
            self.nodes.remove(ni);
        }
        if let Some(node) = self.nodes.iter_mut().find(|n| n.path == old_canon) {
            node.path = new_canon;
        }
        0
    }

    /// `sys_getdents64`: Lists direct child entries of directory `dir_path`.
    pub fn sys_getdents64(&self, dir_path: &str) -> Result<Vec<LinuxDirent64>, i64> {
        let canon = self.canonicalize(dir_path);
        match self.find_node(&canon) {
            Some(n) if n.d_type == DT_DIR => {}
            Some(_) => return Err(ENOTDIR),
            None => return Err(ENOENT),
        }

        let mut entries = Vec::new();
        let prefix = if canon == "/" {
            String::from("/")
        } else {
            alloc::format!("{}/", canon)
        };

        for (idx, node) in self.nodes.iter().enumerate() {
            if node.path == canon || !node.path.starts_with(&prefix) {
                continue;
            }
            let remainder = &node.path[prefix.len()..];
            if !remainder.contains('/') && !remainder.is_empty() {
                let reclen = (24 + remainder.len() + 8) & !7;
                entries.push(LinuxDirent64 {
                    d_ino: node.ino,
                    d_off: (idx + 1) as i64,
                    d_reclen: reclen as u16,
                    d_type: node.d_type,
                    d_name: String::from(remainder),
                });
            }
        }
        Ok(entries)
    }

    /// `sys_statx`: Retrieves extended inode attributes for `path`.
    pub fn sys_statx(&self, path: &str, mask: u32) -> Result<Statx, i64> {
        let canon = self.canonicalize(path);
        let node = self.find_node(&canon).ok_or(ENOENT)?;
        Ok(Statx {
            stx_mask: mask,
            stx_blksize: 4096,
            stx_attributes: 0,
            stx_nlink: node.nlink,
            stx_uid: 0,
            stx_gid: 0,
            stx_mode: node.mode,
            pad1: 0,
            stx_ino: node.ino,
            stx_size: node.size,
            stx_blocks: (node.size + 511) / 512,
            stx_atime: StatxTimestamp { tv_sec: 1_700_000_000, tv_nsec: 0, reserved: 0 },
            stx_btime: StatxTimestamp { tv_sec: 1_700_000_000, tv_nsec: 0, reserved: 0 },
            stx_ctime: StatxTimestamp { tv_sec: 1_700_000_000, tv_nsec: 0, reserved: 0 },
            stx_mtime: StatxTimestamp { tv_sec: 1_700_000_000, tv_nsec: 0, reserved: 0 },
        })
    }

    /// `sys_chdir`: Changes the current working directory.
    pub fn sys_chdir(&mut self, path: &str) -> i64 {
        let canon = self.canonicalize(path);
        match self.find_node(&canon) {
            Some(n) if n.d_type == DT_DIR => {
                self.cwd = canon;
                0
            }
            Some(_) => ENOTDIR,
            None => ENOENT,
        }
    }

    /// `sys_getcwd`: Copies the current working directory into `buf`.
    pub fn sys_getcwd(&self, buf: &mut [u8]) -> i64 {
        let bytes = self.cwd.as_bytes();
        if buf.len() < bytes.len() + 1 {
            return ERANGE;
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[bytes.len()] = 0;
        (bytes.len() + 1) as i64
    }
}

/// Runs comprehensive self-tests on `directory_ops` structs and VFS directory state machine.
pub fn verify_domain_directory_ops() -> u32 {
    let mut passed = 0u32;
    let mut vfs = PathResolver::new();

    // 1. Create /etc and /etc/coros.conf
    if vfs.sys_mkdirat("/etc", 0o755) == 0 && vfs.create_regular_file("/etc/coros.conf", 512, 0o644) == 0 {
        passed += 1;
    }

    // 2. Test chdir and getcwd with relative path resolution
    if vfs.sys_chdir("/etc") == 0 {
        let mut cwd_buf = [0u8; 32];
        if vfs.sys_getcwd(&mut cwd_buf) == 5 && &cwd_buf[..4] == b"/etc" {
            passed += 1;
        }
    }

    // 3. Test symlinkat and readlinkat
    if vfs.sys_symlinkat("/etc/coros.conf", "active.conf") == 0 {
        let mut link_buf = [0u8; 32];
        let n = vfs.sys_readlinkat("/etc/active.conf", &mut link_buf);
        if n == 15 && &link_buf[..15] == b"/etc/coros.conf" {
            passed += 1;
        }
    }

    // 4. Test getdents64 on /etc
    if let Ok(dents) = vfs.sys_getdents64("/etc") {
        if dents.len() == 2 {
            passed += 1;
        }
    }

    // 5. Test statx on /etc/coros.conf
    if let Ok(stx) = vfs.sys_statx("/etc/coros.conf", 0x7FF) {
        if stx.stx_size == 512 && (stx.stx_mode & 0o777) == 0o644 {
            passed += 1;
        }
    }

    // 6. Test renameat2 with RENAME_NOREPLACE and cleanup with unlinkat/rmdirat
    if vfs.sys_renameat2("/etc/coros.conf", "/etc/active.conf", RENAME_NOREPLACE) == EEXIST {
        passed += 1;
    }
    if vfs.sys_unlinkat("/etc/coros.conf", 0) == 0
        && vfs.sys_unlinkat("/etc/active.conf", 0) == 0
        && vfs.sys_rmdirat("/etc") == 0
    {
        passed += 1;
    }

    // 7. Test sys_mknodat & sys_mknod creating FIFO special file with S_IFIFO
    if vfs.sys_mkdirat("/tmp", 0o777) == 0 {
        if vfs.sys_mknodat(0, "/tmp/pipe.fifo", S_IFIFO | 0o666, 0) == 0 {
            if let Ok(stx) = vfs.sys_statx("/tmp/pipe.fifo", 0x7FF) {
                if (stx.stx_mode as u32 & S_IFIFO) == S_IFIFO {
                    passed += 1;
                }
            }
        }
        let _ = vfs.sys_unlinkat("/tmp/pipe.fifo", 0);
        let _ = vfs.sys_rmdirat("/tmp");
    }

    passed
}
