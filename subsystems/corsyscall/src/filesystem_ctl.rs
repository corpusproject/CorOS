//! CorOS Syscall Domain Module: `filesystem_ctl`
//! Mount Namespace & Filesystem Administration (`mount`, `umount2`, `pivot_root`, `chroot`, `sync`, `syncfs`, `statfs`, `fstatfs`, `quotactl`).

use alloc::string::String;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EBUSY: i64 = -16;
pub const ENOENT: i64 = -2;
pub const EEXIST: i64 = -17;
pub const EDQUOT: i64 = -122;

pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;

/// Mount option flags (`MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`, `MS_REMOUNT`, `MS_BIND`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountFlags(pub u64);

impl MountFlags {
    pub const RDONLY: Self = Self(1 << 0);
    pub const NOSUID: Self = Self(1 << 1);
    pub const NODEV: Self = Self(1 << 2);
    pub const NOEXEC: Self = Self(1 << 3);
    pub const SYNCHRONOUS: Self = Self(1 << 4);
    pub const REMOUNT: Self = Self(1 << 5);
    pub const NOATIME: Self = Self(1 << 10);
    pub const BIND: Self = Self(1 << 12);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Filesystem statistics structure (`struct statfs`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [u32; 2],
    pub f_namelen: u64,
    pub f_frsize: u64,
    pub f_flags: u64,
}

/// Per-UID disk quota limits and usage (`quotactl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskQuota {
    pub uid: u32,
    pub block_hardlimit: u64,
    pub block_softlimit: u64,
    pub current_blocks: u64,
    pub inode_hardlimit: u64,
    pub current_inodes: u64,
}

/// Active mount point entry in a `MountNamespace`.
#[derive(Clone, Debug)]
pub struct MountEntry {
    pub mount_id: u32,
    pub source_dev: String,
    pub target_path: String,
    pub fstype: String,
    pub flags: MountFlags,
    pub open_files: u32,
    pub dirty_buffers: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
}

/// Mount Namespace managing mounted filesystems, chroot/pivot_root jails, and disk quotas.
pub struct MountNamespace {
    mounts: Vec<MountEntry>,
    quotas: Vec<DiskQuota>,
    pub root_dir: String,
    next_mount_id: u32,
}

impl MountNamespace {
    pub fn new() -> Self {
        let mut ns = Self {
            mounts: Vec::new(),
            quotas: Vec::new(),
            root_dir: String::from("/"),
            next_mount_id: 2,
        };
        ns.mounts.push(MountEntry {
            mount_id: 1,
            source_dev: String::from("/dev/nvme0n1p1"),
            target_path: String::from("/"),
            fstype: String::from("corfs"),
            flags: MountFlags::NOATIME,
            open_files: 1,
            dirty_buffers: 12,
            total_blocks: 1_048_576,
            free_blocks: 800_000,
        });
        ns
    }

    fn fstype_magic(fstype: &str) -> u64 {
        match fstype {
            "corfs" => 0x434F_5246_5300,
            "tmpfs" => 0x0102_1994,
            "proc" => 0x9FA0,
            "sysfs" => 0x6265_6572,
            "ext4" => 0xEF53,
            _ => 0xDEAD_BEEF,
        }
    }

    /// `sys_mount`: Mounts a new filesystem or remounts an existing mount point with updated flags.
    pub fn sys_mount(
        &mut self,
        source: &str,
        target: &str,
        fstype: &str,
        flags: MountFlags,
    ) -> i64 {
        if target.is_empty() || !target.starts_with('/') {
            return EINVAL;
        }
        if flags.contains(MountFlags::REMOUNT) {
            match self.mounts.iter_mut().find(|m| m.target_path == target) {
                Some(m) => {
                    m.flags = flags;
                    return 0;
                }
                None => return EINVAL,
            }
        }
        if self.mounts.iter().any(|m| m.target_path == target) {
            return EBUSY;
        }

        let id = self.next_mount_id;
        self.next_mount_id += 1;
        self.mounts.push(MountEntry {
            mount_id: id,
            source_dev: String::from(source),
            target_path: String::from(target),
            fstype: String::from(fstype),
            flags,
            open_files: 0,
            dirty_buffers: 4,
            total_blocks: 262_144,
            free_blocks: 250_000,
        });
        0
    }

    /// `sys_umount2`: Unmounts `target` (supports `MNT_FORCE` and `MNT_DETACH`).
    pub fn sys_umount2(&mut self, target: &str, flags: u32) -> i64 {
        if target == "/" {
            return EBUSY;
        }
        let idx = match self.mounts.iter().position(|m| m.target_path == target) {
            Some(i) => i,
            None => return ENOENT,
        };
        if self.mounts[idx].open_files > 0 && (flags & (MNT_FORCE | MNT_DETACH)) == 0 {
            return EBUSY;
        }
        self.mounts.remove(idx);
        0
    }

    /// `sys_chroot`: Changes the root directory of the calling process.
    pub fn sys_chroot(&mut self, new_root: &str) -> i64 {
        if new_root.is_empty() || !new_root.starts_with('/') {
            return EINVAL;
        }
        self.root_dir = String::from(new_root);
        0
    }

    /// `sys_pivot_root`: Moves the root mount to `put_old` and makes `new_root` the new root mount.
    pub fn sys_pivot_root(&mut self, new_root: &str, put_old: &str) -> i64 {
        if !new_root.starts_with('/') || !put_old.starts_with('/') || new_root == "/" {
            return EINVAL;
        }
        let new_idx = match self.mounts.iter().position(|m| m.target_path == new_root) {
            Some(i) => i,
            None => return EINVAL,
        };
        if let Some(old_root) = self.mounts.iter_mut().find(|m| m.target_path == "/") {
            old_root.target_path = String::from(put_old);
        }
        self.mounts[new_idx].target_path = String::from("/");
        self.root_dir = String::from("/");
        0
    }

    /// `sys_sync`: Flushes dirty buffers across all mounted filesystems.
    pub fn sys_sync(&mut self) -> i64 {
        for m in &mut self.mounts {
            m.dirty_buffers = 0;
        }
        0
    }

    /// `sys_syncfs`: Flushes dirty buffers on the filesystem identified by `mount_id`.
    pub fn sys_syncfs(&mut self, mount_id: u32) -> i64 {
        match self.mounts.iter_mut().find(|m| m.mount_id == mount_id) {
            Some(m) => {
                m.dirty_buffers = 0;
                0
            }
            None => EINVAL,
        }
    }

    /// `sys_statfs`: Queries filesystem statistics for the longest-prefix mount matching `path`.
    pub fn sys_statfs(&self, path: &str) -> Result<StatFs, i64> {
        if !path.starts_with('/') {
            return Err(EINVAL);
        }
        let m = self
            .mounts
            .iter()
            .filter(|m| path.starts_with(&m.target_path))
            .max_by_key(|m| m.target_path.len())
            .ok_or(ENOENT)?;

        Ok(StatFs {
            f_type: Self::fstype_magic(&m.fstype),
            f_bsize: 4096,
            f_blocks: m.total_blocks,
            f_bfree: m.free_blocks,
            f_bavail: m.free_blocks,
            f_files: 65536,
            f_ffree: 60000,
            f_fsid: [m.mount_id, 0x2026],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: m.flags.0,
        })
    }

    /// `sys_quotactl`: Sets or queries per-UID disk quotas.
    pub fn sys_quotactl_set(&mut self, quota: DiskQuota) -> i64 {
        if quota.current_blocks > quota.block_hardlimit {
            return EDQUOT;
        }
        if let Some(q) = self.quotas.iter_mut().find(|q| q.uid == quota.uid) {
            *q = quota;
        } else {
            self.quotas.push(quota);
        }
        0
    }

    pub fn sys_quotactl_get(&self, uid: u32) -> Result<DiskQuota, i64> {
        self.quotas.iter().copied().find(|q| q.uid == uid).ok_or(ENOENT)
    }
}

/// Runs comprehensive self-tests on `filesystem_ctl` structs and mount namespace operations.
pub fn verify_domain_filesystem_ctl() -> u32 {
    let mut passed = 0u32;
    let mut mns = MountNamespace::new();

    // 1. Mount tmpfs at /run
    let flags = MountFlags::NOSUID.union(MountFlags::NODEV);
    if mns.sys_mount("tmpfs", "/run", "tmpfs", flags) == 0 {
        passed += 1;
    }

    // 2. Query statfs on /run/lock and verify tmpfs magic
    if let Ok(st) = mns.sys_statfs("/run/lock") {
        if st.f_type == 0x0102_1994 && st.f_bsize == 4096 {
            passed += 1;
        }
    }

    // 3. Remount /run as read-only
    let ro_flags = flags.union(MountFlags::RDONLY).union(MountFlags::REMOUNT);
    if mns.sys_mount("tmpfs", "/run", "tmpfs", ro_flags) == 0 {
        passed += 1;
    }

    // 4. Test sync and quotactl
    let q = DiskQuota {
        uid: 1000,
        block_hardlimit: 10_000,
        block_softlimit: 8_000,
        current_blocks: 2_500,
        inode_hardlimit: 1000,
        current_inodes: 40,
    };
    if mns.sys_sync() == 0 && mns.sys_quotactl_set(q) == 0 && mns.sys_quotactl_get(1000) == Ok(q) {
        passed += 1;
    }

    // 5. Test pivot_root to /run and unmount old root at /old_root
    if mns.sys_pivot_root("/run", "/old_root") == 0 && mns.sys_umount2("/old_root", MNT_DETACH) == 0 {
        passed += 1;
    }

    passed
}
