//! CorOS VFS Module: `mount_table`
//!
//! Longest-prefix path mount point router supporting `/`, `/boot/efi`, `/proc`,
//! `/sys`, `/dev`, `/tmp`, `/initrd`, and `/mnt`, with path normalization (`..`, `.`,
//! duplicate slashes), mount option bitflags, and superblock routing.

use alloc::string::String;
use alloc::vec::Vec;

/// Supported filesystem drivers in CorOS VFS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    /// Native extent-based journaled block filesystem (`CorFS`).
    CorFs,
    /// FAT32 EFI System Partition filesystem.
    Fat32Esp,
    /// Dynamic kernel & process telemetry virtual filesystem (`/proc`).
    ProcFs,
    /// Kernel object & hardware topology virtual filesystem (`/sys`).
    SysFs,
    /// Character & block device node virtual filesystem (`/dev`).
    DevFs,
    /// Volatile page-backed in-memory filesystem (`/tmp`, `/run`).
    TmpFs,
    /// Early-boot SVR4/newc CPIO initial RAM filesystem (`/initrd`).
    InitRamFs,
    /// Btrfs (B-Tree Filesystem).
    Btrfs,
    /// ZFS Enterprise Storage Pool.
    Zfs,
    /// Samsung Flash-Friendly File System (`f2fs`).
    F2fs,
    /// SGI XFS 64-bit Filesystem.
    Xfs,
    /// ISO9660 / ECMA-119 Optical Disc with Joliet & Rock Ridge.
    Iso9660,
}

impl FsType {
    /// Returns the canonical filesystem driver identifier string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorFs => "corfs",
            Self::Fat32Esp => "vfat",
            Self::ProcFs => "proc",
            Self::SysFs => "sysfs",
            Self::DevFs => "devtmpfs",
            Self::TmpFs => "tmpfs",
            Self::InitRamFs => "rootfs",
            Self::Btrfs => "btrfs",
            Self::Zfs => "zfs",
            Self::F2fs => "f2fs",
            Self::Xfs => "xfs",
            Self::Iso9660 => "iso9660",
        }
    }

    /// Returns whether this filesystem is backed by a persistent block device.
    pub const fn requires_block_device(self) -> bool {
        matches!(
            self,
            Self::CorFs
                | Self::Fat32Esp
                | Self::Btrfs
                | Self::Zfs
                | Self::F2fs
                | Self::Xfs
                | Self::Iso9660
        )
    }
}

/// POSIX / Linux-style mount option flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountFlags(pub u32);

impl MountFlags {
    pub const RDONLY: Self = Self(1 << 0);
    pub const NOSUID: Self = Self(1 << 1);
    pub const NODEV: Self = Self(1 << 2);
    pub const NOEXEC: Self = Self(1 << 3);
    pub const SYNCHRONOUS: Self = Self(1 << 4);
    pub const NOATIME: Self = Self(1 << 5);
    pub const RELATIME: Self = Self(1 << 6);

    pub const RW_DEFAULT: Self = Self(Self::RELATIME.0);
    pub const PSEUDO_FS: Self = Self(Self::NOSUID.0 | Self::NODEV.0 | Self::NOEXEC.0 | Self::NOATIME.0);
    pub const DEV_FS: Self = Self(Self::NOSUID.0 | Self::NOEXEC.0 | Self::NOATIME.0);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn is_read_only(self) -> bool {
        self.contains(Self::RDONLY)
    }
}

/// Errors encountered during mount table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    InvalidPath,
    AlreadyMounted,
    NotMounted,
    RootUnmountForbidden,
    MountPointBusy,
    TableFull,
}

/// Descriptor for an active filesystem mount point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountPoint {
    pub mount_id: u32,
    pub parent_mount_id: u32,
    pub source_device: String,
    pub target_path: String,
    pub fs_type: FsType,
    pub flags: MountFlags,
    pub superblock_id: u64,
    pub open_ref_count: u32,
}

/// Result of resolving an absolute VFS path against the mount table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountResolution {
    pub mount_id: u32,
    pub fs_type: FsType,
    pub flags: MountFlags,
    pub superblock_id: u64,
    pub mount_prefix: String,
    /// Relative path inside the target filesystem, always starting with `/`.
    pub fs_relative_path: String,
}

/// Normalizes an input VFS path into a canonical absolute path (`/`-prefixed, no `.` or `..` or trailing slash).
pub fn normalize_vfs_path(raw_path: &str) -> Result<String, MountError> {
    if raw_path.is_empty() || !raw_path.starts_with('/') {
        return Err(MountError::InvalidPath);
    }

    let mut stack: Vec<&str> = Vec::new();
    for segment in raw_path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            valid => stack.push(valid),
        }
    }

    if stack.is_empty() {
        return Ok(String::from("/"));
    }

    let mut out = String::new();
    for seg in stack {
        out.push('/');
        out.push_str(seg);
    }
    Ok(out)
}

/// Checks if `candidate_prefix` is a valid path-boundary prefix of `normalized_path`.
#[inline]
fn is_path_prefix(normalized_path: &str, candidate_prefix: &str) -> bool {
    if candidate_prefix == "/" {
        return normalized_path.starts_with('/');
    }
    if !normalized_path.starts_with(candidate_prefix) {
        return false;
    }
    let rem = &normalized_path[candidate_prefix.len()..];
    rem.is_empty() || rem.starts_with('/')
}

/// Unified VFS Mount Table & Namespace Router.
pub struct MountTable {
    mounts: Vec<MountPoint>,
    next_mount_id: u32,
}

impl MountTable {
    pub const MAX_MOUNTS: usize = 64;

    /// Creates an empty mount table.
    pub const fn new() -> Self {
        Self {
            mounts: Vec::new(),
            next_mount_id: 1,
        }
    }

    /// Initializes the standard CorOS hierarchy (`/`, `/boot/efi`, `/proc`, `/sys`, `/dev`, `/tmp`, `/initrd`, `/mnt`).
    pub fn with_coros_defaults() -> Self {
        let mut table = Self::new();
        let _ = table.mount("/dev/nvme0n1p2", "/", FsType::CorFs, MountFlags::RW_DEFAULT, 100);
        let _ = table.mount("/dev/nvme0n1p1", "/boot/efi", FsType::Fat32Esp, MountFlags::RW_DEFAULT, 101);
        let _ = table.mount("proc", "/proc", FsType::ProcFs, MountFlags::PSEUDO_FS, 102);
        let _ = table.mount("sysfs", "/sys", FsType::SysFs, MountFlags::PSEUDO_FS, 103);
        let _ = table.mount("devtmpfs", "/dev", FsType::DevFs, MountFlags::DEV_FS, 104);
        let _ = table.mount("tmpfs", "/tmp", FsType::TmpFs, MountFlags:: NOSUID.union(MountFlags::NODEV), 105);
        let _ = table.mount("initramfs", "/initrd", FsType::InitRamFs, MountFlags::RDONLY, 106);
        let _ = table.mount("/dev/sda1", "/mnt", FsType::CorFs, MountFlags::RW_DEFAULT, 107);
        table
    }

    /// Mounts a filesystem at `target_path`.
    pub fn mount(
        &mut self,
        source_device: &str,
        target_path: &str,
        fs_type: FsType,
        flags: MountFlags,
        superblock_id: u64,
    ) -> Result<u32, MountError> {
        if self.mounts.len() >= Self::MAX_MOUNTS {
            return Err(MountError::TableFull);
        }

        let canonical_target = normalize_vfs_path(target_path)?;
        if self.mounts.iter().any(|m| m.target_path == canonical_target) {
            return Err(MountError::AlreadyMounted);
        }

        // Determine parent mount ID by longest existing prefix
        let parent_mount_id = self
            .mounts
            .iter()
            .filter(|m| is_path_prefix(&canonical_target, &m.target_path))
            .max_by_key(|m| m.target_path.len())
            .map(|m| m.mount_id)
            .unwrap_or(0);

        let mount_id = self.next_mount_id;
        self.next_mount_id += 1;

        self.mounts.push(MountPoint {
            mount_id,
            parent_mount_id,
            source_device: String::from(source_device),
            target_path: canonical_target,
            fs_type,
            flags,
            superblock_id,
            open_ref_count: 0,
        });

        Ok(mount_id)
    }

    /// Unmounts a filesystem by target path if it is not busy and has no active child mounts.
    pub fn unmount(&mut self, target_path: &str) -> Result<MountPoint, MountError> {
        let canonical = normalize_vfs_path(target_path)?;
        if canonical == "/" {
            return Err(MountError::RootUnmountForbidden);
        }

        let pos = self
            .mounts
            .iter()
            .position(|m| m.target_path == canonical)
            .ok_or(MountError::NotMounted)?;

        let target_id = self.mounts[pos].mount_id;
        if self.mounts[pos].open_ref_count > 0 {
            return Err(MountError::MountPointBusy);
        }
        if self.mounts.iter().any(|m| m.parent_mount_id == target_id) {
            return Err(MountError::MountPointBusy);
        }

        Ok(self.mounts.remove(pos))
    }

    /// Updates mount flags in-place (e.g., remounting read-only or read-write).
    pub fn remount(&mut self, target_path: &str, new_flags: MountFlags) -> Result<(), MountError> {
        let canonical = normalize_vfs_path(target_path)?;
        let mp = self
            .mounts
            .iter_mut()
            .find(|m| m.target_path == canonical)
            .ok_or(MountError::NotMounted)?;
        mp.flags = new_flags;
        Ok(())
    }

    /// Adjusts the open file reference count on a mount point.
    pub fn adjust_ref_count(&mut self, mount_id: u32, delta: i32) -> Result<u32, MountError> {
        let mp = self
            .mounts
            .iter_mut()
            .find(|m| m.mount_id == mount_id)
            .ok_or(MountError::NotMounted)?;
        if delta >= 0 {
            mp.open_ref_count = mp.open_ref_count.saturating_add(delta as u32);
        } else {
            mp.open_ref_count = mp.open_ref_count.saturating_sub((-delta) as u32);
        }
        Ok(mp.open_ref_count)
    }

    /// Resolves any raw path to its longest-prefix mount point and relative sub-path.
    pub fn resolve_path(&self, raw_path: &str) -> Result<MountResolution, MountError> {
        let canonical = normalize_vfs_path(raw_path)?;

        let best = self
            .mounts
            .iter()
            .filter(|m| is_path_prefix(&canonical, &m.target_path))
            .max_by_key(|m| m.target_path.len())
            .ok_or(MountError::NotMounted)?;

        let relative = if best.target_path == "/" {
            canonical.clone()
        } else {
            let stripped = &canonical[best.target_path.len()..];
            if stripped.is_empty() {
                String::from("/")
            } else {
                String::from(stripped)
            }
        };

        Ok(MountResolution {
            mount_id: best.mount_id,
            fs_type: best.fs_type,
            flags: best.flags,
            superblock_id: best.superblock_id,
            mount_prefix: best.target_path.clone(),
            fs_relative_path: relative,
        })
    }

    /// Returns a slice of all active mounts.
    pub fn entries(&self) -> &[MountPoint] {
        &self.mounts
    }
}

/// Self-test suite for `mount_table`.
pub fn verify_vfs_mount_table() -> u32 {
    let mut passed = 0u32;
    let mut table = MountTable::with_coros_defaults();

    if table.entries().len() == 8 {
        passed += 1;
    }

    if let Ok(res) = table.resolve_path("/boot/efi/EFI/COROS/BOOTX64.EFI") {
        if res.fs_type == FsType::Fat32Esp
            && res.mount_prefix == "/boot/efi"
            && res.fs_relative_path == "/EFI/COROS/BOOTX64.EFI"
        {
            passed += 1;
        }
    }

    if let Ok(res) = table.resolve_path("/proc/1/../cpuinfo") {
        if res.fs_type == FsType::ProcFs && res.fs_relative_path == "/cpuinfo" {
            passed += 1;
        }
    }

    if let Ok(res) = table.resolve_path("/etc/coros/system.conf") {
        if res.fs_type == FsType::CorFs && res.mount_prefix == "/" && res.fs_relative_path == "/etc/coros/system.conf" {
            passed += 1;
        }
    }

    if table.unmount("/") == Err(MountError::RootUnmountForbidden) {
        passed += 1;
    }

    if table.unmount("/mnt").is_ok() && table.entries().len() == 7 {
        passed += 1;
    }

    passed
}
