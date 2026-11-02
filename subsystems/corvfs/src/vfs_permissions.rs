//! CorOS VFS Module: `vfs_permissions`
//!
//! POSIX permission & Discretionary Access Control (DAC) evaluator (`ModeBits`,
//! `AccessMask`, `Creds`, `check_permission`, `apply_umask`, `chmod_mode`,
//! sticky-bit directory deletion check (`S_ISVTX`), `setuid`/`setgid` execution
//! transition, and POSIX.1e ACL entry evaluator).

use alloc::vec::Vec;

/// POSIX file mode permission & special bit constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeBits(pub u16);

impl ModeBits {
    pub const S_ISUID: u16 = 0o4000;
    pub const S_ISGID: u16 = 0o2000;
    pub const S_ISVTX: u16 = 0o1000;

    pub const S_IRWXU: u16 = 0o0700;
    pub const S_IRUSR: u16 = 0o0400;
    pub const S_IWUSR: u16 = 0o0200;
    pub const S_IXUSR: u16 = 0o0100;

    pub const S_IRWXG: u16 = 0o0070;
    pub const S_IRGRP: u16 = 0o0040;
    pub const S_IWGRP: u16 = 0o0020;
    pub const S_IXGRP: u16 = 0o0010;

    pub const S_IRWXO: u16 = 0o0007;
    pub const S_IROTH: u16 = 0o0004;
    pub const S_IWOTH: u16 = 0o0002;
    pub const S_IXOTH: u16 = 0o0001;

    #[inline]
    pub const fn has_sticky_bit(self) -> bool {
        (self.0 & Self::S_ISVTX) != 0
    }

    #[inline]
    pub const fn has_setuid(self) -> bool {
        (self.0 & Self::S_ISUID) != 0
    }

    #[inline]
    pub const fn has_setgid(self) -> bool {
        (self.0 & Self::S_ISGID) != 0
    }
}

/// Requested access mask (`R_OK = 4`, `W_OK = 2`, `X_OK = 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessMask(pub u8);

impl AccessMask {
    pub const READ: Self = Self(0b100);
    pub const WRITE: Self = Self(0b010);
    pub const EXEC: Self = Self(0b001);
    pub const READ_WRITE: Self = Self(0b110);
    pub const READ_EXEC: Self = Self(0b101);

    #[inline]
    pub const fn is_subset_of(self, granted_rwx: u8) -> bool {
        (self.0 & granted_rwx) == self.0
    }
}

/// Process security credentials (`euid`, `egid`, and supplementary group list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Creds {
    pub euid: u32,
    pub egid: u32,
    pub groups: Vec<u32>,
}

impl Creds {
    pub fn root() -> Self {
        Self {
            euid: 0,
            egid: 0,
            groups: Vec::new(),
        }
    }

    pub fn user(euid: u32, egid: u32, extra_groups: &[u32]) -> Self {
        let mut groups = Vec::with_capacity(extra_groups.len());
        groups.extend_from_slice(extra_groups);
        Self { euid, egid, groups }
    }

    #[inline]
    pub fn is_in_group(&self, target_gid: u32) -> bool {
        self.egid == target_gid || self.groups.contains(&target_gid)
    }
}

/// Evaluates standard POSIX DAC permissions for `creds` requesting `want` on an inode owned by `(inode_uid, inode_gid)`.
pub fn check_permission(
    creds: &Creds,
    inode_uid: u32,
    inode_gid: u32,
    mode: ModeBits,
    is_directory: bool,
    want: AccessMask,
) -> bool {
    // Root (euid == 0) bypasses read/write checks, and bypasses execute if it's a directory or any x bit is set
    if creds.euid == 0 {
        if (want.0 & AccessMask::EXEC.0) == 0 || is_directory {
            return true;
        }
        return (mode.0 & 0o0111) != 0;
    }

    let granted_rwx: u8 = if creds.euid == inode_uid {
        ((mode.0 >> 6) & 0o7) as u8
    } else if creds.is_in_group(inode_gid) {
        ((mode.0 >> 3) & 0o7) as u8
    } else {
        (mode.0 & 0o7) as u8
    };

    want.is_subset_of(granted_rwx)
}

/// Applies a process `umask` when creating a new file or directory.
#[inline]
pub const fn apply_umask(requested_mode: ModeBits, umask: u16) -> ModeBits {
    ModeBits((requested_mode.0 & 0o0777) & !(umask & 0o0777))
}

/// Computes the resulting `ModeBits` for `chmod`, clearing `S_ISGID` if a non-root caller is not in the file's group.
pub fn chmod_mode(
    creds: &Creds,
    inode_uid: u32,
    inode_gid: u32,
    new_mode: ModeBits,
) -> Result<ModeBits, &'static str> {
    if creds.euid != 0 && creds.euid != inode_uid {
        return Err("Operation not permitted: caller is neither root nor owner");
    }

    let mut sanitized = new_mode.0 & 0o7777;
    if creds.euid != 0 && !creds.is_in_group(inode_gid) {
        sanitized &= !ModeBits::S_ISGID;
    }
    Ok(ModeBits(sanitized))
}

/// Evaluates sticky-bit (`S_ISVTX`, e.g. `/tmp` `0o1777`) deletion/rename rules.
/// In a sticky directory, unprivileged users may only unlink/rename files if they own the directory or the target file.
pub const fn check_sticky_unlink(
    creds_euid: u32,
    dir_uid: u32,
    dir_mode: ModeBits,
    victim_file_uid: u32,
) -> bool {
    if !dir_mode.has_sticky_bit() {
        return true;
    }
    creds_euid == 0 || creds_euid == dir_uid || creds_euid == victim_file_uid
}

/// POSIX.1e Access Control List (ACL) entry tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclTag {
    UserObj,
    User(u32),
    GroupObj,
    Group(u32),
    Mask,
    Other,
}

/// Single POSIX.1e ACL entry granting `rwx` bits (`0..=7`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PosixAclEntry {
    pub tag: AclTag,
    pub perms_rwx: u8,
}

/// Evaluates an extended POSIX.1e ACL table against `creds`.
pub fn evaluate_posix_acl(
    creds: &Creds,
    inode_uid: u32,
    inode_gid: u32,
    entries: &[PosixAclEntry],
    want: AccessMask,
) -> bool {
    if creds.euid == 0 {
        return true;
    }

    let mask_rwx = entries
        .iter()
        .find(|e| e.tag == AclTag::Mask)
        .map(|e| e.perms_rwx)
        .unwrap_or(0o7);

    // 1. Owner match (UserObj is not masked by ACL_MASK)
    if creds.euid == inode_uid {
        if let Some(uo) = entries.iter().find(|e| e.tag == AclTag::UserObj) {
            return want.is_subset_of(uo.perms_rwx);
        }
    }

    // 2. Named User match (masked by ACL_MASK)
    if let Some(named_u) = entries.iter().find(|e| e.tag == AclTag::User(creds.euid)) {
        return want.is_subset_of(named_u.perms_rwx & mask_rwx);
    }

    // 3. Owning Group or Named Group match (union of all matching group entries, masked by ACL_MASK)
    let mut matched_any_group = false;
    let mut combined_group_rwx = 0u8;

    if creds.is_in_group(inode_gid) {
        if let Some(go) = entries.iter().find(|e| e.tag == AclTag::GroupObj) {
            matched_any_group = true;
            combined_group_rwx |= go.perms_rwx;
        }
    }

    for entry in entries {
        if let AclTag::Group(gid) = entry.tag {
            if creds.is_in_group(gid) {
                matched_any_group = true;
                combined_group_rwx |= entry.perms_rwx;
            }
        }
    }

    if matched_any_group {
        return want.is_subset_of(combined_group_rwx & mask_rwx);
    }

    // 4. Fallback to Other
    if let Some(oth) = entries.iter().find(|e| e.tag == AclTag::Other) {
        return want.is_subset_of(oth.perms_rwx);
    }

    false
}

/// Self-test suite for `vfs_permissions`.
pub fn verify_vfs_vfs_permissions() -> u32 {
    let mut passed = 0u32;

    let alice = Creds::user(1000, 1000, &[27, 100]);
    let bob = Creds::user(1001, 1001, &[100]);

    // Mode 0o640 owned by alice:100
    let mode = ModeBits(0o640);
    if check_permission(&alice, 1000, 100, mode, false, AccessMask::READ_WRITE)
        && check_permission(&bob, 1000, 100, mode, false, AccessMask::READ)
        && !check_permission(&bob, 1000, 100, mode, false, AccessMask::WRITE)
    {
        passed += 1;
    }

    // Umask 0o022 on 0o666 -> 0o644
    if apply_umask(ModeBits(0o666), 0o022) == ModeBits(0o644) {
        passed += 1;
    }

    // Sticky-bit check on /tmp (0o1777): bob cannot delete alice's file, but alice can
    let tmp_mode = ModeBits(0o1777);
    if !check_sticky_unlink(1001, 0, tmp_mode, 1000) && check_sticky_unlink(1000, 0, tmp_mode, 1000) {
        passed += 1;
    }

    // POSIX.1e ACL evaluation with named user and mask
    let acl = [
        PosixAclEntry { tag: AclTag::UserObj, perms_rwx: 0o7 },
        PosixAclEntry { tag: AclTag::User(1001), perms_rwx: 0o6 },
        PosixAclEntry { tag: AclTag::GroupObj, perms_rwx: 0o4 },
        PosixAclEntry { tag: AclTag::Mask, perms_rwx: 0o4 }, // Mask restricts named user 1001 to read-only!
        PosixAclEntry { tag: AclTag::Other, perms_rwx: 0o0 },
    ];
    if evaluate_posix_acl(&bob, 1000, 1000, &acl, AccessMask::READ)
        && !evaluate_posix_acl(&bob, 1000, 1000, &acl, AccessMask::WRITE)
    {
        passed += 1;
    }

    passed
}
