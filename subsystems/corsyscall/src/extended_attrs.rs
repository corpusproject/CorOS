//! CorOS Syscall Domain Module: `extended_attrs`
//! Extended Inode Attributes (`setxattr`, `getxattr`, `listxattr`, `removexattr`).

use alloc::string::String;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EEXIST: i64 = -17;
pub const ENODATA: i64 = -61;
pub const ERANGE: i64 = -34;
pub const EPERM: i64 = -1;
pub const E2BIG: i64 = -7;

pub const XATTR_SIZE_MAX: usize = 65536;

/// `setxattr` creation/replacement flags (`XATTR_CREATE`, `XATTR_REPLACE`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XattrFlags(pub u32);

impl XattrFlags {
    pub const ANY: Self = Self(0);
    pub const CREATE: Self = Self(1);
    pub const REPLACE: Self = Self(2);

    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 <= 2
    }
}

/// Extended attribute namespace prefixes (`user.`, `trusted.`, `security.`, `system.`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrNamespace {
    User,
    Trusted,
    Security,
    System,
}

impl XattrNamespace {
    pub fn parse(full_name: &str) -> Option<(Self, &str)> {
        if let Some(rest) = full_name.strip_prefix("user.") {
            if !rest.is_empty() {
                return Some((Self::User, rest));
            }
        } else if let Some(rest) = full_name.strip_prefix("trusted.") {
            if !rest.is_empty() {
                return Some((Self::Trusted, rest));
            }
        } else if let Some(rest) = full_name.strip_prefix("security.") {
            if !rest.is_empty() {
                return Some((Self::Security, rest));
            }
        } else if let Some(rest) = full_name.strip_prefix("system.") {
            if !rest.is_empty() {
                return Some((Self::System, rest));
            }
        }
        None
    }

    #[inline]
    pub const fn requires_privilege(self) -> bool {
        matches!(self, Self::Trusted | Self::Security)
    }
}

/// Single Extended Attribute key-value pair bound to an inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrEntry {
    pub inode_id: u64,
    pub namespace: XattrNamespace,
    pub full_name: String,
    pub value: Vec<u8>,
}

/// Kernel Inode Extended Attribute Store supporting `setxattr`, `getxattr`, `listxattr`, and `removexattr`.
pub struct InodeXattrStore {
    entries: Vec<XattrEntry>,
}

impl InodeXattrStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// `sys_setxattr`: Associates `value` with `name` on `inode_id`, honoring `XATTR_CREATE` and `XATTR_REPLACE`.
    pub fn sys_setxattr(
        &mut self,
        inode_id: u64,
        name: &str,
        value: &[u8],
        flags: XattrFlags,
        is_privileged: bool,
    ) -> i64 {
        if !flags.is_valid() {
            return EINVAL;
        }
        if value.len() > XATTR_SIZE_MAX {
            return E2BIG;
        }
        let (ns, _) = match XattrNamespace::parse(name) {
            Some(parsed) => parsed,
            None => return EINVAL,
        };
        if ns.requires_privilege() && !is_privileged {
            return EPERM;
        }

        let existing_idx = self
            .entries
            .iter()
            .position(|e| e.inode_id == inode_id && e.full_name == name);

        match (existing_idx, flags) {
            (Some(_), XattrFlags::CREATE) => EEXIST,
            (None, XattrFlags::REPLACE) => ENODATA,
            (Some(idx), _) => {
                self.entries[idx].value = value.to_vec();
                0
            }
            (None, _) => {
                self.entries.push(XattrEntry {
                    inode_id,
                    namespace: ns,
                    full_name: String::from(name),
                    value: value.to_vec(),
                });
                0
            }
        }
    }

    /// `sys_getxattr`: Retrieves the value of extended attribute `name` on `inode_id`.
    /// When `buf` is empty, returns the attribute byte length without copying.
    pub fn sys_getxattr(
        &self,
        inode_id: u64,
        name: &str,
        buf: &mut [u8],
        is_privileged: bool,
    ) -> i64 {
        let (ns, _) = match XattrNamespace::parse(name) {
            Some(parsed) => parsed,
            None => return EINVAL,
        };
        if ns == XattrNamespace::Trusted && !is_privileged {
            return ENODATA;
        }

        let entry = match self
            .entries
            .iter()
            .find(|e| e.inode_id == inode_id && e.full_name == name)
        {
            Some(e) => e,
            None => return ENODATA,
        };

        if buf.is_empty() {
            return entry.value.len() as i64;
        }
        if buf.len() < entry.value.len() {
            return ERANGE;
        }
        buf[..entry.value.len()].copy_from_slice(&entry.value);
        entry.value.len() as i64
    }

    /// `sys_listxattr`: Writes null-terminated attribute names for `inode_id` into `list_buf`.
    pub fn sys_listxattr(&self, inode_id: u64, list_buf: &mut [u8], is_privileged: bool) -> i64 {
        let mut total_len = 0usize;
        for e in &self.entries {
            if e.inode_id == inode_id && (is_privileged || e.namespace != XattrNamespace::Trusted) {
                total_len += e.full_name.len() + 1;
            }
        }
        if list_buf.is_empty() {
            return total_len as i64;
        }
        if list_buf.len() < total_len {
            return ERANGE;
        }

        let mut offset = 0usize;
        for e in &self.entries {
            if e.inode_id == inode_id && (is_privileged || e.namespace != XattrNamespace::Trusted) {
                let bytes = e.full_name.as_bytes();
                list_buf[offset..offset + bytes.len()].copy_from_slice(bytes);
                list_buf[offset + bytes.len()] = 0;
                offset += bytes.len() + 1;
            }
        }
        total_len as i64
    }

    /// `sys_removexattr`: Deletes extended attribute `name` from `inode_id`.
    pub fn sys_removexattr(&mut self, inode_id: u64, name: &str, is_privileged: bool) -> i64 {
        let (ns, _) = match XattrNamespace::parse(name) {
            Some(parsed) => parsed,
            None => return EINVAL,
        };
        if ns.requires_privilege() && !is_privileged {
            return EPERM;
        }
        match self
            .entries
            .iter()
            .position(|e| e.inode_id == inode_id && e.full_name == name)
        {
            Some(idx) => {
                self.entries.remove(idx);
                0
            }
            None => ENODATA,
        }
    }
}

/// Runs comprehensive self-tests on `extended_attrs` structs and xattr namespace rules.
pub fn verify_domain_extended_attrs() -> u32 {
    let mut passed = 0u32;
    let mut store = InodeXattrStore::new();

    // 1. Set user.mime_type unprivileged and verify XATTR_CREATE rejects duplicate
    if store.sys_setxattr(42, "user.mime_type", b"text/plain", XattrFlags::CREATE, false) == 0
        && store.sys_setxattr(42, "user.mime_type", b"text/html", XattrFlags::CREATE, false) == EEXIST
    {
        passed += 1;
    }

    // 2. Security namespace requires privilege
    if store.sys_setxattr(42, "security.coros_label", b"system_u", XattrFlags::ANY, false) == EPERM
        && store.sys_setxattr(42, "security.coros_label", b"system_u", XattrFlags::ANY, true) == 0
    {
        passed += 1;
    }

    // 3. Query size with empty buffer, then read value with getxattr
    let mut val_buf = [0u8; 16];
    if store.sys_getxattr(42, "user.mime_type", &mut [], false) == 10
        && store.sys_getxattr(42, "user.mime_type", &mut val_buf, false) == 10
        && &val_buf[..10] == b"text/plain"
    {
        passed += 1;
    }

    // 4. Test listxattr returns concatenated null-terminated attribute names
    let mut list_buf = [0u8; 64];
    let list_len = store.sys_listxattr(42, &mut list_buf, true);
    if list_len == (14 + 1 + 20 + 1) {
        passed += 1;
    }

    // 5. Remove attribute and verify subsequent getxattr returns ENODATA
    if store.sys_removexattr(42, "user.mime_type", false) == 0
        && store.sys_getxattr(42, "user.mime_type", &mut val_buf, false) == ENODATA
    {
        passed += 1;
    }

    passed
}
