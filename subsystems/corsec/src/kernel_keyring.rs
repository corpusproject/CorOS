//! In-kernel cryptographic key retention service (`Keyring`).
//!
//! Provides `KeySerial`, `KeyType` (`User`, `Logon`, `Keyring`, `Asymmetric`),
//! 24-bit `KeyPerm` mask (`Possessor`/`User`/`Group`/`Other` × `View`/`Read`/`Write`/`Search`/`Link`/`SetAttr`),
//! process/session/user keyrings, per-UID byte quota enforcement, and expiration/revocation lifecycle.

use alloc::string::String;
use alloc::vec::Vec;

/// Positive 32-bit serial number uniquely identifying an in-kernel key or keyring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeySerial(pub i32);

/// Classification of in-kernel cryptographic keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// General user-defined payload readable by user space.
    User,
    /// Kernel-only payload (`logon` key); payload reading from user space is strictly prohibited.
    Logon,
    /// Collection of links to other keys or nested keyrings.
    Keyring,
    /// Public/private asymmetric key material.
    Asymmetric,
}

/// 6-bit permission nibbles replicated across `Possessor` (bits 18..23), `User` (bits 12..17),
/// `Group` (bits 6..11), and `Other` (bits 0..5) for a compact 24-bit permission mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPerm(pub u32);

impl KeyPerm {
    pub const VIEW: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE: u8 = 0x04;
    pub const SEARCH: u8 = 0x08;
    pub const LINK: u8 = 0x10;
    pub const SETATTR: u8 = 0x20;
    pub const ALL_SIX: u8 = 0x3F;

    #[inline]
    pub const fn from_roles(possessor: u8, user: u8, group: u8, other: u8) -> Self {
        let p = ((possessor & 0x3F) as u32) << 18;
        let u = ((user & 0x3F) as u32) << 12;
        let g = ((group & 0x3F) as u32) << 6;
        let o = (other & 0x3F) as u32;
        Self(p | u | g | o)
    }

    #[inline]
    pub const fn possessor_bits(self) -> u8 {
        ((self.0 >> 18) & 0x3F) as u8
    }

    #[inline]
    pub const fn user_bits(self) -> u8 {
        ((self.0 >> 12) & 0x3F) as u8
    }

    #[inline]
    pub const fn group_bits(self) -> u8 {
        ((self.0 >> 6) & 0x3F) as u8
    }

    #[inline]
    pub const fn other_bits(self) -> u8 {
        (self.0 & 0x3F) as u8
    }
}

/// Current lifecycle state of a key in the retention service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Active,
    Revoked,
    Dead,
}

/// Error codes returned by kernel keyring operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringError {
    KeyNotFound,
    KeyRevoked,
    KeyExpired,
    PermissionDenied,
    QuotaExceeded,
    NotAKeyring,
    LogonKeyUnreadable,
    InvalidDescription,
}

/// Caller security identity used when checking key permissions and possession.
#[derive(Debug, Clone)]
pub struct KeyCallerContext {
    pub uid: u32,
    pub gid: u32,
    pub process_keyring: Option<KeySerial>,
    pub session_keyring: Option<KeySerial>,
    pub user_keyring: Option<KeySerial>,
}

/// Individual cryptographic key or keyring stored in the kernel table.
#[derive(Debug, Clone)]
pub struct KernelKey {
    pub serial: KeySerial,
    pub key_type: KeyType,
    pub description: String,
    pub uid: u32,
    pub gid: u32,
    pub perm: KeyPerm,
    pub state: KeyState,
    pub expiry_epoch_secs: Option<u64>,
    payload: Vec<u8>,
    linked_keys: Vec<KeySerial>,
}

/// Per-UID quota usage tracking entry.
#[derive(Debug, Clone, Copy)]
struct UidQuotaUsage {
    uid: u32,
    bytes_used: usize,
    keys_count: usize,
}

/// In-kernel key retention subsystem managing keys, keyrings, possession, quotas, and expiration.
pub struct KernelKeyringService {
    keys: Vec<KernelKey>,
    quotas: Vec<UidQuotaUsage>,
    next_serial: i32,
    pub max_bytes_per_uid: usize,
    pub max_keys_per_uid: usize,
}

impl KernelKeyringService {
    pub fn new(max_bytes_per_uid: usize, max_keys_per_uid: usize) -> Self {
        Self {
            keys: Vec::new(),
            quotas: Vec::new(),
            next_serial: 100,
            max_bytes_per_uid,
            max_keys_per_uid,
        }
    }

    fn allocate_serial(&mut self) -> KeySerial {
        let s = KeySerial(self.next_serial);
        self.next_serial += 1;
        s
    }

    fn charge_quota(&mut self, uid: u32, byte_delta: usize) -> Result<(), KeyringError> {
        for q in self.quotas.iter_mut() {
            if q.uid == uid {
                if q.keys_count + 1 > self.max_keys_per_uid
                    || q.bytes_used + byte_delta > self.max_bytes_per_uid
                {
                    return Err(KeyringError::QuotaExceeded);
                }
                q.keys_count += 1;
                q.bytes_used += byte_delta;
                return Ok(());
            }
        }
        if 1 > self.max_keys_per_uid || byte_delta > self.max_bytes_per_uid {
            return Err(KeyringError::QuotaExceeded);
        }
        self.quotas.push(UidQuotaUsage {
            uid,
            bytes_used: byte_delta,
            keys_count: 1,
        });
        Ok(())
    }

    fn release_quota(&mut self, uid: u32, bytes_freed: usize) {
        for q in self.quotas.iter_mut() {
            if q.uid == uid {
                q.bytes_used = q.bytes_used.saturating_sub(bytes_freed);
                q.keys_count = q.keys_count.saturating_sub(1);
                return;
            }
        }
    }

    pub fn uid_bytes_used(&self, uid: u32) -> usize {
        self.quotas
            .iter()
            .find(|q| q.uid == uid)
            .map(|q| q.bytes_used)
            .unwrap_or(0)
    }

    /// Allocates a new empty keyring (`process`, `session`, or `user` keyring).
    pub fn create_keyring(
        &mut self,
        description: &str,
        uid: u32,
        gid: u32,
        perm: KeyPerm,
    ) -> Result<KeySerial, KeyringError> {
        if description.is_empty() {
            return Err(KeyringError::InvalidDescription);
        }
        let cost = description.len();
        self.charge_quota(uid, cost)?;
        let serial = self.allocate_serial();
        self.keys.push(KernelKey {
            serial,
            key_type: KeyType::Keyring,
            description: String::from(description),
            uid,
            gid,
            perm,
            state: KeyState::Active,
            expiry_epoch_secs: None,
            payload: Vec::new(),
            linked_keys: Vec::new(),
        });
        Ok(serial)
    }

    /// Creates a new cryptographic key and links it into `target_keyring` if provided.
    pub fn add_key(
        &mut self,
        caller: &KeyCallerContext,
        key_type: KeyType,
        description: &str,
        payload: &[u8],
        perm: KeyPerm,
        target_keyring: Option<KeySerial>,
        now_secs: u64,
    ) -> Result<KeySerial, KeyringError> {
        if description.is_empty() {
            return Err(KeyringError::InvalidDescription);
        }
        if let Some(ring_serial) = target_keyring {
            self.verify_permission(caller, ring_serial, KeyPerm::WRITE, now_secs)?;
            let ring = self
                .find_key(ring_serial)
                .ok_or(KeyringError::KeyNotFound)?;
            if ring.key_type != KeyType::Keyring {
                return Err(KeyringError::NotAKeyring);
            }
        }

        let quota_cost = description.len() + payload.len();
        self.charge_quota(caller.uid, quota_cost)?;
        let serial = self.allocate_serial();

        self.keys.push(KernelKey {
            serial,
            key_type,
            description: String::from(description),
            uid: caller.uid,
            gid: caller.gid,
            perm,
            state: KeyState::Active,
            expiry_epoch_secs: None,
            payload: Vec::from(payload),
            linked_keys: Vec::new(),
        });

        if let Some(ring_serial) = target_keyring {
            if let Some(ring) = self.find_key_mut(ring_serial) {
                if !ring.linked_keys.contains(&serial) {
                    ring.linked_keys.push(serial);
                }
            }
        }
        Ok(serial)
    }

    /// Links an existing key into a keyring (`keyctl_link`).
    pub fn link_key_to_keyring(
        &mut self,
        caller: &KeyCallerContext,
        key_serial: KeySerial,
        keyring_serial: KeySerial,
        now_secs: u64,
    ) -> Result<(), KeyringError> {
        self.verify_permission(caller, key_serial, KeyPerm::LINK, now_secs)?;
        self.verify_permission(caller, keyring_serial, KeyPerm::WRITE, now_secs)?;

        let ring = self
            .find_key_mut(keyring_serial)
            .ok_or(KeyringError::KeyNotFound)?;
        if ring.key_type != KeyType::Keyring {
            return Err(KeyringError::NotAKeyring);
        }
        if !ring.linked_keys.contains(&key_serial) {
            ring.linked_keys.push(key_serial);
        }
        Ok(())
    }

    /// Reads the payload of a key (`keyctl_read`). `KeyType::Logon` keys forbid reading.
    pub fn read_key_payload(
        &self,
        caller: &KeyCallerContext,
        serial: KeySerial,
        now_secs: u64,
    ) -> Result<Vec<u8>, KeyringError> {
        self.verify_permission(caller, serial, KeyPerm::READ, now_secs)?;
        let key = self.find_key(serial).ok_or(KeyringError::KeyNotFound)?;
        if key.key_type == KeyType::Logon {
            return Err(KeyringError::LogonKeyUnreadable);
        }
        Ok(key.payload.clone())
    }

    /// Sets the expiration timestamp (in epoch seconds) on a key.
    pub fn set_key_timeout(
        &mut self,
        caller: &KeyCallerContext,
        serial: KeySerial,
        expiry_epoch_secs: u64,
        now_secs: u64,
    ) -> Result<(), KeyringError> {
        self.verify_permission(caller, serial, KeyPerm::SETATTR, now_secs)?;
        let key = self.find_key_mut(serial).ok_or(KeyringError::KeyNotFound)?;
        key.expiry_epoch_secs = Some(expiry_epoch_secs);
        Ok(())
    }

    /// Revokes a key (`keyctl_revoke`), wiping its payload, freeing quota bytes, and blocking all future operations.
    pub fn revoke_key(
        &mut self,
        caller: &KeyCallerContext,
        serial: KeySerial,
        now_secs: u64,
    ) -> Result<(), KeyringError> {
        self.verify_permission(caller, serial, KeyPerm::WRITE, now_secs)?;
        let (uid, freed) = {
            let key = self.find_key_mut(serial).ok_or(KeyringError::KeyNotFound)?;
            key.state = KeyState::Revoked;
            let bytes = key.payload.len() + key.description.len();
            key.payload.clear();
            key.linked_keys.clear();
            (key.uid, bytes)
        };
        self.release_quota(uid, freed);
        Ok(())
    }

    /// Searches the caller's process, session, and user keyrings recursively for a matching `(key_type, description)`.
    pub fn request_key(
        &self,
        caller: &KeyCallerContext,
        key_type: KeyType,
        description: &str,
        now_secs: u64,
    ) -> Result<KeySerial, KeyringError> {
        let roots = [
            caller.process_keyring,
            caller.session_keyring,
            caller.user_keyring,
        ];
        for maybe_ring in roots.iter().flatten() {
            if let Some(found) =
                self.search_keyring_recursive(caller, *maybe_ring, key_type, description, now_secs, 0)
            {
                return Ok(found);
            }
        }
        Err(KeyringError::KeyNotFound)
    }

    fn search_keyring_recursive(
        &self,
        caller: &KeyCallerContext,
        ring_serial: KeySerial,
        key_type: KeyType,
        description: &str,
        now_secs: u64,
        depth: usize,
    ) -> Option<KeySerial> {
        if depth > 8 {
            return None;
        }
        if self
            .verify_permission(caller, ring_serial, KeyPerm::SEARCH, now_secs)
            .is_err()
        {
            return None;
        }
        let ring = self.find_key(ring_serial)?;
        for &child_serial in &ring.linked_keys {
            let child = self.find_key(child_serial)?;
            if child.state != KeyState::Active {
                continue;
            }
            if let Some(exp) = child.expiry_epoch_secs {
                if now_secs >= exp {
                    continue;
                }
            }
            if child.key_type == key_type
                && child.description == description
                && self
                    .verify_permission(caller, child_serial, KeyPerm::SEARCH, now_secs)
                    .is_ok()
            {
                return Some(child_serial);
            }
            if child.key_type == KeyType::Keyring {
                if let Some(nested) = self.search_keyring_recursive(
                    caller,
                    child_serial,
                    key_type,
                    description,
                    now_secs,
                    depth + 1,
                ) {
                    return Some(nested);
                }
            }
        }
        None
    }

    fn verify_permission(
        &self,
        caller: &KeyCallerContext,
        serial: KeySerial,
        required_bit: u8,
        now_secs: u64,
    ) -> Result<(), KeyringError> {
        let key = self.find_key(serial).ok_or(KeyringError::KeyNotFound)?;
        if key.state == KeyState::Revoked || key.state == KeyState::Dead {
            return Err(KeyringError::KeyRevoked);
        }
        if let Some(exp) = key.expiry_epoch_secs {
            if now_secs >= exp {
                return Err(KeyringError::KeyExpired);
            }
        }

        let mut granted_nibble = key.perm.other_bits();
        if caller.uid == key.uid {
            granted_nibble |= key.perm.user_bits();
        } else if caller.gid == key.gid {
            granted_nibble |= key.perm.group_bits();
        }
        if self.is_possessed_by(caller, serial) {
            granted_nibble |= key.perm.possessor_bits();
        }

        if (granted_nibble & required_bit) == required_bit {
            Ok(())
        } else {
            Err(KeyringError::PermissionDenied)
        }
    }

    /// Determines whether `target` is possessed by `caller` (either directly one of the caller's
    /// subscribed keyrings or reachable from them).
    pub fn is_possessed_by(&self, caller: &KeyCallerContext, target: KeySerial) -> bool {
        let roots = [
            caller.process_keyring,
            caller.session_keyring,
            caller.user_keyring,
        ];
        for maybe_ring in roots.iter().flatten() {
            if *maybe_ring == target || self.keyring_contains_recursive(*maybe_ring, target, 0) {
                return true;
            }
        }
        false
    }

    fn keyring_contains_recursive(
        &self,
        ring_serial: KeySerial,
        target: KeySerial,
        depth: usize,
    ) -> bool {
        if depth > 8 {
            return false;
        }
        let Some(ring) = self.find_key(ring_serial) else {
            return false;
        };
        if ring.state != KeyState::Active {
            return false;
        }
        for &child in &ring.linked_keys {
            if child == target {
                return true;
            }
            if self.keyring_contains_recursive(child, target, depth + 1) {
                return true;
            }
        }
        false
    }

    fn find_key(&self, serial: KeySerial) -> Option<&KernelKey> {
        self.keys.iter().find(|k| k.serial == serial)
    }

    fn find_key_mut(&mut self, serial: KeySerial) -> Option<&mut KernelKey> {
        self.keys.iter_mut().find(|k| k.serial == serial)
    }
}
