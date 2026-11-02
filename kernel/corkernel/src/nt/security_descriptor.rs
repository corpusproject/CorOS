//! CorOS Windows NT Security Descriptor & Access Control Engine (`security_descriptor.rs`)
//!
//! Implements Windows NT Security Model:
//! - Security Identifiers (SID: Revision, SubAuthorityCount, IdentifierAuthority, SubAuthorities)
//! - Well-Known SIDs (LocalSystem, NetworkService, LocalService, Administrators, Everyone)
//! - Access Control Entries (ACE: ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, SYSTEM_AUDIT_ACE)
//! - Discretionary Access Control Lists (DACL) & System Access Control Lists (SACL)
//! - Self-relative and Absolute SECURITY_DESCRIPTOR structures
//! - AccessCheck() evaluation algorithm against Token Privilege masks

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const SID_REVISION: u8 = 1;
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;

/// Security Descriptor Control Flags
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

/// ACE Types
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
pub const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;

/// ACE Flags
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

/// Windows NT Security Identifier (SID)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub sub_authority_count: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    pub fn new(authority: [u8; 6], sub_authorities: &[u32]) -> Self {
        Self {
            revision: SID_REVISION,
            sub_authority_count: sub_authorities.len() as u8,
            identifier_authority: authority,
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    /// S-1-1-0: Everyone
    pub fn everyone() -> Self {
        Self::new([0, 0, 0, 0, 0, 1], &[0])
    }

    /// S-1-5-18: NT AUTHORITY\SYSTEM (LocalSystem)
    pub fn local_system() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], &[18])
    }

    /// S-1-5-19: NT AUTHORITY\LOCAL SERVICE
    pub fn local_service() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], &[19])
    }

    /// S-1-5-20: NT AUTHORITY\NETWORK SERVICE
    pub fn network_service() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], &[20])
    }

    /// S-1-5-32-544: BUILTIN\Administrators
    pub fn administrators() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], &[32, 544])
    }

    /// S-1-5-32-545: BUILTIN\Users
    pub fn users() -> Self {
        Self::new([0, 0, 0, 0, 0, 5], &[32, 545])
    }

    /// Parse SDDL SID string e.g. "S-1-5-32-544"
    pub fn to_string(&self) -> String {
        let mut s = alloc::format!("S-{}-{}", self.revision, self.identifier_authority[5]);
        for sa in &self.sub_authorities {
            s.push_str(&alloc::format!("-{}", sa));
        }
        s
    }

    /// Serialize SID to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        bytes.push(self.revision);
        bytes.push(self.sub_authority_count);
        bytes.extend_from_slice(&self.identifier_authority);
        for &sa in &self.sub_authorities {
            bytes.extend_from_slice(&sa.to_le_bytes());
        }
        bytes
    }

    /// Deserialize SID from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let rev = bytes[0];
        let count = bytes[1] as usize;
        if bytes.len() < 8 + count * 4 {
            return None;
        }
        let mut auth = [0u8; 6];
        auth.copy_from_slice(&bytes[2..8]);
        let mut sub_auths = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 8 + i * 4;
            let val = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            sub_auths.push(val);
        }
        Some(Self {
            revision: rev,
            sub_authority_count: count as u8,
            identifier_authority: auth,
            sub_authorities: sub_auths,
        })
    }
}

/// Access Control Entry (ACE)
#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub mask: u32,
    pub sid: Sid,
}

impl Ace {
    pub fn new_access_allowed(mask: u32, sid: Sid) -> Self {
        Self {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            ace_flags: 0,
            mask,
            sid,
        }
    }

    pub fn new_access_denied(mask: u32, sid: Sid) -> Self {
        Self {
            ace_type: ACCESS_DENIED_ACE_TYPE,
            ace_flags: 0,
            mask,
            sid,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let sid_bytes = self.sid.to_bytes();
        let size = (4 + 4 + sid_bytes.len()) as u16;
        let mut bytes = Vec::with_capacity(size as usize);
        bytes.push(self.ace_type);
        bytes.push(self.ace_flags);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&self.mask.to_le_bytes());
        bytes.extend_from_slice(&sid_bytes);
        bytes
    }
}

/// Access Control List (ACL)
#[derive(Debug, Clone)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            revision: 2, // ACL_REVISION
            aces: Vec::new(),
        }
    }

    pub fn add_ace(&mut self, ace: Ace) {
        self.aces.push(ace);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ace_data = Vec::new();
        for ace in &self.aces {
            ace_data.extend_from_slice(&ace.to_bytes());
        }

        let total_size = (8 + ace_data.len()) as u16;
        let mut bytes = Vec::with_capacity(total_size as usize);
        bytes.push(self.revision);
        bytes.push(0); // Sbz1
        bytes.extend_from_slice(&total_size.to_le_bytes());
        bytes.extend_from_slice(&(self.aces.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        bytes.extend_from_slice(&ace_data);
        bytes
    }
}

/// Windows NT Security Descriptor
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn new_empty() -> Self {
        Self {
            revision: SECURITY_DESCRIPTOR_REVISION,
            control: SE_SELF_RELATIVE,
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
        }
    }

    /// Create standard Administrator + System full control descriptor
    pub fn new_admin_full_access() -> Self {
        let mut dacl = Acl::new();
        // Grant SYSTEM full access (0x10000000 = GENERIC_ALL)
        dacl.add_ace(Ace::new_access_allowed(0x10000000, Sid::local_system()));
        // Grant Administrators full access
        dacl.add_ace(Ace::new_access_allowed(0x10000000, Sid::administrators()));
        // Grant Users read/execute access (0x20000000 | 0x80000000)
        dacl.add_ace(Ace::new_access_allowed(0xA0000000, Sid::users()));

        Self {
            revision: SECURITY_DESCRIPTOR_REVISION,
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(Sid::administrators()),
            group: Some(Sid::administrators()),
            dacl: Some(dacl),
            sacl: None,
        }
    }

    /// Perform Windows AccessCheck algorithm
    /// Returns true if `desired_access` is fully granted given user/group SIDs
    pub fn access_check(&self, user_sid: &Sid, group_sids: &[Sid], desired_access: u32) -> bool {
        // If owner matches and WRITE_OWNER is desired, allow it
        if let Some(ref owner) = self.owner {
            if owner == user_sid && desired_access == 0x00080000 {
                return true;
            }
        }

        let dacl = match &self.dacl {
            Some(d) => d,
            None => {
                // NULL DACL implies full access to everyone
                return true;
            }
        };

        if dacl.aces.is_empty() {
            // Empty DACL grants no access to anyone
            return false;
        }

        let mut remaining_access = desired_access;
        let mut granted_access = 0u32;

        for ace in &dacl.aces {
            let matches_sid = ace.sid == *user_sid || group_sids.iter().any(|g| *g == ace.sid) || ace.sid == Sid::everyone();

            if matches_sid {
                if ace.ace_type == ACCESS_DENIED_ACE_TYPE {
                    // Explicit DENY overrides any grant
                    if (remaining_access & ace.mask) != 0 {
                        return false;
                    }
                } else if ace.ace_type == ACCESS_ALLOWED_ACE_TYPE {
                    let newly_granted = remaining_access & ace.mask;
                    granted_access |= newly_granted;
                    remaining_access &= !newly_granted;

                    if remaining_access == 0 {
                        return true;
                    }
                }
            }
        }

        remaining_access == 0
    }
}
