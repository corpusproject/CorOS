//! Access Control List (ACL) & Access Mask System for CorOS
//!
//! Provides Windows NT Security Descriptor components: DACL (Discretionary ACL)
//! and SACL (System Access Control List) with Access Check algorithms.

use alloc::vec::Vec;
use super::sid::Sid;

pub type AccessMask = u32;

pub const DELETE: AccessMask = 0x00010000;
pub const READ_CONTROL: AccessMask = 0x00020000;
pub const WRITE_DAC: AccessMask = 0x00040000;
pub const WRITE_OWNER: AccessMask = 0x00080000;
pub const SYNCHRONIZE: AccessMask = 0x00100000;

pub const STANDARD_RIGHTS_REQUIRED: AccessMask = 0x000F0000;
pub const STANDARD_RIGHTS_ALL: AccessMask = 0x001F0000;

pub const GENERIC_READ: AccessMask = 0x80000000;
pub const GENERIC_WRITE: AccessMask = 0x40000000;
pub const GENERIC_EXECUTE: AccessMask = 0x20000000;
pub const GENERIC_ALL: AccessMask = 0x10000000;

// File-specific rights
pub const FILE_READ_DATA: AccessMask = 0x0001;
pub const FILE_WRITE_DATA: AccessMask = 0x0002;
pub const FILE_APPEND_DATA: AccessMask = 0x0004;
pub const FILE_EXECUTE: AccessMask = 0x0020;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    SystemAudit,
}

#[derive(Clone, Debug)]
pub struct Ace {
    pub ace_type: AceType,
    pub flags: u8,
    pub mask: AccessMask,
    pub sid: Sid,
}

#[derive(Clone, Debug)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self {
            revision: 2,
            aces: Vec::new(),
        }
    }

    pub fn allow(&mut self, sid: Sid, mask: AccessMask) {
        self.aces.push(Ace {
            ace_type: AceType::AccessAllowed,
            flags: 0,
            mask,
            sid,
        });
    }

    pub fn deny(&mut self, sid: Sid, mask: AccessMask) {
        // In NT security, Deny ACEs must appear before Allow ACEs
        self.aces.insert(0, Ace {
            ace_type: AceType::AccessDenied,
            flags: 0,
            mask,
            sid,
        });
    }

    /// Evaluates if the given user SIDs and requested rights are permitted by this ACL.
    pub fn check_access(&self, principal_sids: &[Sid], desired_access: AccessMask) -> bool {
        let mut remaining_access = desired_access;
        let mut granted_access = 0u32;

        for ace in &self.aces {
            let matches_principal = principal_sids.iter().any(|s| *s == ace.sid);
            if !matches_principal {
                continue;
            }

            match ace.ace_type {
                AceType::AccessDenied => {
                    // If any denied bit intersects with desired access, immediately fail
                    if (remaining_access & ace.mask) != 0 {
                        return false;
                    }
                }
                AceType::AccessAllowed => {
                    let newly_granted = remaining_access & ace.mask;
                    granted_access |= newly_granted;
                    remaining_access &= !newly_granted;

                    if remaining_access == 0 {
                        return true;
                    }
                }
                AceType::SystemAudit => {}
            }
        }

        remaining_access == 0
    }
}
