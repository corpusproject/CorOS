//! Process & Thread Security Access Token (NT-Style)
//!
//! Encapsulates credentials, primary identity, group memberships, and privileged rights.

use alloc::vec::Vec;
use super::sid::Sid;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Privilege {
    SeCreateTokenPrivilege = 1,
    SeAssignPrimaryTokenPrivilege = 2,
    SeLockMemoryPrivilege = 3,
    SeIncreaseQuotaPrivilege = 4,
    SeTcbPrivilege = 5,
    SeSecurityPrivilege = 6,
    SeBackupPrivilege = 7,
    SeRestorePrivilege = 8,
    SeShutdownPrivilege = 9,
    SeDebugPrivilege = 10,
    SeAuditPrivilege = 11,
    SeSystemEnvironmentPrivilege = 12,
    SeChangeNotifyPrivilege = 13,
    SeRemoteShutdownPrivilege = 14,
    SeUndockPrivilege = 15,
    SeSyncAgentPrivilege = 16,
    SeEnableDelegationPrivilege = 17,
    SeManageVolumePrivilege = 18,
    SeImpersonatePrivilege = 19,
    SeCreateGlobalPrivilege = 20,
    SeLoadDriverPrivilege = 21,
}

impl Privilege {
    pub fn name(&self) -> &'static str {
        match self {
            Privilege::SeCreateTokenPrivilege => "SeCreateTokenPrivilege",
            Privilege::SeAssignPrimaryTokenPrivilege => "SeAssignPrimaryTokenPrivilege",
            Privilege::SeLockMemoryPrivilege => "SeLockMemoryPrivilege",
            Privilege::SeIncreaseQuotaPrivilege => "SeIncreaseQuotaPrivilege",
            Privilege::SeTcbPrivilege => "SeTcbPrivilege",
            Privilege::SeSecurityPrivilege => "SeSecurityPrivilege",
            Privilege::SeBackupPrivilege => "SeBackupPrivilege",
            Privilege::SeRestorePrivilege => "SeRestorePrivilege",
            Privilege::SeShutdownPrivilege => "SeShutdownPrivilege",
            Privilege::SeDebugPrivilege => "SeDebugPrivilege",
            Privilege::SeAuditPrivilege => "SeAuditPrivilege",
            Privilege::SeSystemEnvironmentPrivilege => "SeSystemEnvironmentPrivilege",
            Privilege::SeChangeNotifyPrivilege => "SeChangeNotifyPrivilege",
            Privilege::SeRemoteShutdownPrivilege => "SeRemoteShutdownPrivilege",
            Privilege::SeUndockPrivilege => "SeUndockPrivilege",
            Privilege::SeSyncAgentPrivilege => "SeSyncAgentPrivilege",
            Privilege::SeEnableDelegationPrivilege => "SeEnableDelegationPrivilege",
            Privilege::SeManageVolumePrivilege => "SeManageVolumePrivilege",
            Privilege::SeImpersonatePrivilege => "SeImpersonatePrivilege",
            Privilege::SeCreateGlobalPrivilege => "SeCreateGlobalPrivilege",
            Privilege::SeLoadDriverPrivilege => "SeLoadDriverPrivilege",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivilegeEntry {
    pub privilege: Privilege,
    pub enabled: bool,
    pub enabled_by_default: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenType {
    Primary,
    Impersonation,
}

#[derive(Clone, Debug)]
pub struct SecurityToken {
    pub token_type: TokenType,
    pub user_sid: Sid,
    pub group_sids: Vec<Sid>,
    pub privileges: Vec<PrivilegeEntry>,
}

impl SecurityToken {
    /// Creates a system-level administrative token with full privileges enabled
    pub fn new_system() -> Self {
        let mut privs = Vec::new();
        let all_privs = [
            Privilege::SeTcbPrivilege,
            Privilege::SeSecurityPrivilege,
            Privilege::SeBackupPrivilege,
            Privilege::SeRestorePrivilege,
            Privilege::SeShutdownPrivilege,
            Privilege::SeDebugPrivilege,
            Privilege::SeAuditPrivilege,
            Privilege::SeSystemEnvironmentPrivilege,
            Privilege::SeChangeNotifyPrivilege,
            Privilege::SeImpersonatePrivilege,
            Privilege::SeCreateGlobalPrivilege,
            Privilege::SeLoadDriverPrivilege,
        ];

        for p in all_privs {
            privs.push(PrivilegeEntry {
                privilege: p,
                enabled: true,
                enabled_by_default: true,
            });
        }

        Self {
            token_type: TokenType::Primary,
            user_sid: Sid::local_system(),
            group_sids: alloc::vec![Sid::administrators(), Sid::everyone()],
            privileges: privs,
        }
    }

    /// Creates a standard user token
    pub fn new_standard_user(user_sid: Sid) -> Self {
        Self {
            token_type: TokenType::Primary,
            user_sid,
            group_sids: alloc::vec![Sid::standard_users(), Sid::everyone()],
            privileges: alloc::vec![
                PrivilegeEntry { privilege: Privilege::SeShutdownPrivilege, enabled: true, enabled_by_default: true },
                PrivilegeEntry { privilege: Privilege::SeChangeNotifyPrivilege, enabled: true, enabled_by_default: true },
                PrivilegeEntry { privilege: Privilege::SeUndockPrivilege, enabled: true, enabled_by_default: true },
            ],
        }
    }

    pub fn has_privilege(&self, priv_type: Privilege) -> bool {
        self.privileges.iter().any(|p| p.privilege == priv_type && p.enabled)
    }

    pub fn enable_privilege(&mut self, priv_type: Privilege) -> bool {
        if let Some(entry) = self.privileges.iter_mut().find(|p| p.privilege == priv_type) {
            entry.enabled = true;
            true
        } else {
            false
        }
    }

    pub fn all_sids(&self) -> Vec<Sid> {
        let mut list = Vec::with_capacity(1 + self.group_sids.len());
        list.push(self.user_sid.clone());
        list.extend_from_slice(&self.group_sids);
        list
    }
}
