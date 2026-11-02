//! CorOS Security & Sandboxing Subsystem Bridge (`security_bridge.rs`)
//!
//! Integrates:
//! - `corsec::lsm_hooks::{TaskCreds, Capability, LsmHookChain, FilePermMask, LsmError}`
//! - `corsec::mac_policy::{MacPolicyEngine, SecurityLabel, ObjectClass, AccessPermission}`
//! - `corsec::landlock_sandbox::{LandlockRuleset, LandlockSandboxDomain, FsAccessBit, NetPortAccessBit}`
//! - `corsec::lockdown_mode::{KernelLockdownState, LockdownLevel}`

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use corsec::landlock_sandbox::{FsAccessBit, LandlockRuleset, LandlockSandboxDomain, NetPortAccessBit};
use corsec::lockdown_mode::{KernelLockdownState, LockdownLevel};
use corsec::lsm_hooks::{Capability, FilePermMask, LsmError, TaskCreds};
use corsec::mac_policy::{AccessPermission, MacPolicyEngine, ObjectClass, SecurityLabel};

pub struct SecurityBridge {
    creds: SpinLock<Vec<TaskCreds>>,
    mac_engine: SpinLock<Option<MacPolicyEngine>>,
    landlock_domain: SpinLock<Option<LandlockSandboxDomain>>,
    lockdown: SpinLock<KernelLockdownState>,
}

unsafe impl Send for SecurityBridge {}
unsafe impl Sync for SecurityBridge {}

impl SecurityBridge {
    pub const fn uninit() -> Self {
        Self {
            creds: SpinLock::new(Vec::new()),
            mac_engine: SpinLock::new(None),
            landlock_domain: SpinLock::new(None),
            lockdown: SpinLock::new(KernelLockdownState::new(LockdownLevel::None)),
        }
    }

    /// Initializes default security domains, MAC policies, and Landlock rulesets.
    pub fn initialize(&self) {
        let mut mac = self.mac_engine.lock_irqsave();
        if mac.is_none() {
            let mut engine = MacPolicyEngine::new(64, true, true);
            // Allow kernel domain unrestricted process management
            engine.add_allow_rule(
                "kernel_t",
                "kernel_t",
                ObjectClass::Process,
                AccessPermission::READ.union(AccessPermission::WRITE).union(AccessPermission::EXECUTE),
            );
            // Allow system services file read/write
            engine.add_allow_rule(
                "system_t",
                "file_t",
                ObjectClass::File,
                AccessPermission::READ.union(AccessPermission::WRITE),
            );
            *mac = Some(engine);
        }
        drop(mac);

        let mut ll = self.landlock_domain.lock_irqsave();
        if ll.is_none() {
            let mut ruleset = LandlockRuleset::new(FsAccessBit::ALL_FS_ACCESS, NetPortAccessBit::NONE);
            // Protect sensitive system paths
            let _ = ruleset.add_path_beneath_rule("/etc", FsAccessBit::READ_FILE.union(FsAccessBit::READ_DIR));
            let _ = ruleset.add_path_beneath_rule("/usr", FsAccessBit::READ_FILE.union(FsAccessBit::EXECUTE));
            let mut domain = LandlockSandboxDomain::new();
            let _ = domain.restrict_self(ruleset);
            *ll = Some(domain);
        }
        drop(ll);

        let mut creds = self.creds.lock_irqsave();
        if creds.is_empty() {
            // Register root kernel init credentials (PID 1)
            creds.push(TaskCreds::new_root(1, "kernel_t"));
        }
    }

    /// Attaches security credentials for a newly spawned task.
    pub fn register_task_creds(&self, pid: u32, uid: u32, gid: u32, domain: &str) {
        self.initialize();
        let mut creds = self.creds.lock_irqsave();
        let new_cred = if uid == 0 {
            TaskCreds::new_root(pid, domain)
        } else {
            TaskCreds::new_unprivileged(pid, uid, gid, domain)
        };
        creds.retain(|c| c.pid != pid);
        creds.push(new_cred);
    }

    /// Verifies if a given task has the requested POSIX capability.
    pub fn check_capability(&self, pid: u32, cap: Capability) -> bool {
        self.initialize();
        let creds = self.creds.lock_irqsave();
        if let Some(c) = creds.iter().find(|c| c.pid == pid) {
            c.has_capability(cap)
        } else {
            false
        }
    }

    /// Enforces Landlock sandbox and MAC policy access rules for file I/O operations.
    pub fn check_file_permission(&self, pid: u32, path: &str, mask: FilePermMask) -> Result<(), LsmError> {
        self.initialize();

        // 1. Check Landlock path confinement
        let ll_guard = self.landlock_domain.lock_irqsave();
        if let Some(ref domain) = *ll_guard {
            let mut requested_fs = FsAccessBit::NONE;
            if mask.contains(FilePermMask::MAY_READ) {
                requested_fs = requested_fs.union(FsAccessBit::READ_FILE);
            }
            if mask.contains(FilePermMask::MAY_WRITE) {
                requested_fs = requested_fs.union(FsAccessBit::WRITE_FILE);
            }
            if mask.contains(FilePermMask::MAY_EXEC) {
                requested_fs = requested_fs.union(FsAccessBit::EXECUTE);
            }
            if domain.check_fs_access(path, requested_fs).is_err() {
                return Err(LsmError::Sandboxed);
            }
        }
        drop(ll_guard);

        // 2. Check MAC Type Enforcement
        let creds = self.creds.lock_irqsave();
        let task_domain = creds
            .iter()
            .find(|c| c.pid == pid)
            .map(|c| c.security_domain.clone())
            .unwrap_or_else(|| String::from("unconfined_t"));
        drop(creds);

        let mut mac_guard = self.mac_engine.lock_irqsave();
        if let Some(ref mut mac) = *mac_guard {
            let source_label = SecurityLabel::new("system_u", "system_r", &task_domain, 0);
            let target_label = SecurityLabel::new("system_u", "object_r", "file_t", 0);

            let mut req_perm = AccessPermission::NONE;
            if mask.contains(FilePermMask::MAY_READ) {
                req_perm = req_perm.union(AccessPermission::READ);
            }
            if mask.contains(FilePermMask::MAY_WRITE) {
                req_perm = req_perm.union(AccessPermission::WRITE);
            }
            if mask.contains(FilePermMask::MAY_EXEC) {
                req_perm = req_perm.union(AccessPermission::EXECUTE);
            }

            if !mac.check_access(&source_label, &target_label, ObjectClass::File, req_perm) {
                return Err(LsmError::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Queries the active kernel lockdown status.
    pub fn is_locked_down(&self) -> bool {
        self.lockdown.lock_irqsave().current_level() != LockdownLevel::None
    }
}

pub static GLOBAL_SECURITY_BRIDGE: SecurityBridge = SecurityBridge::uninit();
