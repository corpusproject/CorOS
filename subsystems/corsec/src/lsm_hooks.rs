//! Composable Linux Security Module (`LSM`) hook table and security context evaluation.
//!
//! Provides `LsmHookChain`, `TaskCreds`, `InodeSecLabel`, and `SocketSecContext`,
//! evaluating `bprm_check_security`, `inode_permission`, `file_open`, `task_kill`,
//! `socket_bind`, `socket_connect`, and `capable` with restrictive-wins semantics.

use alloc::string::String;
use alloc::vec::Vec;

/// POSIX / Linux capability identifier.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    NetBindService = 10,
    NetAdmin = 12,
    NetRaw = 13,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysAdmin = 21,
    SysBoot = 22,
    AuditWrite = 29,
    AuditControl = 30,
    MacOverride = 32,
    MacAdmin = 33,
    Bpf = 39,
}

impl Capability {
    #[inline]
    pub const fn bit_mask(self) -> u64 {
        1u64 << (self as u8)
    }
}

/// Bitmask flags for inode/file access permission checks (`MAY_READ`, `MAY_WRITE`, `MAY_EXEC`, `MAY_APPEND`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilePermMask(pub u32);

impl FilePermMask {
    pub const MAY_EXEC: Self = Self(0x01);
    pub const MAY_WRITE: Self = Self(0x02);
    pub const MAY_READ: Self = Self(0x04);
    pub const MAY_APPEND: Self = Self(0x08);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Security error codes returned by LSM hooks (modeled after negative errno constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmError {
    OperationNotPermitted,
    PermissionDenied,
    InvalidContext,
    ReadOnlyFilesystem,
    Sandboxed,
    HookLimitReached,
}

/// Task credentials & security label attached to a kernel thread/process (`struct cred`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCreds {
    pub pid: u32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
    pub no_new_privs: bool,
    pub security_domain: String,
}

impl TaskCreds {
    pub fn new_root(pid: u32, domain: &str) -> Self {
        Self {
            pid,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            cap_effective: u64::MAX,
            cap_permitted: u64::MAX,
            cap_inheritable: 0,
            no_new_privs: false,
            security_domain: String::from(domain),
        }
    }

    pub fn new_unprivileged(pid: u32, uid: u32, gid: u32, domain: &str) -> Self {
        Self {
            pid,
            uid,
            euid: uid,
            gid,
            egid: gid,
            cap_effective: 0,
            cap_permitted: 0,
            cap_inheritable: 0,
            no_new_privs: false,
            security_domain: String::from(domain),
        }
    }

    #[inline]
    pub fn has_capability(&self, cap: Capability) -> bool {
        (self.cap_effective & cap.bit_mask()) != 0
    }

    pub fn grant_capability(&mut self, cap: Capability) {
        let mask = cap.bit_mask();
        self.cap_permitted |= mask;
        self.cap_effective |= mask;
    }

    pub fn drop_capability(&mut self, cap: Capability) {
        let mask = !cap.bit_mask();
        self.cap_effective &= mask;
    }
}

/// Inode security attributes (`i_security`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InodeSecLabel {
    pub inode_no: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode_bits: u16,
    pub security_type: String,
    pub is_immutable: bool,
    pub is_suid: bool,
}

impl InodeSecLabel {
    pub fn new(inode_no: u64, owner_uid: u32, owner_gid: u32, mode_bits: u16, security_type: &str) -> Self {
        Self {
            inode_no,
            owner_uid,
            owner_gid,
            mode_bits: mode_bits & 0o777,
            security_type: String::from(security_type),
            is_immutable: false,
            is_suid: (mode_bits & 0o4000) != 0,
        }
    }
}

/// Socket security context and network endpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSecContext {
    pub owner_uid: u32,
    pub security_label: String,
    pub local_port: u16,
    pub remote_ipv4: u32,
    pub remote_port: u16,
    pub is_loopback: bool,
}

/// Pluggable LSM module trait. Every module implements a subset or all of the security hooks.
pub trait SecurityModule {
    fn module_name(&self) -> &'static str;

    fn bprm_check_security(&self, creds: &TaskCreds, exec_inode: &InodeSecLabel) -> Result<(), LsmError> {
        let _ = (creds, exec_inode);
        Ok(())
    }

    fn inode_permission(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        let _ = (creds, inode, mask);
        Ok(())
    }

    fn file_open(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        let _ = (creds, inode, mask);
        Ok(())
    }

    fn task_kill(&self, sender: &TaskCreds, target: &TaskCreds, signal: u32) -> Result<(), LsmError> {
        let _ = (sender, target, signal);
        Ok(())
    }

    fn socket_bind(&self, creds: &TaskCreds, sock: &SocketSecContext, port: u16) -> Result<(), LsmError> {
        let _ = (creds, sock, port);
        Ok(())
    }

    fn socket_connect(
        &self,
        creds: &TaskCreds,
        sock: &SocketSecContext,
        remote_ip: u32,
        remote_port: u16,
    ) -> Result<(), LsmError> {
        let _ = (creds, sock, remote_ip, remote_port);
        Ok(())
    }

    fn capable(&self, creds: &TaskCreds, cap: Capability) -> Result<(), LsmError> {
        let _ = (creds, cap);
        Ok(())
    }
}

/// Built-in Discretionary Access Control (`DAC`) & Capability LSM.
#[derive(Debug, Default)]
pub struct PosixDacCapModule;

impl SecurityModule for PosixDacCapModule {
    fn module_name(&self) -> &'static str {
        "posix_dac_cap"
    }

    fn bprm_check_security(&self, creds: &TaskCreds, exec_inode: &InodeSecLabel) -> Result<(), LsmError> {
        if creds.no_new_privs && exec_inode.is_suid && exec_inode.owner_uid != creds.euid {
            return Err(LsmError::OperationNotPermitted);
        }
        self.inode_permission(creds, exec_inode, FilePermMask::MAY_EXEC)
    }

    fn inode_permission(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        if inode.is_immutable && (mask.contains(FilePermMask::MAY_WRITE) || mask.contains(FilePermMask::MAY_APPEND)) {
            return Err(LsmError::OperationNotPermitted);
        }

        if creds.has_capability(Capability::DacOverride) {
            // Even root with DAC_OVERRIDE requires at least one execute bit if MAY_EXEC is requested
            if mask.contains(FilePermMask::MAY_EXEC) && (inode.mode_bits & 0o111) == 0 {
                return Err(LsmError::PermissionDenied);
            }
            return Ok(());
        }

        let shift = if creds.euid == inode.owner_uid {
            6
        } else if creds.egid == inode.owner_gid {
            3
        } else {
            0
        };
        let triad = ((inode.mode_bits >> shift) & 0o7) as u32;

        if mask.contains(FilePermMask::MAY_READ) && (triad & 0o4) == 0 {
            if !creds.has_capability(Capability::DacReadSearch) {
                return Err(LsmError::PermissionDenied);
            }
        }
        if (mask.contains(FilePermMask::MAY_WRITE) || mask.contains(FilePermMask::MAY_APPEND))
            && (triad & 0o2) == 0
        {
            return Err(LsmError::PermissionDenied);
        }
        if mask.contains(FilePermMask::MAY_EXEC) && (triad & 0o1) == 0 {
            return Err(LsmError::PermissionDenied);
        }
        Ok(())
    }

    fn file_open(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        self.inode_permission(creds, inode, mask)
    }

    fn task_kill(&self, sender: &TaskCreds, target: &TaskCreds, _signal: u32) -> Result<(), LsmError> {
        if sender.euid == target.uid
            || sender.uid == target.uid
            || sender.has_capability(Capability::Kill)
        {
            Ok(())
        } else {
            Err(LsmError::OperationNotPermitted)
        }
    }

    fn socket_bind(&self, creds: &TaskCreds, _sock: &SocketSecContext, port: u16) -> Result<(), LsmError> {
        if port > 0 && port < 1024 && !creds.has_capability(Capability::NetBindService) {
            return Err(LsmError::PermissionDenied);
        }
        Ok(())
    }

    fn capable(&self, creds: &TaskCreds, cap: Capability) -> Result<(), LsmError> {
        if creds.has_capability(cap) {
            Ok(())
        } else {
            Err(LsmError::OperationNotPermitted)
        }
    }
}

/// Built-in Domain Isolation LSM enforcing domain containment rules across tasks, inodes, and sockets.
#[derive(Debug, Default)]
pub struct DomainIsolationModule {
    pub restricted_domains: Vec<String>,
    pub protected_inode_types: Vec<String>,
    pub allow_outbound_for_restricted: bool,
}

impl DomainIsolationModule {
    pub fn new(allow_outbound_for_restricted: bool) -> Self {
        Self {
            restricted_domains: Vec::new(),
            protected_inode_types: Vec::new(),
            allow_outbound_for_restricted,
        }
    }

    pub fn add_restricted_domain(&mut self, domain: &str) {
        self.restricted_domains.push(String::from(domain));
    }

    pub fn add_protected_inode_type(&mut self, sec_type: &str) {
        self.protected_inode_types.push(String::from(sec_type));
    }

    fn is_restricted(&self, domain: &str) -> bool {
        self.restricted_domains.iter().any(|d| d == domain)
    }

    fn is_protected_type(&self, sec_type: &str) -> bool {
        self.protected_inode_types.iter().any(|t| t == sec_type)
    }
}

impl SecurityModule for DomainIsolationModule {
    fn module_name(&self) -> &'static str {
        "domain_isolation"
    }

    fn inode_permission(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        if self.is_restricted(&creds.security_domain) && self.is_protected_type(&inode.security_type) {
            if mask.contains(FilePermMask::MAY_WRITE)
                || mask.contains(FilePermMask::MAY_READ)
                || mask.contains(FilePermMask::MAY_EXEC)
            {
                return Err(LsmError::PermissionDenied);
            }
        }
        Ok(())
    }

    fn file_open(
        &self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        self.inode_permission(creds, inode, mask)
    }

    fn task_kill(&self, sender: &TaskCreds, target: &TaskCreds, _signal: u32) -> Result<(), LsmError> {
        if self.is_restricted(&sender.security_domain)
            && sender.security_domain != target.security_domain
        {
            return Err(LsmError::PermissionDenied);
        }
        Ok(())
    }

    fn socket_connect(
        &self,
        creds: &TaskCreds,
        sock: &SocketSecContext,
        remote_ip: u32,
        _remote_port: u16,
    ) -> Result<(), LsmError> {
        let is_loopback = sock.is_loopback || (remote_ip >> 24) == 127;
        if self.is_restricted(&creds.security_domain)
            && !self.allow_outbound_for_restricted
            && !is_loopback
        {
            return Err(LsmError::Sandboxed);
        }
        Ok(())
    }
}

/// Ordered chain of Linux Security Modules with restrictive-wins evaluation semantics.
/// If any registered module denies an operation, the hook immediately returns that denial.
pub struct LsmHookChain {
    dac_module: PosixDacCapModule,
    isolation_module: DomainIsolationModule,
    pub total_evaluations: u64,
    pub total_denials: u64,
}

impl LsmHookChain {
    pub fn new(isolation_module: DomainIsolationModule) -> Self {
        Self {
            dac_module: PosixDacCapModule,
            isolation_module,
            total_evaluations: 0,
            total_denials: 0,
        }
    }

    fn record_result(&mut self, res: Result<(), LsmError>) -> Result<(), LsmError> {
        self.total_evaluations += 1;
        if res.is_err() {
            self.total_denials += 1;
        }
        res
    }

    pub fn eval_bprm_check_security(
        &mut self,
        creds: &TaskCreds,
        exec_inode: &InodeSecLabel,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .bprm_check_security(creds, exec_inode)
            .and_then(|()| self.isolation_module.bprm_check_security(creds, exec_inode));
        self.record_result(res)
    }

    pub fn eval_inode_permission(
        &mut self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .inode_permission(creds, inode, mask)
            .and_then(|()| self.isolation_module.inode_permission(creds, inode, mask));
        self.record_result(res)
    }

    pub fn eval_file_open(
        &mut self,
        creds: &TaskCreds,
        inode: &InodeSecLabel,
        mask: FilePermMask,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .file_open(creds, inode, mask)
            .and_then(|()| self.isolation_module.file_open(creds, inode, mask));
        self.record_result(res)
    }

    pub fn eval_task_kill(
        &mut self,
        sender: &TaskCreds,
        target: &TaskCreds,
        signal: u32,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .task_kill(sender, target, signal)
            .and_then(|()| self.isolation_module.task_kill(sender, target, signal));
        self.record_result(res)
    }

    pub fn eval_socket_bind(
        &mut self,
        creds: &TaskCreds,
        sock: &SocketSecContext,
        port: u16,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .socket_bind(creds, sock, port)
            .and_then(|()| self.isolation_module.socket_bind(creds, sock, port));
        self.record_result(res)
    }

    pub fn eval_socket_connect(
        &mut self,
        creds: &TaskCreds,
        sock: &SocketSecContext,
        remote_ip: u32,
        remote_port: u16,
    ) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .socket_connect(creds, sock, remote_ip, remote_port)
            .and_then(|()| {
                self.isolation_module
                    .socket_connect(creds, sock, remote_ip, remote_port)
            });
        self.record_result(res)
    }

    pub fn eval_capable(&mut self, creds: &TaskCreds, cap: Capability) -> Result<(), LsmError> {
        let res = self
            .dac_module
            .capable(creds, cap)
            .and_then(|()| self.isolation_module.capable(creds, cap));
        self.record_result(res)
    }
}
