//! CorOS Syscall Domain Module: `security_caps`
//! POSIX Capabilities, Seccomp Sandbox Filters, Process Control (`capget`, `capset`, `seccomp`, `prctl`, `arch_prctl`, `ptrace`).

use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EPERM: i64 = -1;
pub const ESRCH: i64 = -3;

pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
pub const ARCH_SET_GS: u32 = 0x1001;
pub const ARCH_SET_FS: u32 = 0x1002;
pub const ARCH_GET_FS: u32 = 0x1003;
pub const ARCH_GET_GS: u32 = 0x1004;

/// User capability header (`struct __user_cap_header_struct`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapHeader {
    pub version: u32,
    pub pid: i32,
}

/// 64-bit capability sets (`effective`, `permitted`, `inheritable`, `bounding`, `ambient`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapData {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl CapData {
    pub const fn root_all() -> Self {
        Self {
            effective: 0x0001_FFFF_FFFF_FFFF,
            permitted: 0x0001_FFFF_FFFF_FFFF,
            inheritable: 0,
            bounding: 0x0001_FFFF_FFFF_FFFF,
            ambient: 0,
        }
    }

    pub const fn unprivileged() -> Self {
        Self {
            effective: 0,
            permitted: 0,
            inheritable: 0,
            bounding: 0x0001_FFFF_FFFF_FFFF,
            ambient: 0,
        }
    }
}

/// Individual Linux/CorOS Capability Bits.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityBit {
    Chown = 0,
    DacOverride = 1,
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
    SysResource = 24,
    SysTime = 25,
}

impl CapabilityBit {
    #[inline]
    pub const fn mask(self) -> u64 {
        1u64 << (self as u8)
    }
}

/// Seccomp sandbox operational modes.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompMode {
    Disabled = 0,
    Strict = 1,
    Filter = 2,
}

/// Seccomp filter action verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompAction {
    Allow,
    Errno(u16),
    Trap,
    KillThread,
    KillProcess,
}

/// Rule entry in a `SeccompFilter` matching syscall numbers.
#[derive(Clone, Copy, Debug)]
pub struct SeccompRule {
    pub syscall_nr: u64,
    pub action: SeccompAction,
}

/// Installed BPF-style syscall filter program.
#[derive(Clone, Debug)]
pub struct SeccompFilter {
    pub default_action: SeccompAction,
    pub rules: Vec<SeccompRule>,
}

impl SeccompFilter {
    pub fn evaluate(&self, syscall_nr: u64) -> SeccompAction {
        for r in &self.rules {
            if r.syscall_nr == syscall_nr {
                return r.action;
            }
        }
        self.default_action
    }
}

/// Supported `sys_prctl` options.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrctlOption {
    SetPdeathsig = 1,
    GetDumpable = 3,
    SetDumpable = 4,
    SetName = 15,
    GetName = 16,
    GetSeccomp = 21,
    CapBsetRead = 23,
    CapBsetDrop = 24,
    SetNoNewPrivs = 38,
    GetNoNewPrivs = 39,
}

/// Per-task security, capability, TLS base, and seccomp sandbox context.
pub struct SecurityContext {
    pub pid: i32,
    pub caps: CapData,
    pub seccomp_mode: SeccompMode,
    pub filters: Vec<SeccompFilter>,
    pub no_new_privs: bool,
    pub dumpable: bool,
    pub comm_name: [u8; 16],
    pub fs_base: u64,
    pub gs_base: u64,
    pub ptrace_attached_tid: Option<u32>,
}

impl SecurityContext {
    pub fn new_root(pid: i32) -> Self {
        Self {
            pid,
            caps: CapData::root_all(),
            seccomp_mode: SeccompMode::Disabled,
            filters: Vec::new(),
            no_new_privs: false,
            dumpable: true,
            comm_name: *b"coros_task\0\0\0\0\0\0",
            fs_base: 0,
            gs_base: 0,
            ptrace_attached_tid: None,
        }
    }

    pub fn has_cap(&self, cap: CapabilityBit) -> bool {
        (self.caps.effective & cap.mask()) != 0
    }

    /// `sys_capget`: Reads the capability sets of the target task.
    pub fn sys_capget(&self, hdr: CapHeader) -> Result<CapData, i64> {
        if hdr.version != LINUX_CAPABILITY_VERSION_3 || (hdr.pid != 0 && hdr.pid != self.pid) {
            return Err(EINVAL);
        }
        Ok(self.caps)
    }

    /// `sys_capset`: Updates effective, permitted, and inheritable capabilities obeying monotonic subset rules.
    pub fn sys_capset(&mut self, hdr: CapHeader, new_caps: CapData) -> i64 {
        if hdr.version != LINUX_CAPABILITY_VERSION_3 || (hdr.pid != 0 && hdr.pid != self.pid) {
            return EINVAL;
        }
        // Effective must be a subset of Permitted; new Permitted cannot exceed old Permitted
        if (new_caps.effective & !new_caps.permitted) != 0 {
            return EPERM;
        }
        if (new_caps.permitted & !self.caps.permitted) != 0 {
            return EPERM;
        }
        if (new_caps.inheritable & !(self.caps.inheritable | self.caps.permitted)) != 0
            && !self.has_cap(CapabilityBit::Setuid)
        {
            return EPERM;
        }
        self.caps.effective = new_caps.effective;
        self.caps.permitted = new_caps.permitted;
        self.caps.inheritable = new_caps.inheritable;
        0
    }

    /// `sys_seccomp`: Transitions task into `Strict` or `Filter` mode.
    pub fn sys_seccomp(&mut self, mode: SeccompMode, filter: Option<SeccompFilter>) -> i64 {
        match mode {
            SeccompMode::Disabled => EINVAL,
            SeccompMode::Strict => {
                self.seccomp_mode = SeccompMode::Strict;
                0
            }
            SeccompMode::Filter => {
                if !self.no_new_privs && !self.has_cap(CapabilityBit::SysAdmin) {
                    return EPERM;
                }
                let f = match filter {
                    Some(f) => f,
                    None => return EINVAL,
                };
                self.seccomp_mode = SeccompMode::Filter;
                self.filters.push(f);
                0
            }
        }
    }

    /// Evaluates whether `syscall_nr` is permitted under active seccomp mode.
    pub fn check_syscall(&self, syscall_nr: u64) -> SeccompAction {
        match self.seccomp_mode {
            SeccompMode::Disabled => SeccompAction::Allow,
            SeccompMode::Strict => {
                // Only read(0), write(1), exit(60), sigreturn(15) allowed in strict mode
                if matches!(syscall_nr, 0 | 1 | 15 | 60) {
                    SeccompAction::Allow
                } else {
                    SeccompAction::KillThread
                }
            }
            SeccompMode::Filter => {
                for f in &self.filters {
                    let verdict = f.evaluate(syscall_nr);
                    if verdict != SeccompAction::Allow {
                        return verdict;
                    }
                }
                SeccompAction::Allow
            }
        }
    }

    /// `sys_prctl`: Process control operations (`PR_SET_NO_NEW_PRIVS`, `PR_CAPBSET_DROP`, `PR_SET_DUMPABLE`, etc.).
    pub fn sys_prctl(&mut self, option: u32, arg2: u64) -> i64 {
        match option {
            3 => i64::from(self.dumpable),
            4 => {
                if arg2 > 1 {
                    return EINVAL;
                }
                self.dumpable = arg2 == 1;
                0
            }
            21 => self.seccomp_mode as i64,
            23 => {
                if arg2 >= 64 {
                    return EINVAL;
                }
                i64::from((self.caps.bounding & (1u64 << arg2)) != 0)
            }
            24 => {
                if arg2 >= 64 {
                    return EINVAL;
                }
                self.caps.bounding &= !(1u64 << arg2);
                0
            }
            38 => {
                if arg2 != 1 {
                    return EINVAL;
                }
                self.no_new_privs = true;
                0
            }
            39 => i64::from(self.no_new_privs),
            _ => EINVAL,
        }
    }

    /// `sys_arch_prctl`: Reads or writes x86_64 `FS.base` and `GS.base` MSRs.
    pub fn sys_arch_prctl(&mut self, code: u32, addr: u64) -> Result<u64, i64> {
        match code {
            ARCH_SET_FS => {
                self.fs_base = addr;
                Ok(0)
            }
            ARCH_GET_FS => Ok(self.fs_base),
            ARCH_SET_GS => {
                self.gs_base = addr;
                Ok(0)
            }
            ARCH_GET_GS => Ok(self.gs_base),
            _ => Err(EINVAL),
        }
    }

    /// `sys_ptrace`: Attaches/detaches debugger (`PTRACE_ATTACH=16`, `PTRACE_DETACH=17`).
    pub fn sys_ptrace(&mut self, request: u32, target_tid: u32) -> i64 {
        if !self.has_cap(CapabilityBit::SysPtrace) {
            return EPERM;
        }
        match request {
            16 => {
                self.ptrace_attached_tid = Some(target_tid);
                0
            }
            17 => {
                if self.ptrace_attached_tid == Some(target_tid) {
                    self.ptrace_attached_tid = None;
                    0
                } else {
                    ESRCH
                }
            }
            _ => EINVAL,
        }
    }
}

/// Runs comprehensive self-tests on `security_caps` structs and capability/seccomp state machines.
pub fn verify_domain_security_caps() -> u32 {
    let mut passed = 0u32;
    let mut sec = SecurityContext::new_root(10);
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 10,
    };

    // 1. Drop CAP_SYS_MODULE from bounding set via prctl
    if sec.sys_prctl(PrctlOption::CapBsetDrop as u32, CapabilityBit::SysModule as u64) == 0
        && sec.sys_prctl(PrctlOption::CapBsetRead as u32, CapabilityBit::SysModule as u64) == 0
    {
        passed += 1;
    }

    // 2. Test arch_prctl setting and reading FS.base
    if sec.sys_arch_prctl(ARCH_SET_FS, 0x0000_7F00_1234_0000) == Ok(0)
        && sec.sys_arch_prctl(ARCH_GET_FS, 0) == Ok(0x0000_7F00_1234_0000)
    {
        passed += 1;
    }

    // 3. Test ptrace attach while holding CAP_SYS_PTRACE
    if sec.sys_ptrace(16, 99) == 0 && sec.sys_ptrace(17, 99) == 0 {
        passed += 1;
    }

    // 4. Drop all capabilities via capset and verify cannot re-escalate
    let empty_caps = CapData::unprivileged();
    if sec.sys_capset(hdr, empty_caps) == 0 && sec.sys_capset(hdr, CapData::root_all()) == EPERM {
        passed += 1;
    }

    // 5. Enable PR_SET_NO_NEW_PRIVS and install a SeccompFilter blocking syscall 59 (execve) with EACCES(13)
    if sec.sys_prctl(PrctlOption::SetNoNewPrivs as u32, 1) == 0 {
        let filter = SeccompFilter {
            default_action: SeccompAction::Allow,
            rules: alloc::vec![SeccompRule {
                syscall_nr: 59,
                action: SeccompAction::Errno(13),
            }],
        };
        if sec.sys_seccomp(SeccompMode::Filter, Some(filter)) == 0
            && sec.check_syscall(59) == SeccompAction::Errno(13)
            && sec.check_syscall(1) == SeccompAction::Allow
        {
            passed += 1;
        }
    }

    passed
}
