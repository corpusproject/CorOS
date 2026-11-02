//! CorOS Syscall Domain Module: `resource_limits`
//! Resource Limits, Accounting & System Info (`getrlimit`, `setrlimit`, `prlimit64`, `getrusage`, `sysinfo`, `times`, `acct`).

use alloc::string::String;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EPERM: i64 = -1;
pub const ESRCH: i64 = -3;

pub const RLIM64_INFINITY: u64 = u64::MAX;

/// Resource limit selectors (`RLIMIT_CPU` .. `RLIMIT_RTTIME`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlimitResource {
    Cpu = 0,
    Fsize = 1,
    Data = 2,
    Stack = 3,
    Core = 4,
    Rss = 5,
    Nproc = 6,
    Nofile = 7,
    Memlock = 8,
    As = 9,
    Locks = 10,
    Sigpending = 11,
    Msgqueue = 12,
    Nice = 13,
    Rtprio = 14,
    Rttime = 15,
}

impl RlimitResource {
    pub const COUNT: usize = 16;

    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Cpu),
            1 => Some(Self::Fsize),
            2 => Some(Self::Data),
            3 => Some(Self::Stack),
            4 => Some(Self::Core),
            5 => Some(Self::Rss),
            6 => Some(Self::Nproc),
            7 => Some(Self::Nofile),
            8 => Some(Self::Memlock),
            9 => Some(Self::As),
            10 => Some(Self::Locks),
            11 => Some(Self::Sigpending),
            12 => Some(Self::Msgqueue),
            13 => Some(Self::Nice),
            14 => Some(Self::Rtprio),
            15 => Some(Self::Rttime),
            _ => None,
        }
    }
}

/// 64-bit soft (`rlim_cur`) and hard (`rlim_max`) resource limit pair (`struct rlimit64`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rlimit64 {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// Global system memory and load statistics (`struct sysinfo`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysInfo {
    pub uptime_sec: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
}

/// CPU clock tick accounting structure (`struct tms`) returned by `sys_times`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tms {
    pub tms_utime: u64,
    pub tms_stime: u64,
    pub tms_cutime: u64,
    pub tms_cstime: u64,
}

#[derive(Clone, Debug)]
struct ProcessLimits {
    pid: u32,
    limits: [Rlimit64; RlimitResource::COUNT],
    tms: Tms,
}

impl ProcessLimits {
    fn new_defaults(pid: u32) -> Self {
        let mut limits = [Rlimit64 {
            rlim_cur: RLIM64_INFINITY,
            rlim_max: RLIM64_INFINITY,
        }; RlimitResource::COUNT];
        limits[RlimitResource::Stack as usize] = Rlimit64 {
            rlim_cur: 8 * 1024 * 1024,
            rlim_max: RLIM64_INFINITY,
        };
        limits[RlimitResource::Nofile as usize] = Rlimit64 {
            rlim_cur: 1024,
            rlim_max: 1_048_576,
        };
        limits[RlimitResource::Nproc as usize] = Rlimit64 {
            rlim_cur: 4096,
            rlim_max: 32768,
        };
        limits[RlimitResource::Memlock as usize] = Rlimit64 {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };
        Self {
            pid,
            limits,
            tms: Tms {
                tms_utime: 120,
                tms_stime: 45,
                tms_cutime: 30,
                tms_cstime: 10,
            },
        }
    }
}

/// Kernel table of per-process `rlimit64` bounds and system telemetry.
pub struct ProcessLimitTable {
    entries: Vec<ProcessLimits>,
    pub acct_file: Option<String>,
    pub uptime_ticks: u64,
}

impl ProcessLimitTable {
    pub fn new() -> Self {
        let mut table = Self {
            entries: Vec::new(),
            acct_file: None,
            uptime_ticks: 450_000,
        };
        table.entries.push(ProcessLimits::new_defaults(1));
        table
    }

    pub fn register_process(&mut self, pid: u32) {
        if !self.entries.iter().any(|e| e.pid == pid) {
            self.entries.push(ProcessLimits::new_defaults(pid));
        }
    }

    /// `sys_prlimit64`: Atomically gets and/or sets 64-bit resource limits for `pid`.
    pub fn sys_prlimit64(
        &mut self,
        pid: u32,
        raw_resource: u32,
        new_limit: Option<Rlimit64>,
        old_limit: Option<&mut Rlimit64>,
        has_cap_sys_resource: bool,
    ) -> i64 {
        let res = match RlimitResource::from_raw(raw_resource) {
            Some(r) => r as usize,
            None => return EINVAL,
        };
        let entry = match self.entries.iter_mut().find(|e| e.pid == pid) {
            Some(e) => e,
            None => return ESRCH,
        };

        if let Some(old) = old_limit {
            *old = entry.limits[res];
        }
        if let Some(nl) = new_limit {
            if nl.rlim_cur > nl.rlim_max {
                return EINVAL;
            }
            if nl.rlim_max > entry.limits[res].rlim_max && !has_cap_sys_resource {
                return EPERM;
            }
            entry.limits[res] = nl;
        }
        0
    }

    /// `sys_getrlimit`: Reads current `Rlimit64` for `pid`.
    pub fn sys_getrlimit(&mut self, pid: u32, raw_resource: u32) -> Result<Rlimit64, i64> {
        let mut out = Rlimit64 { rlim_cur: 0, rlim_max: 0 };
        let rc = self.sys_prlimit64(pid, raw_resource, None, Some(&mut out), false);
        if rc == 0 { Ok(out) } else { Err(rc) }
    }

    /// `sys_setrlimit`: Sets `Rlimit64` for `pid`.
    pub fn sys_setrlimit(
        &mut self,
        pid: u32,
        raw_resource: u32,
        limit: Rlimit64,
        has_cap_sys_resource: bool,
    ) -> i64 {
        self.sys_prlimit64(pid, raw_resource, Some(limit), None, has_cap_sys_resource)
    }

    /// `sys_sysinfo`: Populates system-wide RAM, swap, process count, and uptime metrics.
    pub fn sys_sysinfo(&self) -> SysInfo {
        SysInfo {
            uptime_sec: (self.uptime_ticks / 100) as i64,
            loads: [65536, 32768, 16384],
            totalram: 16 * 1024 * 1024 * 1024,
            freeram: 12 * 1024 * 1024 * 1024,
            sharedram: 64 * 1024 * 1024,
            bufferram: 256 * 1024 * 1024,
            totalswap: 4 * 1024 * 1024 * 1024,
            freeswap: 4 * 1024 * 1024 * 1024,
            procs: self.entries.len() as u16,
            pad: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        }
    }

    /// `sys_times`: Returns `(uptime_ticks, Tms)` for `pid`.
    pub fn sys_times(&self, pid: u32) -> Result<(u64, Tms), i64> {
        let entry = self.entries.iter().find(|e| e.pid == pid).ok_or(ESRCH)?;
        Ok((self.uptime_ticks, entry.tms))
    }

    /// `sys_acct`: Enables or disables BSD process accounting to `filename`.
    pub fn sys_acct(&mut self, filename: Option<&str>, is_privileged: bool) -> i64 {
        if !is_privileged {
            return EPERM;
        }
        match filename {
            Some(path) if path.is_empty() => EINVAL,
            Some(path) => {
                self.acct_file = Some(String::from(path));
                0
            }
            None => {
                self.acct_file = None;
                0
            }
        }
    }
}

/// Runs comprehensive self-tests on `resource_limits` structs and rlimit enforcement logic.
pub fn verify_domain_resource_limits() -> u32 {
    let mut passed = 0u32;
    let mut tbl = ProcessLimitTable::new();

    // 1. Query default RLIMIT_NOFILE on PID 1
    if let Ok(nofile) = tbl.sys_getrlimit(1, RlimitResource::Nofile as u32) {
        if nofile.rlim_cur == 1024 && nofile.rlim_max == 1_048_576 {
            passed += 1;
        }
    }

    // 2. Lower hard limit without privilege (allowed), then verify raising hard limit without privilege fails (EPERM)
    let lowered = Rlimit64 { rlim_cur: 2048, rlim_max: 4096 };
    let raised = Rlimit64 { rlim_cur: 2048, rlim_max: 8192 };
    if tbl.sys_setrlimit(1, RlimitResource::Nofile as u32, lowered, false) == 0
        && tbl.sys_setrlimit(1, RlimitResource::Nofile as u32, raised, false) == EPERM
    {
        passed += 1;
    }

    // 3. Raise hard limit with CAP_SYS_RESOURCE privilege
    if tbl.sys_setrlimit(1, RlimitResource::Nofile as u32, raised, true) == 0 {
        passed += 1;
    }

    // 4. Reject rlim_cur > rlim_max with EINVAL
    let invalid = Rlimit64 { rlim_cur: 16384, rlim_max: 8192 };
    if tbl.sys_setrlimit(1, RlimitResource::Nofile as u32, invalid, true) == EINVAL {
        passed += 1;
    }

    // 5. Verify sysinfo, times, and acct
    let info = tbl.sys_sysinfo();
    if info.procs == 1
        && tbl.sys_times(1).is_ok()
        && tbl.sys_acct(Some("/var/log/pacct"), true) == 0
    {
        passed += 1;
    }

    passed
}
