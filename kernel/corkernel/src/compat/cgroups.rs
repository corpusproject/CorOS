//! Linux Control Groups v2 (cgroups) Subsystem
//!
//! Provides resource accounting, throttling, and hierarchical control:
//! - Unified single hierarchy tree with delegation support
//! - `cpu.weight` & `cpu.max` (CFS bandwidth quota and period accounting)
//! - `memory.current`, `memory.min`, `memory.low`, `memory.high`, `memory.max` (OOM mediation)
//! - `io.weight` & `io.max` (BPS / IOPS throttling per block device)
//! - `pids.max` & `pids.current` (Fork bomb prevention)
//! - Cgroup v2 core controllers interface (`cgroup.controllers`, `cgroup.subtree_control`)

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

/// CPU Controller Parameters
#[derive(Debug, Clone, Copy)]
pub struct CpuController {
    pub weight: u32,       // 1..10000 (default 100)
    pub quota_us: i64,     // -1 for unlimited, or microsecond budget
    pub period_us: u64,    // typically 100,000us (100ms)
    pub usage_usec: u64,
}

impl Default for CpuController {
    fn default() -> Self {
        Self {
            weight: 100,
            quota_us: -1,
            period_us: 100_000,
            usage_usec: 0,
        }
    }
}

/// Memory Controller Parameters
#[derive(Debug, Clone, Copy)]
pub struct MemoryController {
    pub min_bytes: u64,
    pub low_bytes: u64,
    pub high_bytes: u64,
    pub max_bytes: u64,     // u64::MAX for unlimited
    pub current_bytes: u64,
    pub oom_kill_count: u64,
}

impl Default for MemoryController {
    fn default() -> Self {
        Self {
            min_bytes: 0,
            low_bytes: 0,
            high_bytes: u64::MAX,
            max_bytes: u64::MAX,
            current_bytes: 0,
            oom_kill_count: 0,
        }
    }
}

/// PIDs Controller Parameters
#[derive(Debug, Clone, Copy)]
pub struct PidsController {
    pub max_pids: u32,
    pub current_pids: u32,
}

impl Default for PidsController {
    fn default() -> Self {
        Self {
            max_pids: 4096,
            current_pids: 0,
        }
    }
}

/// I/O Controller Parameters (`io.max`)
#[derive(Debug, Clone, Copy)]
pub struct IoController {
    pub rbps: u64,
    pub wbps: u64,
    pub riops: u32,
    pub wiops: u32,
    pub read_bytes_avail: u64,
    pub write_bytes_avail: u64,
    pub read_iops_avail: u32,
    pub write_iops_avail: u32,
    pub last_refill_timestamp_ns: u64,
    pub rbps_rem_ns: u64,
    pub wbps_rem_ns: u64,
    pub riops_rem_ns: u64,
    pub wiops_rem_ns: u64,
}

impl Default for IoController {
    fn default() -> Self {
        Self {
            rbps: u64::MAX,
            wbps: u64::MAX,
            riops: u32::MAX,
            wiops: u32::MAX,
            read_bytes_avail: u64::MAX,
            write_bytes_avail: u64::MAX,
            read_iops_avail: u32::MAX,
            write_iops_avail: u32::MAX,
            last_refill_timestamp_ns: 0,
            rbps_rem_ns: 0,
            wbps_rem_ns: 0,
            riops_rem_ns: 0,
            wiops_rem_ns: 0,
        }
    }
}

impl IoController {
    /// Refills I/O bandwidth and IOPS tokens based on elapsed nanoseconds without truncation starvation.
    pub fn refill(&mut self, now_ns: u64) {
        if now_ns <= self.last_refill_timestamp_ns {
            return;
        }
        let elapsed_ns = now_ns - self.last_refill_timestamp_ns;
        self.last_refill_timestamp_ns = now_ns;

        if self.rbps > 0 && self.rbps != u64::MAX {
            let total_ns = (elapsed_ns as u128) + (self.rbps_rem_ns as u128);
            let tokens = (self.rbps as u128 * total_ns) / 1_000_000_000;
            if tokens > 0 {
                self.read_bytes_avail = (self.read_bytes_avail.saturating_add(tokens as u64)).min(self.rbps);
                let consumed_ns = (tokens * 1_000_000_000) / (self.rbps as u128);
                self.rbps_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
            } else {
                self.rbps_rem_ns = total_ns.min(1_000_000_000) as u64;
            }
        }
        if self.wbps > 0 && self.wbps != u64::MAX {
            let total_ns = (elapsed_ns as u128) + (self.wbps_rem_ns as u128);
            let tokens = (self.wbps as u128 * total_ns) / 1_000_000_000;
            if tokens > 0 {
                self.write_bytes_avail = (self.write_bytes_avail.saturating_add(tokens as u64)).min(self.wbps);
                let consumed_ns = (tokens * 1_000_000_000) / (self.wbps as u128);
                self.wbps_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
            } else {
                self.wbps_rem_ns = total_ns.min(1_000_000_000) as u64;
            }
        }
        if self.riops > 0 && self.riops != u32::MAX {
            let total_ns = (elapsed_ns as u128) + (self.riops_rem_ns as u128);
            let tokens = (self.riops as u128 * total_ns) / 1_000_000_000;
            if tokens > 0 {
                self.read_iops_avail = (self.read_iops_avail.saturating_add(tokens as u32)).min(self.riops);
                let consumed_ns = (tokens * 1_000_000_000) / (self.riops as u128);
                self.riops_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
            } else {
                self.riops_rem_ns = total_ns.min(1_000_000_000) as u64;
            }
        }
        if self.wiops > 0 && self.wiops != u32::MAX {
            let total_ns = (elapsed_ns as u128) + (self.wiops_rem_ns as u128);
            let tokens = (self.wiops as u128 * total_ns) / 1_000_000_000;
            if tokens > 0 {
                self.write_iops_avail = (self.write_iops_avail.saturating_add(tokens as u32)).min(self.wiops);
                let consumed_ns = (tokens * 1_000_000_000) / (self.wiops as u128);
                self.wiops_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
            } else {
                self.wiops_rem_ns = total_ns.min(1_000_000_000) as u64;
            }
        }
    }
}

/// Single Cgroup v2 Node in the unified tree
#[derive(Debug, Clone)]
pub struct CgroupNode {
    pub id: u64,
    pub name: String,
    pub parent_id: Option<u64>,
    pub pids: Vec<u32>,
    pub cpu: CpuController,
    pub memory: MemoryController,
    pub pids_ctrl: PidsController,
    pub io: IoController,
    pub enabled_controllers: Vec<String>,
}

impl CgroupNode {
    pub fn new(id: u64, name: &str, parent: Option<u64>) -> Self {
        let mut controllers = Vec::new();
        controllers.push(String::from("cpu"));
        controllers.push(String::from("memory"));
        controllers.push(String::from("io"));
        controllers.push(String::from("pids"));

        Self {
            id,
            name: String::from(name),
            parent_id: parent,
            pids: Vec::new(),
            cpu: CpuController::default(),
            memory: MemoryController::default(),
            pids_ctrl: PidsController::default(),
            io: IoController::default(),
            enabled_controllers: controllers,
        }
    }

    /// Add a process PID to this control group
    pub fn attach_pid(&mut self, pid: u32) -> Result<(), &'static str> {
        if self.pids_ctrl.current_pids >= self.pids_ctrl.max_pids {
            return Err("Cgroup PID limit reached");
        }
        if !self.pids.contains(&pid) {
            self.pids.push(pid);
            self.pids_ctrl.current_pids += 1;
        }
        Ok(())
    }

    /// Remove a process PID from this control group
    pub fn detach_pid(&mut self, pid: u32) {
        if let Some(pos) = self.pids.iter().position(|&p| p == pid) {
            self.pids.remove(pos);
            self.pids_ctrl.current_pids = self.pids_ctrl.current_pids.saturating_sub(1);
        }
    }

    /// Charge memory allocation against cgroup limit
    pub fn charge_memory(&mut self, bytes: u64) -> Result<(), &'static str> {
        let new_val = self.memory.current_bytes.saturating_add(bytes);
        if new_val > self.memory.max_bytes {
            self.memory.oom_kill_count += 1;
            return Err("Cgroup memory limit exceeded (OOM)");
        }
        self.memory.current_bytes = new_val;
        Ok(())
    }

    /// Uncharge memory deallocation
    pub fn uncharge_memory(&mut self, bytes: u64) {
        self.memory.current_bytes = self.memory.current_bytes.saturating_sub(bytes);
    }

    /// Charge I/O request against cgroup io.max limits
    pub fn charge_io(&mut self, is_write: bool, bytes: u64) -> Result<(), &'static str> {
        let now = crate::time::monotonic_time_ns().unwrap_or(0);
        self.io.refill(now);
        if is_write {
            if self.io.write_bytes_avail < bytes || self.io.write_iops_avail == 0 {
                return Err("Cgroup I/O write limit exceeded (throttled)");
            }
            self.io.write_bytes_avail = self.io.write_bytes_avail.saturating_sub(bytes);
            self.io.write_iops_avail = self.io.write_iops_avail.saturating_sub(1);
        } else {
            if self.io.read_bytes_avail < bytes || self.io.read_iops_avail == 0 {
                return Err("Cgroup I/O read limit exceeded (throttled)");
            }
            self.io.read_bytes_avail = self.io.read_bytes_avail.saturating_sub(bytes);
            self.io.read_iops_avail = self.io.read_iops_avail.saturating_sub(1);
        }
        Ok(())
    }

    /// Explicitly refill I/O tokens for testing or periodic scheduler tick
    pub fn refill_io(&mut self, now_ns: u64) {
        self.io.refill(now_ns);
    }
}

/// Unified Cgroup v2 Engine Manager
pub struct CgroupManager {
    pub groups: Vec<CgroupNode>,
    pub next_group_id: u64,
}

impl CgroupManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            groups: Vec::new(),
            next_group_id: 1,
        };

        // Root cgroup
        let root = CgroupNode::new(0, "/", None);
        mgr.groups.push(root);

        mgr
    }

    /// Create child cgroup under specified parent
    pub fn create_group(&mut self, name: &str, parent_id: u64) -> Result<u64, &'static str> {
        if !self.groups.iter().any(|g| g.id == parent_id) {
            return Err("Parent cgroup not found");
        }
        let id = self.next_group_id;
        self.next_group_id += 1;
        let node = CgroupNode::new(id, name, Some(parent_id));
        self.groups.push(node);
        Ok(id)
    }

    /// Find cgroup by id
    pub fn get_group_mut(&mut self, id: u64) -> Option<&mut CgroupNode> {
        self.groups.iter_mut().find(|g| g.id == id)
    }
}
