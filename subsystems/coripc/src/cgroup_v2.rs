//! Unified Control Group v2 (`cgroup2`) hierarchy, controller distribution,
//! `cpu.weight` share proportional splitter, `cpu.max` quota/period bandwidth
//! throttler, `pids.max` fork admission guard, `memory.max`/`memory.high` accounting,
//! and `cgroup.events` populated/frozen state transitions.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Bitmask of Cgroup v2 controllers (`CPU | MEMORY | IO | PIDS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CgroupControllers(pub u32);

impl CgroupControllers {
    pub const NONE: Self = Self(0);
    pub const CPU: Self = Self(1 << 0);
    pub const MEMORY: Self = Self(1 << 1);
    pub const IO: Self = Self(1 << 2);
    pub const PIDS: Self = Self(1 << 3);
    pub const ALL: Self = Self((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3));

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[inline]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Error codes returned by Cgroup v2 operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupError {
    /// Target cgroup node ID does not exist.
    NotFound,
    /// Root cgroup cannot be removed or lack parent operations.
    InvalidOperationOnRoot,
    /// Cgroup v2 "no internal process" constraint violated: an intermediate cgroup
    /// with active subtree_control cannot directly hold tasks, or vice versa.
    NoInternalProcessConstraint,
    /// A child enables a controller not enabled in its parent's `subtree_control`.
    ControllerNotEnabledInParent,
    /// `cpu.weight` must lie within `1..=10000`.
    InvalidCpuWeight,
    /// `cpu.max` period must be at least 1000 microseconds.
    InvalidCpuPeriod,
    /// `pids.max` admission limit reached (`EAGAIN` on fork).
    PidsMaxLimitReached,
    /// Memory allocation exceeds `memory.max` hard limit (`ENOMEM` / OOM trigger).
    MemoryMaxExceeded,
    /// Cannot delete a cgroup that still has child cgroups or attached tasks.
    CgroupBusy,
    /// Task is already a member or not found.
    TaskNotFound,
    /// Block I/O bandwidth or IOPS quota reached (`io.max`).
    IoThrottled,
    /// Invalid I/O parameter format.
    InvalidIoParameter,
}

/// CPU bandwidth throttling settings (`cpu.max`: quota and period in microseconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuBandwidth {
    /// Maximum runtime in microseconds per period, or `None` for `"max"` (unlimited).
    pub quota_us: Option<u64>,
    /// Accounting period in microseconds (default 100_000 us = 100 ms).
    pub period_us: u64,
    /// Runtime consumed in the current period in microseconds.
    pub consumed_in_period_us: u64,
    /// Total accumulated CPU usage in microseconds.
    pub total_usage_us: u64,
    /// Number of periods in which tasks in this cgroup were throttled.
    pub nr_throttled: u64,
    /// Total duration in microseconds that tasks in this cgroup spent throttled.
    pub throttled_usec: u64,
    /// Whether this cgroup is currently throttled for the remainder of the period.
    pub is_throttled: bool,
}

impl Default for CpuBandwidth {
    fn default() -> Self {
        Self {
            quota_us: None,
            period_us: 100_000,
            consumed_in_period_us: 0,
            total_usage_us: 0,
            nr_throttled: 0,
            throttled_usec: 0,
            is_throttled: false,
        }
    }
}

impl CpuBandwidth {
    /// Charge `delta_us` of CPU execution time and return how many microseconds
    /// were allowed before hitting the quota (`allowed_us`, `overrun_throttled_us`).
    pub fn charge_runtime(&mut self, delta_us: u64) -> (u64, u64) {
        self.total_usage_us = self.total_usage_us.saturating_add(delta_us);
        match self.quota_us {
            None => {
                self.consumed_in_period_us = self.consumed_in_period_us.saturating_add(delta_us);
                (delta_us, 0)
            }
            Some(quota) => {
                let prev = self.consumed_in_period_us;
                let next = prev.saturating_add(delta_us);
                self.consumed_in_period_us = next;
                if next > quota {
                    if !self.is_throttled {
                        self.is_throttled = true;
                        self.nr_throttled = self.nr_throttled.saturating_add(1);
                    }
                    let allowed = quota.saturating_sub(prev);
                    let overrun = delta_us.saturating_sub(allowed);
                    self.throttled_usec = self.throttled_usec.saturating_add(overrun);
                    (allowed, overrun)
                } else {
                    (delta_us, 0)
                }
            }
        }
    }

    /// Advance to the next period, resetting `consumed_in_period_us` and unthrottling.
    pub fn refill_period(&mut self) {
        self.consumed_in_period_us = 0;
        self.is_throttled = false;
    }
}

/// Memory controller state (`memory.current`, `memory.high`, `memory.max`, `memory.events`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryControllerState {
    pub current_bytes: u64,
    pub high_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub events_high: u64,
    pub events_max: u64,
    pub events_oom: u64,
}

impl Default for MemoryControllerState {
    fn default() -> Self {
        Self {
            current_bytes: 0,
            high_bytes: None,
            max_bytes: None,
            events_high: 0,
            events_max: 0,
            events_oom: 0,
        }
    }
}

/// `cgroup.events` notification fields (`populated` and `frozen`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CgroupEvents {
    /// True if this cgroup or any of its descendants contains at least one live process.
    pub populated: bool,
    /// True if all processes in this cgroup subtree are frozen via `cgroup.freeze`.
    pub frozen: bool,
    /// Monotonic counter incremented every time `populated` or `frozen` transitions.
    pub event_seq: u64,
}

/// I/O bandwidth and IOPS limits for a specific block device (`io.max`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoDeviceLimits {
    pub major: u32,
    pub minor: u32,
    pub rbps: Option<u64>,  // Max read bytes per second
    pub wbps: Option<u64>,  // Max write bytes per second
    pub riops: Option<u32>, // Max read I/O operations per second
    pub wiops: Option<u32>, // Max write I/O operations per second
}

/// Token bucket throttler enforcing `io.max` limits with nanosecond refill granularity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoTokenBucket {
    pub limits: IoDeviceLimits,
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

impl IoTokenBucket {
    pub fn new(limits: IoDeviceLimits, now_ns: u64) -> Self {
        Self {
            read_bytes_avail: limits.rbps.unwrap_or(u64::MAX),
            write_bytes_avail: limits.wbps.unwrap_or(u64::MAX),
            read_iops_avail: limits.riops.unwrap_or(u32::MAX),
            write_iops_avail: limits.wiops.unwrap_or(u32::MAX),
            limits,
            last_refill_timestamp_ns: now_ns,
            rbps_rem_ns: 0,
            wbps_rem_ns: 0,
            riops_rem_ns: 0,
            wiops_rem_ns: 0,
        }
    }

    /// Refill available bandwidth tokens proportional to elapsed nanoseconds with zero integer-truncation loss.
    pub fn refill(&mut self, now_ns: u64) {
        if now_ns <= self.last_refill_timestamp_ns {
            return;
        }
        let elapsed_ns = now_ns - self.last_refill_timestamp_ns;
        self.last_refill_timestamp_ns = now_ns;

        // 1 second = 1_000_000_000 ns
        if let Some(rbps) = self.limits.rbps {
            if rbps > 0 {
                let total_ns = (elapsed_ns as u128) + (self.rbps_rem_ns as u128);
                let tokens = (rbps as u128 * total_ns) / 1_000_000_000;
                if tokens > 0 {
                    self.read_bytes_avail = (self.read_bytes_avail.saturating_add(tokens as u64)).min(rbps);
                    let consumed_ns = (tokens * 1_000_000_000) / (rbps as u128);
                    self.rbps_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
                } else {
                    self.rbps_rem_ns = total_ns.min(1_000_000_000) as u64;
                }
            }
        }
        if let Some(wbps) = self.limits.wbps {
            if wbps > 0 {
                let total_ns = (elapsed_ns as u128) + (self.wbps_rem_ns as u128);
                let tokens = (wbps as u128 * total_ns) / 1_000_000_000;
                if tokens > 0 {
                    self.write_bytes_avail = (self.write_bytes_avail.saturating_add(tokens as u64)).min(wbps);
                    let consumed_ns = (tokens * 1_000_000_000) / (wbps as u128);
                    self.wbps_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
                } else {
                    self.wbps_rem_ns = total_ns.min(1_000_000_000) as u64;
                }
            }
        }
        if let Some(riops) = self.limits.riops {
            if riops > 0 {
                let total_ns = (elapsed_ns as u128) + (self.riops_rem_ns as u128);
                let tokens = (riops as u128 * total_ns) / 1_000_000_000;
                if tokens > 0 {
                    self.read_iops_avail = (self.read_iops_avail.saturating_add(tokens as u32)).min(riops);
                    let consumed_ns = (tokens * 1_000_000_000) / (riops as u128);
                    self.riops_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
                } else {
                    self.riops_rem_ns = total_ns.min(1_000_000_000) as u64;
                }
            }
        }
        if let Some(wiops) = self.limits.wiops {
            if wiops > 0 {
                let total_ns = (elapsed_ns as u128) + (self.wiops_rem_ns as u128);
                let tokens = (wiops as u128 * total_ns) / 1_000_000_000;
                if tokens > 0 {
                    self.write_iops_avail = (self.write_iops_avail.saturating_add(tokens as u32)).min(wiops);
                    let consumed_ns = (tokens * 1_000_000_000) / (wiops as u128);
                    self.wiops_rem_ns = (total_ns.saturating_sub(consumed_ns)).min(1_000_000_000) as u64;
                } else {
                    self.wiops_rem_ns = total_ns.min(1_000_000_000) as u64;
                }
            }
        }
    }

    /// Charge bytes and IOPS against the token bucket.
    pub fn charge_io(&mut self, is_write: bool, bytes: u64, now_ns: u64) -> Result<(), CgroupError> {
        self.refill(now_ns);

        if is_write {
            if let Some(_limit_bytes) = self.limits.wbps {
                if self.write_bytes_avail < bytes {
                    return Err(CgroupError::IoThrottled);
                }
                self.write_bytes_avail -= bytes;
            }
            if let Some(_limit_iops) = self.limits.wiops {
                if self.write_iops_avail == 0 {
                    return Err(CgroupError::IoThrottled);
                }
                self.write_iops_avail -= 1;
            }
        } else {
            if let Some(_limit_bytes) = self.limits.rbps {
                if self.read_bytes_avail < bytes {
                    return Err(CgroupError::IoThrottled);
                }
                self.read_bytes_avail -= bytes;
            }
            if let Some(_limit_iops) = self.limits.riops {
                if self.read_iops_avail == 0 {
                    return Err(CgroupError::IoThrottled);
                }
                self.read_iops_avail -= 1;
            }
        }

        Ok(())
    }
}

/// Unified Control Group v2 Node (`CgroupNode`).
#[derive(Clone, Debug)]
pub struct CgroupNode {
    pub id: u64,
    pub name: String,
    pub parent_id: Option<u64>,
    pub children: Vec<u64>,
    /// Controllers available to this node (inherited from parent's `subtree_control`).
    pub available_controllers: CgroupControllers,
    /// Controllers enabled for direct children (`cgroup.subtree_control`).
    pub subtree_control: CgroupControllers,
    /// Direct task PIDs attached to `cgroup.procs` (only allowed on leaf nodes if subtree_control != NONE).
    pub procs: Vec<u32>,
    /// `cpu.weight` in `1..=10000` (default 100).
    pub cpu_weight: u32,
    /// `cpu.max` bandwidth limiter.
    pub cpu_bandwidth: CpuBandwidth,
    /// `io.max` token bucket rate limiters per block device `(major, minor)`.
    pub io_limits: BTreeMap<(u32, u32), IoTokenBucket>,
    /// `pids.current` (inclusive of entire subtree).
    pub pids_current: u32,
    /// `pids.max` admission limit (`None` means `"max"`).
    pub pids_max: Option<u32>,
    /// Number of times fork/clone was rejected due to `pids.max`.
    pub pids_events_max: u64,
    /// Memory accounting and limits.
    pub memory: MemoryControllerState,
    /// Desired freeze state written to `cgroup.freeze`.
    pub freeze_requested: bool,
    /// Observable `cgroup.events` state.
    pub events: CgroupEvents,
}

impl CgroupNode {
    pub const DEFAULT_CPU_WEIGHT: u32 = 100;
    pub const MIN_CPU_WEIGHT: u32 = 1;
    pub const MAX_CPU_WEIGHT: u32 = 10_000;

    pub fn new_root() -> Self {
        Self {
            id: 1,
            name: String::from("/"),
            parent_id: None,
            children: Vec::new(),
            available_controllers: CgroupControllers::ALL,
            subtree_control: CgroupControllers::NONE,
            procs: Vec::new(),
            cpu_weight: Self::DEFAULT_CPU_WEIGHT,
            cpu_bandwidth: CpuBandwidth::default(),
            io_limits: BTreeMap::new(),
            pids_current: 0,
            pids_max: None,
            pids_events_max: 0,
            memory: MemoryControllerState::default(),
            freeze_requested: false,
            events: CgroupEvents::default(),
        }
    }
}

/// Complete Unified Cgroup v2 Hierarchy tree manager.
pub struct CgroupHierarchy {
    nodes: BTreeMap<u64, CgroupNode>,
    next_id: u64,
}

impl Default for CgroupHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupHierarchy {
    pub const ROOT_ID: u64 = 1;

    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(Self::ROOT_ID, CgroupNode::new_root());
        Self {
            nodes,
            next_id: 2,
        }
    }

    pub fn get_node(&self, id: u64) -> Option<&CgroupNode> {
        self.nodes.get(&id)
    }

    /// Create a child cgroup under `parent_id`.
    pub fn create_cgroup(&mut self, parent_id: u64, name: &str) -> Result<u64, CgroupError> {
        let parent_subtree = {
            let parent = self.nodes.get(&parent_id).ok_or(CgroupError::NotFound)?;
            parent.subtree_control
        };

        let id = self.next_id;
        self.next_id += 1;

        let child = CgroupNode {
            id,
            name: String::from(name),
            parent_id: Some(parent_id),
            children: Vec::new(),
            available_controllers: parent_subtree,
            subtree_control: CgroupControllers::NONE,
            procs: Vec::new(),
            cpu_weight: CgroupNode::DEFAULT_CPU_WEIGHT,
            cpu_bandwidth: CpuBandwidth::default(),
            io_limits: BTreeMap::new(),
            pids_current: 0,
            pids_max: None,
            pids_events_max: 0,
            memory: MemoryControllerState::default(),
            freeze_requested: false,
            events: CgroupEvents::default(),
        };

        self.nodes.insert(id, child);
        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.push(id);
        }
        Ok(id)
    }

    /// Configure `cgroup.subtree_control` on `node_id`, enforcing the Cgroup v2
    /// "no internal processes" rule (non-root nodes with direct processes cannot enable
    /// subtree controllers).
    pub fn set_subtree_control(
        &mut self,
        node_id: u64,
        controllers: CgroupControllers,
    ) -> Result<(), CgroupError> {
        let child_ids = {
            let node = self.nodes.get(&node_id).ok_or(CgroupError::NotFound)?;
            if !node.available_controllers.contains(controllers) {
                return Err(CgroupError::ControllerNotEnabledInParent);
            }
            if node_id != Self::ROOT_ID && !node.procs.is_empty() && !controllers.is_empty() {
                return Err(CgroupError::NoInternalProcessConstraint);
            }
            node.children.clone()
        };

        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.subtree_control = controllers;
        }
        for cid in child_ids {
            if let Some(child) = self.nodes.get_mut(&cid) {
                child.available_controllers = controllers;
            }
        }
        Ok(())
    }

    /// Set `cpu.weight` (`1..=10000`) on `node_id`.
    pub fn set_cpu_weight(&mut self, node_id: u64, weight: u32) -> Result<(), CgroupError> {
        if !(CgroupNode::MIN_CPU_WEIGHT..=CgroupNode::MAX_CPU_WEIGHT).contains(&weight) {
            return Err(CgroupError::InvalidCpuWeight);
        }
        let node = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
        node.cpu_weight = weight;
        Ok(())
    }

    /// Split `total_slice_us` proportionally across active sibling cgroups under `parent_id`
    /// according to their `cpu.weight` (`1..=10000`). Only populated, non-frozen,
    /// non-throttled children participate.
    pub fn split_cpu_shares(
        &self,
        parent_id: u64,
        total_slice_us: u64,
    ) -> Result<Vec<(u64, u64)>, CgroupError> {
        let parent = self.nodes.get(&parent_id).ok_or(CgroupError::NotFound)?;
        let mut active_children = Vec::new();
        let mut weight_sum: u64 = 0;

        for &cid in &parent.children {
            if let Some(child) = self.nodes.get(&cid) {
                if child.events.populated && !child.events.frozen && !child.cpu_bandwidth.is_throttled {
                    let w = child.cpu_weight as u64;
                    weight_sum += w;
                    active_children.push((cid, w));
                }
            }
        }

        if weight_sum == 0 {
            return Ok(Vec::new());
        }

        let mut allocations = Vec::with_capacity(active_children.len());
        let mut distributed: u64 = 0;
        let len = active_children.len();
        for (idx, (cid, w)) in active_children.into_iter().enumerate() {
            let share = if idx + 1 == len {
                total_slice_us.saturating_sub(distributed)
            } else {
                (total_slice_us.saturating_mul(w)) / weight_sum
            };
            distributed = distributed.saturating_add(share);
            allocations.push((cid, share));
        }
        Ok(allocations)
    }

    /// Configure `cpu.max` quota and period in microseconds.
    pub fn set_cpu_max(
        &mut self,
        node_id: u64,
        quota_us: Option<u64>,
        period_us: u64,
    ) -> Result<(), CgroupError> {
        if period_us < 1_000 {
            return Err(CgroupError::InvalidCpuPeriod);
        }
        let node = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
        node.cpu_bandwidth.quota_us = quota_us;
        node.cpu_bandwidth.period_us = period_us;
        Ok(())
    }

    /// Charge CPU execution time `delta_us` to `node_id` and its ancestors that have `CPU` enabled.
    pub fn charge_cpu_usage(
        &mut self,
        node_id: u64,
        delta_us: u64,
    ) -> Result<(u64, u64), CgroupError> {
        let mut chain = Vec::new();
        let mut cur = Some(node_id);
        while let Some(id) = cur {
            let node = self.nodes.get(&id).ok_or(CgroupError::NotFound)?;
            chain.push(id);
            cur = node.parent_id;
        }

        let mut leaf_result = (delta_us, 0);
        for (idx, id) in chain.into_iter().enumerate() {
            if let Some(node) = self.nodes.get_mut(&id) {
                let res = node.cpu_bandwidth.charge_runtime(delta_us);
                if idx == 0 {
                    leaf_result = res;
                }
            }
        }
        Ok(leaf_result)
    }

    /// Configure `pids.max` on `node_id`.
    pub fn set_pids_max(&mut self, node_id: u64, max_pids: Option<u32>) -> Result<(), CgroupError> {
        let node = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
        node.pids_max = max_pids;
        Ok(())
    }

    /// Configure `memory.high` and `memory.max` on `node_id`.
    pub fn set_memory_limits(
        &mut self,
        node_id: u64,
        high_bytes: Option<u64>,
        max_bytes: Option<u64>,
    ) -> Result<(), CgroupError> {
        let node = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
        node.memory.high_bytes = high_bytes;
        node.memory.max_bytes = max_bytes;
        Ok(())
    }

    /// Charge memory allocation across `node_id` and its ancestor chain.
    pub fn charge_memory(&mut self, node_id: u64, bytes: u64) -> Result<(), CgroupError> {
        let mut chain = Vec::new();
        let mut cur = Some(node_id);
        while let Some(id) = cur {
            let node = self.nodes.get(&id).ok_or(CgroupError::NotFound)?;
            chain.push(id);
            cur = node.parent_id;
        }

        // First check if any ancestor would breach `memory.max`.
        for &id in &chain {
            if let Some(node) = self.nodes.get(&id) {
                if let Some(max_b) = node.memory.max_bytes {
                    if node.memory.current_bytes.saturating_add(bytes) > max_b {
                        if let Some(mut_node) = self.nodes.get_mut(&id) {
                            mut_node.memory.events_max += 1;
                            mut_node.memory.events_oom += 1;
                        }
                        return Err(CgroupError::MemoryMaxExceeded);
                    }
                }
            }
        }

        // Apply memory charge and record `memory.high` throttle events.
        for id in chain {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.memory.current_bytes = node.memory.current_bytes.saturating_add(bytes);
                if let Some(high_b) = node.memory.high_bytes {
                    if node.memory.current_bytes > high_b {
                        node.memory.events_high += 1;
                    }
                }
            }
        }
        Ok(())
    }

    /// Admission control guard (`pids.max`) and task attachment (`cgroup.procs`).
    pub fn attach_task(&mut self, node_id: u64, pid: u32) -> Result<(), CgroupError> {
        let mut chain = Vec::new();
        let mut cur = Some(node_id);
        while let Some(id) = cur {
            let node = self.nodes.get(&id).ok_or(CgroupError::NotFound)?;
            if id == node_id
                && id != Self::ROOT_ID
                && !node.subtree_control.is_empty()
            {
                return Err(CgroupError::NoInternalProcessConstraint);
            }
            chain.push(id);
            cur = node.parent_id;
        }

        // Check `pids.max` across the entire ancestor chain.
        for &id in &chain {
            if let Some(node) = self.nodes.get(&id) {
                if let Some(max_p) = node.pids_max {
                    if node.pids_current >= max_p {
                        if let Some(mut_node) = self.nodes.get_mut(&id) {
                            mut_node.pids_events_max += 1;
                        }
                        return Err(CgroupError::PidsMaxLimitReached);
                    }
                }
            }
        }

        if let Some(leaf) = self.nodes.get_mut(&node_id) {
            leaf.procs.push(pid);
        }

        for id in chain {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.pids_current = node.pids_current.saturating_add(1);
                if !node.events.populated {
                    node.events.populated = true;
                    node.events.event_seq += 1;
                }
            }
        }
        Ok(())
    }

    /// Detach an exiting or migrating task from `node_id` and update `cgroup.events` populated state.
    pub fn detach_task(&mut self, node_id: u64, pid: u32) -> Result<(), CgroupError> {
        let mut chain = Vec::new();
        let mut cur = Some(node_id);
        while let Some(id) = cur {
            let node = self.nodes.get(&id).ok_or(CgroupError::NotFound)?;
            chain.push(id);
            cur = node.parent_id;
        }

        {
            let leaf = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
            let pos = leaf
                .procs
                .iter()
                .position(|&p| p == pid)
                .ok_or(CgroupError::TaskNotFound)?;
            leaf.procs.remove(pos);
        }

        for id in chain {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.pids_current = node.pids_current.saturating_sub(1);
                let now_populated = node.pids_current > 0;
                if node.events.populated != now_populated {
                    node.events.populated = now_populated;
                    node.events.event_seq += 1;
                }
            }
        }
        Ok(())
    }

    /// Freeze or unfreeze an entire cgroup subtree (`cgroup.freeze`), updating `cgroup.events`.
    pub fn set_frozen(&mut self, node_id: u64, freeze: bool) -> Result<(), CgroupError> {
        if node_id == Self::ROOT_ID {
            return Err(CgroupError::InvalidOperationOnRoot);
        }
        if !self.nodes.contains_key(&node_id) {
            return Err(CgroupError::NotFound);
        }

        let mut stack = alloc::vec![node_id];
        while let Some(id) = stack.pop() {
            let children = if let Some(node) = self.nodes.get_mut(&id) {
                if id == node_id {
                    node.freeze_requested = freeze;
                }
                if node.events.frozen != freeze {
                    node.events.frozen = freeze;
                    node.events.event_seq += 1;
                }
                node.children.clone()
            } else {
                Vec::new()
            };
            for cid in children {
                stack.push(cid);
            }
        }
        Ok(())
    }

    /// Configure `io.max` limits on `node_id` for block device `(major, minor)`.
    pub fn set_io_max(&mut self, node_id: u64, limits: IoDeviceLimits, now_ns: u64) -> Result<(), CgroupError> {
        let node = self.nodes.get_mut(&node_id).ok_or(CgroupError::NotFound)?;
        let key = (limits.major, limits.minor);
        node.io_limits.insert(key, IoTokenBucket::new(limits, now_ns));
        Ok(())
    }

    /// Charge block I/O bandwidth/IOPS on `node_id` for device `(major, minor)`.
    /// Traverses ancestors to root, charging tokens at every level.
    pub fn charge_io(
        &mut self,
        node_id: u64,
        major: u32,
        minor: u32,
        is_write: bool,
        bytes: u64,
        now_ns: u64,
    ) -> Result<(), CgroupError> {
        let key = (major, minor);
        let mut curr_id = Some(node_id);

        while let Some(id) = curr_id {
            if let Some(node) = self.nodes.get_mut(&id) {
                if let Some(bucket) = node.io_limits.get_mut(&key) {
                    bucket.charge_io(is_write, bytes, now_ns)?;
                }
                curr_id = node.parent_id;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Resolves `/sys/fs/cgroup/...` relative or absolute path into `(node_id, filename)`.
    pub fn resolve_cgroupfs_path<'a>(&self, path: &'a str) -> Option<(u64, &'a str)> {
        let trimmed = path
            .strip_prefix("/sys/fs/cgroup/")
            .or_else(|| path.strip_prefix("/sys/fs/cgroup"))
            .or_else(|| path.strip_prefix("/"))
            .unwrap_or(path);

        if trimmed.is_empty() {
            return None;
        }

        let parts: Vec<&'a str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }

        let filename = *parts.last()?;
        let mut curr_id = Self::ROOT_ID;

        for &dir in &parts[..parts.len() - 1] {
            let node = self.nodes.get(&curr_id)?;
            let child_id = node.children.iter().find(|&&cid| {
                if let Some(child) = self.nodes.get(&cid) {
                    child.name == dir
                } else {
                    false
                }
            })?;
            curr_id = *child_id;
        }

        Some((curr_id, filename))
    }

    /// Read pseudo-filesystem node at `/sys/fs/cgroup/...`.
    pub fn read_cgroupfs_path(&self, path: &str) -> Option<String> {
        let (node_id, filename) = self.resolve_cgroupfs_path(path)?;
        self.render_cgroupfs_file(node_id, filename)
    }

    /// Render pseudo-file content for a specific cgroup node.
    pub fn render_cgroupfs_file(&self, node_id: u64, filename: &str) -> Option<String> {
        use alloc::format;
        let node = self.nodes.get(&node_id)?;

        match filename {
            "cgroup.procs" => {
                let mut out = String::new();
                for pid in &node.procs {
                    out.push_str(&format!("{}\n", pid));
                }
                Some(out)
            }
            "cgroup.controllers" => {
                let mut out = String::new();
                if node.available_controllers.contains(CgroupControllers::CPU) {
                    out.push_str("cpu ");
                }
                if node.available_controllers.contains(CgroupControllers::MEMORY) {
                    out.push_str("memory ");
                }
                if node.available_controllers.contains(CgroupControllers::IO) {
                    out.push_str("io ");
                }
                if node.available_controllers.contains(CgroupControllers::PIDS) {
                    out.push_str("pids ");
                }
                if out.ends_with(' ') {
                    out.pop();
                }
                out.push('\n');
                Some(out)
            }
            "cgroup.subtree_control" => {
                let mut out = String::new();
                if node.subtree_control.contains(CgroupControllers::CPU) {
                    out.push_str("cpu ");
                }
                if node.subtree_control.contains(CgroupControllers::MEMORY) {
                    out.push_str("memory ");
                }
                if node.subtree_control.contains(CgroupControllers::IO) {
                    out.push_str("io ");
                }
                if node.subtree_control.contains(CgroupControllers::PIDS) {
                    out.push_str("pids ");
                }
                if out.ends_with(' ') {
                    out.pop();
                }
                out.push('\n');
                Some(out)
            }
            "cpu.max" => {
                let quota_str = match node.cpu_bandwidth.quota_us {
                    Some(q) => format!("{}", q),
                    None => String::from("max"),
                };
                Some(format!("{} {}\n", quota_str, node.cpu_bandwidth.period_us))
            }
            "cpu.weight" => {
                Some(format!("{}\n", node.cpu_weight))
            }
            "memory.max" => {
                let max_str = match node.memory.max_bytes {
                    Some(m) => format!("{}", m),
                    None => String::from("max"),
                };
                Some(format!("{}\n", max_str))
            }
            "memory.current" => {
                Some(format!("{}\n", node.memory.current_bytes))
            }
            "io.max" => {
                if node.io_limits.is_empty() {
                    Some(String::from("max\n"))
                } else {
                    let mut out = String::new();
                    for ((maj, min), b) in &node.io_limits {
                        let mut line = format!("{}:{}", maj, min);
                        if let Some(rbps) = b.limits.rbps {
                            line.push_str(&format!(" rbps={}", rbps));
                        }
                        if let Some(wbps) = b.limits.wbps {
                            line.push_str(&format!(" wbps={}", wbps));
                        }
                        if let Some(riops) = b.limits.riops {
                            line.push_str(&format!(" riops={}", riops));
                        }
                        if let Some(wiops) = b.limits.wiops {
                            line.push_str(&format!(" wiops={}", wiops));
                        }
                        line.push('\n');
                        out.push_str(&line);
                    }
                    Some(out)
                }
            }
            "cgroup.events" => {
                Some(format!(
                    "populated {}\nfrozen {}\n",
                    if node.events.populated { 1 } else { 0 },
                    if node.events.frozen { 1 } else { 0 },
                ))
            }
            _ => None,
        }
    }

    /// Write pseudo-filesystem node at `/sys/fs/cgroup/...`.
    pub fn write_cgroupfs_path(&mut self, path: &str, content: &str, now_ns: u64) -> Result<(), CgroupError> {
        let (node_id, filename) = self.resolve_cgroupfs_path(path).ok_or(CgroupError::NotFound)?;
        self.write_cgroupfs_file(node_id, filename, content, now_ns)
    }

    /// Write pseudo-file content for a specific cgroup node.
    pub fn write_cgroupfs_file(&mut self, node_id: u64, filename: &str, content: &str, now_ns: u64) -> Result<(), CgroupError> {
        let trimmed = content.trim();
        match filename {
            "cgroup.procs" => {
                let pid: u32 = trimmed.parse().map_err(|_| CgroupError::TaskNotFound)?;
                self.attach_task(node_id, pid)
            }
            "cpu.weight" => {
                let w: u32 = trimmed.parse().map_err(|_| CgroupError::InvalidCpuWeight)?;
                self.set_cpu_weight(node_id, w)
            }
            "cpu.max" => {
                let mut parts = trimmed.split_whitespace();
                let quota_part = parts.next().ok_or(CgroupError::InvalidCpuPeriod)?;
                let period_part = parts.next();

                let quota = if quota_part == "max" {
                    None
                } else {
                    Some(quota_part.parse::<u64>().map_err(|_| CgroupError::InvalidCpuPeriod)?)
                };

                let period = if let Some(p_str) = period_part {
                    p_str.parse::<u64>().map_err(|_| CgroupError::InvalidCpuPeriod)?
                } else {
                    100_000
                };

                self.set_cpu_max(node_id, quota, period)
            }
            "io.max" => {
                let mut parts = trimmed.split_whitespace();
                let dev_part = parts.next().ok_or(CgroupError::InvalidIoParameter)?;
                let mut dev_split = dev_part.split(':');
                let major: u32 = dev_split.next().and_then(|s| s.parse().ok()).ok_or(CgroupError::InvalidIoParameter)?;
                let minor: u32 = dev_split.next().and_then(|s| s.parse().ok()).ok_or(CgroupError::InvalidIoParameter)?;

                let mut limits = IoDeviceLimits {
                    major,
                    minor,
                    rbps: None,
                    wbps: None,
                    riops: None,
                    wiops: None,
                };

                for token in parts {
                    if let Some(val) = token.strip_prefix("rbps=") {
                        limits.rbps = val.parse().ok();
                    } else if let Some(val) = token.strip_prefix("wbps=") {
                        limits.wbps = val.parse().ok();
                    } else if let Some(val) = token.strip_prefix("riops=") {
                        limits.riops = val.parse().ok();
                    } else if let Some(val) = token.strip_prefix("wiops=") {
                        limits.wiops = val.parse().ok();
                    }
                }

                self.set_io_max(node_id, limits, now_ns)
            }
            "cgroup.freeze" => {
                let freeze = trimmed == "1";
                self.set_frozen(node_id, freeze)
            }
            _ => Err(CgroupError::NotFound),
        }
    }
}

/// Self-test exercising Cgroup v2 hierarchy, `cpu.weight` share splitter, `cpu.max`
/// bandwidth throttler, `pids.max` admission guard, `io.max` token bucket rate limiter,
/// and `cgroup.events` transitions.
pub fn self_test() -> bool {
    let mut tree = CgroupHierarchy::new();
    if tree
        .set_subtree_control(
            CgroupHierarchy::ROOT_ID,
            CgroupControllers::CPU
                .union(CgroupControllers::PIDS)
                .union(CgroupControllers::MEMORY)
                .union(CgroupControllers::IO),
        )
        .is_err()
    {
        return false;
    }

    let cg_high = match tree.create_cgroup(CgroupHierarchy::ROOT_ID, "service-high") {
        Ok(id) => id,
        Err(_) => return false,
    };
    let cg_low = match tree.create_cgroup(CgroupHierarchy::ROOT_ID, "service-low") {
        Ok(id) => id,
        Err(_) => return false,
    };

    if tree.set_cpu_weight(cg_high, 300).is_err() || tree.set_cpu_weight(cg_low, 100).is_err() {
        return false;
    }
    if tree.set_pids_max(cg_low, Some(2)).is_err() {
        return false;
    }

    if tree.attach_task(cg_high, 101).is_err()
        || tree.attach_task(cg_low, 201).is_err()
        || tree.attach_task(cg_low, 202).is_err()
    {
        return false;
    }

    // Third task in cg_low must fail with PidsMaxLimitReached.
    if tree.attach_task(cg_low, 203) != Err(CgroupError::PidsMaxLimitReached) {
        return false;
    }

    // Proportional CPU weight split (300 : 100 -> 75_000 us : 25_000 us out of 100_000 us).
    let shares = match tree.split_cpu_shares(CgroupHierarchy::ROOT_ID, 100_000) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if shares.len() != 2 || shares[0] != (cg_high, 75_000) || shares[1] != (cg_low, 25_000) {
        return false;
    }

    // Configure cpu.max on cg_low (quota = 20_000 us per 100_000 us) and exceed it.
    if tree.set_cpu_max(cg_low, Some(20_000), 100_000).is_err() {
        return false;
    }
    let (allowed, overrun) = match tree.charge_cpu_usage(cg_low, 25_000) {
        Ok(res) => res,
        Err(_) => return false,
    };
    if allowed != 20_000 || overrun != 5_000 {
        return false;
    }

    // Configure io.max on cg_low (block device 8:0, 500 KB/s write limit)
    let io_limits = IoDeviceLimits {
        major: 8,
        minor: 0,
        rbps: Some(1_048_576),
        wbps: Some(524_288),
        riops: Some(100),
        wiops: Some(50),
    };
    if tree.set_io_max(cg_low, io_limits, 0).is_err() {
        return false;
    }
    // Write 200 KB -> allowed
    if tree.charge_io(cg_low, 8, 0, true, 200_000, 0).is_err() {
        return false;
    }
    // Write 400 KB -> throttled (exceeds remaining 324_288 tokens)
    if tree.charge_io(cg_low, 8, 0, true, 400_000, 0) != Err(CgroupError::IoThrottled) {
        return false;
    }

    // Test /sys/fs/cgroup pseudo-fs interfaces
    let weight_val = match tree.read_cgroupfs_path("/sys/fs/cgroup/service-low/cpu.weight") {
        Some(v) => v,
        None => return false,
    };
    if weight_val.trim() != "100" {
        return false;
    }
    if tree.write_cgroupfs_path("/sys/fs/cgroup/service-low/cpu.weight", "150", 0).is_err() {
        return false;
    }
    if tree.get_node(cg_low).map(|n| n.cpu_weight) != Some(150) {
        return false;
    }

    // Freeze cg_high and verify populated/frozen events.
    if tree.set_frozen(cg_high, true).is_err() {
        return false;
    }
    let node_high = match tree.get_node(cg_high) {
        Some(n) => n,
        None => return false,
    };
    if !node_high.events.populated || !node_high.events.frozen {
        return false;
    }

    // Detach task 101 from cg_high -> populated becomes false.
    if tree.detach_task(cg_high, 101).is_err() {
        return false;
    }
    match tree.get_node(cg_high) {
        Some(n) => !n.events.populated && n.events.event_seq >= 3,
        None => false,
    }
}
