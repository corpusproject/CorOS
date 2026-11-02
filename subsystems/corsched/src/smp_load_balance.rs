//! Hierarchical SMP Load Balancer.
//!
//! Implements multi-level domain balancing (SMT, MC, LLC, NUMA) with:
//! - Bitmask-based CPU affinity tracking (`CpuSet`)
//! - Cache-hotness heuristics to avoid costly cache-line migrations
//! - Group and queue imbalance calculation with capacity scaling
//! - Pull-based idle balancing and periodic domain balancing

extern crate alloc;

use alloc::vec::Vec;

/// Maximum number of CPUs supported in the load balancing domain mask.
pub const MAX_CPUS: usize = 64;
/// Default CPU capacity scaling (1024 = 1.0x baseline computing capacity).
pub const SCHED_CAPACITY_SCALE: u32 = 1024;
/// Cache hotness threshold in nanoseconds (500 microseconds).
pub const CACHE_HOT_THRESHOLD_NS: u64 = 500_000;

/// 64-bit CPU affinity and domain bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSet {
    pub mask: u64,
}

impl CpuSet {
    pub const fn empty() -> Self {
        Self { mask: 0 }
    }

    pub const fn all() -> Self {
        Self { mask: u64::MAX }
    }

    pub const fn single(cpu_id: u32) -> Self {
        if cpu_id < 64 {
            Self { mask: 1u64 << cpu_id }
        } else {
            Self { mask: 0 }
        }
    }

    pub fn set(&mut self, cpu_id: u32) {
        if cpu_id < 64 {
            self.mask |= 1u64 << cpu_id;
        }
    }

    pub fn clear(&mut self, cpu_id: u32) {
        if cpu_id < 64 {
            self.mask &= !(1u64 << cpu_id);
        }
    }

    pub fn contains(&self, cpu_id: u32) -> bool {
        if cpu_id < 64 {
            (self.mask & (1u64 << cpu_id)) != 0
        } else {
            false
        }
    }

    pub fn count(&self) -> u32 {
        self.mask.count_ones()
    }

    pub fn is_empty(&self) -> bool {
        self.mask == 0
    }

    pub fn union(&self, other: CpuSet) -> CpuSet {
        CpuSet { mask: self.mask | other.mask }
    }

    pub fn intersection(&self, other: CpuSet) -> CpuSet {
        CpuSet { mask: self.mask & other.mask }
    }
}

/// Sched domain hierarchy levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedDomainLevel {
    Smt,   // Simultaneous Multi-Threading (hyperthreads sharing L1/L2)
    Mc,    // Multi-Core (cores sharing LLC)
    Llc,   // Last Level Cache cluster
    Numa,  // Non-Uniform Memory Access (inter-socket)
}

/// Sched group representing a set of CPUs within a sched domain.
#[derive(Debug, Clone)]
pub struct SchedGroup {
    pub span: CpuSet,
    pub capacity: u32,
    pub total_load: u64,
}

/// Sched domain defining the balancing scope and parameters.
#[derive(Debug, Clone)]
pub struct SchedDomain {
    pub level: SchedDomainLevel,
    pub span: CpuSet,
    pub groups: Vec<SchedGroup>,
    pub balance_interval_ms: u32,
    pub min_interval_ms: u32,
    pub max_interval_ms: u32,
    pub imbalance_pct: u32,
}

/// Task eligible for migration across CPU runqueues.
#[derive(Debug, Clone)]
pub struct MigratableTask {
    pub id: u64,
    pub weight: u32,
    pub affinity: CpuSet,
    pub last_cpu: u32,
    pub last_run_timestamp_ns: u64,
    pub migration_count: u64,
}

impl MigratableTask {
    pub fn new(id: u64, weight: u32, affinity: CpuSet, initial_cpu: u32) -> Self {
        Self {
            id,
            weight,
            affinity,
            last_cpu: initial_cpu,
            last_run_timestamp_ns: 0,
            migration_count: 0,
        }
    }

    /// Check if task is cache-hot on its current CPU.
    pub fn is_cache_hot(&self, now_ns: u64) -> bool {
        now_ns.saturating_sub(self.last_run_timestamp_ns) < CACHE_HOT_THRESHOLD_NS
    }
}

/// Per-CPU runqueue state for load balancing.
#[derive(Debug, Clone)]
pub struct PerCpuRunQueue {
    pub cpu_id: u32,
    pub capacity: u32,
    pub tasks: Vec<MigratableTask>,
}

impl PerCpuRunQueue {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            capacity: SCHED_CAPACITY_SCALE,
            tasks: Vec::new(),
        }
    }

    pub fn nr_running(&self) -> usize {
        self.tasks.len()
    }

    pub fn total_load(&self) -> u64 {
        self.tasks.iter().map(|t| t.weight as u64).sum()
    }
}

/// SMP Hierarchical Load Balancer managing multi-core runqueues.
pub struct SmpLoadBalancer {
    pub runqueues: Vec<PerCpuRunQueue>,
    pub domains: Vec<SchedDomain>,
    pub total_migrations: u64,
}

impl SmpLoadBalancer {
    pub fn new(num_cpus: u32) -> Self {
        let count = num_cpus.min(64);
        let mut runqueues = Vec::with_capacity(count as usize);
        for i in 0..count {
            runqueues.push(PerCpuRunQueue::new(i));
        }

        Self {
            runqueues,
            domains: Vec::new(),
            total_migrations: 0,
        }
    }

    /// Add a sched domain to the hierarchy.
    pub fn add_domain(&mut self, domain: SchedDomain) {
        self.domains.push(domain);
    }

    /// Enqueue a task onto a specific CPU runqueue.
    pub fn enqueue_task(&mut self, cpu_id: u32, task: MigratableTask) -> Result<(), &'static str> {
        let rq = self.runqueues.get_mut(cpu_id as usize).ok_or("Invalid CPU ID")?;
        rq.tasks.push(task);
        Ok(())
    }

    /// Find the busiest CPU inside a given CPU set.
    pub fn find_busiest_cpu(&self, cpus: CpuSet) -> Option<u32> {
        let mut busiest_cpu = None;
        let mut max_load = 0;

        for rq in &self.runqueues {
            if cpus.contains(rq.cpu_id) {
                let load = rq.total_load();
                if load > max_load && rq.nr_running() > 1 {
                    max_load = load;
                    busiest_cpu = Some(rq.cpu_id);
                }
            }
        }

        busiest_cpu
    }

    /// Calculate load imbalance between a source and destination CPU.
    pub fn calculate_imbalance(&self, src_cpu: u32, dst_cpu: u32) -> u64 {
        let src_load = self.runqueues.get(src_cpu as usize).map(|rq| rq.total_load()).unwrap_or(0);
        let dst_load = self.runqueues.get(dst_cpu as usize).map(|rq| rq.total_load()).unwrap_or(0);

        if src_load > dst_load {
            (src_load - dst_load) / 2
        } else {
            0
        }
    }

    /// Pull tasks from `src_cpu` to `dst_cpu` up to the calculated imbalance.
    pub fn migrate_tasks(&mut self, src_cpu: u32, dst_cpu: u32, max_imbalance: u64, now_ns: u64) -> usize {
        if src_cpu == dst_cpu || max_imbalance == 0 {
            return 0;
        }

        let mut moved = 0;
        let mut load_moved = 0;

        // Collect candidates from src_cpu that are allowed on dst_cpu
        let mut candidates = Vec::new();
        if let Some(src_rq) = self.runqueues.get(src_cpu as usize) {
            for (idx, task) in src_rq.tasks.iter().enumerate() {
                if task.affinity.contains(dst_cpu) {
                    candidates.push((idx, task.weight as u64, task.is_cache_hot(now_ns)));
                }
            }
        }

        // Sort candidates: prefer cache-cold tasks first
        candidates.sort_by_key(|&(_, _, is_hot)| is_hot);

        let mut to_remove_indices = Vec::new();
        for (idx, weight, is_hot) in candidates {
            // Do not leave src_cpu completely empty
            if let Some(src_rq) = self.runqueues.get(src_cpu as usize) {
                if src_rq.nr_running() <= to_remove_indices.len() + 1 {
                    break;
                }
            }

            if is_hot && load_moved > 0 {
                // If we already moved something, avoid moving cache-hot task
                continue;
            }

            if load_moved + weight <= max_imbalance || moved == 0 {
                to_remove_indices.push(idx);
                load_moved += weight;
                moved += 1;
            }
        }

        // Remove in reverse order so indices remain valid
        to_remove_indices.sort_unstable_by(|a, b| b.cmp(a));
        let mut migrated_tasks = Vec::new();

        if let Some(src_rq) = self.runqueues.get_mut(src_cpu as usize) {
            for idx in to_remove_indices {
                let mut task = src_rq.tasks.remove(idx);
                task.last_cpu = dst_cpu;
                task.last_run_timestamp_ns = now_ns;
                task.migration_count += 1;
                migrated_tasks.push(task);
            }
        }

        if let Some(dst_rq) = self.runqueues.get_mut(dst_cpu as usize) {
            for task in migrated_tasks {
                dst_rq.tasks.push(task);
            }
        }

        self.total_migrations += moved as u64;
        moved
    }

    /// Balance load on behalf of `this_cpu` across all configured sched domains.
    pub fn balance(&mut self, this_cpu: u32, now_ns: u64) -> usize {
        let mut total_moved = 0;
        let domain_spans: Vec<CpuSet> = self.domains.iter().map(|d| d.span).collect();

        for span in domain_spans {
            if !span.contains(this_cpu) {
                continue;
            }

            // Find busiest CPU in this domain
            if let Some(busiest_cpu) = self.find_busiest_cpu(span) {
                if busiest_cpu != this_cpu {
                    let imbalance = self.calculate_imbalance(busiest_cpu, this_cpu);
                    if imbalance > 0 {
                        let moved = self.migrate_tasks(busiest_cpu, this_cpu, imbalance, now_ns);
                        total_moved += moved;
                        if total_moved > 0 {
                            break;
                        }
                    }
                }
            }
        }

        total_moved
    }
}
