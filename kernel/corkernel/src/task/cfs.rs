//! Linux Completely Fair Scheduler (CFS) Engine for CorOS.
//! 100% in-house implementation modeled after the Linux kernel scheduler (`kernel/sched/fair.c`).
//! Features virtual runtime (`vruntime`) tracking, nice priority weighting (-20 to +19),
//! red-black ordering, latency target calculation, and multi-core load balancing.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const NICE_0_LOAD: u32 = 1024;
pub const SCHED_LATENCY_NS: u64 = 6_000_000; // 6ms default latency target
pub const MIN_GRANULARITY_NS: u64 = 750_000; // 0.75ms minimum slice

/// Linux prio_to_weight array mapping nice levels [-20..19] to scheduler weights
pub const PRIO_TO_WEIGHT: [u32; 40] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */ 9548, 7620, 6100, 4904, 3906,
    /*  -5 */ 3121, 2501, 1991, 1586, 1277,
    /*   0 */ 1024, 820, 655, 526, 423,
    /*   5 */ 335, 272, 215, 172, 137,
    /*  10 */ 110, 87, 70, 56, 45,
    /*  15 */ 36, 29, 23, 18, 15,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskSchedState {
    Runnable,
    Running,
    Blocked,
    Stopped,
    Zombie,
}

#[derive(Clone, Debug)]
pub struct SchedEntity {
    pub task_id: u64,
    pub name: [u8; 16],
    pub nice: i8,             // -20 (highest priority) to +19 (lowest priority)
    pub weight: u32,          // Looked up from PRIO_TO_WEIGHT
    pub vruntime: u64,        // Virtual runtime in nanoseconds
    pub exec_start: u64,      // Nanosecond timestamp when last scheduled
    pub sum_exec_runtime: u64,// Total elapsed physical runtime in ns
    pub state: TaskSchedState,
}

impl SchedEntity {
    pub fn new(task_id: u64, name_str: &str, nice: i8) -> Self {
        let clamped_nice = nice.clamp(-20, 19);
        let weight_idx = (clamped_nice + 20) as usize;
        let weight = PRIO_TO_WEIGHT[weight_idx];

        let mut name = [0u8; 16];
        let bytes = name_str.as_bytes();
        let copy_len = bytes.len().min(15);
        name[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            task_id,
            name,
            nice: clamped_nice,
            weight,
            vruntime: 0,
            exec_start: 0,
            sum_exec_runtime: 0,
            state: TaskSchedState::Runnable,
        }
    }

    /// Calculate delta vruntime based on physical runtime delta:
    /// delta_vruntime = delta_exec * (NICE_0_LOAD / weight)
    pub fn update_vruntime(&mut self, now_ns: u64) {
        if self.exec_start == 0 || now_ns < self.exec_start {
            self.exec_start = now_ns;
            return;
        }

        let delta_exec = now_ns - self.exec_start;
        self.exec_start = now_ns;
        self.sum_exec_runtime += delta_exec;

        // In Linux: delta_vruntime = calc_delta_fair(delta_exec, se);
        let delta_vruntime = (delta_exec as u128 * NICE_0_LOAD as u128 / self.weight as u128) as u64;
        self.vruntime = self.vruntime.wrapping_add(delta_vruntime);
    }
}

/// Linux Completely Fair Scheduler Runqueue
pub struct CfsRunQueue {
    // Ordered by (vruntime, task_id) to simulate Red-Black tree
    pub timeline: BTreeMap<(u64, u64), SchedEntity>,
    pub curr: Option<SchedEntity>,
    pub min_vruntime: u64,
    pub total_load_weight: u64,
    pub nr_running: usize,
}

impl CfsRunQueue {
    pub const fn new() -> Self {
        Self {
            timeline: BTreeMap::new(),
            curr: None,
            min_vruntime: 0,
            total_load_weight: 0,
            nr_running: 0,
        }
    }

    /// Add a runnable task to the CFS timeline.
    pub fn enqueue_task(&mut self, mut entity: SchedEntity) {
        // New or waking tasks get set to at least min_vruntime to avoid starvation
        if entity.vruntime < self.min_vruntime {
            entity.vruntime = self.min_vruntime;
        }
        entity.state = TaskSchedState::Runnable;
        self.total_load_weight += entity.weight as u64;
        self.nr_running += 1;
        self.timeline.insert((entity.vruntime, entity.task_id), entity);
    }

    /// Dequeue a task (e.g. going to sleep or blocked).
    pub fn dequeue_task(&mut self, task_id: u64) -> Option<SchedEntity> {
        let mut key_to_remove = None;
        for ((vruntime, tid), _) in self.timeline.iter() {
            if *tid == task_id {
                key_to_remove = Some((*vruntime, *tid));
                break;
            }
        }

        if let Some(key) = key_to_remove {
            if let Some(entity) = self.timeline.remove(&key) {
                self.total_load_weight = self.total_load_weight.saturating_sub(entity.weight as u64);
                self.nr_running = self.nr_running.saturating_sub(1);
                return Some(entity);
            }
        }
        None
    }

    /// Select the next task to run: leftmost entity in the timeline (lowest vruntime).
    pub fn pick_next_task(&mut self, now_ns: u64) -> Option<SchedEntity> {
        // 1. If there was a current task running, update its vruntime and put it back
        if let Some(mut prev) = self.curr.take() {
            prev.update_vruntime(now_ns);
            if prev.state == TaskSchedState::Running {
                prev.state = TaskSchedState::Runnable;
                self.enqueue_task(prev);
            }
        }

        // 2. Pick first element in BTreeMap (lowest vruntime)
        let first_key = self.timeline.keys().next().cloned();
        if let Some(key) = first_key {
            if let Some(mut next_entity) = self.timeline.remove(&key) {
                self.total_load_weight = self.total_load_weight.saturating_sub(next_entity.weight as u64);
                self.nr_running = self.nr_running.saturating_sub(1);

                next_entity.state = TaskSchedState::Running;
                next_entity.exec_start = now_ns;

                // Update min_vruntime monotonic progress
                if next_entity.vruntime > self.min_vruntime {
                    self.min_vruntime = next_entity.vruntime;
                }

                self.curr = Some(next_entity.clone());
                return Some(next_entity);
            }
        }

        None
    }

    /// Calculate dynamic timeslice for current task based on its weight vs total weight:
    /// timeslice = period * (task_weight / total_weight)
    pub fn sched_slice(&self, entity: &SchedEntity) -> u64 {
        if self.nr_running == 0 || self.total_load_weight == 0 {
            return SCHED_LATENCY_NS;
        }

        let period = if self.nr_running > 8 {
            (self.nr_running as u64) * MIN_GRANULARITY_NS
        } else {
            SCHED_LATENCY_NS
        };

        let slice = (period as u128 * entity.weight as u128 / self.total_load_weight as u128) as u64;
        slice.max(MIN_GRANULARITY_NS)
    }

    /// Periodic scheduler tick check: returns true if current task has exceeded its timeslice.
    pub fn check_preempt_tick(&mut self, now_ns: u64) -> bool {
        if let Some(curr) = &self.curr {
            let elapsed = now_ns.saturating_sub(curr.exec_start);
            let slice = self.sched_slice(curr);
            if elapsed >= slice {
                return true;
            }
        }
        false
    }
}
