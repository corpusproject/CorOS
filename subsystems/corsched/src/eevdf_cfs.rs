//! Earliest Eligible Virtual Deadline First (EEVDF) & Completely Fair Scheduler (CFS).
//!
//! Implements the modern Linux EEVDF scheduling algorithm with:
//! - Priority-to-weight mapping for nice levels [-20, 19]
//! - Virtual runtime (vruntime) tracking and monotonic virtual time ($V_{rq}$) progression
//! - Task lag calculation ($Lag_i = (V_{rq} - v_i) \times w_i$)
//! - Virtual deadline calculation ($d_i = v_i + \frac{q_i}{w_i}$)
//! - Eligibility determination ($v_i \le V_{rq}$)
//! - Earliest eligible virtual deadline task selection

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Standard Linux nice-to-weight table.
/// Index 0 corresponds to nice -20 (weight 88761), index 20 to nice 0 (weight 1024),
/// and index 39 to nice 19 (weight 15).
pub const PRIO_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, // -20 .. -16
    29154, 23254, 18705, 14949, 11916, // -15 .. -11
    9548, 7620, 6100, 4904, 3906,       // -10 .. -6
    3121, 2501, 1991, 1586, 1277,       // -5 .. -1
    1024, 820, 655, 526, 423,           //  0 .. 4
    335, 272, 215, 172, 137,            //  5 .. 9
    110, 87, 70, 56, 45,                // 10 .. 14
    36, 29, 23, 18, 15,                 // 15 .. 19
];

/// Inverse weights ($2^{32} / weight$) for fast scaling without 64-bit hardware division.
pub const PRIO_TO_WMULT: [u32; 40] = [
    48388, 59856, 76040, 92818, 118345,
    147320, 184698, 229616, 287308, 360437,
    449829, 563644, 704093, 875809, 1099582,
    1376151, 1717300, 2157191, 2708050, 3363326,
    4194304, 5237765, 6557201, 8165337, 10153587,
    12820798, 15790321, 19976592, 24970740, 31350126,
    39045157, 49367440, 61356676, 76695844, 95443717,
    119304647, 148102322, 186737708, 238609294, 286331153,
];

/// Default scheduling slice quantum: 3 milliseconds in nanoseconds.
pub const DEFAULT_BASE_SLICE_NS: u64 = 3_000_000;
/// Minimum scheduling granularity: 750 microseconds in nanoseconds.
pub const MIN_GRANULARITY_NS: u64 = 750_000;
/// Nice 0 default weight.
pub const NICE_0_WEIGHT: u32 = 1024;

/// Scheduling entity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityState {
    Runnable,
    Running,
    Sleeping,
    Stopped,
}

/// Schedulable entity tracked by EEVDF/CFS.
#[derive(Debug, Clone)]
pub struct SchedEntity {
    pub id: u64,
    pub name: String,
    pub nice: i8,
    pub weight: u32,
    pub wmult: u32,
    pub state: EntityState,
    /// Virtual runtime of the entity in nanoseconds.
    pub vruntime: u64,
    /// Absolute execution start timestamp (nanoseconds).
    pub exec_start_ns: u64,
    /// Cumulative execution runtime (nanoseconds).
    pub sum_exec_runtime_ns: u64,
    /// Allocated timeslice in nanoseconds.
    pub slice_ns: u64,
    /// Virtual deadline in nanoseconds ($d_i = v_i + \frac{q_i}{w_i}$).
    pub virtual_deadline_ns: u64,
    /// Current lag relative to runqueue virtual time ($Lag_i = (V - v_i) \times w_i / 1024$).
    pub lag_ns: i64,
    /// Whether the entity is eligible ($v_i \le V_{rq}$).
    pub is_eligible: bool,
    /// Optional Cgroup v2 Node ID owning this entity.
    pub cgroup_id: Option<u64>,
    /// Whether the entity is throttled by cgroups v2 `cpu.max` bandwidth control.
    pub is_throttled: bool,
}

impl SchedEntity {
    /// Create a new scheduling entity with given ID, name, and nice value.
    pub fn new(id: u64, name: &str, nice: i8) -> Self {
        let clamped_nice = nice.clamp(-20, 19);
        let index = (clamped_nice + 20) as usize;
        let weight = PRIO_TO_WEIGHT[index];
        let wmult = PRIO_TO_WMULT[index];

        Self {
            id,
            name: String::from(name),
            nice: clamped_nice,
            weight,
            wmult,
            state: EntityState::Runnable,
            vruntime: 0,
            exec_start_ns: 0,
            sum_exec_runtime_ns: 0,
            slice_ns: DEFAULT_BASE_SLICE_NS,
            virtual_deadline_ns: 0,
            lag_ns: 0,
            is_eligible: true,
            cgroup_id: None,
            is_throttled: false,
        }
    }

    /// Calculate virtual runtime increment for a given physical execution delta.
    pub fn calc_delta_vruntime(&self, delta_exec_ns: u64) -> u64 {
        if self.weight == NICE_0_WEIGHT {
            delta_exec_ns
        } else {
            // delta_vruntime = delta_exec * (NICE_0_WEIGHT / weight)
            // Using fast fixed-point multiplication: (delta_exec * wmult) >> 22
            ((delta_exec_ns as u128 * self.wmult as u128) >> 22) as u64
        }
    }

    /// Compute virtual deadline based on current vruntime, slice, and weight.
    pub fn update_virtual_deadline(&mut self) {
        let virtual_slice = self.calc_delta_vruntime(self.slice_ns);
        self.virtual_deadline_ns = self.vruntime.saturating_add(virtual_slice);
    }

    /// Update lag given the current runqueue virtual time $V_{rq}$.
    pub fn update_lag(&mut self, rq_vruntime: u64) {
        if rq_vruntime >= self.vruntime {
            let diff = rq_vruntime - self.vruntime;
            self.lag_ns = ((diff as u128 * self.weight as u128) / (NICE_0_WEIGHT as u128)) as i64;
            self.is_eligible = true;
        } else {
            let diff = self.vruntime - rq_vruntime;
            self.lag_ns = -(((diff as u128 * self.weight as u128) / (NICE_0_WEIGHT as u128)) as i64);
            self.is_eligible = false;
        }
    }
}

/// Runqueue for EEVDF/CFS scheduler.
pub struct CfsRunQueue {
    /// Monotonically advancing virtual time of the runqueue ($V_{rq}$).
    pub vruntime: u64,
    /// Lowest vruntime among all active runnable entities.
    pub min_vruntime: u64,
    /// Sum of weights of all runnable entities.
    pub total_weight: u64,
    /// Number of runnable entities.
    pub nr_running: usize,
    /// Base timeslice in nanoseconds.
    pub base_slice_ns: u64,
    /// Minimum scheduling granularity in nanoseconds.
    pub min_granularity_ns: u64,
    /// Active entities on the runqueue.
    pub entities: Vec<SchedEntity>,
    /// Index of the currently executing entity, if any.
    pub current_idx: Option<usize>,
    /// Last scheduler clock update timestamp (nanoseconds).
    pub last_update_ns: u64,
}

impl CfsRunQueue {
    /// Initialize a new CFS runqueue.
    pub fn new() -> Self {
        Self {
            vruntime: 0,
            min_vruntime: 0,
            total_weight: 0,
            nr_running: 0,
            base_slice_ns: DEFAULT_BASE_SLICE_NS,
            min_granularity_ns: MIN_GRANULARITY_NS,
            entities: Vec::new(),
            current_idx: None,
            last_update_ns: 0,
        }
    }

    /// Calculate the timeslice for an entity based on its proportion of total runqueue weight.
    pub fn calc_slice(&self, entity: &SchedEntity) -> u64 {
        if self.total_weight == 0 || self.nr_running <= 1 {
            return self.base_slice_ns;
        }
        let slice = (self.base_slice_ns as u128 * entity.weight as u128) / (self.total_weight as u128);
        (slice as u64).max(self.min_granularity_ns)
    }

    /// Enqueue a scheduling entity.
    pub fn enqueue_task(&mut self, mut entity: SchedEntity) {
        // Normalize vruntime for new tasks to prevent unfair head-start or starvation
        if entity.vruntime < self.min_vruntime {
            entity.vruntime = self.min_vruntime;
        }
        entity.slice_ns = self.calc_slice(&entity);
        entity.update_lag(self.vruntime);
        entity.update_virtual_deadline();
        entity.state = EntityState::Runnable;

        self.total_weight += entity.weight as u64;
        self.nr_running += 1;
        self.entities.push(entity);
        self.update_min_vruntime();
    }

    /// Dequeue a task by entity ID.
    pub fn dequeue_task(&mut self, id: u64) -> Option<SchedEntity> {
        let pos = self.entities.iter().position(|e| e.id == id)?;
        let entity = self.entities.remove(pos);

        self.total_weight = self.total_weight.saturating_sub(entity.weight as u64);
        self.nr_running = self.nr_running.saturating_sub(1);

        if let Some(curr) = self.current_idx {
            if curr == pos {
                self.current_idx = None;
            } else if curr > pos {
                self.current_idx = Some(curr - 1);
            }
        }

        self.update_min_vruntime();
        Some(entity)
    }

    /// Update minimum vruntime across all runnable entities.
    fn update_min_vruntime(&mut self) {
        let mut min = self.vruntime;
        if let Some(curr) = self.current_idx {
            if let Some(e) = self.entities.get(curr) {
                min = e.vruntime;
            }
        }
        for e in &self.entities {
            if e.state == EntityState::Runnable {
                min = min.min(e.vruntime);
            }
        }
        // min_vruntime must advance monotonically
        self.min_vruntime = self.min_vruntime.max(min);
    }

    /// Update runqueue timeline accounting for current entity runtime progression.
    pub fn update_curr(&mut self, now_ns: u64) {
        if self.last_update_ns == 0 {
            self.last_update_ns = now_ns;
            return;
        }

        let delta_exec = now_ns.saturating_sub(self.last_update_ns);
        self.last_update_ns = now_ns;

        if delta_exec == 0 {
            return;
        }

        if let Some(curr_idx) = self.current_idx {
            if let Some(curr) = self.entities.get_mut(curr_idx) {
                let delta_vruntime = curr.calc_delta_vruntime(delta_exec);
                curr.vruntime = curr.vruntime.saturating_add(delta_vruntime);
                curr.sum_exec_runtime_ns = curr.sum_exec_runtime_ns.saturating_add(delta_exec);
                curr.update_virtual_deadline();

                // Advance system virtual time V proportional to total weight
                if self.total_weight > 0 {
                    let v_delta = (delta_exec as u128 * curr.weight as u128) / (self.total_weight as u128);
                    self.vruntime = self.vruntime.saturating_add(v_delta as u64);
                }
            }
        }

        // Refresh lag and eligibility for all entities
        let v_now = self.vruntime;
        for e in &mut self.entities {
            e.update_lag(v_now);
        }
        self.update_min_vruntime();
    }

    /// EEVDF selection: picks the eligible entity with the earliest virtual deadline.
    pub fn pick_next_task(&mut self, now_ns: u64) -> Option<u64> {
        self.update_curr(now_ns);

        if self.entities.is_empty() {
            return None;
        }

        // Pass 1: Select eligible entity (vruntime <= V_rq) with minimum virtual_deadline_ns
        let mut best_idx: Option<usize> = None;
        let mut min_deadline = u64::MAX;

        for (idx, e) in self.entities.iter().enumerate() {
            if e.state == EntityState::Runnable && e.is_eligible && !e.is_throttled {
                if e.virtual_deadline_ns < min_deadline {
                    min_deadline = e.virtual_deadline_ns;
                    best_idx = Some(idx);
                }
            }
        }

        // Pass 2: Fallback if no task is strictly eligible (pick entity with minimum vruntime)
        if best_idx.is_none() {
            let mut min_vruntime = u64::MAX;
            for (idx, e) in self.entities.iter().enumerate() {
                if e.state == EntityState::Runnable && !e.is_throttled && e.vruntime < min_vruntime {
                    min_vruntime = e.vruntime;
                    best_idx = Some(idx);
                }
            }
        }

        if let Some(idx) = best_idx {
            // Set old current to Runnable
            if let Some(prev) = self.current_idx {
                if prev != idx {
                    if let Some(p) = self.entities.get_mut(prev) {
                        if p.state == EntityState::Running {
                            p.state = EntityState::Runnable;
                        }
                    }
                }
            }

            if let Some(chosen) = self.entities.get_mut(idx) {
                chosen.state = EntityState::Running;
                chosen.exec_start_ns = now_ns;
                self.current_idx = Some(idx);
                return Some(chosen.id);
            }
        }

        None
    }

    /// Mark a task entity as throttled or unthrottled under cgroup v2 bandwidth enforcement.
    pub fn set_entity_throttled(&mut self, id: u64, throttled: bool) {
        if let Some(e) = self.entities.iter_mut().find(|e| e.id == id) {
            e.is_throttled = throttled;
        }
    }

    /// Mark all entities belonging to a cgroup as throttled or unthrottled.
    pub fn set_cgroup_throttled(&mut self, cgroup_id: u64, throttled: bool) {
        for e in &mut self.entities {
            if e.cgroup_id == Some(cgroup_id) {
                e.is_throttled = throttled;
            }
        }
    }

    /// Put the previous task to rest, transitioning it from Running to Runnable.
    pub fn put_prev_task(&mut self, now_ns: u64) {
        self.update_curr(now_ns);
        if let Some(curr_idx) = self.current_idx {
            if let Some(curr) = self.entities.get_mut(curr_idx) {
                if curr.state == EntityState::Running {
                    curr.state = EntityState::Runnable;
                }
            }
            self.current_idx = None;
        }
    }

    /// Yield execution of current entity by giving it a fresh virtual deadline at the tail.
    pub fn yield_task(&mut self, now_ns: u64) {
        self.update_curr(now_ns);
        if let Some(curr_idx) = self.current_idx {
            if let Some(curr) = self.entities.get_mut(curr_idx) {
                // Advance vruntime by one slice to yield priority
                let extra_vruntime = curr.calc_delta_vruntime(curr.slice_ns);
                curr.vruntime = curr.vruntime.saturating_add(extra_vruntime);
                curr.update_virtual_deadline();
                curr.state = EntityState::Runnable;
            }
            self.current_idx = None;
        }
        self.update_min_vruntime();
    }

    /// Deschedules an entity by ID and transitions it to Sleeping state (e.g. waiting on a futex).
    pub fn deschedule_task_sleeping(&mut self, id: u64) -> bool {
        if let Some(pos) = self.entities.iter().position(|e| e.id == id) {
            let entity = &mut self.entities[pos];
            if entity.state == EntityState::Runnable || entity.state == EntityState::Running {
                entity.state = EntityState::Sleeping;
                self.total_weight = self.total_weight.saturating_sub(entity.weight as u64);
                self.nr_running = self.nr_running.saturating_sub(1);
                if self.current_idx == Some(pos) {
                    self.current_idx = None;
                }
                self.update_min_vruntime();
                return true;
            }
        }
        false
    }

    /// Wakes up a sleeping entity by ID, restoring it to Runnable state.
    pub fn wake_task(&mut self, id: u64) -> bool {
        if let Some(pos) = self.entities.iter().position(|e| e.id == id) {
            let entity = &mut self.entities[pos];
            if entity.state == EntityState::Sleeping {
                if entity.vruntime < self.min_vruntime {
                    entity.vruntime = self.min_vruntime;
                }
                entity.state = EntityState::Runnable;
                self.total_weight += entity.weight as u64;
                self.nr_running += 1;
                self.update_min_vruntime();
                return true;
            }
        }
        false
    }
}
