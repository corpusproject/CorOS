//! POSIX Real-Time & Constant Bandwidth Server (`SCHED_DEADLINE`).
//!
//! Implements Earliest Deadline First (EDF) combined with the Constant Bandwidth Server (CBS):
//! - Strict admission control based on cumulative bandwidth utilization ($\sum C_i / P_i \le U_{\max}$)
//! - Real-time budget enforcement with nanosecond resolution
//! - CBS replenishment rules upon wakeup and period rollovers
//! - Automatic throttling on budget exhaustion to guarantee temporal isolation

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum allowable total utilization in parts-per-million (950,000 ppm = 95.0%).
pub const MAX_DEADLINE_UTILIZATION_PPM: u64 = 950_000;
/// One million parts per million (100%).
pub const PPM_DENOMINATOR: u64 = 1_000_000;

/// State of a real-time deadline task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineTaskState {
    Runnable,
    Running,
    Throttled,
    Sleeping,
    Inactive,
}

/// Task managed under SCHED_DEADLINE policy.
#[derive(Debug, Clone)]
pub struct DeadlineTask {
    pub id: u64,
    pub name: String,
    /// Static budget allocation in nanoseconds ($C$).
    pub runtime_ns: u64,
    /// Relative deadline in nanoseconds ($D$).
    pub deadline_ns: u64,
    /// Period in nanoseconds ($P$).
    pub period_ns: u64,
    /// Remaining runtime budget in current period in nanoseconds ($c$).
    pub current_runtime_ns: u64,
    /// Current absolute deadline in nanoseconds ($d$).
    pub absolute_deadline_ns: u64,
    /// Replenishment timestamp in nanoseconds.
    pub replenish_time_ns: u64,
    /// Current execution state.
    pub state: DeadlineTaskState,
    /// Total cumulative execution time in nanoseconds.
    pub total_runtime_ns: u64,
    /// Count of throttle events experienced.
    pub throttle_count: u64,
    /// Count of missed deadlines.
    pub deadline_miss_count: u64,
}

impl DeadlineTask {
    /// Create a new deadline task.
    /// Requirements: $C \le D \le P$, and $P > 0$.
    pub fn new(id: u64, name: &str, runtime_ns: u64, deadline_ns: u64, period_ns: u64) -> Result<Self, &'static str> {
        if runtime_ns == 0 || deadline_ns == 0 || period_ns == 0 {
            return Err("Runtime, deadline, and period must all be strictly positive");
        }
        if runtime_ns > deadline_ns {
            return Err("Runtime budget cannot exceed relative deadline");
        }
        if deadline_ns > period_ns {
            return Err("Relative deadline cannot exceed period");
        }

        Ok(Self {
            id,
            name: String::from(name),
            runtime_ns,
            deadline_ns,
            period_ns,
            current_runtime_ns: runtime_ns,
            absolute_deadline_ns: 0,
            replenish_time_ns: 0,
            state: DeadlineTaskState::Inactive,
            total_runtime_ns: 0,
            throttle_count: 0,
            deadline_miss_count: 0,
        })
    }

    /// Calculate bandwidth utilization in parts per million ($C / P \times 10^6$).
    pub fn bandwidth_ppm(&self) -> u64 {
        ((self.runtime_ns as u128 * PPM_DENOMINATOR as u128) / (self.period_ns as u128)) as u64
    }

    /// Apply Constant Bandwidth Server (CBS) rule when a task wakes up at timestamp `now_ns`.
    pub fn on_wakeup(&mut self, now_ns: u64) {
        if self.state == DeadlineTaskState::Inactive || self.absolute_deadline_ns <= now_ns {
            // Expired or fresh task: renew deadline and full budget
            self.absolute_deadline_ns = now_ns.saturating_add(self.deadline_ns);
            self.current_runtime_ns = self.runtime_ns;
            self.replenish_time_ns = now_ns.saturating_add(self.period_ns);
            self.state = DeadlineTaskState::Runnable;
            return;
        }

        // CBS condition: if (d - t) * C > c * D, the task cannot fit in the current server instance
        let remaining_deadline = self.absolute_deadline_ns - now_ns;
        let left_side = remaining_deadline as u128 * self.runtime_ns as u128;
        let right_side = self.current_runtime_ns as u128 * self.deadline_ns as u128;

        if left_side > right_side {
            // Replenish budget and post new deadline
            self.absolute_deadline_ns = now_ns.saturating_add(self.deadline_ns);
            self.current_runtime_ns = self.runtime_ns;
            self.replenish_time_ns = now_ns.saturating_add(self.period_ns);
        }

        self.state = DeadlineTaskState::Runnable;
    }
}

/// Admission control and bandwidth enforcer for SCHED_DEADLINE tasks.
pub struct DeadlineAdmissionControl {
    pub max_bandwidth_ppm: u64,
    pub allocated_bandwidth_ppm: u64,
}

impl DeadlineAdmissionControl {
    pub fn new(max_bandwidth_ppm: u64) -> Self {
        Self {
            max_bandwidth_ppm,
            allocated_bandwidth_ppm: 0,
        }
    }

    /// Check if admitting this task would exceed total available bandwidth.
    pub fn can_admit(&self, task: &DeadlineTask) -> bool {
        let task_bw = task.bandwidth_ppm();
        self.allocated_bandwidth_ppm.saturating_add(task_bw) <= self.max_bandwidth_ppm
    }

    /// Commit task bandwidth.
    pub fn admit(&mut self, task: &DeadlineTask) -> Result<(), &'static str> {
        let task_bw = task.bandwidth_ppm();
        if self.allocated_bandwidth_ppm.saturating_add(task_bw) > self.max_bandwidth_ppm {
            return Err("Deadline admission rejected: bandwidth capacity exceeded");
        }
        self.allocated_bandwidth_ppm += task_bw;
        Ok(())
    }

    /// Release task bandwidth upon termination.
    pub fn release(&mut self, task: &DeadlineTask) {
        let task_bw = task.bandwidth_ppm();
        self.allocated_bandwidth_ppm = self.allocated_bandwidth_ppm.saturating_sub(task_bw);
    }
}

/// SCHED_DEADLINE Runqueue executing earliest-deadline-first.
pub struct DeadlineRunQueue {
    pub tasks: Vec<DeadlineTask>,
    pub current_idx: Option<usize>,
    pub admission: DeadlineAdmissionControl,
    pub last_tick_ns: u64,
}

impl DeadlineRunQueue {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_idx: None,
            admission: DeadlineAdmissionControl::new(MAX_DEADLINE_UTILIZATION_PPM),
            last_tick_ns: 0,
        }
    }

    /// Register and activate a new deadline task through admission control.
    pub fn add_task(&mut self, mut task: DeadlineTask, now_ns: u64) -> Result<(), &'static str> {
        self.admission.admit(&task)?;
        task.on_wakeup(now_ns);
        self.tasks.push(task);
        Ok(())
    }

    /// Remove a deadline task and release its allocated bandwidth.
    pub fn remove_task(&mut self, id: u64) -> Option<DeadlineTask> {
        let pos = self.tasks.iter().position(|t| t.id == id)?;
        let task = self.tasks.remove(pos);
        self.admission.release(&task);

        if let Some(curr) = self.current_idx {
            if curr == pos {
                self.current_idx = None;
            } else if curr > pos {
                self.current_idx = Some(curr - 1);
            }
        }
        Some(task)
    }

    /// Process timer tick and advance budget consumption of currently running task.
    pub fn tick(&mut self, now_ns: u64) {
        if self.last_tick_ns == 0 {
            self.last_tick_ns = now_ns;
            return;
        }

        let delta = now_ns.saturating_sub(self.last_tick_ns);
        self.last_tick_ns = now_ns;

        // Check replenish timers for throttled tasks
        for task in &mut self.tasks {
            if task.state == DeadlineTaskState::Throttled && now_ns >= task.replenish_time_ns {
                task.current_runtime_ns = task.runtime_ns;
                task.absolute_deadline_ns = task.replenish_time_ns.saturating_add(task.deadline_ns);
                task.replenish_time_ns = task.replenish_time_ns.saturating_add(task.period_ns);
                task.state = DeadlineTaskState::Runnable;
            }
        }

        // Account current running task
        if let Some(curr_idx) = self.current_idx {
            if let Some(curr) = self.tasks.get_mut(curr_idx) {
                curr.total_runtime_ns = curr.total_runtime_ns.saturating_add(delta);

                if delta >= curr.current_runtime_ns {
                    // Budget exhausted! Throttle the task
                    curr.current_runtime_ns = 0;
                    curr.state = DeadlineTaskState::Throttled;
                    curr.throttle_count += 1;
                    self.current_idx = None;
                } else {
                    curr.current_runtime_ns -= delta;
                }

                // Check deadline miss
                if now_ns > curr.absolute_deadline_ns {
                    curr.deadline_miss_count += 1;
                }
            }
        }
    }

    /// Pick the runnable task with the earliest absolute deadline.
    pub fn pick_next_task(&mut self, now_ns: u64) -> Option<u64> {
        self.tick(now_ns);

        let mut earliest_idx: Option<usize> = None;
        let mut min_deadline = u64::MAX;

        for (idx, task) in self.tasks.iter().enumerate() {
            if task.state == DeadlineTaskState::Runnable && task.current_runtime_ns > 0 {
                if task.absolute_deadline_ns < min_deadline {
                    min_deadline = task.absolute_deadline_ns;
                    earliest_idx = Some(idx);
                }
            }
        }

        if let Some(idx) = earliest_idx {
            // Deselect old running task
            if let Some(curr) = self.current_idx {
                if curr != idx {
                    if let Some(c) = self.tasks.get_mut(curr) {
                        if c.state == DeadlineTaskState::Running {
                            c.state = DeadlineTaskState::Runnable;
                        }
                    }
                }
            }

            if let Some(chosen) = self.tasks.get_mut(idx) {
                chosen.state = DeadlineTaskState::Running;
                self.current_idx = Some(idx);
                return Some(chosen.id);
            }
        }

        None
    }
}
