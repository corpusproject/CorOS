//! Softirq & Tasklet Deferred Execution Engine.
//!
//! Implements interrupt bottom-half deferred processing with:
//! - 10 priority-ordered Softirq vectors (HI, TIMER, NET_TX, NET_RX, BLOCK, IRQ_POLL, TASKLET, SCHED, HRTIMER, RCU)
//! - Bitmask-driven atomic softirq pending states
//! - Bounded loop processing (`max_loops`) preventing softirq starvation of user threads
//! - Dual-priority tasklet subsystem (High and Normal priority tasklets)

extern crate alloc;

use alloc::vec::Vec;

pub const SOFTIRQ_HI: u32 = 0;
pub const SOFTIRQ_TIMER: u32 = 1;
pub const SOFTIRQ_NET_TX: u32 = 2;
pub const SOFTIRQ_NET_RX: u32 = 3;
pub const SOFTIRQ_BLOCK: u32 = 4;
pub const SOFTIRQ_IRQ_POLL: u32 = 5;
pub const SOFTIRQ_TASKLET: u32 = 6;
pub const SOFTIRQ_SCHED: u32 = 7;
pub const SOFTIRQ_HRTIMER: u32 = 8;
pub const SOFTIRQ_RCU: u32 = 9;

pub const NR_SOFTIRQS: usize = 10;
pub const MAX_SOFTIRQ_LOOPS: usize = 10;

/// Softirq handler function signature: (vector, cpu_id, user_data).
pub type SoftirqHandler = fn(u32, u32, u64);

/// Registered Softirq Action.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqAction {
    pub handler: Option<SoftirqHandler>,
    pub data: u64,
}

impl SoftirqAction {
    pub const fn empty() -> Self {
        Self {
            handler: None,
            data: 0,
        }
    }
}

/// Tasklet scheduling priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskletPriority {
    Normal,
    High,
}

/// Tasklet state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskletState {
    Idle,
    Scheduled,
    Running,
}

/// Lightweight deferred tasklet structure.
#[derive(Debug, Clone)]
pub struct Tasklet {
    pub id: u64,
    pub priority: TaskletPriority,
    pub state: TaskletState,
    pub func: fn(u64),
    pub arg: u64,
    pub total_invocations: u64,
}

impl Tasklet {
    pub fn new(id: u64, priority: TaskletPriority, func: fn(u64), arg: u64) -> Self {
        Self {
            id,
            priority,
            state: TaskletState::Idle,
            func,
            arg,
            total_invocations: 0,
        }
    }
}

/// Per-CPU Softirq execution state.
#[derive(Debug, Clone)]
pub struct PerCpuSoftirq {
    pub cpu_id: u32,
    pub pending_mask: u32,
    pub in_softirq: bool,
    pub stats: [u64; NR_SOFTIRQS],
}

impl PerCpuSoftirq {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            pending_mask: 0,
            in_softirq: false,
            stats: [0; NR_SOFTIRQS],
        }
    }
}

/// Global Softirq & Tasklet Execution Engine.
pub struct SoftirqEngine {
    pub actions: [SoftirqAction; NR_SOFTIRQS],
    pub cpu_states: Vec<PerCpuSoftirq>,
    pub high_tasklets: Vec<Tasklet>,
    pub normal_tasklets: Vec<Tasklet>,
}

impl SoftirqEngine {
    pub fn new(num_cpus: u32) -> Self {
        let count = num_cpus.clamp(1, 64) as usize;
        let mut cpu_states = Vec::with_capacity(count);
        for i in 0..count {
            cpu_states.push(PerCpuSoftirq::new(i as u32));
        }

        Self {
            actions: [SoftirqAction::empty(); NR_SOFTIRQS],
            cpu_states,
            high_tasklets: Vec::new(),
            normal_tasklets: Vec::new(),
        }
    }

    /// Register a handler callback for a specific softirq vector.
    pub fn register_action(&mut self, vector: u32, handler: SoftirqHandler, data: u64) {
        if (vector as usize) < NR_SOFTIRQS {
            self.actions[vector as usize] = SoftirqAction {
                handler: Some(handler),
                data,
            };
        }
    }

    /// Mark a softirq vector as pending on the target CPU.
    pub fn raise_softirq(&mut self, vector: u32, cpu_id: u32) {
        if (vector as usize) < NR_SOFTIRQS {
            if let Some(state) = self.cpu_states.get_mut(cpu_id as usize) {
                state.pending_mask |= 1u32 << vector;
            }
        }
    }

    /// Schedule a tasklet for deferred execution.
    pub fn schedule_tasklet(&mut self, mut tasklet: Tasklet, cpu_id: u32) {
        tasklet.state = TaskletState::Scheduled;
        match tasklet.priority {
            TaskletPriority::High => {
                self.high_tasklets.push(tasklet);
                self.raise_softirq(SOFTIRQ_HI, cpu_id);
            }
            TaskletPriority::Normal => {
                self.normal_tasklets.push(tasklet);
                self.raise_softirq(SOFTIRQ_TASKLET, cpu_id);
            }
        }
    }

    /// Process high-priority tasklets queue (associated with SOFTIRQ_HI).
    pub fn process_high_tasklets(&mut self) -> usize {
        let mut executed = 0;
        let mut tasklets = core::mem::take(&mut self.high_tasklets);

        for tasklet in &mut tasklets {
            tasklet.state = TaskletState::Running;
            (tasklet.func)(tasklet.arg);
            tasklet.total_invocations += 1;
            tasklet.state = TaskletState::Idle;
            executed += 1;
        }

        executed
    }

    /// Process normal-priority tasklets queue (associated with SOFTIRQ_TASKLET).
    pub fn process_normal_tasklets(&mut self) -> usize {
        let mut executed = 0;
        let mut tasklets = core::mem::take(&mut self.normal_tasklets);

        for tasklet in &mut tasklets {
            tasklet.state = TaskletState::Running;
            (tasklet.func)(tasklet.arg);
            tasklet.total_invocations += 1;
            tasklet.state = TaskletState::Idle;
            executed += 1;
        }

        executed
    }

    /// Execute pending softirqs for the specified CPU.
    /// Iterates through pending bits in priority order (lowest index first).
    pub fn do_softirq(&mut self, cpu_id: u32) -> usize {
        let state_idx = cpu_id as usize;
        if state_idx >= self.cpu_states.len() {
            return 0;
        }

        if self.cpu_states[state_idx].in_softirq {
            return 0; // Prevent nested execution
        }

        self.cpu_states[state_idx].in_softirq = true;
        let mut total_dispatched = 0;
        let mut loop_count = 0;

        while loop_count < MAX_SOFTIRQ_LOOPS {
            let pending = self.cpu_states[state_idx].pending_mask;
            if pending == 0 {
                break;
            }

            // Clear pending mask before executing current wave
            self.cpu_states[state_idx].pending_mask = 0;

            for vec_idx in 0..NR_SOFTIRQS {
                if (pending & (1u32 << vec_idx)) != 0 {
                    // Check built-in tasklet handling
                    if vec_idx == (SOFTIRQ_HI as usize) {
                        total_dispatched += self.process_high_tasklets();
                    } else if vec_idx == (SOFTIRQ_TASKLET as usize) {
                        total_dispatched += self.process_normal_tasklets();
                    }

                    // Dispatch registered custom handler
                    let action = self.actions[vec_idx];
                    if let Some(handler) = action.handler {
                        handler(vec_idx as u32, cpu_id, action.data);
                        total_dispatched += 1;
                    }

                    self.cpu_states[state_idx].stats[vec_idx] += 1;
                }
            }

            loop_count += 1;
        }

        self.cpu_states[state_idx].in_softirq = false;
        total_dispatched
    }
}
