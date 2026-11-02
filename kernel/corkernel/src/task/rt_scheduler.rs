//! Real-Time POSIX Priority Preemptive Scheduler (SCHED_FIFO / SCHED_RR)
//!
//! Provides deterministic microsecond hard real-time scheduling for audio, DSP, and I/O tasks:
//! - 100 Real-Time Priority levels (0 to 99), with 99 being highest real-time priority
//! - 100 Multi-Level Queue (MLQ) FIFO linked lists with \(O(1)\) highest-priority selection via bitmap bit-scan (`bsrq`)
//! - Round-Robin (SCHED_RR) time slicing quantum replenishment (typically 10ms - 100ms)
//! - First-In First-Out (SCHED_FIFO) run-to-completion or until blocked on mutex/I/O
//! - Strict preemption over standard Completely Fair Scheduler (CFS) tasks
//! - Priority Inheritance Protocol (PIP) to prevent unbounded Priority Inversion

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

pub const RT_PRIO_MIN: u32 = 0;
pub const RT_PRIO_MAX: u32 = 99;
pub const RT_PRIO_COUNT: usize = 100;
pub const DEFAULT_RR_QUANTUM_TICKS: u32 = 10; // 10 timer ticks

/// Real-Time Scheduling Policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtPolicy {
    Fifo,       // SCHED_FIFO: runs until yield, exit, or block
    RoundRobin, // SCHED_RR: preempted after quantum depletion
}

/// Real-Time Task Descriptor
#[derive(Debug, Clone)]
pub struct RtTaskEntity {
    pub tid: u32,
    pub pid: u32,
    pub priority: u32, // 0..99 (99 highest)
    pub policy: RtPolicy,
    pub time_slice_remaining: u32,
    pub total_runtime_ticks: u64,
    pub inherited_priority: Option<u32>, // Priority inheritance for mutex locking
}

impl RtTaskEntity {
    pub fn new(tid: u32, pid: u32, priority: u32, policy: RtPolicy) -> Self {
        Self {
            tid,
            pid,
            priority: priority.min(RT_PRIO_MAX),
            policy,
            time_slice_remaining: DEFAULT_RR_QUANTUM_TICKS,
            total_runtime_ticks: 0,
            inherited_priority: None,
        }
    }

    /// Effective priority taking Priority Inheritance into account
    pub fn effective_priority(&self) -> u32 {
        self.inherited_priority.unwrap_or(self.priority)
    }
}

/// Priority Inheritance Mutex
pub struct RtMutex {
    pub owner_tid: Option<u32>,
    pub ceiling_priority: u32,
    pub waiters: Vec<u32>, // Waiting TIDs
}

impl RtMutex {
    pub fn new(ceiling: u32) -> Self {
        Self {
            owner_tid: None,
            ceiling_priority: ceiling,
            waiters: Vec::new(),
        }
    }
}

/// Complete Multi-Level Real-Time RunQueue
pub struct RtRunQueue {
    pub queues: [Vec<RtTaskEntity>; RT_PRIO_COUNT],
    pub active_bitmap: [u64; 2], // 128-bit bitmap tracking non-empty queues
    pub nr_running: AtomicU32,
}

impl RtRunQueue {
    pub const fn new() -> Self {
        const EMPTY_VEC: Vec<RtTaskEntity> = Vec::new();
        Self {
            queues: [EMPTY_VEC; RT_PRIO_COUNT],
            active_bitmap: [0, 0],
            nr_running: AtomicU32::new(0),
        }
    }

    fn set_bit(&mut self, prio: usize) {
        if prio < 64 {
            self.active_bitmap[0] |= 1 << prio;
        } else if prio < 128 {
            self.active_bitmap[1] |= 1 << (prio - 64);
        }
    }

    fn clear_bit(&mut self, prio: usize) {
        if prio < 64 {
            self.active_bitmap[0] &= !(1 << prio);
        } else if prio < 128 {
            self.active_bitmap[1] &= !(1 << (prio - 64));
        }
    }

    /// Enqueue a real-time task
    pub fn enqueue(&mut self, task: RtTaskEntity) {
        let prio = task.effective_priority() as usize;
        self.queues[prio].push(task);
        self.set_bit(prio);
        self.nr_running.fetch_add(1, Ordering::SeqCst);
    }

    /// Find the highest priority ready real-time task in \(O(1)\)
    pub fn pick_highest_priority(&self) -> Option<usize> {
        // High word (priorities 64..99)
        if self.active_bitmap[1] != 0 {
            let leading_zeros = self.active_bitmap[1].leading_zeros();
            let bit = 63 - leading_zeros;
            return Some((bit + 64) as usize);
        }
        // Low word (priorities 0..63)
        if self.active_bitmap[0] != 0 {
            let leading_zeros = self.active_bitmap[0].leading_zeros();
            let bit = 63 - leading_zeros;
            return Some(bit as usize);
        }
        None
    }

    /// Dequeue the next task to run
    pub fn dequeue_next(&mut self) -> Option<RtTaskEntity> {
        let prio = self.pick_highest_priority()?;
        let task = self.queues[prio].remove(0);

        if self.queues[prio].is_empty() {
            self.clear_bit(prio);
        }
        self.nr_running.fetch_sub(1, Ordering::SeqCst);
        Some(task)
    }

    /// Periodic timer tick: decrement Round-Robin time slice and rotate queue
    pub fn on_timer_tick(&mut self) -> bool {
        let prio = match self.pick_highest_priority() {
            Some(p) => p,
            None => return false,
        };

        if let Some(task) = self.queues[prio].first_mut() {
            task.total_runtime_ticks += 1;
            if task.policy == RtPolicy::RoundRobin {
                task.time_slice_remaining = task.time_slice_remaining.saturating_sub(1);
                if task.time_slice_remaining == 0 {
                    task.time_slice_remaining = DEFAULT_RR_QUANTUM_TICKS;
                    // Rotate to back of line
                    let expired = self.queues[prio].remove(0);
                    self.queues[prio].push(expired);
                    return true; // Preemption requested
                }
            }
        }
        false
    }

    /// Priority Inheritance: Boost task priority if blocking a higher priority thread
    pub fn boost_priority(&mut self, tid: u32, boosted_prio: u32) {
        for q in 0..RT_PRIO_COUNT {
            if let Some(pos) = self.queues[q].iter().position(|t| t.tid == tid) {
                let mut task = self.queues[q].remove(pos);
                if self.queues[q].is_empty() {
                    self.clear_bit(q);
                }
                task.inherited_priority = Some(boosted_prio);
                let new_prio = task.effective_priority() as usize;
                self.queues[new_prio].push(task);
                self.set_bit(new_prio);
                break;
            }
        }
    }
}
