//! CorOS Windows NT Executive Worker Subsystem (`executive_worker.rs`)
//!
//! Implements Windows NT Executive Worker Threads and Asynchronous Work Queues:
//! - CriticalWorkQueue: Priority for real-time filesystem and storage flushes
//! - DelayedWorkQueue: Background non-urgent housekeeping and GC
//! - HyperCriticalWorkQueue: Kernel panics, fatal error logging, hardware reset
//! - WORK_QUEUE_ITEM callbacks with worker context parameters

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkQueueType {
    CriticalWorkQueue = 0,
    DelayedWorkQueue = 1,
    HyperCriticalWorkQueue = 2,
}

pub type WorkerRoutine = fn(parameter: u64);

/// Structure representing a queued work item (`WORK_QUEUE_ITEM`)
#[derive(Clone)]
pub struct WorkQueueItem {
    pub routine: WorkerRoutine,
    pub parameter: u64,
    pub queue_type: WorkQueueType,
    pub enqueued_time: u64,
}

/// Statistics for worker threads
#[derive(Debug, Clone, Default)]
pub struct WorkerStats {
    pub critical_executed: u64,
    pub delayed_executed: u64,
    pub hypercritical_executed: u64,
    pub total_latency_ticks: u64,
}

/// Windows NT Executive Worker Queue Manager
pub struct ExecutiveWorkerManager {
    critical_queue: VecDeque<WorkQueueItem>,
    delayed_queue: VecDeque<WorkQueueItem>,
    hypercritical_queue: VecDeque<WorkQueueItem>,
    pub stats: WorkerStats,
    enabled: AtomicBool,
}

impl ExecutiveWorkerManager {
    pub fn new() -> Self {
        Self {
            critical_queue: VecDeque::new(),
            delayed_queue: VecDeque::new(),
            hypercritical_queue: VecDeque::new(),
            stats: WorkerStats::default(),
            enabled: AtomicBool::new(true),
        }
    }

    /// `ExQueueWorkItem` - Enqueues a work routine to the appropriate NT worker queue
    pub fn queue_work_item(&mut self, routine: WorkerRoutine, param: u64, qtype: WorkQueueType, now: u64) {
        let item = WorkQueueItem {
            routine,
            parameter: param,
            queue_type: qtype,
            enqueued_time: now,
        };

        match qtype {
            WorkQueueType::HyperCriticalWorkQueue => self.hypercritical_queue.push_back(item),
            WorkQueueType::CriticalWorkQueue => self.critical_queue.push_back(item),
            WorkQueueType::DelayedWorkQueue => self.delayed_queue.push_back(item),
        }
    }

    /// Process next highest priority item
    /// Order: HyperCritical -> Critical -> Delayed
    pub fn process_one(&mut self, now: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return false;
        }

        if let Some(item) = self.hypercritical_queue.pop_front() {
            (item.routine)(item.parameter);
            self.stats.hypercritical_executed += 1;
            self.stats.total_latency_ticks += now.saturating_sub(item.enqueued_time);
            return true;
        }

        if let Some(item) = self.critical_queue.pop_front() {
            (item.routine)(item.parameter);
            self.stats.critical_executed += 1;
            self.stats.total_latency_ticks += now.saturating_sub(item.enqueued_time);
            return true;
        }

        if let Some(item) = self.delayed_queue.pop_front() {
            (item.routine)(item.parameter);
            self.stats.delayed_executed += 1;
            self.stats.total_latency_ticks += now.saturating_sub(item.enqueued_time);
            return true;
        }

        false
    }

    /// Drain all pending critical work items immediately
    pub fn drain_critical(&mut self, now: u64) -> usize {
        let mut count = 0;
        while let Some(item) = self.hypercritical_queue.pop_front() {
            (item.routine)(item.parameter);
            self.stats.hypercritical_executed += 1;
            count += 1;
        }
        while let Some(item) = self.critical_queue.pop_front() {
            (item.routine)(item.parameter);
            self.stats.critical_executed += 1;
            count += 1;
        }
        let _ = now;
        count
    }

    pub fn pending_count(&self) -> usize {
        self.hypercritical_queue.len() + self.critical_queue.len() + self.delayed_queue.len()
    }
}
