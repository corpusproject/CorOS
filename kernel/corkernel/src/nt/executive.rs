//! Windows NT Executive Synchronization & Work Queues (Ex)
//!
//! Provides ERESOURCE (Shared/Exclusive read-write locks), Executive Fast Mutexes,
//! and Executive Work Queues for asynchronous deferred kernel procedure execution.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::sync::Spinlock;

/// Executive Read/Write Shared-Exclusive Resource Lock (`ERESOURCE`)
pub struct ExecutiveResource {
    lock: Spinlock<()>,
    active_shared: AtomicU32,
    active_exclusive: AtomicBool,
    waiting_exclusive: AtomicU32,
}

impl ExecutiveResource {
    pub const fn new() -> Self {
        Self {
            lock: Spinlock::new(()),
            active_shared: AtomicU32::new(0),
            active_exclusive: AtomicBool::new(false),
            waiting_exclusive: AtomicU32::new(0),
        }
    }

    /// Acquires the resource for shared (read-only) access
    pub fn acquire_shared(&self, wait: bool) -> bool {
        loop {
            let _guard = self.lock.lock();
            // Don't starve exclusive writers
            if !self.active_exclusive.load(Ordering::Relaxed) && self.waiting_exclusive.load(Ordering::Relaxed) == 0 {
                self.active_shared.fetch_add(1, Ordering::SeqCst);
                return true;
            }
            if !wait {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// Releases shared access
    pub fn release_shared(&self) {
        self.active_shared.fetch_sub(1, Ordering::SeqCst);
    }

    /// Acquires the resource for exclusive (read-write) access
    pub fn acquire_exclusive(&self, wait: bool) -> bool {
        self.waiting_exclusive.fetch_add(1, Ordering::SeqCst);
        loop {
            let _guard = self.lock.lock();
            if !self.active_exclusive.load(Ordering::Relaxed) && self.active_shared.load(Ordering::Relaxed) == 0 {
                self.active_exclusive.store(true, Ordering::SeqCst);
                self.waiting_exclusive.fetch_sub(1, Ordering::SeqCst);
                return true;
            }
            if !wait {
                self.waiting_exclusive.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// Releases exclusive access
    pub fn release_exclusive(&self) {
        self.active_exclusive.store(false, Ordering::SeqCst);
    }
}

pub type WorkCallback = fn(param: usize);

pub struct WorkItem {
    pub callback: WorkCallback,
    pub parameter: usize,
}

pub enum WorkQueueType {
    Critical,
    Delayed,
    HyperCritical,
}

pub struct WorkQueue {
    critical_queue: Spinlock<VecDeque<WorkItem>>,
    delayed_queue: Spinlock<VecDeque<WorkItem>>,
}

impl WorkQueue {
    pub const fn new() -> Self {
        Self {
            critical_queue: Spinlock::new(VecDeque::new()),
            delayed_queue: Spinlock::new(VecDeque::new()),
        }
    }

    pub fn queue_work_item(&self, item: WorkItem, queue_type: WorkQueueType) {
        match queue_type {
            WorkQueueType::Critical | WorkQueueType::HyperCritical => {
                self.critical_queue.lock().push_back(item);
            }
            WorkQueueType::Delayed => {
                self.delayed_queue.lock().push_back(item);
            }
        }
    }

    /// Processes any pending executive worker queue items
    pub fn process_work(&self) {
        while let Some(item) = self.critical_queue.lock().pop_front() {
            (item.callback)(item.parameter);
        }
        while let Some(item) = self.delayed_queue.lock().pop_front() {
            (item.callback)(item.parameter);
        }
    }
}

pub static GLOBAL_EX_RESOURCES: ExecutiveResource = ExecutiveResource::new();
pub static GLOBAL_WORK_QUEUE: WorkQueue = WorkQueue::new();
