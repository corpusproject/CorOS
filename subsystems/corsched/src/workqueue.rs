//! Concurrency-Managed Workqueues (`cmwq`).
//!
//! Implements multi-pool asynchronous execution queues with:
//! - Bound per-CPU pools and global unbound pools
//! - Dynamic concurrency management respecting `max_active` limits
//! - Delayed work scheduling with tick-based expiration
//! - System standard workqueues (default, high-priority, long-running, unbound)
//! - Synchronous workqueue flushing and work item cancellation

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

pub const WORK_FLAG_PENDING: u32 = 1 << 0;
pub const WORK_FLAG_RUNNING: u32 = 1 << 1;
pub const WORK_FLAG_CANCELLED: u32 = 1 << 2;
pub const WORK_FLAG_DELAYED: u32 = 1 << 3;

/// Well-known system workqueue IDs.
pub const WQ_SYSTEM: u32 = 1;
pub const WQ_SYSTEM_HIGHPRI: u32 = 2;
pub const WQ_SYSTEM_LONG: u32 = 3;
pub const WQ_SYSTEM_UNBOUND: u32 = 4;

/// Work item flags.
pub const WQ_FLAG_UNBOUND: u32 = 1 << 0;
pub const WQ_FLAG_HIGHPRI: u32 = 1 << 1;
pub const WQ_FLAG_FREEZABLE: u32 = 1 << 2;

/// Discrete deferred work item.
#[derive(Debug, Clone)]
pub struct WorkItem {
    pub id: u64,
    pub name: String,
    pub flags: u32,
    pub func: fn(u64),
    pub arg: u64,
    pub wq_id: u32,
}

impl WorkItem {
    pub fn new(id: u64, name: &str, func: fn(u64), arg: u64, wq_id: u32) -> Self {
        Self {
            id,
            name: String::from(name),
            flags: WORK_FLAG_PENDING,
            func,
            arg,
            wq_id,
        }
    }
}

/// Delayed work item pending execution at a future tick.
#[derive(Debug, Clone)]
pub struct DelayedWorkItem {
    pub work: WorkItem,
    pub target_tick: u64,
}

/// Worker thread state inside a worker pool.
#[derive(Debug, Clone)]
pub struct WorkerThread {
    pub worker_id: u32,
    pub is_idle: bool,
    pub current_work_id: Option<u64>,
    pub total_executed: u64,
}

impl WorkerThread {
    pub fn new(worker_id: u32) -> Self {
        Self {
            worker_id,
            is_idle: true,
            current_work_id: None,
            total_executed: 0,
        }
    }
}

/// Worker pool hosting active worklists and worker threads.
pub struct WorkerPool {
    pub pool_id: u32,
    pub cpu_id: Option<u32>,
    pub max_active: usize,
    pub workers: Vec<WorkerThread>,
    pub worklist: VecDeque<WorkItem>,
    pub delayed_worklist: Vec<DelayedWorkItem>,
}

impl WorkerPool {
    pub fn new(pool_id: u32, cpu_id: Option<u32>, max_active: usize, initial_workers: usize) -> Self {
        let mut workers = Vec::with_capacity(initial_workers);
        for i in 0..initial_workers {
            workers.push(WorkerThread::new(i as u32));
        }

        Self {
            pool_id,
            cpu_id,
            max_active,
            workers,
            worklist: VecDeque::new(),
            delayed_worklist: Vec::new(),
        }
    }

    /// Count how many workers are currently running work.
    pub fn active_workers_count(&self) -> usize {
        self.workers.iter().filter(|w| !w.is_idle).count()
    }
}

/// Configuration descriptor for a workqueue.
#[derive(Debug, Clone)]
pub struct WorkqueueDesc {
    pub id: u32,
    pub name: String,
    pub flags: u32,
    pub max_active: usize,
}

/// Concurrency-Managed Workqueue Manager.
pub struct WorkqueueManager {
    pub queues: Vec<WorkqueueDesc>,
    pub pools: Vec<WorkerPool>,
    pub total_work_completed: u64,
}

impl WorkqueueManager {
    /// Initialize manager with standard system workqueues and default worker pools.
    pub fn new() -> Self {
        let mut mgr = Self {
            queues: Vec::new(),
            pools: Vec::new(),
            total_work_completed: 0,
        };

        // Standard system workqueues
        mgr.create_workqueue(WQ_SYSTEM, "system_wq", 0, 8);
        mgr.create_workqueue(WQ_SYSTEM_HIGHPRI, "system_highpri_wq", WQ_FLAG_HIGHPRI, 16);
        mgr.create_workqueue(WQ_SYSTEM_LONG, "system_long_wq", 0, 4);
        mgr.create_workqueue(WQ_SYSTEM_UNBOUND, "system_unbound_wq", WQ_FLAG_UNBOUND, 16);

        // Standard worker pools: Pool 0 (per-CPU / primary) and Pool 1 (unbound)
        mgr.pools.push(WorkerPool::new(0, Some(0), 8, 4));
        mgr.pools.push(WorkerPool::new(1, None, 16, 4));

        mgr
    }

    /// Create and register a custom workqueue.
    pub fn create_workqueue(&mut self, id: u32, name: &str, flags: u32, max_active: usize) {
        self.queues.push(WorkqueueDesc {
            id,
            name: String::from(name),
            flags,
            max_active,
        });
    }

    /// Find destination pool ID for a workqueue.
    fn get_pool_id_for_wq(&self, wq_id: u32) -> usize {
        if let Some(desc) = self.queues.iter().find(|q| q.id == wq_id) {
            if desc.flags & WQ_FLAG_UNBOUND != 0 {
                return 1; // Unbound pool
            }
        }
        0 // Bound primary pool
    }

    /// Submit a work item to a workqueue.
    pub fn queue_work(&mut self, wq_id: u32, mut work: WorkItem) -> Result<(), &'static str> {
        let pool_idx = self.get_pool_id_for_wq(wq_id);
        let pool = self.pools.get_mut(pool_idx).ok_or("Worker pool not found")?;

        work.wq_id = wq_id;
        work.flags = WORK_FLAG_PENDING;
        pool.worklist.push_back(work);
        Ok(())
    }

    /// Submit a delayed work item to execute after `delay_ticks`.
    pub fn queue_delayed_work(&mut self, wq_id: u32, mut work: WorkItem, current_tick: u64, delay_ticks: u64) -> Result<(), &'static str> {
        let pool_idx = self.get_pool_id_for_wq(wq_id);
        let pool = self.pools.get_mut(pool_idx).ok_or("Worker pool not found")?;

        work.wq_id = wq_id;
        work.flags = WORK_FLAG_PENDING | WORK_FLAG_DELAYED;
        pool.delayed_worklist.push(DelayedWorkItem {
            work,
            target_tick: current_tick.saturating_add(delay_ticks),
        });
        Ok(())
    }

    /// Cancel a pending or delayed work item by ID.
    pub fn cancel_work(&mut self, work_id: u64) -> bool {
        for pool in &mut self.pools {
            // Check active worklist
            if let Some(pos) = pool.worklist.iter().position(|w| w.id == work_id) {
                let mut item = pool.worklist.remove(pos).unwrap();
                item.flags |= WORK_FLAG_CANCELLED;
                return true;
            }
            // Check delayed worklist
            if let Some(pos) = pool.delayed_worklist.iter().position(|d| d.work.id == work_id) {
                pool.delayed_worklist.remove(pos);
                return true;
            }
        }
        false
    }

    /// Advance tick timer: migrate matured delayed items to active worklist.
    pub fn tick(&mut self, current_tick: u64) {
        for pool in &mut self.pools {
            let mut matured = Vec::new();
            let mut remaining = Vec::new();

            for item in pool.delayed_worklist.drain(..) {
                if current_tick >= item.target_tick {
                    let mut work = item.work;
                    work.flags &= !WORK_FLAG_DELAYED;
                    matured.push(work);
                } else {
                    remaining.push(item);
                }
            }

            pool.delayed_worklist = remaining;
            for work in matured {
                pool.worklist.push_back(work);
            }
        }
    }

    /// Step execution: assign pending work items to available workers up to max_active limit.
    pub fn step(&mut self) -> usize {
        let mut executed = 0;

        for pool in &mut self.pools {
            while pool.active_workers_count() < pool.max_active && !pool.worklist.is_empty() {
                // Find an idle worker
                let idle_worker_idx = pool.workers.iter().position(|w| w.is_idle);
                let worker_idx = match idle_worker_idx {
                    Some(idx) => idx,
                    None => {
                        // Dynamically allocate new worker if under max_active
                        if pool.workers.len() < pool.max_active {
                            let new_id = pool.workers.len() as u32;
                            pool.workers.push(WorkerThread::new(new_id));
                            pool.workers.len() - 1
                        } else {
                            break;
                        }
                    }
                };

                let mut work = pool.worklist.pop_front().unwrap();
                if work.flags & WORK_FLAG_CANCELLED != 0 {
                    continue;
                }

                // Dispatch to worker
                work.flags = WORK_FLAG_RUNNING;
                pool.workers[worker_idx].is_idle = false;
                pool.workers[worker_idx].current_work_id = Some(work.id);

                // Execute function
                (work.func)(work.arg);

                // Complete work
                pool.workers[worker_idx].is_idle = true;
                pool.workers[worker_idx].current_work_id = None;
                pool.workers[worker_idx].total_executed += 1;
                executed += 1;
            }
        }

        self.total_work_completed += executed as u64;
        executed
    }

    /// Flush all pending and delayed work items in the specified workqueue synchronously.
    pub fn flush_workqueue(&mut self, wq_id: u32) -> usize {
        let mut executed = 0;
        let pool_idx = self.get_pool_id_for_wq(wq_id);

        if let Some(pool) = self.pools.get_mut(pool_idx) {
            // Drain delayed items belonging to this wq
            let mut matured = Vec::new();
            let mut remaining = Vec::new();
            for item in pool.delayed_worklist.drain(..) {
                if item.work.wq_id == wq_id {
                    matured.push(item.work);
                } else {
                    remaining.push(item);
                }
            }
            pool.delayed_worklist = remaining;
            for work in matured {
                pool.worklist.push_back(work);
            }

            // Drain active worklist items for this wq
            let mut wq_items = VecDeque::new();
            let mut other_items = VecDeque::new();
            for work in pool.worklist.drain(..) {
                if work.wq_id == wq_id {
                    wq_items.push_back(work);
                } else {
                    other_items.push_back(work);
                }
            }
            pool.worklist = other_items;

            for mut work in wq_items {
                if work.flags & WORK_FLAG_CANCELLED == 0 {
                    work.flags = WORK_FLAG_RUNNING;
                    (work.func)(work.arg);
                    executed += 1;
                }
            }
        }

        self.total_work_completed += executed as u64;
        executed
    }
}
