//! High-Performance Preemptive & Cooperative Task Scheduler
//!
//! Provides zero-allocation, ultra-low-latency task scheduling.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::sync::SpinLock;
use super::context::{coros_switch_context, TaskContext};

pub const DEFAULT_STACK_SIZE: usize = 64 * 1024; // 64 KiB dedicated stack

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

pub struct Task {
    pub id: u64,
    pub name: &'static str,
    pub context: TaskContext,
    pub stack: Vec<u8>,
    pub state: TaskState,
}

impl Task {
    pub fn new(id: u64, name: &'static str, entry_fn: fn(usize), arg: usize) -> Self {
        let mut stack = vec![0u8; DEFAULT_STACK_SIZE];
        let stack_top = unsafe { stack.as_mut_ptr().add(DEFAULT_STACK_SIZE) };
        let context = unsafe { TaskContext::initialize_stack(stack_top, entry_fn, arg) };

        Self {
            id,
            name,
            context,
            stack,
            state: TaskState::Ready,
        }
    }
}

pub struct Scheduler {
    tasks: SpinLock<Vec<Task>>,
    current: SpinLock<Option<usize>>,
    main_context: SpinLock<TaskContext>,
    next_task_id: AtomicU64,
    cfs_rq: SpinLock<Option<corsched::eevdf_cfs::CfsRunQueue>>,
    deadline_rq: SpinLock<Option<corsched::sched_deadline::DeadlineRunQueue>>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            tasks: SpinLock::new(Vec::new()),
            current: SpinLock::new(None),
            main_context: SpinLock::new(TaskContext::empty()),
            next_task_id: AtomicU64::new(1),
            cfs_rq: SpinLock::new(None),
            deadline_rq: SpinLock::new(None),
        }
    }

    /// Spawns a new independent kernel task
    pub fn spawn(&self, name: &'static str, entry_fn: fn(usize), arg: usize) -> u64 {
        let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        let task = Task::new(id, name, entry_fn, arg);
        let mut tasks = self.tasks.lock_irqsave();
        tasks.push(task);
        drop(tasks);

        let mut cfs = self.cfs_rq.lock_irqsave();
        if cfs.is_none() {
            *cfs = Some(corsched::eevdf_cfs::CfsRunQueue::new());
        }
        if let Some(rq) = cfs.as_mut() {
            let entity = corsched::eevdf_cfs::SchedEntity::new(id, name, 0);
            rq.enqueue_task(entity);
        }

        id
    }

    /// Yields execution to the next available ready task
    pub fn schedule(&self) {
        let mut prev_rsp = 0u64;
        let mut next_rsp = 0u64;

        {
            let mut tasks = self.tasks.lock_irqsave();
            let mut cur_guard = self.current.lock_irqsave();

            if tasks.is_empty() {
                return;
            }

            let old_curr = *cur_guard;
            let current_idx = old_curr.unwrap_or(0);

            // Find next ready task using round-robin search
            let mut next_idx = if old_curr.is_some() {
                (current_idx + 1) % tasks.len()
            } else {
                0
            };
            let mut found = false;

            for _ in 0..tasks.len() {
                if tasks[next_idx].state == TaskState::Ready {
                    found = true;
                    break;
                }
                next_idx = (next_idx + 1) % tasks.len();
            }

            if !found {
                // If no task is ready and we came from a running task, keep running it
                if let Some(curr) = old_curr {
                    if tasks[curr].state == TaskState::Running {
                        return;
                    }
                }
                return;
            }

            if old_curr.is_some() && current_idx == next_idx && tasks[current_idx].state == TaskState::Running {
                return;
            }

            // Mark previous task Ready if it was Running
            if let Some(curr) = old_curr {
                if tasks[curr].state == TaskState::Running {
                    tasks[curr].state = TaskState::Ready;
                }
            }

            // Mark next task Running
            tasks[next_idx].state = TaskState::Running;
            *cur_guard = Some(next_idx);

            next_rsp = tasks[next_idx].context.rsp;
            if let Some(curr) = old_curr {
                prev_rsp = core::ptr::addr_of_mut!(tasks[curr].context.rsp) as u64;
            } else {
                // Bootstrap switch from kernel_main: save kernel_main's RSP to main_context
                let mut main_guard = self.main_context.lock_irqsave();
                prev_rsp = core::ptr::addr_of_mut!(main_guard.rsp) as u64;
                drop(main_guard);
            }
        }

        if prev_rsp != 0 && next_rsp != 0 {
            unsafe {
                coros_switch_context(prev_rsp as *mut u64, next_rsp);
            }
        }
    }

    /// Gracefully exits the currently executing task
    pub fn exit_current(&self) -> ! {
        let mut next_rsp = 0u64;
        let mut main_rsp = 0u64;

        {
            let mut tasks = self.tasks.lock_irqsave();
            let mut cur_guard = self.current.lock_irqsave();
            if let Some(curr) = *cur_guard {
                tasks[curr].state = TaskState::Terminated;
            }

            // Search for next ready task using round-robin search
            let current_idx = cur_guard.unwrap_or(0);
            let mut next_idx = None;
            if !tasks.is_empty() {
                for offset in 1..=tasks.len() {
                    let idx = (current_idx + offset) % tasks.len();
                    if tasks[idx].state == TaskState::Ready {
                        next_idx = Some(idx);
                        break;
                    }
                }
            }

            if let Some(idx) = next_idx {
                tasks[idx].state = TaskState::Running;
                *cur_guard = Some(idx);
                next_rsp = tasks[idx].context.rsp;
            } else {
                *cur_guard = None;
                let mut main_guard = self.main_context.lock_irqsave();
                main_rsp = main_guard.rsp;
                main_guard.rsp = 0;
            }
        }

        let mut dummy_prev = 0u64;
        if next_rsp != 0 {
            unsafe {
                coros_switch_context(core::ptr::addr_of_mut!(dummy_prev), next_rsp);
            }
        } else if main_rsp != 0 {
            unsafe {
                coros_switch_context(core::ptr::addr_of_mut!(dummy_prev), main_rsp);
            }
        }

        // Return to main kernel thread if saved
        // If no tasks left to run and no main thread, safely idle the CPU
        loop {
            unsafe { crate::arch::x86_64::cpu::halt(); }
        }
    }

    pub fn task_count(&self) -> usize {
        self.tasks.lock_irqsave().len()
    }

    pub fn get_task_info(&self) -> Vec<(u64, &'static str, TaskState)> {
        let tasks = self.tasks.lock_irqsave();
        tasks.iter().map(|t| (t.id, t.name, t.state)).collect()
    }

    /// Invoked periodically from Local APIC Timer (Vector 32) every ~10ms for preemptive round-robin scheduling
    pub fn tick_preempt(&self) {
        PREEMPTION_TICKS.fetch_add(1, Ordering::Relaxed);
        let now_ns = PREEMPTION_TICKS.load(Ordering::Relaxed).saturating_mul(10_000_000);

        let mut dl_guard = self.deadline_rq.lock_irqsave();
        if let Some(dl) = dl_guard.as_mut() {
            dl.tick(now_ns);
        }
        drop(dl_guard);

        let mut cfs_guard = self.cfs_rq.lock_irqsave();
        if let Some(cfs) = cfs_guard.as_mut() {
            if cfs.nr_running > 0 {
                let _ = cfs.pick_next_task(now_ns);
            }
        }
    }

    pub fn enqueue_sched_entity(&self, entity: corsched::eevdf_cfs::SchedEntity) {
        let mut cfs = self.cfs_rq.lock_irqsave();
        if cfs.is_none() {
            *cfs = Some(corsched::eevdf_cfs::CfsRunQueue::new());
        }
        if let Some(rq) = cfs.as_mut() {
            rq.enqueue_task(entity);
        }
    }

    pub fn enqueue_deadline_task(&self, task: corsched::sched_deadline::DeadlineTask, now_ns: u64) -> Result<(), &'static str> {
        let mut dl = self.deadline_rq.lock_irqsave();
        if dl.is_none() {
            *dl = Some(corsched::sched_deadline::DeadlineRunQueue::new());
        }
        if let Some(rq) = dl.as_mut() {
            rq.add_task(task, now_ns)
        } else {
            Err("Deadline runqueue unavailable")
        }
    }

    pub fn corsched_stats(&self) -> (usize, u64, usize) {
        let cfs = self.cfs_rq.lock_irqsave();
        let (cfs_tasks, cfs_weight) = if let Some(ref rq) = *cfs {
            (rq.nr_running, rq.total_weight)
        } else {
            (0, 0)
        };
        drop(cfs);

        let dl = self.deadline_rq.lock_irqsave();
        let dl_tasks = if let Some(ref rq) = *dl {
            rq.tasks.len()
        } else {
            0
        };
        (cfs_tasks, cfs_weight, dl_tasks)
    }
}

pub static PREEMPTION_TICKS: AtomicU64 = AtomicU64::new(0);
pub static SCHEDULER: Scheduler = Scheduler::new();
