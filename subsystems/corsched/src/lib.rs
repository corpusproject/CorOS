#![no_std]
//! `corsched` — CorOS EEVDF/CFS, Real-Time CBS (`SCHED_DEADLINE`), SMP Load Balancer,
//! Tree RCU, Workqueues, Lockdep, RwSemaphore/SeqLock, HRTimers, Softirq & PSI Subsystem.

extern crate alloc;

pub mod eevdf_cfs;
pub mod sched_deadline;
pub mod smp_load_balance;
pub mod tree_rcu;
pub mod workqueue;
pub mod lockdep;
pub mod rw_semaphore;
pub mod hrtimer;
pub mod softirq;
pub mod psi;

// Re-export principal types for ease of use across the kernel
pub use eevdf_cfs::{CfsRunQueue, SchedEntity, EntityState};
pub use sched_deadline::{DeadlineRunQueue, DeadlineTask, DeadlineTaskState, DeadlineAdmissionControl};
pub use smp_load_balance::{SmpLoadBalancer, SchedDomain, SchedDomainLevel, CpuSet, MigratableTask};
pub use tree_rcu::{TreeRcu, RcuCallback, RcuGpState};
pub use workqueue::{WorkqueueManager, WorkItem, WQ_SYSTEM, WQ_SYSTEM_HIGHPRI};
pub use lockdep::{LockdepValidator, LockClass, LockdepError};
pub use rw_semaphore::{RwSemaphore, SeqLock};
pub use hrtimer::{HrTimerQueue, HrTimer, HrTimerMode, HrTimerRestart};
pub use softirq::{SoftirqEngine, Tasklet, TaskletPriority, TaskletState};
pub use psi::{PsiMonitor, PsiResource, PsiTrigger};

/// Run dynamic self-tests across all 10 scheduling and concurrency modules.
/// Returns the total count of passed test assertions (> 0).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // =========================================================================
    // 1. EEVDF / CFS Scheduler Verification
    // =========================================================================
    let mut cfs_rq = CfsRunQueue::new();
    let task_prio_high = SchedEntity::new(1, "prio_worker", -5);
    let task_prio_low = SchedEntity::new(2, "batch_worker", 5);

    if task_prio_high.weight > task_prio_low.weight {
        passed += 1;
    }

    cfs_rq.enqueue_task(task_prio_high);
    cfs_rq.enqueue_task(task_prio_low);

    if cfs_rq.nr_running == 2 && cfs_rq.total_weight > 0 {
        passed += 1;
    }

    // Pick first task at time 1,000,000 ns
    let first_picked = cfs_rq.pick_next_task(1_000_000);
    if first_picked.is_some() {
        passed += 1;
    }

    // Advance execution time by 2,000,000 ns and pick next task
    let second_picked = cfs_rq.pick_next_task(3_000_000);
    if second_picked.is_some() {
        passed += 1;
    }

    // Verify cgroup v2 cpu.max throttling: throttled entity is skipped
    if let Some(picked_id) = second_picked {
        cfs_rq.set_entity_throttled(picked_id, true);
        let third_picked = cfs_rq.pick_next_task(4_000_000);
        if third_picked.is_some() && third_picked != Some(picked_id) {
            passed += 1;
        }
        cfs_rq.set_entity_throttled(picked_id, false);
    }

    // Verify futex waiter deschedule and wakeup
    if cfs_rq.deschedule_task_sleeping(2) {
        if cfs_rq.entities.iter().find(|e| e.id == 2).map(|e| e.state) == Some(EntityState::Sleeping) {
            passed += 1;
        }
        if cfs_rq.wake_task(2) {
            if cfs_rq.entities.iter().find(|e| e.id == 2).map(|e| e.state) == Some(EntityState::Runnable) {
                passed += 1;
            }
        }
    }

    // =========================================================================
    // 2. SCHED_DEADLINE & Constant Bandwidth Server Verification
    // =========================================================================
    let mut dl_rq = DeadlineRunQueue::new();
    let dl_task_valid = DeadlineTask::new(10, "audio_dsp", 2_000_000, 10_000_000, 10_000_000);
    if dl_task_valid.is_ok() {
        let task = dl_task_valid.unwrap();
        if dl_rq.add_task(task, 1_000_000).is_ok() {
            passed += 1;
        }
    }

    // Test admission control rejection on excessive utilization (e.g. 98% when max is 95%)
    let dl_task_excessive = DeadlineTask::new(11, "greedy_rt", 980_000, 1_000_000, 1_000_000).unwrap();
    if dl_rq.add_task(dl_task_excessive, 1_000_000).is_err() {
        passed += 1; // Admission correctly rejected
    }

    let picked_dl = dl_rq.pick_next_task(1_500_000);
    if picked_dl == Some(10) {
        passed += 1;
    }

    // =========================================================================
    // 3. Hierarchical SMP Load Balancer Verification
    // =========================================================================
    let mut smp = SmpLoadBalancer::new(4);
    let mut domain_span = CpuSet::empty();
    domain_span.set(0);
    domain_span.set(1);

    smp.add_domain(SchedDomain {
        level: SchedDomainLevel::Mc,
        span: domain_span,
        groups: alloc::vec![],
        balance_interval_ms: 10,
        min_interval_ms: 5,
        max_interval_ms: 20,
        imbalance_pct: 125,
    });

    let task_cpu0_a = MigratableTask::new(101, 1024, CpuSet::all(), 0);
    let task_cpu0_b = MigratableTask::new(102, 1024, CpuSet::all(), 0);
    let _ = smp.enqueue_task(0, task_cpu0_a);
    let _ = smp.enqueue_task(0, task_cpu0_b);

    if smp.runqueues[0].nr_running() == 2 && smp.runqueues[1].nr_running() == 0 {
        passed += 1;
    }

    // Balance on CPU 1 (pull tasks from busy CPU 0)
    let moved = smp.balance(1, 1_000_000_000);
    if moved >= 1 && smp.runqueues[1].nr_running() >= 1 {
        passed += 1;
    }

    // =========================================================================
    // 4. Tree RCU Grace-Period State Machine Verification
    // =========================================================================
    let mut rcu = TreeRcu::new(16);
    static mut RCU_CALLBACK_EXECUTED: bool = false;
    fn rcu_test_cb(_arg: u64) {
        unsafe {
            RCU_CALLBACK_EXECUTED = true;
        }
    }

    rcu.call_rcu(0, RcuCallback {
        id: 1,
        func: rcu_test_cb,
        arg: 42,
        gp_seq: 0,
    });

    if rcu.start_grace_period() {
        passed += 1;
    }

    // Report quiescent state on all 16 CPUs
    for cpu in 0..16 {
        rcu.report_quiescent_state(cpu);
    }

    if rcu.state == RcuGpState::Idle {
        passed += 1;
    }

    let invoked = rcu.do_batch(0, 10);
    if invoked == 1 && unsafe { RCU_CALLBACK_EXECUTED } {
        passed += 1;
    }

    // =========================================================================
    // 5. Concurrency-Managed Workqueue Verification
    // =========================================================================
    let mut wq_mgr = WorkqueueManager::new();
    static mut WQ_COUNT: u64 = 0;
    fn wq_test_fn(val: u64) {
        unsafe {
            WQ_COUNT += val;
        }
    }

    let work1 = WorkItem::new(201, "sys_init_work", wq_test_fn, 10, WQ_SYSTEM);
    let _ = wq_mgr.queue_work(WQ_SYSTEM, work1);

    let delayed_work = WorkItem::new(202, "delayed_cleanup", wq_test_fn, 5, WQ_SYSTEM);
    let _ = wq_mgr.queue_delayed_work(WQ_SYSTEM, delayed_work, 100, 50);

    let flushed = wq_mgr.flush_workqueue(WQ_SYSTEM);
    if flushed == 2 && unsafe { WQ_COUNT } == 15 {
        passed += 1;
    }

    // =========================================================================
    // 6. Lockdep Runtime Deadlock Validator Verification
    // =========================================================================
    let mut lockdep = LockdepValidator::new();
    lockdep.register_class(1, "fs_lock_class", 0);
    lockdep.register_class(2, "net_lock_class", 0);

    // Thread 1 acquires class 1 then class 2
    let acq1 = lockdep.acquire(1, 0x1000, false, false, 0, 100);
    let acq2 = lockdep.acquire(2, 0x2000, false, false, 0, 200);
    if acq1.is_ok() && acq2.is_ok() {
        passed += 1;
    }

    let _ = lockdep.release(0x2000);
    let _ = lockdep.release(0x1000);

    // Thread 2 acquires class 2 then tries class 1 -> ABBA cycle!
    let _ = lockdep.acquire(2, 0x2000, false, false, 1, 300);
    let abba_result = lockdep.acquire(1, 0x1000, false, false, 1, 400);
    if let Err(LockdepError::DeadlockCycle { from_class, to_class, .. }) = abba_result {
        if from_class == 2 && to_class == 1 {
            passed += 1; // Deadlock correctly caught!
        }
    }

    // =========================================================================
    // 7. Reader-Writer Semaphore & SeqLock Verification
    // =========================================================================
    let mut rw_sem = RwSemaphore::new();
    if rw_sem.try_down_read() && rw_sem.try_down_read() {
        if rw_sem.readers_active == 2 {
            passed += 1;
        }
    }

    // Writer tries to acquire: blocked by readers
    if !rw_sem.try_down_write() {
        let _ = rw_sem.down_write(); // Enqueues waiting writer
        if rw_sem.writers_waiting == 1 {
            passed += 1;
        }
    }

    // New reader tries to barge: rejected due to waiting writer
    if !rw_sem.try_down_read() {
        passed += 1; // Reader anti-starvation policy verified
    }

    rw_sem.up_read();
    rw_sem.up_read();
    if rw_sem.complete_waiting_write() && rw_sem.writer_active {
        passed += 1;
    }

    rw_sem.downgrade_write();
    if !rw_sem.writer_active && rw_sem.readers_active >= 1 {
        passed += 1;
    }

    let seqlock = SeqLock::new();
    let read_seq = seqlock.read_begin();
    let write_seq = seqlock.write_begin();
    if seqlock.read_retry(read_seq) {
        passed += 1; // Concurrent write detected
    }
    seqlock.write_end();
    if !seqlock.read_retry(write_seq + 1) {
        passed += 1; // Quiescent write verified
    }

    // =========================================================================
    // 8. Nanosecond High-Resolution Timers Verification
    // =========================================================================
    let mut hrtimers = HrTimerQueue::new(0);
    static mut TIMER_FIRED: u32 = 0;
    fn timer_cb(_arg: u64) -> HrTimerRestart {
        unsafe {
            TIMER_FIRED += 1;
        }
        HrTimerRestart::NoRestart
    }

    let timer = HrTimer::new(501, hrtimer::CLOCK_MONOTONIC, timer_cb, 0);
    hrtimers.start_timer(timer, 5_000_000, HrTimerMode::Absolute, 0);

    // Run at 4,000,000 ns: should not fire
    let fired_early = hrtimers.run_expired_timers(4_000_000);
    if fired_early == 0 {
        passed += 1;
    }

    // Run at 6,000,000 ns: should fire
    let fired_on_time = hrtimers.run_expired_timers(6_000_000);
    if fired_on_time == 1 && unsafe { TIMER_FIRED } == 1 {
        passed += 1;
    }

    // =========================================================================
    // 9. Softirq & Tasklet Deferred Execution Verification
    // =========================================================================
    let mut softirq_engine = SoftirqEngine::new(2);
    static mut SOFTIRQ_COUNT: u32 = 0;
    fn net_softirq_handler(_vec: u32, _cpu: u32, _data: u64) {
        unsafe {
            SOFTIRQ_COUNT += 1;
        }
    }

    softirq_engine.register_action(softirq::SOFTIRQ_NET_RX, net_softirq_handler, 0);
    softirq_engine.raise_softirq(softirq::SOFTIRQ_NET_RX, 0);

    static mut TASKLET_COUNT: u32 = 0;
    fn tasklet_cb(_arg: u64) {
        unsafe {
            TASKLET_COUNT += 1;
        }
    }

    let tasklet = Tasklet::new(701, TaskletPriority::High, tasklet_cb, 0);
    softirq_engine.schedule_tasklet(tasklet, 0);

    let executed_softirqs = softirq_engine.do_softirq(0);
    if executed_softirqs >= 2 && unsafe { SOFTIRQ_COUNT } == 1 && unsafe { TASKLET_COUNT } == 1 {
        passed += 1;
    }

    // =========================================================================
    // 10. Pressure Stall Information (PSI) Verification
    // =========================================================================
    let mut psi = PsiMonitor::new();
    psi.register_trigger(PsiTrigger::new(PsiResource::Memory, true, 500, 1_000_000_000));

    // Simulate 2,000,000 ns of full memory stall
    psi.get_resource_mut(PsiResource::Memory).enter_stall(true, 10_000_000);
    psi.get_resource_mut(PsiResource::Memory).exit_stall(true, 12_000_000);

    let triggers_fired = psi.update(15_000_000);
    let mem_pressure_str = psi.format_pressure(PsiResource::Memory);

    if triggers_fired >= 1 && mem_pressure_str.contains("some avg10=") && mem_pressure_str.contains("full avg10=") {
        passed += 1;
    }

    passed
}
