//! CorOS Syscall Domain Module: `smp_scheduling`
//! Preemptive SMP & CFS Scheduling (`sched_yield`, `sched_setaffinity`, `sched_getaffinity`, `sched_setscheduler`, `getpriority`, `setpriority`, `getcpu`).

use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const ESRCH: i64 = -3;
pub const EPERM: i64 = -1;

/// Linux/CorOS scheduling policies.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedPolicy {
    Normal = 0,
    Fifo = 1,
    RoundRobin = 2,
    Batch = 3,
    Idle = 5,
    Deadline = 6,
}

impl SchedPolicy {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Normal),
            1 => Some(Self::Fifo),
            2 => Some(Self::RoundRobin),
            3 => Some(Self::Batch),
            5 => Some(Self::Idle),
            6 => Some(Self::Deadline),
            _ => None,
        }
    }
}

/// Extended scheduling attributes (`struct sched_attr`) supporting EDF `SCHED_DEADLINE`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedAttr {
    pub size: u32,
    pub sched_policy: SchedPolicy,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
}

/// 64-core SMP CPU affinity bitmask (`cpu_set_t`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSet(pub u64);

impl CpuSet {
    pub const fn all(num_cores: u8) -> Self {
        if num_cores >= 64 {
            Self(u64::MAX)
        } else {
            Self((1u64 << num_cores) - 1)
        }
    }

    #[inline]
    pub const fn set_cpu(&mut self, cpu: u8) {
        if cpu < 64 {
            self.0 |= 1u64 << cpu;
        }
    }

    #[inline]
    pub const fn clear_cpu(&mut self, cpu: u8) {
        if cpu < 64 {
            self.0 &= !(1u64 << cpu);
        }
    }

    #[inline]
    pub const fn allows(&self, cpu: u8) -> bool {
        cpu < 64 && (self.0 & (1u64 << cpu)) != 0
    }
}

/// Nice value (`-20..=19`) to CFS weight lookup table (Linux kernel `sched_prio_to_weight`).
pub const NICE_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, // -20 .. -16
    29154, 23254, 18705, 14949, 11916, // -15 .. -11
    9548, 7620, 6100, 4904, 3906,      // -10 .. -6
    3121, 2501, 1991, 1586, 1277,      // -5  .. -1
    1024, 820, 655, 526, 423,          //  0  ..  4
    335, 272, 215, 172, 137,           //  5  ..  9
    110, 87, 70, 56, 45,               // 10  .. 14
    36, 29, 23, 18, 15,                // 15  .. 19
];

#[derive(Clone, Debug)]
pub struct SchedEntity {
    pub pid: u32,
    pub policy: SchedPolicy,
    pub nice: i32,
    pub rt_priority: u32,
    pub vruntime: u64,
    pub affinity: CpuSet,
    pub last_cpu: u8,
    pub deadline_runtime_ns: u64,
    pub deadline_period_ns: u64,
}

impl SchedEntity {
    pub const fn weight(&self) -> u32 {
        let clamped = if self.nice < -20 {
            -20
        } else if self.nice > 19 {
            19
        } else {
            self.nice
        };
        let idx = (clamped + 20) as usize;
        NICE_TO_WEIGHT[idx]
    }
}

/// Completely Fair Scheduler (CFS) + Real-Time RunQueue across `online_cpus`.
pub struct CfsRunQueue {
    tasks: Vec<SchedEntity>,
    pub online_cpus: u8,
    pub min_vruntime: u64,
}

impl CfsRunQueue {
    pub fn new(online_cpus: u8) -> Self {
        Self {
            tasks: Vec::new(),
            online_cpus: online_cpus.clamp(1, 64),
            min_vruntime: 0,
        }
    }

    pub fn add_task(&mut self, pid: u32, nice: i32) {
        let clamped_nice = nice.clamp(-20, 19);
        self.tasks.push(SchedEntity {
            pid,
            policy: SchedPolicy::Normal,
            nice: clamped_nice,
            rt_priority: 0,
            vruntime: self.min_vruntime,
            affinity: CpuSet::all(self.online_cpus),
            last_cpu: 0,
            deadline_runtime_ns: 0,
            deadline_period_ns: 0,
        });
    }

    /// Charges physical execution time (`delta_exec_ns`) to `pid`, scaled inversely by nice weight.
    pub fn account_execution(&mut self, pid: u32, delta_exec_ns: u64) {
        if let Some(t) = self.tasks.iter_mut().find(|t| t.pid == pid) {
            let weight = t.weight() as u64;
            let weighted_delta = (delta_exec_ns.saturating_mul(1024)) / weight.max(1);
            t.vruntime = t.vruntime.saturating_add(weighted_delta);
        }
        if let Some(min_v) = self.tasks.iter().map(|t| t.vruntime).min() {
            self.min_vruntime = min_v;
        }
    }

    /// Picks the next runnable task for `cpu` (Real-Time FIFO/RR highest priority first, then minimum CFS `vruntime`).
    pub fn pick_next_task(&mut self, cpu: u8) -> Option<u32> {
        // Check Real-Time tasks first
        if let Some(rt_task) = self
            .tasks
            .iter_mut()
            .filter(|t| {
                t.affinity.allows(cpu)
                    && matches!(t.policy, SchedPolicy::Fifo | SchedPolicy::RoundRobin)
            })
            .max_by_key(|t| t.rt_priority)
        {
            rt_task.last_cpu = cpu;
            return Some(rt_task.pid);
        }

        // Otherwise pick CFS task with smallest vruntime
        let cfs_task = self
            .tasks
            .iter_mut()
            .filter(|t| t.affinity.allows(cpu))
            .min_by_key(|t| t.vruntime)?;
        cfs_task.last_cpu = cpu;
        Some(cfs_task.pid)
    }

    /// `sys_sched_yield`: Advances caller's `vruntime` past the current maximum so another task runs.
    pub fn sys_sched_yield(&mut self, caller_pid: u32) -> i64 {
        let max_v = self.tasks.iter().map(|t| t.vruntime).max().unwrap_or(0);
        match self.tasks.iter_mut().find(|t| t.pid == caller_pid) {
            Some(t) => {
                t.vruntime = max_v + 1;
                0
            }
            None => ESRCH,
        }
    }

    /// `sys_sched_setaffinity`: Restricts `pid` to run only on cores in `mask`.
    pub fn sys_sched_setaffinity(&mut self, pid: u32, mask: CpuSet) -> i64 {
        let valid_mask = CpuSet(mask.0 & CpuSet::all(self.online_cpus).0);
        if valid_mask.0 == 0 {
            return EINVAL;
        }
        match self.tasks.iter_mut().find(|t| t.pid == pid) {
            Some(t) => {
                t.affinity = valid_mask;
                if !valid_mask.allows(t.last_cpu) {
                    t.last_cpu = valid_mask.0.trailing_zeros() as u8;
                }
                0
            }
            None => ESRCH,
        }
    }

    /// `sys_sched_getaffinity`: Returns the CPU affinity mask for `pid`.
    pub fn sys_sched_getaffinity(&self, pid: u32) -> Result<CpuSet, i64> {
        self.tasks
            .iter()
            .find(|t| t.pid == pid)
            .map(|t| t.affinity)
            .ok_or(ESRCH)
    }

    /// `sys_sched_setscheduler`: Updates scheduling policy and real-time priority (`1..=99`).
    pub fn sys_sched_setscheduler(&mut self, pid: u32, raw_policy: u32, priority: u32) -> i64 {
        let policy = match SchedPolicy::from_raw(raw_policy) {
            Some(p) => p,
            None => return EINVAL,
        };
        match policy {
            SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
                if priority < 1 || priority > 99 {
                    return EINVAL;
                }
            }
            _ => {
                if priority != 0 {
                    return EINVAL;
                }
            }
        }
        match self.tasks.iter_mut().find(|t| t.pid == pid) {
            Some(t) => {
                t.policy = policy;
                t.rt_priority = priority;
                0
            }
            None => ESRCH,
        }
    }

    /// `sys_getpriority`: Returns Linux nice value encoded as `20 - nice` (`1..=40`).
    pub fn sys_getpriority(&self, pid: u32) -> i64 {
        match self.tasks.iter().find(|t| t.pid == pid) {
            Some(t) => (20 - t.nice) as i64,
            None => ESRCH,
        }
    }

    /// `sys_setpriority`: Sets the nice value (`-20..=19`) of `pid`.
    pub fn sys_setpriority(&mut self, pid: u32, nice: i32, is_privileged: bool) -> i64 {
        let clamped = nice.clamp(-20, 19);
        match self.tasks.iter_mut().find(|t| t.pid == pid) {
            Some(t) => {
                if clamped < t.nice && !is_privileged {
                    return EPERM;
                }
                t.nice = clamped;
                0
            }
            None => ESRCH,
        }
    }

    /// `sys_getcpu`: Returns `(cpu_id, numa_node)` for `pid`.
    pub fn sys_getcpu(&self, pid: u32) -> Result<(u32, u32), i64> {
        let t = self.tasks.iter().find(|t| t.pid == pid).ok_or(ESRCH)?;
        let cpu = t.last_cpu as u32;
        let numa_node = cpu / 4;
        Ok((cpu, numa_node))
    }
}

/// Runs comprehensive self-tests on `smp_scheduling` structs and CFS/RT runqueue selection.
pub fn verify_domain_smp_scheduling() -> u32 {
    let mut passed = 0u32;
    let mut rq = CfsRunQueue::new(8);

    rq.add_task(10, 0);   // normal priority
    rq.add_task(20, -10); // high priority (larger weight -> slower vruntime growth)

    // 1. Account 1,000,000 ns to both tasks; PID 20 (nice -10) should have much lower vruntime
    rq.account_execution(10, 1_000_000);
    rq.account_execution(20, 1_000_000);
    if rq.pick_next_task(0) == Some(20) {
        passed += 1;
    }

    // 2. Yield PID 20 so PID 10 becomes next runnable
    if rq.sys_sched_yield(20) == 0 && rq.pick_next_task(0) == Some(10) {
        passed += 1;
    }

    // 3. Pin PID 10 exclusively to CPU 3 and verify getaffinity + getcpu
    let mut mask = CpuSet(0);
    mask.set_cpu(3);
    if rq.sys_sched_setaffinity(10, mask) == 0 && rq.sys_sched_getaffinity(10) == Ok(mask) {
        if rq. sys_getcpu(10) == Ok((3, 0)) {
            passed += 1;
        }
    }

    // 4. Promote PID 10 to SCHED_FIFO priority 50 and verify it preempts on CPU 3
    if rq.sys_sched_setscheduler(10, SchedPolicy::Fifo as u32, 50) == 0 && rq.pick_next_task(3) == Some(10) {
        passed += 1;
    }

    // 5. Test setpriority and getpriority permission checks
    if rq.sys_setpriority(10, -5, false) == EPERM && rq.sys_setpriority(10, -5, true) == 0 {
        if rq.sys_getpriority(10) == 25 {
            passed += 1;
        }
    }

    passed
}
