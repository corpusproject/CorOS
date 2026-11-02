//! CorOS Syscall Domain Module: `futex_sync`
//! Fast Userspace Mutexes & Memory Barriers (`futex_wait`, `futex_wake`, `futex_requeue`, `futex_cmp_requeue`, `set_robust_list`, `get_robust_list`, `membarrier`).

use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EAGAIN: i64 = -11;
pub const ESRCH: i64 = -3;

pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

/// Futex command operations.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexOp {
    Wait = 0,
    Wake = 1,
    Requeue = 3,
    CmpRequeue = 4,
    WakeOp = 5,
    WaitBitset = 9,
    WakeBitset = 10,
}

/// Unique kernel key identifying a futex word across private or shared address spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexKey {
    pub aspace_id: u64, // 0 if shared inode-backed
    pub word_addr: u64,
}

/// Sleeping thread entry queued inside a `FutexHashBucket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWaiter {
    pub tid: u32,
    pub key: FutexKey,
    pub bitset: u32,
}

/// Userspace robust futex list head registered via `sys_set_robust_list`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RobustListHead {
    pub list_head_ptr: u64,
    pub futex_offset: i64,
    pub list_op_pending: u64,
}

#[derive(Clone, Copy, Debug)]
struct RobustRegistration {
    tid: u32,
    head: RobustListHead,
    len: usize,
}

/// Kernel Futex Hash Bucket managing wait queues, atomic requeues, robust lists, and SMP memory barriers.
pub struct FutexHashBucket {
    waiters: Vec<FutexWaiter>,
    robust_lists: Vec<RobustRegistration>,
    pub membarrier_registrations: u64,
    pub ipi_barriers_issued: u64,
}

impl FutexHashBucket {
    pub fn new() -> Self {
        Self {
            waiters: Vec::new(),
            robust_lists: Vec::new(),
            membarrier_registrations: 0,
            ipi_barriers_issued: 0,
        }
    }

    pub fn waiter_count(&self, key: FutexKey) -> usize {
        self.waiters.iter().filter(|w| w.key == key).count()
    }

    pub fn is_waiter_queued(&self, tid: u32, key: FutexKey) -> bool {
        self.waiters.iter().any(|w| w.tid == tid && w.key == key)
    }

    pub fn remove_waiter(&mut self, tid: u32, key: FutexKey) -> bool {
        if let Some(pos) = self.waiters.iter().position(|w| w.tid == tid && w.key == key) {
            self.waiters.remove(pos);
            true
        } else {
            false
        }
    }

    /// `sys_futex_wait`: Atomically verifies `current_uval == expected_val` and enqueues `tid`.
    pub fn sys_futex_wait(
        &mut self,
        tid: u32,
        key: FutexKey,
        current_uval: u32,
        expected_val: u32,
        bitset: u32,
    ) -> i64 {
        if (key.word_addr & 0x3) != 0 || bitset == 0 {
            return EINVAL;
        }
        if current_uval != expected_val {
            return EAGAIN;
        }
        self.waiters.push(FutexWaiter { tid, key, bitset });
        0
    }

    /// `sys_futex_wake`: Wakes up to `max_wake` threads waiting on `key` matching `bitset`.
    pub fn sys_futex_wake(&mut self, key: FutexKey, max_wake: usize, bitset: u32) -> i64 {
        if bitset == 0 {
            return EINVAL;
        }
        let mut woken = 0usize;
        let mut remaining = Vec::with_capacity(self.waiters.len());

        for w in self.waiters.drain(..) {
            if woken < max_wake && w.key == key && (w.bitset & bitset) != 0 {
                woken += 1;
            } else {
                remaining.push(w);
            }
        }
        self.waiters = remaining;
        woken as i64
    }

    /// `sys_futex_cmp_requeue`: Wakes up to `nr_wake` waiters on `src_key` and moves up to `nr_requeue` waiters to `dst_key`.
    pub fn sys_futex_cmp_requeue(
        &mut self,
        src_key: FutexKey,
        dst_key: FutexKey,
        nr_wake: usize,
        nr_requeue: usize,
        current_uval: u32,
        expected_val: Option<u32>,
    ) -> i64 {
        if let Some(exp) = expected_val {
            if current_uval != exp {
                return EAGAIN;
            }
        }
        let mut woken = 0usize;
        let mut requeued = 0usize;
        let mut updated = Vec::with_capacity(self.waiters.len());

        for mut w in self.waiters.drain(..) {
            if w.key == src_key {
                if woken < nr_wake {
                    woken += 1;
                    continue;
                } else if requeued < nr_requeue {
                    w.key = dst_key;
                    requeued += 1;
                }
            }
            updated.push(w);
        }
        self.waiters = updated;
        (woken + requeued) as i64
    }

    /// `sys_futex_requeue`: Wrapper over `sys_futex_cmp_requeue` without value comparison.
    pub fn sys_futex_requeue(
        &mut self,
        src_key: FutexKey,
        dst_key: FutexKey,
        nr_wake: usize,
        nr_requeue: usize,
    ) -> i64 {
        self.sys_futex_cmp_requeue(src_key, dst_key, nr_wake, nr_requeue, 0, None)
    }

    /// `sys_set_robust_list`: Registers the userspace robust futex list head for `tid`.
    pub fn sys_set_robust_list(&mut self, tid: u32, head: RobustListHead, len: usize) -> i64 {
        if len != core::mem::size_of::<RobustListHead>() {
            return EINVAL;
        }
        if let Some(reg) = self.robust_lists.iter_mut().find(|r| r.tid == tid) {
            reg.head = head;
            reg.len = len;
        } else {
            self.robust_lists.push(RobustRegistration { tid, head, len });
        }
        0
    }

    /// `sys_get_robust_list`: Retrieves `(RobustListHead, len)` registered for `tid`.
    pub fn sys_get_robust_list(&self, tid: u32) -> Result<(RobustListHead, usize), i64> {
        self.robust_lists
            .iter()
            .find(|r| r.tid == tid)
            .map(|r| (r.head, r.len))
            .ok_or(ESRCH)
    }

    /// Handles thread exit for a robust futex word: sets `FUTEX_OWNER_DIED` and wakes a waiter.
    pub fn handle_owner_exit(&mut self, dead_tid: u32, key: FutexKey, futex_word: &mut u32) -> bool {
        self.robust_lists.retain(|r| r.tid != dead_tid);
        if (*futex_word & FUTEX_TID_MASK) == dead_tid {
            *futex_word = (*futex_word & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
            let _ = self.sys_futex_wake(key, 1, FUTEX_BITSET_MATCH_ANY);
            true
        } else {
            false
        }
    }

    /// `sys_membarrier`: Executes process-wide or expedited SMP memory barrier commands.
    pub fn sys_membarrier(&mut self, cmd: u32) -> i64 {
        match cmd {
            0 => 0x1F, // MEMBARRIER_CMD_QUERY: return supported command bitmask
            1 | 8 | 16 => {
                // Global or Private Expedited barrier
                self.ipi_barriers_issued += 1;
                0
            }
            32 => {
                // Register Private Expedited
                self.membarrier_registrations += 1;
                0
            }
            _ => EINVAL,
        }
    }
}

/// Runs comprehensive self-tests on `futex_sync` structs and wait/requeue/robust state machines.
pub fn verify_domain_futex_sync() -> u32 {
    let mut passed = 0u32;
    let mut bucket = FutexHashBucket::new();
    let key_a = FutexKey { aspace_id: 1, word_addr: 0x6000_1000 };
    let key_b = FutexKey { aspace_id: 1, word_addr: 0x6000_2000 };

    // 1. Futex wait fails with EAGAIN if current value != expected
    if bucket.sys_futex_wait(101, key_a, 1, 0, FUTEX_BITSET_MATCH_ANY) == EAGAIN {
        passed += 1;
    }

    // 2. Enqueue 3 threads on key_a
    if bucket.sys_futex_wait(101, key_a, 1, 1, 0x01) == 0
        && bucket.sys_futex_wait(102, key_a, 1, 1, 0x02) == 0
        && bucket.sys_futex_wait(103, key_a, 1, 1, 0x02) == 0
    {
        passed += 1;
    }

    // 3. Cmp-requeue: wake 1 waiter on key_a and move 2 waiters to key_b
    if bucket.sys_futex_cmp_requeue(key_a, key_b, 1, 2, 1, Some(1)) == 3
        && bucket.waiter_count(key_a) == 0
        && bucket.waiter_count(key_b) == 2
    {
        passed += 1;
    }

    // 4. Wake remaining 2 waiters on key_b
    if bucket.sys_futex_wake(key_b, 2, FUTEX_BITSET_MATCH_ANY) == 2 && bucket.waiter_count(key_b) == 0 {
        passed += 1;
    }

    // 5. Register and query robust futex list, then simulate owner death
    let head = RobustListHead {
        list_head_ptr: 0x7FFF_1000,
        futex_offset: -8,
        list_op_pending: 0,
    };
    let sz = core::mem::size_of::<RobustListHead>();
    if bucket.sys_set_robust_list(200, head, sz) == 0 && bucket.sys_get_robust_list(200) == Ok((head, sz)) {
        let mut word = 200u32 | FUTEX_WAITERS;
        if bucket.handle_owner_exit(200, key_a, &mut word) && (word & FUTEX_OWNER_DIED) != 0 {
            passed += 1;
        }
    }

    // 6. Test membarrier query and expedited barrier
    if bucket.sys_membarrier(0) == 0x1F && bucket.sys_membarrier(8) == 0 && bucket.ipi_barriers_issued == 1 {
        passed += 1;
    }

    passed
}
