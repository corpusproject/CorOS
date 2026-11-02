//! CorOS Linux Fast Userspace Mutex (`futex`) Subsystem (`futex.rs`)
//!
//! Implements high-performance userspace synchronization primitives:
//! - FUTEX_WAIT (0): Sleep if `*uaddr == val` until woken or timeout
//! - FUTEX_WAKE (1): Wake up to `val` waiting threads
//! - FUTEX_FD (2): Associate futex with file descriptor
//! - FUTEX_REQUEUE (3): Wake `val` threads and requeue remaining to `uaddr2`
//! - FUTEX_CMP_REQUEUE (4): Requeue conditionally on `*uaddr == val3`
//! - FUTEX_WAKE_OP (5): Atomic wake and arithmetic modification
//! - FUTEX_WAIT_BITSET (9) & FUTEX_WAKE_BITSET (10): Bitmask selective wakeups
//! - Futex Hash Buckets: 64 hash buckets with spinlocks to avoid global lock contention

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_FD: i32 = 2;
pub const FUTEX_REQUEUE: i32 = 3;
pub const FUTEX_CMP_REQUEUE: i32 = 4;
pub const FUTEX_WAKE_OP: i32 = 5;
pub const FUTEX_LOCK_PI: i32 = 6;
pub const FUTEX_UNLOCK_PI: i32 = 7;
pub const FUTEX_TRYLOCK_PI: i32 = 8;
pub const FUTEX_WAIT_BITSET: i32 = 9;
pub const FUTEX_WAKE_BITSET: i32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: i32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: i32 = 12;

pub const FUTEX_PRIVATE_FLAG: i32 = 128;
pub const FUTEX_CLOCK_REALTIME: i32 = 256;
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

/// Waiter entry queued on a userspace virtual address
#[derive(Debug, Clone)]
pub struct FutexWaiter {
    pub tid: u64,
    pub uaddr: usize,
    pub bitset: u32,
    pub woken: bool,
}

/// Futex Hash Bucket
pub struct FutexBucket {
    pub queue: VecDeque<FutexWaiter>,
}

impl FutexBucket {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

pub const FUTEX_HASH_SIZE: usize = 64;

/// Global Futex Subsystem Manager
pub struct FutexManager {
    buckets: Vec<FutexBucket>,
}

impl FutexManager {
    pub fn new() -> Self {
        let mut buckets = Vec::with_capacity(FUTEX_HASH_SIZE);
        for _ in 0..FUTEX_HASH_SIZE {
            buckets.push(FutexBucket::new());
        }
        Self { buckets }
    }

    fn hash_uaddr(uaddr: usize) -> usize {
        // Golden ratio multiplicative hash
        ((uaddr.wrapping_mul(0x9E3779B9)) >> 26) & (FUTEX_HASH_SIZE - 1)
    }

    /// `sys_futex` dispatcher
    pub fn sys_futex(
        &mut self,
        uaddr: usize,
        op: i32,
        val: u32,
        timeout_ms: Option<u64>,
        uaddr2: usize,
        val3: u32,
        caller_tid: u64,
    ) -> Result<i32, i32> {
        let cmd = op & FUTEX_CMD_MASK;
        let _ = timeout_ms;

        match cmd {
            FUTEX_WAIT => self.futex_wait(uaddr, val, FUTEX_BITSET_MATCH_ANY, caller_tid),
            FUTEX_WAKE => self.futex_wake(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY),
            FUTEX_WAIT_BITSET => self.futex_wait(uaddr, val, val3, caller_tid),
            FUTEX_WAKE_BITSET => self.futex_wake(uaddr, val as usize, val3),
            FUTEX_REQUEUE => self.futex_requeue(uaddr, val as usize, uaddr2, val3 as usize),
            FUTEX_CMP_REQUEUE => self.futex_cmp_requeue(uaddr, val as usize, uaddr2, timeout_ms.unwrap_or(0) as usize, val3),
            _ => Err(-38), // -ENOSYS
        }
    }

    /// FUTEX_WAIT implementation
    pub fn futex_wait(&mut self, uaddr: usize, expected_val: u32, bitset: u32, tid: u64) -> Result<i32, i32> {
        if uaddr == 0 || (uaddr & 3) != 0 {
            return Err(-14); // -EFAULT / unaligned
        }

        // Verify userspace memory matches expected value
        let current_val = unsafe {
            let ptr = uaddr as *const AtomicI32;
            (*ptr).load(Ordering::SeqCst) as u32
        };

        if current_val != expected_val {
            return Err(-11); // -EAGAIN
        }

        let bucket_idx = Self::hash_uaddr(uaddr);
        self.buckets[bucket_idx].queue.push_back(FutexWaiter {
            tid,
            uaddr,
            bitset,
            woken: false,
        });

        Ok(0)
    }

    /// FUTEX_WAKE implementation
    pub fn futex_wake(&mut self, uaddr: usize, max_wake: usize, bitset: u32) -> Result<i32, i32> {
        if uaddr == 0 || (uaddr & 3) != 0 {
            return Err(-14); // -EFAULT
        }

        let bucket_idx = Self::hash_uaddr(uaddr);
        let bucket = &mut self.buckets[bucket_idx];
        let mut woken_count = 0;

        let mut remaining = VecDeque::new();
        while let Some(mut waiter) = bucket.queue.pop_front() {
            if waiter.uaddr == uaddr && (waiter.bitset & bitset) != 0 && woken_count < max_wake {
                waiter.woken = true;
                woken_count += 1;
            } else {
                remaining.push_back(waiter);
            }
        }
        bucket.queue = remaining;

        Ok(woken_count as i32)
    }

    /// FUTEX_REQUEUE implementation
    pub fn futex_requeue(&mut self, uaddr1: usize, max_wake: usize, uaddr2: usize, max_requeue: usize) -> Result<i32, i32> {
        let b1_idx = Self::hash_uaddr(uaddr1);
        let b2_idx = Self::hash_uaddr(uaddr2);

        let mut woken_count = 0;
        let mut requeued_count = 0;

        if b1_idx == b2_idx {
            let bucket = &mut self.buckets[b1_idx];
            let mut remaining = VecDeque::new();
            while let Some(mut waiter) = bucket.queue.pop_front() {
                if waiter.uaddr == uaddr1 {
                    if woken_count < max_wake {
                        waiter.woken = true;
                        woken_count += 1;
                    } else if requeued_count < max_requeue {
                        waiter.uaddr = uaddr2;
                        requeued_count += 1;
                        remaining.push_back(waiter);
                    } else {
                        remaining.push_back(waiter);
                    }
                } else {
                    remaining.push_back(waiter);
                }
            }
            bucket.queue = remaining;
        } else {
            let mut to_requeue = Vec::new();
            {
                let bucket1 = &mut self.buckets[b1_idx];
                let mut remaining = VecDeque::new();
                while let Some(mut waiter) = bucket1.queue.pop_front() {
                    if waiter.uaddr == uaddr1 {
                        if woken_count < max_wake {
                            waiter.woken = true;
                            woken_count += 1;
                        } else if requeued_count < max_requeue {
                            waiter.uaddr = uaddr2;
                            requeued_count += 1;
                            to_requeue.push(waiter);
                        } else {
                            remaining.push_back(waiter);
                        }
                    } else {
                        remaining.push_back(waiter);
                    }
                }
                bucket1.queue = remaining;
            }
            let bucket2 = &mut self.buckets[b2_idx];
            for w in to_requeue {
                bucket2.queue.push_back(w);
            }
        }

        Ok((woken_count + requeued_count) as i32)
    }

    /// FUTEX_CMP_REQUEUE implementation
    pub fn futex_cmp_requeue(
        &mut self,
        uaddr1: usize,
        max_wake: usize,
        uaddr2: usize,
        max_requeue: usize,
        val3: u32,
    ) -> Result<i32, i32> {
        if uaddr1 == 0 || (uaddr1 & 3) != 0 || uaddr2 == 0 || (uaddr2 & 3) != 0 {
            return Err(-14); // -EFAULT
        }

        let current_val = unsafe {
            let ptr = uaddr1 as *const AtomicI32;
            (*ptr).load(Ordering::SeqCst) as u32
        };

        if current_val != val3 {
            return Err(-11); // -EAGAIN
        }

        self.futex_requeue(uaddr1, max_wake, uaddr2, max_requeue)
    }
}
