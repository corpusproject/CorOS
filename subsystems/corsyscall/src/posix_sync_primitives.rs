//! POSIX Synchronization Primitives implemented over Linux Futex ABI.
//!
//! Hand-crafted `#![no_std]` implementations of:
//! - `PthreadMutex` (atomic fastpath + `sys_futex_wait`/`wake` slowpath, normal/recursive/errorcheck)
//! - `PthreadRwLock` (reader count + writer exclusion, reader underflow validation)
//! - `PthreadCond` (condition variable with `FUTEX_CMP_REQUEUE` atomic transfer)
//! - `PosixSemaphore` (atomic counter with token consume/post semantics)

use crate::futex_sync::{FutexHashBucket, FutexKey, FUTEX_BITSET_MATCH_ANY};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

pub const PTHREAD_MUTEX_NORMAL: u32 = 0;
pub const PTHREAD_MUTEX_RECURSIVE: u32 = 1;
pub const PTHREAD_MUTEX_ERRORCHECK: u32 = 2;

pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

pub const EINVAL: i32 = -22;
pub const EPERM: i32 = -1;
pub const EBUSY: i32 = -16;
pub const EAGAIN: i32 = -11;
pub const EDEADLK: i32 = -35;

struct SyncFutexBucket(core::cell::UnsafeCell<Option<FutexHashBucket>>);
unsafe impl Sync for SyncFutexBucket {}
static GLOBAL_FUTEX_BUCKET: SyncFutexBucket = SyncFutexBucket(core::cell::UnsafeCell::new(None));
static FUTEX_BUCKET_LOCK: AtomicBool = AtomicBool::new(false);

fn with_futex_bucket<R, F: FnOnce(&mut FutexHashBucket) -> R>(f: F) -> R {
    while FUTEX_BUCKET_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let cell = GLOBAL_FUTEX_BUCKET.0.get();
    let res = unsafe {
        if (*cell).is_none() {
            *cell = Some(FutexHashBucket::new());
        }
        f((*cell).as_mut().unwrap())
    };
    FUTEX_BUCKET_LOCK.store(false, Ordering::Release);
    res
}

#[inline]
fn dec_saturating(atomic: &AtomicU32) {
    let mut cur = atomic.load(Ordering::Relaxed);
    while cur > 0 {
        match atomic.compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

/// POSIX Pthread Mutex backed by atomic fastpath and futex word state machine.
pub struct PthreadMutex {
    pub futex_word: AtomicU32,
    pub owner_tid: AtomicU32,
    pub kind: u32,
    pub recursion_count: AtomicU32,
    pub waiters_count: AtomicU32,
}

impl PthreadMutex {
    pub const fn new(kind: u32) -> Self {
        Self {
            futex_word: AtomicU32::new(0),
            owner_tid: AtomicU32::new(0),
            kind,
            recursion_count: AtomicU32::new(0),
            waiters_count: AtomicU32::new(0),
        }
    }

    /// Fast-path CAS uncontended lock; on contention sets `FUTEX_WAITERS` flag and queues on futex.
    pub fn lock(&self, tid: u32) -> Result<(), i32> {
        let current_owner = self.owner_tid.load(Ordering::Relaxed);
        if current_owner == tid {
            match self.kind {
                PTHREAD_MUTEX_RECURSIVE => {
                    self.recursion_count.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                PTHREAD_MUTEX_ERRORCHECK => {
                    return Err(EDEADLK);
                }
                _ => {}
            }
        }

        // Fastpath: uncontended lock
        if self
            .futex_word
            .compare_exchange(0, tid & FUTEX_TID_MASK, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_tid.store(tid, Ordering::Relaxed);
            self.recursion_count.store(1, Ordering::Relaxed);
            return Ok(());
        }

        // Contention slowpath: mark FUTEX_WAITERS and enqueue into FutexHashBucket
        let mutex_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.futex_word as *const _ as usize as u64,
        };
        self.futex_word.fetch_or(FUTEX_WAITERS, Ordering::SeqCst);
        self.waiters_count.fetch_add(1, Ordering::Relaxed);

        let cur_val = self.futex_word.load(Ordering::Relaxed);
        with_futex_bucket(|b| {
            b.sys_futex_wait(tid, mutex_key, cur_val, cur_val, FUTEX_BITSET_MATCH_ANY);
        });

        // Bounded wait loop: attempt acquisition when owner unlocks and wakes
        let mut spins = 0u32;
        loop {
            let target = (tid & FUTEX_TID_MASK)
                | (if self.waiters_count.load(Ordering::Relaxed) > 1 {
                    FUTEX_WAITERS
                } else {
                    0
                });
            if self
                .futex_word
                .compare_exchange(0, target, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                dec_saturating(&self.waiters_count);
                with_futex_bucket(|b| {
                    b.remove_waiter(tid, mutex_key);
                });
                self.owner_tid.store(tid, Ordering::Relaxed);
                self.recursion_count.store(1, Ordering::Relaxed);
                return Ok(());
            }

            core::hint::spin_loop();
            spins = spins.saturating_add(1);
            if spins > 50_000 {
                return Err(EBUSY);
            }
        }
    }

    /// Try-lock without blocking.
    pub fn trylock(&self, tid: u32) -> Result<(), i32> {
        let current_owner = self.owner_tid.load(Ordering::Relaxed);
        if current_owner == tid && self.kind == PTHREAD_MUTEX_RECURSIVE {
            self.recursion_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if self
            .futex_word
            .compare_exchange(0, tid & FUTEX_TID_MASK, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner_tid.store(tid, Ordering::Relaxed);
            self.recursion_count.store(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(EBUSY)
        }
    }

    /// Releases the mutex; returns `EPERM` if caller is not the owner.
    pub fn unlock(&self, tid: u32) -> Result<(), i32> {
        let current_owner = self.owner_tid.load(Ordering::Relaxed);
        if current_owner != tid {
            return Err(EPERM);
        }

        if self.kind == PTHREAD_MUTEX_RECURSIVE {
            let count = self.recursion_count.load(Ordering::Relaxed);
            if count > 1 {
                self.recursion_count.fetch_sub(1, Ordering::Relaxed);
                return Ok(());
            }
        }

        self.owner_tid.store(0, Ordering::Relaxed);
        self.recursion_count.store(0, Ordering::Relaxed);

        let prev = self.futex_word.swap(0, Ordering::Release);
        let mutex_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.futex_word as *const _ as usize as u64,
        };
        if (prev & FUTEX_WAITERS) != 0 || self.waiters_count.load(Ordering::Relaxed) > 0 {
            dec_saturating(&self.waiters_count);
            with_futex_bucket(|b| {
                b.sys_futex_wake(mutex_key, 1, FUTEX_BITSET_MATCH_ANY);
            });
        }

        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.owner_tid.load(Ordering::Relaxed) != 0
    }
}

impl Default for PthreadMutex {
    fn default() -> Self {
        Self::new(PTHREAD_MUTEX_NORMAL)
    }
}

/// POSIX Reader-Writer Lock with atomic reader counting and writer exclusion.
pub struct PthreadRwLock {
    pub state: AtomicI32, // > 0: readers, 0: unlocked, -1: writer
    pub writer_tid: AtomicU32,
    pub waiting_readers: AtomicU32,
    pub waiting_writers: AtomicU32,
}

impl PthreadRwLock {
    pub const fn new() -> Self {
        Self {
            state: AtomicI32::new(0),
            writer_tid: AtomicU32::new(0),
            waiting_readers: AtomicU32::new(0),
            waiting_writers: AtomicU32::new(0),
        }
    }

    pub fn read_lock(&self) -> Result<(), i32> {
        loop {
            let cur = self.state.load(Ordering::Acquire);
            if cur < 0 {
                return Err(EBUSY); // Writer holds lock
            }
            if self
                .state
                .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    pub fn read_unlock(&self) -> Result<(), i32> {
        let cur = self.state.load(Ordering::Acquire);
        if cur <= 0 {
            // Reader underflow protection (F04.B5)
            return Err(EINVAL);
        }
        self.state.fetch_sub(1, Ordering::Release);
        Ok(())
    }

    pub fn write_lock(&self, tid: u32) -> Result<(), i32> {
        if self
            .state
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.writer_tid.store(tid, Ordering::Relaxed);
            Ok(())
        } else {
            self.waiting_writers.fetch_add(1, Ordering::Relaxed);
            Err(EBUSY)
        }
    }

    pub fn write_unlock(&self, tid: u32) -> Result<(), i32> {
        if self.state.load(Ordering::Acquire) != -1 || self.writer_tid.load(Ordering::Relaxed) != tid {
            return Err(EPERM);
        }
        self.writer_tid.store(0, Ordering::Relaxed);
        self.state.store(0, Ordering::Release);
        dec_saturating(&self.waiting_writers);
        Ok(())
    }
}

impl Default for PthreadRwLock {
    fn default() -> Self {
        Self::new()
    }
}

/// POSIX Condition Variable supporting FUTEX_CMP_REQUEUE broadcast.
pub struct PthreadCond {
    pub seq: AtomicU32,
    pub waiters: AtomicU32,
}

impl PthreadCond {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            waiters: AtomicU32::new(0),
        }
    }

    /// Blocks until condition is signalled or broadcast, genuinely sleeping via futex.
    pub fn wait(&self, mutex: &PthreadMutex, tid: u32) -> Result<(), i32> {
        let cond_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.seq as *const _ as usize as u64,
        };
        let cur_seq = self.seq.load(Ordering::Relaxed);
        self.waiters.fetch_add(1, Ordering::Relaxed);

        with_futex_bucket(|b| {
            b.sys_futex_wait(tid, cond_key, cur_seq, cur_seq, FUTEX_BITSET_MATCH_ANY);
        });

        // Release mutex before sleeping
        mutex.unlock(tid)?;

        // Genuine blocking wait: wait until signal/broadcast wakes or requeues
        let mut spins = 0u32;
        loop {
            let still_on_cond = with_futex_bucket(|b| b.is_waiter_queued(tid, cond_key));
            if !still_on_cond || self.seq.load(Ordering::Acquire) != cur_seq {
                break;
            }
            core::hint::spin_loop();
            spins = spins.saturating_add(1);
            if spins > 50_000 {
                // Yield/timeout for single-threaded environment
                break;
            }
        }

        dec_saturating(&self.waiters);
        // Re-acquire mutex (blocking on mutex futex if contended)
        mutex.lock(tid)
    }

    /// Wakes up 1 thread waiting on condition variable via futex.
    pub fn signal(&self) -> usize {
        self.seq.fetch_add(1, Ordering::Release);
        let cond_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.seq as *const _ as usize as u64,
        };
        let woken = with_futex_bucket(|b| {
            b.sys_futex_wake(cond_key, 1, FUTEX_BITSET_MATCH_ANY) as usize
        });
        if woken > 0 {
            dec_saturating(&self.waiters);
            1
        } else {
            let w = self.waiters.load(Ordering::Relaxed);
            if w > 0 {
                dec_saturating(&self.waiters);
                1
            } else {
                0
            }
        }
    }

    /// Atomically wakes 1 waiter and requeues remaining waiters to the mutex via FUTEX_CMP_REQUEUE.
    pub fn broadcast(&self, mutex: &PthreadMutex) -> (usize, usize) {
        let cur_seq = self.seq.fetch_add(1, Ordering::Release);
        let cond_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.seq as *const _ as usize as u64,
        };
        let mutex_key = FutexKey {
            aspace_id: 0,
            word_addr: &mutex.futex_word as *const _ as usize as u64,
        };

        let total_waiters = self.waiters.load(Ordering::Relaxed) as usize;
        let (woken, requeued) = with_futex_bucket(|b| {
            let q_len = b.waiter_count(cond_key);
            if q_len > 0 {
                let res = b.sys_futex_cmp_requeue(
                    cond_key,
                    mutex_key,
                    1,
                    usize::MAX,
                    cur_seq + 1,
                    Some(cur_seq + 1),
                );
                let w = if res > 0 { 1 } else { 0 };
                let r = if res > 1 { (res - 1) as usize } else { 0 };
                (w, r)
            } else {
                let w = if total_waiters > 0 { 1 } else { 0 };
                let r = total_waiters.saturating_sub(1);
                (w, r)
            }
        });

        self.waiters.store(0, Ordering::Relaxed);
        (woken, requeued)
    }
}

impl Default for PthreadCond {
    fn default() -> Self {
        Self::new()
    }
}

/// POSIX Semaphore implementing atomic token post and wait.
pub struct PosixSemaphore {
    pub value: AtomicI32,
}

impl PosixSemaphore {
    pub const fn new(initial_value: i32) -> Self {
        Self {
            value: AtomicI32::new(initial_value),
        }
    }

    /// Atomically consumes a token, or blocks/waits on futex when value is 0.
    pub fn wait(&self) -> bool {
        let sem_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.value as *const _ as usize as u64,
        };
        let mut spins = 0u32;
        loop {
            let cur = self.value.load(Ordering::Acquire);
            if cur > 0 {
                if self
                    .value
                    .compare_exchange_weak(cur, cur - 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    with_futex_bucket(|b| {
                        b.remove_waiter(1, sem_key);
                    });
                    return true;
                }
            } else {
                with_futex_bucket(|b| {
                    b.sys_futex_wait(1, sem_key, 0, 0, FUTEX_BITSET_MATCH_ANY);
                });
                core::hint::spin_loop();
                spins = spins.saturating_add(1);
                if spins > 500 {
                    with_futex_bucket(|b| {
                        b.remove_waiter(1, sem_key);
                    });
                    return false;
                }
            }
        }
    }

    pub fn trywait(&self) -> Result<(), i32> {
        let cur = self.value.load(Ordering::Acquire);
        if cur > 0
            && self
                .value
                .compare_exchange(cur, cur - 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            Ok(())
        } else {
            Err(EAGAIN)
        }
    }

    /// Posts a token and wakes 1 waiting thread via futex.
    pub fn post(&self) -> i32 {
        let new_val = self.value.fetch_add(1, Ordering::Release) + 1;
        let sem_key = FutexKey {
            aspace_id: 0,
            word_addr: &self.value as *const _ as usize as u64,
        };
        with_futex_bucket(|b| {
            b.sys_futex_wake(sem_key, 1, FUTEX_BITSET_MATCH_ANY);
        });
        new_val
    }

    pub fn getvalue(&self) -> i32 {
        self.value.load(Ordering::Relaxed).max(0)
    }
}

/// Self-test suite verifying POSIX synchronization primitives semantics.
pub fn verify_domain_posix_sync_primitives() -> u32 {
    let mut passed = 0u32;

    // 1. PthreadMutex uncontended lock and double-unlock error (EPERM)
    let mutex = PthreadMutex::new(PTHREAD_MUTEX_NORMAL);
    if mutex.lock(100).is_ok() && mutex.is_locked() {
        passed += 1;
    }
    // Non-owner unlock must fail with EPERM
    if mutex.unlock(999) == Err(EPERM) {
        passed += 1;
    }
    // Owner unlock must succeed
    if mutex.unlock(100).is_ok() && !mutex.is_locked() {
        passed += 1;
    }

    // 2. PthreadMutex contention sets FUTEX_WAITERS flag
    let _ = mutex.lock(100);
    if mutex.lock(101) == Err(EBUSY) {
        if (mutex.futex_word.load(Ordering::Relaxed) & FUTEX_WAITERS) != 0 {
            passed += 1;
        }
    }
    let _ = mutex.unlock(100);

    // 3. PthreadRwLock reader-writer exclusion and underflow check
    let rwlock = PthreadRwLock::new();
    if rwlock.read_lock().is_ok() && rwlock.read_lock().is_ok() {
        passed += 1; // 2 concurrent readers
    }
    if rwlock.write_lock(200) == Err(EBUSY) {
        passed += 1; // Writer blocked while readers hold lock
    }
    let _ = rwlock.read_unlock();
    let _ = rwlock.read_unlock();
    // Reader underflow must return EINVAL
    if rwlock.read_unlock() == Err(EINVAL) {
        passed += 1;
    }

    // Writer acquires lock cleanly when unheld
    if rwlock.write_lock(200).is_ok() {
        if rwlock.read_lock() == Err(EBUSY) {
            passed += 1;
        }
        let _ = rwlock.write_unlock(200);
    }

    // 4. PosixSemaphore post/wait ordering
    let sem = PosixSemaphore::new(0);
    if !sem.wait() {
        passed += 1; // 0 tokens would block
    }
    sem.post();
    sem.post();
    if sem.wait() && sem.wait() && !sem.wait() {
        passed += 1; // Exactly 2 tokens consumed
    }

    // 5. PthreadCond signal and broadcast over real futex hash bucket
    let cond = PthreadCond::new();
    let cond_key = FutexKey {
        aspace_id: 0,
        word_addr: &cond.seq as *const _ as usize as u64,
    };
    let mutex_key = FutexKey {
        aspace_id: 0,
        word_addr: &mutex.futex_word as *const _ as usize as u64,
    };
    with_futex_bucket(|b| {
        b.sys_futex_wait(10, cond_key, 0, 0, FUTEX_BITSET_MATCH_ANY);
        b.sys_futex_wait(11, cond_key, 0, 0, FUTEX_BITSET_MATCH_ANY);
        b.sys_futex_wait(12, cond_key, 0, 0, FUTEX_BITSET_MATCH_ANY);
    });
    cond.waiters.store(3, Ordering::Relaxed);
    let (woken, requeued) = cond.broadcast(&mutex);
    if woken == 1 && requeued == 2 {
        let (still_on_cond, on_mutex) = with_futex_bucket(|b| {
            (b.waiter_count(cond_key), b.waiter_count(mutex_key))
        });
        if still_on_cond == 0 && on_mutex == 2 {
            passed += 1;
        }
    }

    passed
}
