//! Reader-Writer Semaphores (`RwSemaphore`) & Sequential Locks (`SeqLock`).
//!
//! Implements concurrency synchronization primitives with:
//! - Reader-writer semaphore featuring writer-preference to eliminate reader barge starvation
//! - Atomic-grade write downgrade without yielding lock exclusion to competing writers
//! - Sequential lock (`SeqLock`) for optimistic, lock-free reader synchronization
//! - Consistent sequence validation and retry loop mechanisms

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

/// Reader-Writer Semaphore with reader starvation avoidance.
#[derive(Debug)]
pub struct RwSemaphore {
    /// Number of concurrent active readers.
    pub readers_active: u32,
    /// Whether an exclusive writer is currently executing.
    pub writer_active: bool,
    /// Number of queued writers waiting to acquire exclusive lock.
    pub writers_waiting: u32,
    /// Number of queued readers waiting for active writer to finish.
    pub readers_waiting: u32,
    /// Count of successful read acquisitions.
    pub total_read_locks: u64,
    /// Count of successful write acquisitions.
    pub total_write_locks: u64,
}

impl RwSemaphore {
    pub const fn new() -> Self {
        Self {
            readers_active: 0,
            writer_active: false,
            writers_waiting: 0,
            readers_waiting: 0,
            total_read_locks: 0,
            total_write_locks: 0,
        }
    }

    /// Attempt to acquire read lock without blocking.
    /// Fails if a writer is active or if writers are waiting (anti-starvation policy).
    pub fn try_down_read(&mut self) -> bool {
        if !self.writer_active && self.writers_waiting == 0 {
            self.readers_active += 1;
            self.total_read_locks += 1;
            true
        } else {
            false
        }
    }

    /// Acquire read lock. If writer is active or waiting, records waiting reader.
    pub fn down_read(&mut self) -> bool {
        if self.try_down_read() {
            true
        } else {
            self.readers_waiting += 1;
            false
        }
    }

    /// Release read lock.
    pub fn up_read(&mut self) {
        if self.readers_active > 0 {
            self.readers_active -= 1;
        }
    }

    /// Attempt to acquire write lock without blocking.
    /// Fails if another writer is active or if any readers are currently active.
    pub fn try_down_write(&mut self) -> bool {
        if !self.writer_active && self.readers_active == 0 {
            self.writer_active = true;
            self.total_write_locks += 1;
            true
        } else {
            false
        }
    }

    /// Acquire write lock. If blocked, increments writers_waiting to prevent new readers from barging.
    pub fn down_write(&mut self) -> bool {
        if self.try_down_write() {
            true
        } else {
            self.writers_waiting += 1;
            false
        }
    }

    /// Release write lock.
    pub fn up_write(&mut self) {
        if self.writer_active {
            self.writer_active = false;
        }
    }

    /// Successfully complete waiting write lock when readers have drained to zero.
    pub fn complete_waiting_write(&mut self) -> bool {
        if self.writers_waiting > 0 && !self.writer_active && self.readers_active == 0 {
            self.writers_waiting -= 1;
            self.writer_active = true;
            self.total_write_locks += 1;
            true
        } else {
            false
        }
    }

    /// Atomically downgrade write lock to read lock without releasing mutual exclusion to external writers.
    pub fn downgrade_write(&mut self) {
        if self.writer_active {
            self.writer_active = false;
            self.readers_active += 1;
            self.total_read_locks += 1;

            // Wake up waiting readers
            let waiting = self.readers_waiting;
            self.readers_waiting = 0;
            self.readers_active += waiting;
            self.total_read_locks += waiting as u64;
        }
    }
}

/// Sequential Lock (`SeqLock`) for lockless, optimistic read synchronization.
pub struct SeqLock {
    sequence: AtomicU32,
}

impl SeqLock {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
        }
    }

    /// Begin optimistic read transaction.
    /// Spins while an odd sequence indicates an active writer.
    pub fn read_begin(&self) -> u32 {
        loop {
            let seq = self.sequence.load(Ordering::Acquire);
            if seq & 1 == 0 {
                return seq;
            }
            core::hint::spin_loop();
        }
    }

    /// Validate whether the data read during this transaction remains consistent.
    /// Returns true if a write occurred concurrently (caller must retry).
    pub fn read_retry(&self, start_seq: u32) -> bool {
        let current_seq = self.sequence.load(Ordering::Acquire);
        current_seq != start_seq || (current_seq & 1 != 0)
    }

    /// Begin write transaction.
    /// Increments sequence counter from even to odd.
    pub fn write_begin(&self) -> u32 {
        let prev = self.sequence.fetch_add(1, Ordering::AcqRel);
        prev + 1
    }

    /// End write transaction.
    /// Increments sequence counter from odd back to even.
    pub fn write_end(&self) {
        self.sequence.fetch_add(1, Ordering::Release);
    }

    /// Get current raw sequence value.
    pub fn raw_sequence(&self) -> u32 {
        self.sequence.load(Ordering::Relaxed)
    }
}
