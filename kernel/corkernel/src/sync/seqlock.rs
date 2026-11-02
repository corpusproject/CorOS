//! Seqlock (Sequential Lock) Synchronization Primitive
//!
//! Implements sequence lock synchronization for readers prioritizing consistency without blocking writers:
//! - Readers check sequence count before and after copying data
//! - If sequence count was odd (writer in progress) or changed (writer intervened), reader retries
//! - Writers acquire spinlock and increment sequence counter (odd = writing, even = stable)
//! - Zero bus lock contention between concurrent readers

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct SeqLock<T> {
    sequence: AtomicUsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SeqLock<T> {}
unsafe impl<T: Send> Sync for SeqLock<T> {}

impl<T: Copy> SeqLock<T> {
    pub const fn new(val: T) -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            data: UnsafeCell::new(val),
        }
    }

    /// Read data consistently using sequence verification loop
    pub fn read(&self) -> T {
        loop {
            let seq1 = self.sequence.load(Ordering::Acquire);
            if seq1 & 1 != 0 {
                // Writer active, spin
                core::hint::spin_loop();
                continue;
            }

            let val = unsafe { *self.data.get() };

            let seq2 = self.sequence.load(Ordering::Acquire);
            if seq1 == seq2 {
                return val;
            }
            core::hint::spin_loop();
        }
    }

    /// Write data with atomic sequence transitions
    pub fn write<F>(&self, update: F)
    where
        F: FnOnce(&mut T),
    {
        // Acquire writer exclusivity (increment from even to odd)
        let seq = self.sequence.fetch_add(1, Ordering::Acquire);
        assert!(seq & 1 == 0, "Concurrent writers on SeqLock without external serialization");

        unsafe {
            update(&mut *self.data.get());
        }

        // Release writer exclusivity (increment from odd to even)
        self.sequence.fetch_add(1, Ordering::Release);
    }
}
