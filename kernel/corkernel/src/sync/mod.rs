use core::{cell::UnsafeCell, hint::spin_loop, ops::{Deref, DerefMut}, sync::atomic::Ordering};
pub use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize};
pub use SpinLock as Spinlock;

pub mod rcu;
pub mod seqlock;

pub use rcu::{RcuSubsystem, RcuCpuState, RcuCallback};
pub use seqlock::SeqLock;

pub struct SpinLock<T> { held: AtomicBool, value: UnsafeCell<T> }
unsafe impl<T: Send> Sync for SpinLock<T> {}
impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self { Self { held: AtomicBool::new(false), value: UnsafeCell::new(value) } }
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.held.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { spin_loop(); }
        SpinLockGuard { lock: self }
    }
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }
    /// Disables interrupts on the local CPU before locking, preventing a local
    /// interrupt handler from deadlocking on a lock held by the interrupted code.
    pub fn lock_irqsave(&self) -> IrqSpinLockGuard<'_, T> {
        let enabled = crate::arch::x86_64::cpu::interrupts_enabled();
        crate::arch::x86_64::cpu::disable_interrupts();
        let guard = self.lock();
        IrqSpinLockGuard { guard: Some(guard), restore_interrupts: enabled }
    }
}
pub struct SpinLockGuard<'a, T> { lock: &'a SpinLock<T> }
impl<T> Deref for SpinLockGuard<'_, T> { type Target = T; fn deref(&self) -> &T { unsafe { &*self.lock.value.get() } } }
impl<T> DerefMut for SpinLockGuard<'_, T> { fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.value.get() } } }
impl<T> Drop for SpinLockGuard<'_, T> { fn drop(&mut self) { self.lock.held.store(false, Ordering::Release); } }
pub struct IrqSpinLockGuard<'a, T> { guard: Option<SpinLockGuard<'a, T>>, restore_interrupts: bool }
impl<T> Deref for IrqSpinLockGuard<'_, T> { type Target = T; fn deref(&self) -> &T { self.guard.as_ref().unwrap() } }
impl<T> DerefMut for IrqSpinLockGuard<'_, T> { fn deref_mut(&mut self) -> &mut T { self.guard.as_mut().unwrap() } }
impl<T> Drop for IrqSpinLockGuard<'_, T> { fn drop(&mut self) { drop(self.guard.take()); if self.restore_interrupts { unsafe { crate::arch::x86_64::cpu::enable_interrupts(); } } } }

#[cfg(test)]
mod tests {
    use super::SpinLock;
    #[test]
    fn guard_releases_lock_and_preserves_mutations() {
        let lock = SpinLock::new(4u32);
        { let mut value = lock.lock(); *value += 3; }
        assert_eq!(*lock.lock(), 7);
    }
}
