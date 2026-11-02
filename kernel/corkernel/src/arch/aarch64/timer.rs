//! AArch64 ARM Generic Timer Subsystem.

use crate::arch::traits::TimerOps;

pub struct AArch64Timer;

impl TimerOps for AArch64Timer {
    #[inline]
    fn read_ticks() -> u64 {
        read_ticks()
    }

    #[inline]
    fn ticks_per_second() -> u64 {
        ticks_per_second()
    }

    #[inline]
    fn sleep_ns(ns: u64) {
        sleep_ns(ns);
    }
}

pub fn read_ticks() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let ticks: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) ticks, options(nomem, nostack));
        }
        ticks
    }
    #[cfg(not(target_arch = "aarch64"))]
    0
}

pub fn ticks_per_second() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let freq: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        }
        if freq > 0 { freq } else { 24_000_000 }
    }
    #[cfg(not(target_arch = "aarch64"))]
    24_000_000 // Standard 24 MHz ARM Generic Timer frequency
}

pub fn sleep_ns(ns: u64) {
    let freq = ticks_per_second();
    let cycles = (ns * freq) / 1_000_000_000;
    let start = read_ticks();
    while read_ticks().saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Sets the ARM generic virtual timer down-counter.
pub unsafe fn set_virtual_timer(ticks: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        // Write down-counter
        core::arch::asm!("msr cntv_tval_el0, {ticks}", ticks = in(reg) ticks, options(nomem, nostack));
        // Enable timer (bit 0 = 1, bit 1 unmasked = 0)
        core::arch::asm!("msr cntv_ctl_el0, {ctl}", ctl = in(reg) 1u64, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = ticks;
}
