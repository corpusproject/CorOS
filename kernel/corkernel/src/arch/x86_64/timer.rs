//! x86_64 Timer implementation of the HAL `TimerOps` trait.

use crate::arch::traits::TimerOps;

pub struct X86Timer;

impl TimerOps for X86Timer {
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

#[inline]
pub fn read_ticks() -> u64 {
    let mut _aux: u32 = 0;
    unsafe { core::arch::x86_64::__rdtscp(&mut _aux) }
}

pub fn ticks_per_second() -> u64 {
    let mhz = crate::time::detect_cpu_frequency_mhz();
    if mhz > 0 {
        (mhz as u64) * 1_000_000
    } else {
        2_500_000_000 // Fallback 2.5 GHz
    }
}

pub fn sleep_ns(ns: u64) {
    let mhz = crate::time::detect_cpu_frequency_mhz();
    let cycles = if mhz > 0 {
        (ns * (mhz as u64)) / 1000
    } else {
        ns * 3
    };
    let start = read_ticks();
    while read_ticks().saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
}
