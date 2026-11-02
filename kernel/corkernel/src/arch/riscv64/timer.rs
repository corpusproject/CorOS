//! RISC-V Timer Subsystem and SBI Set Timer Extension.

use crate::arch::traits::TimerOps;

pub const SBI_EID_TIMER: usize = 0x54494D45; // "TIME"

pub struct Riscv64Timer;

impl TimerOps for Riscv64Timer {
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
    #[cfg(target_arch = "riscv64")]
    {
        let ticks: u64;
        unsafe {
            core::arch::asm!("rdtime {}", out(reg) ticks, options(nomem, nostack));
        }
        ticks
    }
    #[cfg(not(target_arch = "riscv64"))]
    0
}

pub fn ticks_per_second() -> u64 {
    10_000_000 // Standard 10 MHz timer frequency on RISC-V QEMU virt & SiFive
}

pub fn sleep_ns(ns: u64) {
    let freq = ticks_per_second();
    let cycles = (ns * freq) / 1_000_000_000;
    let start = read_ticks();
    while read_ticks().saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Programs the next supervisor timer interrupt via SBI.
pub unsafe fn sbi_set_timer(stime_value: u64) {
    #[cfg(target_arch = "riscv64")]
    {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EID_TIMER,
            in("a6") 0usize, // FID 0
            in("a0") stime_value as usize,
            options(nomem)
        );
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = stime_value;
}
