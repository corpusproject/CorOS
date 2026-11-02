//! AArch64 CPU lifecycle, system registers, and execution control.

use crate::arch::traits::CpuOps;
use core::sync::atomic::{AtomicU32, Ordering};

pub const SCTLR_M: u64 = 1 << 0;       // MMU enable
pub const SCTLR_A: u64 = 1 << 1;       // Alignment fault check
pub const SCTLR_C: u64 = 1 << 2;       // Data and unified cache enable
pub const SCTLR_SA: u64 = 1 << 3;      // SP Alignment check
pub const SCTLR_I: u64 = 1 << 12;      // Instruction cache enable

pub const CPACR_FPEN_FULL: u64 = 3 << 20; // Enable EL0 and EL1 access to FP and SIMD

pub const DAIF_D: u64 = 1 << 9; // Watchpoint/Breakpoint debug exception mask
pub const DAIF_A: u64 = 1 << 8; // SError interrupt mask
pub const DAIF_I: u64 = 1 << 7; // IRQ interrupt mask
pub const DAIF_F: u64 = 1 << 6; // FIQ interrupt mask

static CURRENT_CPU_ID: AtomicU32 = AtomicU32::new(0);

pub struct AArch64Cpu;

impl CpuOps for AArch64Cpu {
    #[inline]
    fn halt() -> ! {
        halt()
    }

    #[inline]
    fn enable_interrupts() {
        enable_interrupts();
    }

    #[inline]
    fn disable_interrupts() {
        disable_interrupts();
    }

    #[inline]
    fn interrupts_enabled() -> bool {
        interrupts_enabled()
    }

    #[inline]
    fn relax() {
        relax();
    }

    #[inline]
    fn current_cpu_id() -> u32 {
        current_cpu_id()
    }
}

/// Initializes AArch64 CPU EL1 architectural state (FP/SIMD and caching controls).
pub fn initialize() {
    disable_interrupts();
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // Enable FP/SIMD access in EL1 and EL0
        core::arch::asm!(
            "mrs {tmp}, cpacr_el1",
            "orr {tmp}, {tmp}, {fpen}",
            "msr cpacr_el1, {tmp}",
            "isb",
            fpen = in(reg) CPACR_FPEN_FULL,
            tmp = out(reg) _,
            options(nomem, nostack)
        );
    }
}

#[inline]
pub fn halt() -> ! {
    loop {
        disable_interrupts();
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}

#[inline]
pub fn enable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
}

#[inline]
pub fn disable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
}

#[inline]
pub fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack));
        }
        (daif & DAIF_I) == 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    false
}

#[inline]
pub fn relax() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::hint::spin_loop();
}

pub fn current_cpu_id() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
        }
        // Aff0 (bits 0..7) + Aff1 (bits 8..15)
        let aff0 = (mpidr & 0xFF) as u32;
        let aff1 = ((mpidr >> 8) & 0xFF) as u32;
        (aff1 << 8) | aff0
    }
    #[cfg(not(target_arch = "aarch64"))]
    CURRENT_CPU_ID.load(Ordering::Acquire)
}

pub fn set_cpu_id(id: u32) {
    CURRENT_CPU_ID.store(id, Ordering::Release);
}
