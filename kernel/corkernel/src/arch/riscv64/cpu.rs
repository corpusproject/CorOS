//! RISC-V (RV64GC) CPU lifecycle, CSR registers, and execution control.

use crate::arch::traits::CpuOps;
use core::sync::atomic::{AtomicU32, Ordering};

// sstatus CSR bitfields
pub const SSTATUS_UIE: u64 = 1 << 0;  // User interrupt enable
pub const SSTATUS_SIE: u64 = 1 << 1;  // Supervisor interrupt enable
pub const SSTATUS_UPIE: u64 = 1 << 4; // User previous interrupt enable
pub const SSTATUS_SPIE: u64 = 1 << 5; // Supervisor previous interrupt enable
pub const SSTATUS_SPP: u64 = 1 << 8;  // Previous privilege mode (0=U, 1=S)
pub const SSTATUS_FS_INITIAL: u64 = 1 << 13; // FPU initial state
pub const SSTATUS_FS_CLEAN: u64 = 2 << 13;
pub const SSTATUS_FS_DIRTY: u64 = 3 << 13;
pub const SSTATUS_FS_MASK: u64 = 3 << 13;
pub const SSTATUS_XS_MASK: u64 = 3 << 15;
pub const SSTATUS_SUM: u64 = 1 << 18; // Permit Supervisor to access User Memory
pub const SSTATUS_MXR: u64 = 1 << 19; // Make eXecutable Readable

static CURRENT_HART_ID: AtomicU32 = AtomicU32::new(0);

pub struct Riscv64Cpu;

impl CpuOps for Riscv64Cpu {
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

/// Initializes RISC-V supervisor CPU state (FPU clean and user memory access).
pub fn initialize() {
    disable_interrupts();
    #[cfg(target_arch = "riscv64")]
    unsafe {
        // Enable FPU and user memory access
        core::arch::asm!(
            "csrs sstatus, {flags}",
            flags = in(reg) (SSTATUS_FS_INITIAL | SSTATUS_SUM),
            options(nomem, nostack)
        );
    }
}

#[inline]
pub fn halt() -> ! {
    loop {
        disable_interrupts();
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
        #[cfg(not(target_arch = "riscv64"))]
        core::hint::spin_loop();
    }
}

#[inline]
pub fn enable_interrupts() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("csrs sstatus, {sie}", sie = in(reg) SSTATUS_SIE, options(nomem, nostack));
    }
}

#[inline]
pub fn disable_interrupts() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("csrc sstatus, {sie}", sie = in(reg) SSTATUS_SIE, options(nomem, nostack));
    }
}

#[inline]
pub fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        let status: u64;
        unsafe {
            core::arch::asm!("csrr {}, sstatus", out(reg) status, options(nomem, nostack));
        }
        (status & SSTATUS_SIE) != 0
    }
    #[cfg(not(target_arch = "riscv64"))]
    false
}

#[inline]
pub fn relax() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i", options(nomem, nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::hint::spin_loop();
}

pub fn current_cpu_id() -> u32 {
    #[cfg(target_arch = "riscv64")]
    {
        let hartid: u64;
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) hartid, options(nomem, nostack));
        }
        hartid as u32
    }
    #[cfg(not(target_arch = "riscv64"))]
    CURRENT_HART_ID.load(Ordering::Acquire)
}

pub fn set_cpu_id(id: u32) {
    CURRENT_HART_ID.store(id, Ordering::Release);
}
