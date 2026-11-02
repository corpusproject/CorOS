//! RISC-V Supervisor Trap Vectors (stvec), CSR Exceptions, and PLIC Driver.

use crate::arch::traits::TrapOps;
use core::sync::atomic::{AtomicBool, Ordering};

// sie / sip CSR bitfields
pub const SIE_SSIE: u64 = 1 << 1; // Supervisor software interrupt enable
pub const SIE_STIE: u64 = 1 << 5; // Supervisor timer interrupt enable
pub const SIE_SEIE: u64 = 1 << 9; // Supervisor external interrupt enable (PLIC)

// stvec mode
pub const STVEC_DIRECT: u64   = 0;
pub const STVEC_VECTORED: u64 = 1;

/// Saved RISC-V 64-bit trap execution register frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Riscv64TrapFrame {
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub s0: u64,
    pub s1: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
    pub sepc: u64,
    pub sstatus: u64,
    pub scause: u64,
    pub stval: u64,
}

// RISC-V Platform-Level Interrupt Controller (PLIC) MMIO Base and Registers
pub const PLIC_PRIORITY_BASE: usize  = 0x0C00_0000;
pub const PLIC_PENDING_BASE: usize   = 0x0C00_1000;
pub const PLIC_ENABLE_BASE: usize    = 0x0C00_2000;
pub const PLIC_THRESHOLD_BASE: usize = 0x0C20_0000;
pub const PLIC_CLAIM_BASE: usize     = 0x0C20_0004;

pub struct Plic {
    base: usize,
}

impl Plic {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Set priority for an external interrupt source (1..=7).
    pub unsafe fn set_priority(&self, source: u32, priority: u32) {
        let addr = (self.base + PLIC_PRIORITY_BASE + (source as usize * 4)) as *mut u32;
        core::ptr::write_volatile(addr, priority & 0x7);
    }

    /// Enable interrupt source for target supervisor context (hart * 2 + 1).
    pub unsafe fn enable_source(&self, context: usize, source: u32) {
        let reg = (source / 32) as usize * 4;
        let bit = 1u32 << (source % 32);
        let addr = (self.base + PLIC_ENABLE_BASE + (context * 0x80) + reg) as *mut u32;
        let current = core::ptr::read_volatile(addr);
        core::ptr::write_volatile(addr, current | bit);
    }

    /// Set priority threshold for target supervisor context.
    pub unsafe fn set_threshold(&self, context: usize, threshold: u32) {
        let addr = (self.base + PLIC_THRESHOLD_BASE + (context * 0x1000)) as *mut u32;
        core::ptr::write_volatile(addr, threshold);
    }

    /// Claim the highest-priority pending interrupt for context.
    pub unsafe fn claim(&self, context: usize) -> u32 {
        let addr = (self.base + PLIC_CLAIM_BASE + (context * 0x1000)) as *const u32;
        core::ptr::read_volatile(addr)
    }

    /// Signal completion of interrupt handling.
    pub unsafe fn complete(&self, context: usize, source: u32) {
        let addr = (self.base + PLIC_CLAIM_BASE + (context * 0x1000)) as *mut u32;
        core::ptr::write_volatile(addr, source);
    }
}

static PLIC_INSTANCE: Plic = Plic::new(0);
static TRAPS_ACTIVE: AtomicBool = AtomicBool::new(false);

pub struct Riscv64Trap;

impl TrapOps for Riscv64Trap {
    fn initialize() {
        initialize();
    }

    fn register_handler(_vector: u8, _handler: usize) {
        // Dynamic vector registration hook
    }

    fn is_active() -> bool {
        is_active()
    }
}

pub fn initialize() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        // Set stvec to direct trap entry
        extern "C" {
            fn riscv_trap_entry();
        }
        let addr = riscv_trap_entry as usize;
        core::arch::asm!(
            "csrw stvec, {val}",
            val = in(reg) (addr & !0x3),
            options(nomem, nostack)
        );
        // Enable timer and external interrupts in sie
        core::arch::asm!(
            "csrs sie, {flags}",
            flags = in(reg) (SIE_STIE | SIE_SEIE),
            options(nomem, nostack)
        );
    }
    TRAPS_ACTIVE.store(true, Ordering::Release);
}

pub fn is_active() -> bool {
    TRAPS_ACTIVE.load(Ordering::Acquire)
}

pub fn plic() -> &'static Plic {
    &PLIC_INSTANCE
}
