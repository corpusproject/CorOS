//! RISC-V Supervisor Address Translation & Protection (satp) and Sv39/Sv48 MMU.

use crate::arch::traits::MmuOps;
use core::sync::atomic::{AtomicU64, Ordering};

// satp register bitfields
pub const SATP_MODE_BARE: u64 = 0;
pub const SATP_MODE_SV39: u64 = 8 << 60; // 39-bit Virtual Address (3-level)
pub const SATP_MODE_SV48: u64 = 9 << 60; // 48-bit Virtual Address (4-level)
pub const SATP_MODE_SV57: u64 = 10 << 60;

pub const SATP_ASID_SHIFT: u64 = 44;
pub const SATP_ASID_MASK: u64  = 0xFFFF << SATP_ASID_SHIFT;
pub const SATP_PPN_MASK: u64   = 0x0000_0FFF_FFFF_FFFF;

// RISC-V Page Table Entry (PTE) Flags
pub const PTE_V: u64 = 1 << 0; // Valid
pub const PTE_R: u64 = 1 << 1; // Readable
pub const PTE_W: u64 = 1 << 2; // Writable
pub const PTE_X: u64 = 1 << 3; // Executable
pub const PTE_U: u64 = 1 << 4; // User accessible
pub const PTE_G: u64 = 1 << 5; // Global mapping
pub const PTE_A: u64 = 1 << 6; // Accessed
pub const PTE_D: u64 = 1 << 7; // Dirty

pub const PTE_PPN_SHIFT: usize = 10;
pub const PAGE_SIZE: u64       = 4096;

static CURRENT_PAGE_TABLE_ROOT: AtomicU64 = AtomicU64::new(0);

pub struct Riscv64Mmu;

impl MmuOps for Riscv64Mmu {
    #[inline]
    fn current_page_table_root() -> u64 {
        current_page_table_root()
    }

    #[inline]
    unsafe fn switch_page_table(root: u64) {
        unsafe { switch_page_table(root); }
    }

    #[inline]
    fn flush_tlb(vaddr: u64) {
        flush_tlb(vaddr);
    }

    #[inline]
    fn flush_tlb_all() {
        flush_tlb_all();
    }
}

pub fn current_page_table_root() -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let satp: u64;
        unsafe {
            core::arch::asm!("csrr {}, satp", out(reg) satp, options(nomem, nostack));
        }
        (satp & SATP_PPN_MASK) * PAGE_SIZE
    }
    #[cfg(not(target_arch = "riscv64"))]
    CURRENT_PAGE_TABLE_ROOT.load(Ordering::Acquire)
}

pub unsafe fn switch_page_table(root: u64) {
    let ppn = (root / PAGE_SIZE) & SATP_PPN_MASK;
    let satp_val = SATP_MODE_SV39 | ppn;
    CURRENT_PAGE_TABLE_ROOT.store(root, Ordering::Release);
    #[cfg(target_arch = "riscv64")]
    {
        core::arch::asm!(
            "csrw satp, {val}",
            "sfence.vma zero, zero",
            val = in(reg) satp_val,
            options(nomem, nostack)
        );
    }
}

pub fn flush_tlb(vaddr: u64) {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "sfence.vma {vaddr}, zero",
            vaddr = in(reg) vaddr,
            options(nomem, nostack)
        );
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = vaddr;
}

pub fn flush_tlb_all() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("sfence.vma zero, zero", options(nomem, nostack));
    }
}
