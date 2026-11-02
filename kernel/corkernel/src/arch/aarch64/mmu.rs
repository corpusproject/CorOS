//! AArch64 Memory Management Unit (MMU), TTBR0/TTBR1 translation, and TCR/MAIR configuration.

use crate::arch::traits::MmuOps;
use core::sync::atomic::{AtomicU64, Ordering};

pub const TTBR_ASID_SHIFT: u64 = 48;
pub const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// TCR_EL1 Configuration Constants
pub const TCR_T0SZ_48BIT: u64 = 16 << 0;  // 48-bit user virtual address space (64 - 16 = 48)
pub const TCR_T1SZ_48BIT: u64 = 16 << 16; // 48-bit kernel virtual address space
pub const TCR_TG0_4KB: u64    = 0 << 14;  // Granule size 4 KiB for TTBR0
pub const TCR_TG1_4KB: u64    = 2 << 30;  // Granule size 4 KiB for TTBR1
pub const TCR_SH0_INNER: u64  = 3 << 12;  // Inner Shareable
pub const TCR_SH1_INNER: u64  = 3 << 28;
pub const TCR_ORGN0_WBWA: u64 = 1 << 10;  // Normal memory, Outer Write-Back Read/Write-Allocate
pub const TCR_IRGN0_WBWA: u64 = 1 << 8;   // Normal memory, Inner Write-Back Read/Write-Allocate
pub const TCR_ORGN1_WBWA: u64 = 1 << 26;
pub const TCR_IRGN1_WBWA: u64 = 1 << 24;
pub const TCR_IPS_48BIT: u64  = 5 << 32;  // 48-bit Physical Address Size (256 TB)

// MAIR_EL1 Attribute Indices
pub const MAIR_ATTR_DEVICE_nGnRnE: u64 = 0x00; // Index 0: MMIO peripherals
pub const MAIR_ATTR_NORMAL_WB: u64     = 0xFF; // Index 1: System RAM (Write-Back Cacheable)
pub const MAIR_ATTR_NORMAL_NC: u64     = 0x44; // Index 2: Non-Cacheable DMA buffer

pub const MAIR_DEFAULT: u64 = (MAIR_ATTR_DEVICE_nGnRnE << 0)
    | (MAIR_ATTR_NORMAL_WB << 8)
    | (MAIR_ATTR_NORMAL_NC << 16);

static CURRENT_PAGE_TABLE_ROOT: AtomicU64 = AtomicU64::new(0);

pub struct AArch64Mmu;

impl MmuOps for AArch64Mmu {
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
    #[cfg(target_arch = "aarch64")]
    {
        let ttbr0: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
        }
        ttbr0 & TTBR_BADDR_MASK
    }
    #[cfg(not(target_arch = "aarch64"))]
    CURRENT_PAGE_TABLE_ROOT.load(Ordering::Acquire)
}

pub unsafe fn switch_page_table(root: u64) {
    let clean_root = root & TTBR_BADDR_MASK;
    CURRENT_PAGE_TABLE_ROOT.store(clean_root, Ordering::Release);
    #[cfg(target_arch = "aarch64")]
    {
        core::arch::asm!(
            "msr ttbr0_el1, {val}",
            "isb",
            val = in(reg) clean_root,
            options(nomem, nostack)
        );
        flush_tlb_all();
    }
}

pub fn flush_tlb(vaddr: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let page = vaddr >> 12;
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {page}",
            "dsb ish",
            "isb",
            page = in(reg) page,
            options(nomem, nostack)
        );
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = vaddr;
}

pub fn flush_tlb_all() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nomem, nostack)
        );
    }
}
