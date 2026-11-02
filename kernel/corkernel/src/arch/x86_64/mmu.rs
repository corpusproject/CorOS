//! x86_64 MMU implementation of the HAL `MmuOps` trait.

use crate::arch::traits::MmuOps;
use super::cpu;

pub use super::cpu::{
    classify_paging_mode, nx_enabled, paging_snapshot, physical_address_bits,
    PagingMode, PagingSnapshot,
};

pub struct X86Mmu;

impl MmuOps for X86Mmu {
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

#[inline]
pub fn current_page_table_root() -> u64 {
    cpu::read_cr3().0 & 0x000F_FFFF_FFFF_F000
}

#[inline]
pub unsafe fn switch_page_table(root: u64) {
    unsafe { cpu::write_cr3(root); }
}

#[inline]
pub fn flush_tlb(vaddr: u64) {
    unsafe { cpu::invlpg(vaddr); }
}

#[inline]
pub fn flush_tlb_all() {
    unsafe {
        let cr3 = cpu::read_cr3().0;
        cpu::write_cr3(cr3);
    }
}
