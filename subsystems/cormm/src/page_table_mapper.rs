//! Generic multi-architecture Page Table Mapper trait.
//!
//! Provides a unified interface for virtual-to-physical address translation,
//! page mapping, permission updating, and page unmapping across x86_64, AArch64, and RISC-V.

pub trait PageTableMapper {
    type Entry;
    type Flags;

    /// Maps a virtual address to a physical address with architecture-specific flags.
    fn map_page(&mut self, vaddr: u64, paddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str>;

    /// Unmaps a virtual address, returning the removed page table entry.
    fn unmap_page(&mut self, vaddr: u64) -> Option<Self::Entry>;

    /// Modifies permission flags for an existing virtual page mapping.
    fn protect_page(&mut self, vaddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str>;

    /// Translates a virtual address to its corresponding physical address and flags.
    fn translate(&self, vaddr: u64) -> Option<(u64, Self::Flags)>;

    /// Checks if a virtual address is currently mapped.
    fn is_mapped(&self, vaddr: u64) -> bool {
        self.translate(vaddr).is_some()
    }
}
