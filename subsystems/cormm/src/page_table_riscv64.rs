//! RISC-V Address Translation & Protection (satp) Sv39 / Sv48 Manager.
//!
//! Provides hardware descriptor bitfield encoding/decoding for RISC-V privileged
//! architecture (Sv39 3-level and Sv48 4-level translation, 4 KiB granule),
//! ASID-aware `sfence.vma` shootdown tracking, and `PageTableMapper` implementation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use super::page_table_mapper::PageTableMapper;

/// RISC-V Page Table Entry (PTE) Hardware Flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Riscv64PteFlags(u64);

impl Riscv64PteFlags {
    pub const EMPTY: Self    = Self(0);
    pub const VALID: Self    = Self(1 << 0); // V
    pub const READ: Self     = Self(1 << 1); // R
    pub const WRITE: Self    = Self(1 << 2); // W
    pub const EXECUTE: Self  = Self(1 << 3); // X
    pub const USER: Self     = Self(1 << 4); // U
    pub const GLOBAL: Self   = Self(1 << 5); // G
    pub const ACCESSED: Self = Self(1 << 6); // A
    pub const DIRTY: Self    = Self(1 << 7); // D

    pub const ALL_FLAGS_MASK: u64 = 0xFF;

    #[inline]
    pub const fn from_bits_truncate(bits: u64) -> Self {
        Self(bits & Self::ALL_FLAGS_MASK)
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// RISC-V linear addressing paging mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiscvPagingMode {
    /// Sv39: 39-bit virtual address (3 levels: VPN[2], VPN[1], VPN[0]).
    Sv39,
    /// Sv48: 48-bit virtual address (4 levels: VPN[3], VPN[2], VPN[1], VPN[0]).
    Sv48,
}

/// Validates canonical sign-extended RISC-V virtual address under `mode`.
pub const fn is_canonical_riscv_vaddr(vaddr: u64, mode: RiscvPagingMode) -> bool {
    let sign_bit = match mode {
        RiscvPagingMode::Sv39 => 38,
        RiscvPagingMode::Sv48 => 47,
    };
    let shift = 63 - sign_bit;
    let sign_extended = ((vaddr << shift) as i64 >> shift) as u64;
    sign_extended == vaddr
}

/// Decomposed VPN indices and offset for RISC-V Sv39 and Sv48 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiscvAddressIndices {
    pub vpn3: u16,
    pub vpn2: u16,
    pub vpn1: u16,
    pub vpn0: u16,
    pub page_offset: u16,
}

impl RiscvAddressIndices {
    pub const fn decode(vaddr: u64) -> Self {
        Self {
            page_offset: (vaddr & 0xFFF) as u16,
            vpn0: ((vaddr >> 12) & 0x1FF) as u16,
            vpn1: ((vaddr >> 21) & 0x1FF) as u16,
            vpn2: ((vaddr >> 30) & 0x1FF) as u16,
            vpn3: ((vaddr >> 39) & 0x1FF) as u16,
        }
    }
}

/// RISC-V 64-bit Page Table Entry (`PTE`).
/// Bits 0..7: Flags, Bits 8..9: RSW, Bits 10..53: Physical Page Number (PPN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Riscv64Pte(u64);

impl Riscv64Pte {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn encode(phys_addr: u64, flags: Riscv64PteFlags) -> Self {
        let ppn = (phys_addr >> 12) & 0x0000_0FFF_FFFF_FFFF;
        Self((ppn << 10) | flags.bits())
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn phys_addr(self) -> u64 {
        ((self.0 >> 10) & 0x0000_0FFF_FFFF_FFFF) << 12
    }

    pub const fn flags(self) -> Riscv64PteFlags {
        Riscv64PteFlags::from_bits_truncate(self.0)
    }

    pub const fn is_valid(self) -> bool {
        self.flags().contains(Riscv64PteFlags::VALID)
    }
}

/// RISC-V `sfence.vma` shootdown granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiscvTlbFlushKind {
    SinglePage { asid: u16, vaddr: u64 },
    SingleContext { asid: u16 },
    AllContexts,
}

/// Pending TLB shootdown request tracker for RISC-V.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscvTlbTracker {
    pending_requests: Vec<RiscvTlbFlushKind>,
    completed_shootdowns: u64,
}

impl RiscvTlbTracker {
    pub const fn new() -> Self {
        Self {
            pending_requests: Vec::new(),
            completed_shootdowns: 0,
        }
    }

    pub fn queue_page_invalidation(&mut self, asid: u16, vaddr: u64) {
        self.pending_requests.push(RiscvTlbFlushKind::SinglePage {
            asid,
            vaddr: vaddr & !0xFFFu64,
        });
    }

    pub fn drain_and_acknowledge(&mut self) -> usize {
        let count = self.pending_requests.len();
        self.pending_requests.clear();
        self.completed_shootdowns += count as u64;
        count
    }

    pub const fn completed_shootdowns(&self) -> u64 {
        self.completed_shootdowns
    }
}

/// RISC-V Address Space Page Table Manager supporting Sv39 and Sv48.
#[derive(Debug, Clone)]
pub struct Riscv64AddressSpacePageTable {
    mode: RiscvPagingMode,
    asid: u16,
    entries: BTreeMap<u64, Riscv64Pte>,
    tlb_tracker: RiscvTlbTracker,
}

impl Riscv64AddressSpacePageTable {
    pub fn new(mode: RiscvPagingMode, asid: u16) -> Self {
        Self {
            mode,
            asid,
            entries: BTreeMap::new(),
            tlb_tracker: RiscvTlbTracker::new(),
        }
    }

    pub fn map_page(
        &mut self,
        vaddr: u64,
        phys_addr: u64,
        flags: Riscv64PteFlags,
    ) -> Result<Riscv64Pte, &'static str> {
        if !is_canonical_riscv_vaddr(vaddr, self.mode) {
            return Err("Non-canonical RISC-V virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = Riscv64Pte::encode(
            phys_addr,
            flags
                .union(Riscv64PteFlags::VALID)
                .union(Riscv64PteFlags::ACCESSED)
                .union(Riscv64PteFlags::DIRTY),
        );
        if self.entries.insert(aligned_vaddr, pte).is_some() {
            self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        }
        Ok(pte)
    }

    pub fn protect_page(
        &mut self,
        vaddr: u64,
        new_flags: Riscv64PteFlags,
    ) -> Result<Riscv64Pte, &'static str> {
        if !is_canonical_riscv_vaddr(vaddr, self.mode) {
            return Err("Non-canonical RISC-V virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let existing = self.entries.get_mut(&aligned_vaddr).ok_or("Page not mapped")?;
        let updated = Riscv64Pte::encode(
            existing.phys_addr(),
            new_flags
                .union(Riscv64PteFlags::VALID)
                .union(Riscv64PteFlags::ACCESSED)
                .union(Riscv64PteFlags::DIRTY),
        );
        *existing = updated;
        self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        Ok(updated)
    }

    pub fn unmap_page(&mut self, vaddr: u64) -> Option<Riscv64Pte> {
        let aligned_vaddr = vaddr & !0xFFFu64;
        let removed = self.entries.remove(&aligned_vaddr)?;
        self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        Some(removed)
    }

    pub fn translate(&self, vaddr: u64) -> Option<(u64, Riscv64PteFlags)> {
        if !is_canonical_riscv_vaddr(vaddr, self.mode) {
            return None;
        }
        let indices = RiscvAddressIndices::decode(vaddr);
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = self.entries.get(&aligned_vaddr)?;
        if !pte.is_valid() {
            return None;
        }
        Some((pte.phys_addr() + indices.page_offset as u64, pte.flags()))
    }

    pub fn tlb_tracker_mut(&mut self) -> &mut RiscvTlbTracker {
        &mut self.tlb_tracker
    }
}

impl PageTableMapper for Riscv64AddressSpacePageTable {
    type Entry = Riscv64Pte;
    type Flags = Riscv64PteFlags;

    #[inline]
    fn map_page(&mut self, vaddr: u64, paddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str> {
        self.map_page(vaddr, paddr, flags)
    }

    #[inline]
    fn unmap_page(&mut self, vaddr: u64) -> Option<Self::Entry> {
        self.unmap_page(vaddr)
    }

    #[inline]
    fn protect_page(&mut self, vaddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str> {
        self.protect_page(vaddr, flags)
    }

    #[inline]
    fn translate(&self, vaddr: u64) -> Option<(u64, Self::Flags)> {
        self.translate(vaddr)
    }
}
