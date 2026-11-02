//! AArch64 4-Level Translation Table Manager (TTBR0 / TTBR1).
//!
//! Provides hardware descriptor bitfield encoding/decoding for ARMv8-A / ARMv9-A
//! Stage 1 translation (4 KiB granule, 48-bit canonical virtual addressing),
//! ASID-aware TLBI shootdown tracking, and `PageTableMapper` implementation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use super::page_table_mapper::PageTableMapper;

/// Output physical address mask in an AArch64 Page Descriptor (bits 12..48).
pub const AARCH64_DESC_OUTPUT_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// AArch64 Page and Block Descriptor Attribute Flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64PageTableFlags(u64);

impl AArch64PageTableFlags {
    pub const EMPTY: Self             = Self(0);
    pub const VALID: Self             = Self(1 << 0);
    pub const TABLE_OR_PAGE: Self     = Self(1 << 1); // 1 for 4KB page at level 3, table at levels 0..2
    pub const ATTR_DEVICE: Self       = Self(0 << 2); // MAIR index 0: Device-nGnRnE
    pub const ATTR_NORMAL_WB: Self    = Self(1 << 2); // MAIR index 1: Normal WB
    pub const ATTR_NORMAL_NC: Self    = Self(2 << 2); // MAIR index 2: Normal Non-Cacheable
    pub const NON_SECURE: Self        = Self(1 << 5);
    pub const AP_USER_RW: Self        = Self(1 << 6); // AP[1]=1 (EL0 access allowed)
    pub const AP_RO: Self             = Self(2 << 6); // AP[2]=1 (Read-Only)
    pub const SH_INNER_SHAREABLE: Self = Self(3 << 8); // Inner Shareable
    pub const ACCESS_FLAG: Self       = Self(1 << 10); // AF bit (1 = accessed)
    pub const NOT_GLOBAL: Self        = Self(1 << 11); // nG bit (1 = ASID specific)
    pub const PRIV_EXEC_NEVER: Self   = Self(1 << 53); // PXN
    pub const USER_EXEC_NEVER: Self   = Self(1 << 54); // UXN / XN

    pub const ALL_FLAGS_MASK: u64 = (1 << 0)
        | (1 << 1)
        | (0x7 << 2)
        | (1 << 5)
        | (3 << 6)
        | (3 << 8)
        | (1 << 10)
        | (1 << 11)
        | (1 << 53)
        | (1 << 54);

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

/// Decomposed 9-bit table indices (L0..L3) and 12-bit offset for AArch64 48-bit address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AArch64AddressIndices {
    pub l0_index: u16,
    pub l1_index: u16,
    pub l2_index: u16,
    pub l3_index: u16,
    pub page_offset: u16,
}

impl AArch64AddressIndices {
    pub const fn decode(vaddr: u64) -> Self {
        Self {
            page_offset: (vaddr & 0xFFF) as u16,
            l3_index: ((vaddr >> 12) & 0x1FF) as u16,
            l2_index: ((vaddr >> 21) & 0x1FF) as u16,
            l1_index: ((vaddr >> 30) & 0x1FF) as u16,
            l0_index: ((vaddr >> 39) & 0x1FF) as u16,
        }
    }
}

/// Validates whether `vaddr` is canonical 48-bit for AArch64 (either TTBR0 low or TTBR1 high).
pub const fn is_canonical_aarch64_vaddr(vaddr: u64) -> bool {
    let top16 = (vaddr >> 48) & 0xFFFF;
    top16 == 0x0000 || top16 == 0xFFFF
}

/// AArch64 64-bit Page Table Entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct AArch64Pte(u64);

impl AArch64Pte {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn encode(phys_addr: u64, flags: AArch64PageTableFlags) -> Self {
        Self((phys_addr & AARCH64_DESC_OUTPUT_ADDR_MASK) | flags.bits())
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn phys_addr(self) -> u64 {
        self.0 & AARCH64_DESC_OUTPUT_ADDR_MASK
    }

    pub const fn flags(self) -> AArch64PageTableFlags {
        AArch64PageTableFlags::from_bits_truncate(self.0)
    }

    pub const fn is_valid(self) -> bool {
        self.flags().contains(AArch64PageTableFlags::VALID)
    }
}

/// AArch64 TLBI (TLB Invalidate) request granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AArch64TlbFlushKind {
    SinglePage { asid: u16, vaddr: u64 },
    SingleContext { asid: u16 },
    AllContexts,
}

/// Pending TLB invalidation tracker for AArch64 multicore shootdowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AArch64TlbTracker {
    pending_requests: Vec<AArch64TlbFlushKind>,
    completed_shootdowns: u64,
}

impl AArch64TlbTracker {
    pub const fn new() -> Self {
        Self {
            pending_requests: Vec::new(),
            completed_shootdowns: 0,
        }
    }

    pub fn queue_page_invalidation(&mut self, asid: u16, vaddr: u64) {
        self.pending_requests.push(AArch64TlbFlushKind::SinglePage {
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

/// AArch64 Address Space Translation Manager (TTBR0 / TTBR1 4-Level).
#[derive(Debug, Clone)]
pub struct AArch64AddressSpacePageTable {
    asid: u16,
    entries: BTreeMap<u64, AArch64Pte>,
    tlb_tracker: AArch64TlbTracker,
}

impl AArch64AddressSpacePageTable {
    pub fn new(asid: u16) -> Self {
        Self {
            asid,
            entries: BTreeMap::new(),
            tlb_tracker: AArch64TlbTracker::new(),
        }
    }

    pub fn map_page(
        &mut self,
        vaddr: u64,
        phys_addr: u64,
        flags: AArch64PageTableFlags,
    ) -> Result<AArch64Pte, &'static str> {
        if !is_canonical_aarch64_vaddr(vaddr) {
            return Err("Non-canonical AArch64 virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = AArch64Pte::encode(
            phys_addr,
            flags
                .union(AArch64PageTableFlags::VALID)
                .union(AArch64PageTableFlags::TABLE_OR_PAGE)
                .union(AArch64PageTableFlags::ACCESS_FLAG),
        );
        if self.entries.insert(aligned_vaddr, pte).is_some() {
            self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        }
        Ok(pte)
    }

    pub fn protect_page(
        &mut self,
        vaddr: u64,
        new_flags: AArch64PageTableFlags,
    ) -> Result<AArch64Pte, &'static str> {
        if !is_canonical_aarch64_vaddr(vaddr) {
            return Err("Non-canonical AArch64 virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let existing = self.entries.get_mut(&aligned_vaddr).ok_or("Page not mapped")?;
        let updated = AArch64Pte::encode(
            existing.phys_addr(),
            new_flags
                .union(AArch64PageTableFlags::VALID)
                .union(AArch64PageTableFlags::TABLE_OR_PAGE)
                .union(AArch64PageTableFlags::ACCESS_FLAG),
        );
        *existing = updated;
        self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        Ok(updated)
    }

    pub fn unmap_page(&mut self, vaddr: u64) -> Option<AArch64Pte> {
        let aligned_vaddr = vaddr & !0xFFFu64;
        let removed = self.entries.remove(&aligned_vaddr)?;
        self.tlb_tracker.queue_page_invalidation(self.asid, aligned_vaddr);
        Some(removed)
    }

    pub fn translate(&self, vaddr: u64) -> Option<(u64, AArch64PageTableFlags)> {
        if !is_canonical_aarch64_vaddr(vaddr) {
            return None;
        }
        let indices = AArch64AddressIndices::decode(vaddr);
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = self.entries.get(&aligned_vaddr)?;
        if !pte.is_valid() {
            return None;
        }
        Some((pte.phys_addr() + indices.page_offset as u64, pte.flags()))
    }

    pub fn tlb_tracker_mut(&mut self) -> &mut AArch64TlbTracker {
        &mut self.tlb_tracker
    }
}

impl PageTableMapper for AArch64AddressSpacePageTable {
    type Entry = AArch64Pte;
    type Flags = AArch64PageTableFlags;

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
