//! x86_64 4-Level (`PML4`) and 5-Level (`PML5` / `LA57`) Page Table Manager.
//!
//! Provides hardware bitfield encoding/decoding for x86_64 page table entries,
//! canonical virtual address validation (48-bit and 57-bit linear addressing),
//! multi-level page table walks, and PCID-aware TLB shootdown tracking.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Physical address mask inside an x86_64 Page Table Entry (bits `12..52`).
pub const PTE_PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Hardware flags for an x86_64 Page Table Entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableFlags(u64);

impl PageTableFlags {
    pub const EMPTY: Self = Self(0);
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const CACHE_DISABLE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const HUGE_PAGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const NO_EXECUTE: Self = Self(1 << 63);

    /// Mask of all supported architectural PTE flag bits.
    pub const ALL_FLAGS_MASK: u64 = (1 << 0)
        | (1 << 1)
        | (1 << 2)
        | (1 << 3)
        | (1 << 4)
        | (1 << 5)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 63);

    /// Creates flags from raw bits (masked to architectural flag positions).
    #[inline]
    pub const fn from_bits_truncate(bits: u64) -> Self {
        Self(bits & Self::ALL_FLAGS_MASK)
    }

    /// Returns raw 64-bit flag representation.
    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Combines two flag sets.
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes `other` flags from `self`.
    #[inline]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Paging mode for x86_64 linear address translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingMode {
    /// Standard 4-level paging (`PML4 -> PDPT -> PD -> PT`, 48-bit canonical addresses).
    FourLevel,
    /// Intel `LA57` 5-level paging (`PML5 -> PML4 -> PDPT -> PD -> PT`, 57-bit canonical addresses).
    FiveLevelLa57,
}

/// Validates whether `vaddr` is canonical under the specified x86_64 `PagingMode`.
pub const fn is_canonical_vaddr(vaddr: u64, mode: PagingMode) -> bool {
    let sign_bit = match mode {
        PagingMode::FourLevel => 47,
        PagingMode::FiveLevelLa57 => 56,
    };
    let shift = 63 - sign_bit;
    let sign_extended = ((vaddr << shift) as i64 >> shift) as u64;
    sign_extended == vaddr
}

/// Decomposed 9-bit table indices and 12-bit page offset for an x86_64 virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualAddressIndices {
    pub pml5_index: u16,
    pub pml4_index: u16,
    pub pdpt_index: u16,
    pub pd_index: u16,
    pub pt_index: u16,
    pub page_offset: u16,
}

impl VirtualAddressIndices {
    /// Extracts 9-bit indices for `PML5`, `PML4`, `PDPT`, `PD`, `PT` and 12-bit offset.
    pub const fn decode(vaddr: u64) -> Self {
        Self {
            page_offset: (vaddr & 0xFFF) as u16,
            pt_index: ((vaddr >> 12) & 0x1FF) as u16,
            pd_index: ((vaddr >> 21) & 0x1FF) as u16,
            pdpt_index: ((vaddr >> 30) & 0x1FF) as u16,
            pml4_index: ((vaddr >> 39) & 0x1FF) as u16,
            pml5_index: ((vaddr >> 48) & 0x1FF) as u16,
        }
    }
}

/// Hardware-encoded 64-bit x86_64 Page Table Entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Creates an empty, non-present PTE.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Encodes a physical frame address (`4 KiB` aligned) and `PageTableFlags` into a 64-bit PTE.
    pub const fn encode(phys_addr: u64, flags: PageTableFlags) -> Self {
        Self((phys_addr & PTE_PHYS_ADDR_MASK) | flags.bits())
    }

    /// Returns the raw 64-bit hardware value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Extracts the 4 KiB-aligned physical frame address from the entry.
    pub const fn phys_addr(self) -> u64 {
        self.0 & PTE_PHYS_ADDR_MASK
    }

    /// Extracts the `PageTableFlags` from the entry.
    pub const fn flags(self) -> PageTableFlags {
        PageTableFlags::from_bits_truncate(self.0)
    }

    /// Returns `true` if `PRESENT` bit is set.
    pub const fn is_present(self) -> bool {
        self.flags().contains(PageTableFlags::PRESENT)
    }

    /// Returns `true` if `HUGE_PAGE` (`PS`) bit is set.
    pub const fn is_huge(self) -> bool {
        self.flags().contains(PageTableFlags::HUGE_PAGE)
    }
}

/// PCID (Process Context Identifier, 12-bit `0..4096`) TLB shootdown granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbFlushKind {
    /// `INVPCID` / `INVLPG` single linear address within a specific `pcid`.
    SinglePage { pcid: u16, vaddr: u64 },
    /// Flush all non-global entries matching `pcid`.
    SingleContext { pcid: u16 },
    /// Full flush of all contexts including global pages (`CR4.PGE` toggle / `INVPCID` type 2).
    AllContextsGlobal,
}

/// Pending TLB shootdown request queued for inter-processor interrupt (IPI) broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlbShootdownTracker {
    pending_requests: Vec<TlbFlushKind>,
    completed_shootdowns: u64,
}

impl TlbShootdownTracker {
    /// Creates an empty TLB shootdown tracker.
    pub const fn new() -> Self {
        Self {
            pending_requests: Vec::new(),
            completed_shootdowns: 0,
        }
    }

    /// Queues a single-page invalidation for `pcid` and `vaddr`.
    pub fn queue_page_invalidation(&mut self, pcid: u16, vaddr: u64) {
        self.pending_requests.push(TlbFlushKind::SinglePage {
            pcid: pcid & 0x0FFF,
            vaddr: vaddr & !0xFFFu64,
        });
    }

    /// Queues a full context invalidation for `pcid`.
    pub fn queue_context_invalidation(&mut self, pcid: u16) {
        self.pending_requests.push(TlbFlushKind::SingleContext {
            pcid: pcid & 0x0FFF,
        });
    }

    /// Drains and acknowledges all pending TLB shootdown requests, returning how many were flushed.
    pub fn drain_and_acknowledge(&mut self) -> usize {
        let count = self.pending_requests.len();
        self.pending_requests.clear();
        self.completed_shootdowns += count as u64;
        count
    }

    /// Returns total completed shootdowns.
    pub const fn completed_shootdowns(&self) -> u64 {
        self.completed_shootdowns
    }
}

/// Address Space Page Table Manager supporting 4-level and 5-level (`LA57`) mappings.
#[derive(Debug, Clone)]
pub struct AddressSpacePageTable {
    mode: PagingMode,
    pcid: u16,
    entries: BTreeMap<u64, PageTableEntry>,
    tlb_tracker: TlbShootdownTracker,
}

impl AddressSpacePageTable {
    /// Creates a new `AddressSpacePageTable` for `mode` and 12-bit `pcid`.
    pub fn new(mode: PagingMode, pcid: u16) -> Self {
        Self {
            mode,
            pcid: pcid & 0x0FFF,
            entries: BTreeMap::new(),
            tlb_tracker: TlbShootdownTracker::new(),
        }
    }

    /// Maps a canonical virtual address `vaddr` to `phys_addr` with `flags`.
    pub fn map_page(
        &mut self,
        vaddr: u64,
        phys_addr: u64,
        flags: PageTableFlags,
    ) -> Result<PageTableEntry, &'static str> {
        if !is_canonical_vaddr(vaddr, self.mode) {
            return Err("Non-canonical x86_64 virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = PageTableEntry::encode(phys_addr, flags.union(PageTableFlags::PRESENT));
        if self.entries.insert(aligned_vaddr, pte).is_some() {
            self.tlb_tracker
                .queue_page_invalidation(self.pcid, aligned_vaddr);
        }
        Ok(pte)
    }

    /// Updates protection flags on an existing mapping and queues a PCID TLB invalidation.
    pub fn protect_page(
        &mut self,
        vaddr: u64,
        new_flags: PageTableFlags,
    ) -> Result<PageTableEntry, &'static str> {
        if !is_canonical_vaddr(vaddr, self.mode) {
            return Err("Non-canonical x86_64 virtual address");
        }
        let aligned_vaddr = vaddr & !0xFFFu64;
        let existing = self
            .entries
            .get_mut(&aligned_vaddr)
            .ok_or("Virtual page not mapped")?;
        let updated = PageTableEntry::encode(
            existing.phys_addr(),
            new_flags.union(PageTableFlags::PRESENT),
        );
        *existing = updated;
        self.tlb_tracker
            .queue_page_invalidation(self.pcid, aligned_vaddr);
        Ok(updated)
    }

    /// Unmaps `vaddr` and queues a PCID TLB shootdown request.
    pub fn unmap_page(&mut self, vaddr: u64) -> Option<PageTableEntry> {
        let aligned_vaddr = vaddr & !0xFFFu64;
        let removed = self.entries.remove(&aligned_vaddr)?;
        self.tlb_tracker
            .queue_page_invalidation(self.pcid, aligned_vaddr);
        Some(removed)
    }

    /// Translates `vaddr` to its physical address (`phys_frame + page_offset`) and flags.
    pub fn translate(&self, vaddr: u64) -> Option<(u64, PageTableFlags)> {
        if !is_canonical_vaddr(vaddr, self.mode) {
            return None;
        }
        let indices = VirtualAddressIndices::decode(vaddr);
        let aligned_vaddr = vaddr & !0xFFFu64;
        let pte = self.entries.get(&aligned_vaddr)?;
        if !pte.is_present() {
            return None;
        }
        Some((pte.phys_addr() + indices.page_offset as u64, pte.flags()))
    }

    /// Mutable access to the PCID TLB shootdown tracker.
    pub fn tlb_tracker_mut(&mut self) -> &mut TlbShootdownTracker {
        &mut self.tlb_tracker
    }
}

impl super::page_table_mapper::PageTableMapper for AddressSpacePageTable {
    type Entry = PageTableEntry;
    type Flags = PageTableFlags;

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
