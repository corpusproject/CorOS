//! CorOS Hardware Driver Module: `dma_engine`
//!
//! Scatter-Gather DMA list (`ScatterGatherEntry`), physically contiguous segment
//! coalescer with 64 KiB boundary enforcement, 32-bit ISA/PCI Bounce Buffer pool
//! allocator for `> 4 GiB` high-memory pages, and IOMMU (`Intel VT-d` / `AMD-Vi`)
//! IOVA-to-Physical Domain Mapping Table.

use alloc::vec::Vec;

/// 16-byte Scatter-Gather DMA Segment (`ScatterGatherEntry`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScatterGatherEntry {
    pub phys_addr: u64,
    pub length_bytes: u32,
    pub flags: u32,
}

impl ScatterGatherEntry {
    pub const FLAG_END_OF_LIST: u32 = 1 << 0;
    pub const FLAG_BOUNCE_BUFFER: u32 = 1 << 1;

    #[inline]
    pub const fn new(phys_addr: u64, length_bytes: u32, flags: u32) -> Self {
        Self {
            phys_addr,
            length_bytes,
            flags,
        }
    }

    #[inline]
    pub const fn end_phys_addr(&self) -> u64 {
        self.phys_addr.wrapping_add(self.length_bytes as u64)
    }
}

/// Coalesces adjacent physically contiguous `ScatterGatherEntry` segments while respecting
/// `max_segment_bytes` (e.g. `65536`) and an optional `boundary_mask` (e.g. `0xFFFF` for 64 KiB boundary).
pub fn coalesce_scatter_gather_list(
    raw_segments: &[ScatterGatherEntry],
    max_segment_bytes: u32,
    boundary_mask: u64,
) -> Vec<ScatterGatherEntry> {
    let mut merged: Vec<ScatterGatherEntry> = Vec::new();
    for seg in raw_segments {
        if seg.length_bytes == 0 {
            continue;
        }
        if let Some(last) = merged.last_mut() {
            let contiguous = last.end_phys_addr() == seg.phys_addr;
            let combined_len = last.length_bytes.saturating_add(seg.length_bytes);
            let within_max = combined_len <= max_segment_bytes;
            let crosses_boundary = if boundary_mask != 0 {
                (last.phys_addr & !boundary_mask)
                    != ((seg.end_phys_addr().saturating_sub(1)) & !boundary_mask)
            } else {
                false
            };

            if contiguous && within_max && !crosses_boundary {
                last.length_bytes = combined_len;
                continue;
            }
        }
        merged.push(*seg);
    }

    if let Some(tail) = merged.last_mut() {
        tail.flags |= ScatterGatherEntry::FLAG_END_OF_LIST;
    }
    merged
}

/// 64-bit Bitmap-tracked Bounce Buffer Pool in low `< 4 GiB` physical memory for legacy 32-bit DMA devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaBounceBufferPool {
    pub base_phys_32bit: u64,
    pub slot_size_bytes: u32,
    pub total_slots: u8,
    pub allocated_bitmap: u64,
}

impl DmaBounceBufferPool {
    /// Creates a bounce buffer pool of up to 64 fixed-size slots (e.g. 64 * 4 KiB = 256 KiB) below 4 GiB.
    #[inline]
    pub const fn new(base_phys_32bit: u64, slot_size_bytes: u32, total_slots: u8) -> Self {
        let clamped_slots = if total_slots > 64 { 64 } else { total_slots };
        Self {
            base_phys_32bit: base_phys_32bit & 0xFFFF_FFFF,
            slot_size_bytes,
            total_slots: clamped_slots,
            allocated_bitmap: 0,
        }
    }

    /// Returns `true` if `phys_addr + length` exceeds the device's `dma_mask` (e.g., `0xFFFF_FFFF` for 32-bit PCI).
    #[inline]
    pub const fn requires_bounce(phys_addr: u64, length: u32, dma_mask: u64) -> bool {
        let end = phys_addr.saturating_add(length.saturating_sub(1) as u64);
        (end & !dma_mask) != 0
    }

    /// Allocates one bounce buffer slot and returns `(slot_index, bounce_phys_addr)`.
    pub fn alloc_bounce_slot(&mut self) -> Option<(u8, u64)> {
        let mut idx = 0u8;
        while idx < self.total_slots {
            let mask = 1u64 << idx;
            if (self.allocated_bitmap & mask) == 0 {
                self.allocated_bitmap |= mask;
                let addr =
                    self.base_phys_32bit + (idx as u64) * (self.slot_size_bytes as u64);
                return Some((idx, addr));
            }
            idx += 1;
        }
        None
    }

    /// Releases a previously allocated bounce buffer slot.
    pub fn free_bounce_slot(&mut self, slot_index: u8) {
        if slot_index < self.total_slots {
            self.allocated_bitmap &= !(1u64 << slot_index);
        }
    }
}

/// IOMMU Page Table Entry permission flags (compatible with Intel VT-d Second-Level / AMD-Vi).
pub mod iommu_pte_flags {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const SNOOP_COHERENT: u64 = 1 << 11;
    pub const SUPER_PAGE_2M: u64 = 1 << 7;
    pub const ADDR_MASK_4K: u64 = 0x000F_FFFF_FFFF_F000;
}

/// IOMMU Domain IOVA Mapping Entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IommuMappingEntry {
    pub iova_base: u64,
    pub phys_base: u64,
    pub size_bytes: u64,
    pub raw_pte_template: u64,
}

/// IOMMU Domain Address Translation & Protection Table for an isolated PCIe requester group.
pub struct IommuDomain {
    pub domain_id: u16,
    pub next_iova: u64,
    pub mappings: Vec<IommuMappingEntry>,
}

impl IommuDomain {
    #[inline]
    pub const fn new(domain_id: u16, iova_aperture_start: u64) -> Self {
        Self {
            domain_id,
            next_iova: iova_aperture_start & !0xFFFu64,
            mappings: Vec::new(),
        }
    }

    /// Maps a physical memory region into the IOMMU domain's IOVA space and returns the assigned `iova_base`.
    pub fn map_region(
        &mut self,
        phys_base: u64,
        size_bytes: u64,
        readable: bool,
        writable: bool,
    ) -> Option<u64> {
        if size_bytes == 0 || (!readable && !writable) {
            return None;
        }
        let aligned_size = (size_bytes + 0xFFF) & !0xFFFu64;
        let aligned_phys = phys_base & iommu_pte_flags::ADDR_MASK_4K;
        let iova = self.next_iova;
        self.next_iova = self.next_iova.wrapping_add(aligned_size);

        let mut flags = iommu_pte_flags::SNOOP_COHERENT;
        if readable {
            flags |= iommu_pte_flags::READ;
        }
        if writable {
            flags |= iommu_pte_flags::WRITE;
        }

        self.mappings.push(IommuMappingEntry {
            iova_base: iova,
            phys_base: aligned_phys,
            size_bytes: aligned_size,
            raw_pte_template: aligned_phys | flags,
        });
        Some(iova)
    }

    /// Translates a device IOVA back to its host physical address if mapped within this domain.
    pub fn translate_iova(&self, iova: u64) -> Option<u64> {
        for m in &self.mappings {
            if iova >= m.iova_base && iova < m.iova_base + m.size_bytes {
                return Some(m.phys_base + (iova - m.iova_base));
            }
        }
        None
    }
}

/// Self-test for `dma_engine` scatter-gather coalescing, 32-bit bounce buffer allocation, and IOMMU IOVA translation.
pub fn verify_driver_module_dma_engine() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Scatter-Gather coalescer merges 3 contiguous 4 KiB pages into one 12 KiB segment
    let raw = [
        ScatterGatherEntry::new(0x1000_0000, 4096, 0),
        ScatterGatherEntry::new(0x1000_1000, 4096, 0),
        ScatterGatherEntry::new(0x1000_2000, 4096, 0),
        ScatterGatherEntry::new(0x2000_0000, 4096, 0),
    ];
    let merged = coalesce_scatter_gather_list(&raw, 65536, 0xFFFF);
    if merged.len() == 2
        && merged[0].length_bytes == 12_288
        && (merged[1].flags & ScatterGatherEntry::FLAG_END_OF_LIST) != 0
    {
        passed += 1;
    }

    // 2. Verify 64 KiB boundary enforcement prevents merging across `0x1000_FFFF -> 0x1001_0000`
    let cross = [
        ScatterGatherEntry::new(0x1000_F000, 4096, 0),
        ScatterGatherEntry::new(0x1001_0000, 4096, 0),
    ];
    let no_merge = coalesce_scatter_gather_list(&cross, 65536, 0xFFFF);
    if no_merge.len() == 2 {
        passed += 1;
    }

    // 3. Verify 32-bit Bounce Buffer detection and slot allocation
    let mut pool = DmaBounceBufferPool::new(0x0100_0000, 4096, 16);
    if DmaBounceBufferPool::requires_bounce(0x0000_0002_0000_0000, 4096, 0xFFFF_FFFF)
        && !DmaBounceBufferPool::requires_bounce(0x8000_0000, 4096, 0xFFFF_FFFF)
    {
        if let Some((slot, phys)) = pool.alloc_bounce_slot() {
            pool.free_bounce_slot(slot);
            if slot == 0 && phys == 0x0100_0000 && pool.allocated_bitmap == 0 {
                passed += 1;
            }
        }
    }

    // 4. Verify IOMMU Domain IOVA mapping and physical address translation
    let mut domain = IommuDomain::new(1, 0xFFFF_0000);
    if let Some(iova) = domain.map_region(0x0000_0004_8000_0000, 16384, true, true) {
        if iova == 0xFFFF_0000
            && domain.translate_iova(0xFFFF_2345) == Some(0x0000_0004_8000_2345)
            && domain.translate_iova(0xFFFF_5000).is_none()
        {
            passed += 1;
        }
    }

    passed
}
