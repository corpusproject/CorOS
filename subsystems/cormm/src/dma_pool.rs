//! Coherent DMA Page Pool & Software IOMMU (`SwiotlbAperture`) Bounce Buffer Allocator.
//!
//! Enforces hardware device physical address masks (`DmaMask::Bit24` ISA 16 MiB,
//! `DmaMask::Bit32` PCI 4 GiB, and `DmaMask::Bit64` PCIe 64-bit) and provides
//! `SWIOTLB` bounce buffer allocation and synchronization when high physical memory
//! buffers exceed a device's DMA addressing capability.

use alloc::vec;
use alloc::vec::Vec;

/// Size in bytes of a single SWIOTLB bounce slot (`2 KiB`, matching Linux `IO_TLB_SIZE`).
pub const SWIOTLB_SLOT_BYTES: usize = 2048;

/// Hardware DMA physical address capability mask (`dma_addr_t` limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaMask {
    /// 24-bit legacy ISA DMA limit (`0x00FF_FFFF` = 16 MiB).
    Bit24,
    /// 32-bit standard PCI DMA limit (`0xFFFF_FFFF` = 4 GiB).
    Bit32,
    /// 64-bit full physical address space (`0xFFFF_FFFF_FFFF_FFFF`).
    Bit64,
}

impl DmaMask {
    /// Returns the maximum inclusive physical byte address addressable under this `DmaMask`.
    pub const fn max_phys_addr(self) -> u64 {
        match self {
            Self::Bit24 => 0x00FF_FFFF,
            Self::Bit32 => 0xFFFF_FFFF,
            Self::Bit64 => u64::MAX,
        }
    }

    /// Checks whether a buffer spanning `[phys_addr, phys_addr + size_bytes)` is directly
    /// reachable by hardware with this `DmaMask` without bounce buffering.
    pub const fn can_address_directly(self, phys_addr: u64, size_bytes: usize) -> bool {
        if size_bytes == 0 {
            return true;
        }
        let end_inclusive = phys_addr.saturating_add((size_bytes - 1) as u64);
        end_inclusive <= self.max_phys_addr()
    }
}

/// Direction of a streaming DMA transfer for cache/bounce synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

/// Active DMA mapping descriptor (either direct zero-copy or SWIOTLB bounced).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaMapping {
    pub orig_phys_addr: u64,
    pub dma_bus_addr: u64,
    pub size_bytes: usize,
    pub bounce_slot_start: Option<usize>,
    pub bounce_slot_count: usize,
    pub direction: DmaDirection,
}

impl DmaMapping {
    /// Returns `true` if this DMA mapping uses a SWIOTLB bounce buffer.
    pub const fn is_bounced(&self) -> bool {
        self.bounce_slot_start.is_some()
    }
}

/// Software IOMMU (`SWIOTLB`) low-memory bounce buffer aperture and coherent DMA pool.
#[derive(Debug, Clone)]
pub struct SwiotlbAperture {
    aperture_base_phys: u64,
    total_slots: usize,
    slot_used: Vec<bool>,
    bounce_copies_to_device: u64,
    bounce_copies_from_device: u64,
}

impl SwiotlbAperture {
    /// Creates a new `SwiotlbAperture` rooted at low physical address `aperture_base_phys`
    /// with `total_slots` of `2 KiB` each.
    pub fn new(aperture_base_phys: u64, total_slots: usize) -> Self {
        Self {
            aperture_base_phys,
            total_slots,
            slot_used: vec![false; total_slots],
            bounce_copies_to_device: 0,
            bounce_copies_from_device: 0,
        }
    }

    /// Maps a physical memory buffer `[orig_phys_addr, orig_phys_addr + size_bytes)` for
    /// a device with `device_mask`. Uses zero-copy direct mapping if reachable, or allocates
    /// contiguous `SWIOTLB` bounce slots if `orig_phys_addr` exceeds `device_mask`.
    pub fn map_single(
        &mut self,
        orig_phys_addr: u64,
        size_bytes: usize,
        device_mask: DmaMask,
        direction: DmaDirection,
    ) -> Result<DmaMapping, &'static str> {
        if size_bytes == 0 {
            return Err("DMA mapping size must be non-zero");
        }

        // Fast path: buffer is directly reachable by the device's DMA mask
        if device_mask.can_address_directly(orig_phys_addr, size_bytes) {
            return Ok(DmaMapping {
                orig_phys_addr,
                dma_bus_addr: orig_phys_addr,
                size_bytes,
                bounce_slot_start: None,
                bounce_slot_count: 0,
                direction,
            });
        }

        // Slow path: allocate contiguous 2 KiB bounce slots from SWIOTLB aperture
        let needed_slots = (size_bytes + SWIOTLB_SLOT_BYTES - 1) / SWIOTLB_SLOT_BYTES;
        let start_slot = self
            .alloc_contiguous_slots(needed_slots)
            .ok_or("SWIOTLB bounce aperture exhausted")?;

        let dma_bus_addr =
            self.aperture_base_phys + (start_slot * SWIOTLB_SLOT_BYTES) as u64;

        if !device_mask.can_address_directly(dma_bus_addr, size_bytes) {
            self.free_contiguous_slots(start_slot, needed_slots);
            return Err("SWIOTLB aperture itself exceeds device DMA mask");
        }

        if matches!(direction, DmaDirection::ToDevice | DmaDirection::Bidirectional) {
            self.bounce_copies_to_device += 1;
        }

        Ok(DmaMapping {
            orig_phys_addr,
            dma_bus_addr,
            size_bytes,
            bounce_slot_start: Some(start_slot),
            bounce_slot_count: needed_slots,
            direction,
        })
    }

    /// Unmaps a previously mapped `DmaMapping`, syncing bounce buffers back to high
    /// memory if `FromDevice` or `Bidirectional` and releasing SWIOTLB slots.
    pub fn unmap_single(&mut self, mapping: DmaMapping) -> bool {
        let Some(start_slot) = mapping.bounce_slot_start else {
            return true;
        };
        if matches!(
            mapping.direction,
            DmaDirection::FromDevice | DmaDirection::Bidirectional
        ) {
            self.bounce_copies_from_device += 1;
        }
        self.free_contiguous_slots(start_slot, mapping.bounce_slot_count)
    }

    fn alloc_contiguous_slots(&mut self, count: usize) -> Option<usize> {
        if count == 0 || count > self.total_slots {
            return None;
        }
        let limit = self.total_slots - count;
        'outer: for start in 0..=limit {
            for offset in 0..count {
                if self.slot_used[start + offset] {
                    continue 'outer;
                }
            }
            for offset in 0..count {
                self.slot_used[start + offset] = true;
            }
            return Some(start);
        }
        None
    }

    fn free_contiguous_slots(&mut self, start: usize, count: usize) -> bool {
        if start + count > self.total_slots {
            return false;
        }
        for offset in 0..count {
            self.slot_used[start + offset] = false;
        }
        true
    }

    /// Returns number of free 2 KiB SWIOTLB slots.
    pub fn free_slots(&self) -> usize {
        self.slot_used.iter().filter(|&&used| !used).count()
    }

    /// Returns total `ToDevice` bounce copy operations performed.
    pub const fn bounce_copies_to_device(&self) -> u64 {
        self.bounce_copies_to_device
    }

    /// Returns total `FromDevice` bounce copy operations performed.
    pub const fn bounce_copies_from_device(&self) -> u64 {
        self.bounce_copies_from_device
    }
}
