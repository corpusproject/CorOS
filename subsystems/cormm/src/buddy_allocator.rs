//! Physical Page Frame Buddy Allocator (`MAX_ORDER = 11`, orders `0..=10`).
//!
//! Manages physical memory frames in power-of-two blocks from `4 KiB` (Order 0)
//! up to `4 MiB` (Order 10) across Linux-style `MemoryZone` regions (`ZoneDma`,
//! `ZoneNormal`, `ZoneHighMem`) with `min`, `low`, and `high` watermarks.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// Base page frame size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Shift amount for converting between bytes and page frame numbers (PFNs).
pub const PAGE_SHIFT: usize = 12;

/// Number of allocation orders (`0..=10`, where Order 10 is 1024 pages = 4 MiB).
pub const MAX_ORDER: usize = 11;

/// Physical memory zone classification matching Linux kernel conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryZoneKind {
    /// ISA / legacy DMA region (`0..16 MiB`).
    ZoneDma,
    /// Directly mapped kernel normal memory (`16 MiB..896 MiB` or full RAM on 64-bit).
    ZoneNormal,
    /// High memory region requiring dynamic mappings where applicable.
    ZoneHighMem,
}

/// Watermark thresholds for a physical memory zone (expressed in 4 KiB pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneWatermarks {
    /// Minimum emergency reserve (only `PF_MEMALLOC` / OOM paths allowed below this).
    pub min_pages: usize,
    /// Threshold at which background reclaim (`kswapd`) is woken up.
    pub low_pages: usize,
    /// Target threshold at which `kswapd` goes back to sleep.
    pub high_pages: usize,
}

impl ZoneWatermarks {
    /// Computes Linux-like watermarks derived from managed page count.
    pub const fn from_managed_pages(managed_pages: usize) -> Self {
        let min_pages = if managed_pages >= 64 {
            managed_pages / 64
        } else {
            1
        };
        let half = min_pages / 2;
        let low_delta = if half > 1 { half } else { 1 };
        let low_pages = min_pages + low_delta;
        let high_pages = min_pages * 2;
        Self {
            min_pages,
            low_pages,
            high_pages,
        }
    }
}

/// Watermark check state for a memory zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkLevel {
    /// Free pages are above `high` watermark.
    Abundant,
    /// Free pages are between `low` and `high` watermarks.
    Normal,
    /// Free pages fell below `low` watermark; wake `kswapd`.
    NeedBackgroundReclaim,
    /// Free pages fell below `min` watermark; direct reclaim / OOM required.
    CriticalDirectReclaim,
}

/// Computes the XOR buddy Page Frame Number for a block at `pfn` with `order`.
#[inline]
pub const fn buddy_pfn(pfn: usize, order: usize) -> usize {
    pfn ^ (1usize << order)
}

/// Computes the combined parent PFN when merging `pfn` and its buddy at `order`.
#[inline]
pub const fn combined_parent_pfn(pfn: usize, order: usize) -> usize {
    pfn & !(1usize << order)
}

/// Returns whether `pfn` is naturally aligned for the given `order`.
#[inline]
pub const fn is_order_aligned(pfn: usize, order: usize) -> bool {
    (pfn & ((1usize << order) - 1)) == 0
}

/// Statistics snapshot for a `MemoryZone` buddy allocator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuddyZoneStats {
    pub zone_kind: MemoryZoneKind,
    pub start_pfn: usize,
    pub managed_pages: usize,
    pub free_pages: usize,
    pub watermarks: ZoneWatermarks,
    pub free_blocks_per_order: [usize; MAX_ORDER],
    pub total_allocations: u64,
    pub total_frees: u64,
    pub split_events: u64,
    pub coalesce_events: u64,
}

/// Physical page frame Buddy Allocator for a single `MemoryZone`.
#[derive(Debug, Clone)]
pub struct MemoryZone {
    zone_kind: MemoryZoneKind,
    start_pfn: usize,
    end_pfn: usize,
    managed_pages: usize,
    free_pages: usize,
    watermarks: ZoneWatermarks,
    free_lists: [BTreeSet<usize>; MAX_ORDER],
    total_allocations: u64,
    total_frees: u64,
    split_events: u64,
    coalesce_events: u64,
}

impl MemoryZone {
    /// Creates a new `MemoryZone` covering `[start_pfn, end_pfn)` and populates
    /// the buddy free lists with maximal aligned blocks.
    pub fn new(zone_kind: MemoryZoneKind, start_pfn: usize, end_pfn: usize) -> Self {
        let managed_pages = end_pfn.saturating_sub(start_pfn);
        let watermarks = ZoneWatermarks::from_managed_pages(managed_pages);
        let free_lists: [BTreeSet<usize>; MAX_ORDER] = core::array::from_fn(|_| BTreeSet::new());

        let mut zone = Self {
            zone_kind,
            start_pfn,
            end_pfn,
            managed_pages,
            free_pages: 0,
            watermarks,
            free_lists,
            total_allocations: 0,
            total_frees: 0,
            split_events: 0,
            coalesce_events: 0,
        };

        zone.populate_initial_range(start_pfn, end_pfn);
        zone
    }

    /// Populates `[start_pfn, end_pfn)` into maximal power-of-two blocks.
    fn populate_initial_range(&mut self, mut cursor: usize, end_pfn: usize) {
        while cursor < end_pfn {
            let remaining = end_pfn - cursor;
            let mut best_order = 0usize;
            for order in (0..MAX_ORDER).rev() {
                let pages = 1usize << order;
                if pages <= remaining && is_order_aligned(cursor, order) {
                    best_order = order;
                    break;
                }
            }
            self.free_lists[best_order].insert(cursor);
            let block_pages = 1usize << best_order;
            self.free_pages += block_pages;
            cursor += block_pages;
        }
    }

    /// Returns the zone kind.
    pub const fn kind(&self) -> MemoryZoneKind {
        self.zone_kind
    }

    /// Returns current free page count.
    pub const fn free_page_count(&self) -> usize {
        self.free_pages
    }

    /// Returns total managed pages in this zone.
    pub const fn managed_pages(&self) -> usize {
        self.managed_pages
    }

    /// Returns zone watermarks.
    pub const fn watermarks(&self) -> ZoneWatermarks {
        self.watermarks
    }

    /// Evaluates the current watermark state of this zone.
    pub const fn evaluate_watermark(&self) -> WatermarkLevel {
        if self.free_pages >= self.watermarks.high_pages {
            WatermarkLevel::Abundant
        } else if self.free_pages >= self.watermarks.low_pages {
            WatermarkLevel::Normal
        } else if self.free_pages >= self.watermarks.min_pages {
            WatermarkLevel::NeedBackgroundReclaim
        } else {
            WatermarkLevel::CriticalDirectReclaim
        }
    }

    /// Checks whether an allocation of `order` pages can proceed given `allow_reserve`.
    pub const fn watermark_ok(&self, order: usize, allow_reserve: bool) -> bool {
        if order >= MAX_ORDER {
            return false;
        }
        let needed = 1usize << order;
        if self.free_pages < needed {
            return false;
        }
        let remaining = self.free_pages - needed;
        if allow_reserve {
            true
        } else {
            remaining >= self.watermarks.min_pages
        }
    }

    /// Allocates a contiguous block of `2^order` physical pages, returning the base PFN.
    pub fn alloc_pages(&mut self, order: usize, allow_reserve: bool) -> Option<usize> {
        if !self.watermark_ok(order, allow_reserve) {
            return None;
        }

        let mut found_order = None;
        for candidate_order in order..MAX_ORDER {
            if !self.free_lists[candidate_order].is_empty() {
                found_order = Some(candidate_order);
                break;
            }
        }

        let current_order = found_order?;
        let base_pfn = *self.free_lists[current_order].iter().next()?;
        self.free_lists[current_order].remove(&base_pfn);

        // Split down from `current_order` to `order`, placing upper buddies on free lists.
        let mut split_order = current_order;
        while split_order > order {
            split_order -= 1;
            let upper_buddy = base_pfn + (1usize << split_order);
            self.free_lists[split_order].insert(upper_buddy);
            self.split_events += 1;
        }

        let allocated_pages = 1usize << order;
        self.free_pages = self.free_pages.saturating_sub(allocated_pages);
        self.total_allocations += 1;
        Some(base_pfn)
    }

    /// Frees a previously allocated block of `2^order` pages at `pfn` and coalesces
    /// with free XOR buddies up to `MAX_ORDER - 1`.
    pub fn free_pages(&mut self, pfn: usize, order: usize) -> bool {
        if order >= MAX_ORDER || !is_order_aligned(pfn, order) {
            return false;
        }
        let block_pages = 1usize << order;
        if pfn < self.start_pfn || pfn.saturating_add(block_pages) > self.end_pfn {
            return false;
        }

        let mut cur_pfn = pfn;
        let mut cur_order = order;

        while cur_order + 1 < MAX_ORDER {
            let buddy = buddy_pfn(cur_pfn, cur_order);
            let buddy_end = buddy.saturating_add(1usize << cur_order);
            if buddy < self.start_pfn || buddy_end > self.end_pfn {
                break;
            }
            if self.free_lists[cur_order].remove(&buddy) {
                cur_pfn = combined_parent_pfn(cur_pfn, cur_order);
                cur_order += 1;
                self.coalesce_events += 1;
            } else {
                break;
            }
        }

        self.free_lists[cur_order].insert(cur_pfn);
        self.free_pages += block_pages;
        self.total_frees += 1;
        true
    }

    /// Captures a snapshot of zone statistics.
    pub fn stats(&self) -> BuddyZoneStats {
        let mut free_blocks_per_order = [0usize; MAX_ORDER];
        for (idx, set) in self.free_lists.iter().enumerate() {
            free_blocks_per_order[idx] = set.len();
        }
        BuddyZoneStats {
            zone_kind: self.zone_kind,
            start_pfn: self.start_pfn,
            managed_pages: self.managed_pages,
            free_pages: self.free_pages,
            watermarks: self.watermarks,
            free_blocks_per_order,
            total_allocations: self.total_allocations,
            total_frees: self.total_frees,
            split_events: self.split_events,
            coalesce_events: self.coalesce_events,
        }
    }
}

/// Multi-zone Physical Buddy Allocator coordinating `ZoneDma`, `ZoneNormal`, and `ZoneHighMem`.
#[derive(Debug, Clone)]
pub struct PhysicalBuddyAllocator {
    zones: Vec<MemoryZone>,
}

impl PhysicalBuddyAllocator {
    /// Creates a new multi-zone buddy allocator from zone descriptors.
    pub fn new(zones: Vec<MemoryZone>) -> Self {
        Self { zones }
    }

    /// Creates a standard 3-zone physical memory layout for testing or early boot.
    pub fn new_standard_layout(dma_pages: usize, normal_pages: usize, highmem_pages: usize) -> Self {
        let mut zones = Vec::with_capacity(3);
        let dma_end = dma_pages;
        let normal_end = dma_end + normal_pages;
        let highmem_end = normal_end + highmem_pages;

        if dma_pages > 0 {
            zones.push(MemoryZone::new(MemoryZoneKind::ZoneDma, 0, dma_end));
        }
        if normal_pages > 0 {
            zones.push(MemoryZone::new(MemoryZoneKind::ZoneNormal, dma_end, normal_end));
        }
        if highmem_pages > 0 {
            zones.push(MemoryZone::new(
                MemoryZoneKind::ZoneHighMem,
                normal_end,
                highmem_end,
            ));
        }
        Self { zones }
    }

    /// Allocates `2^order` pages from `preferred_zone` with automatic fallback to lower zones.
    pub fn alloc_from_zone(
        &mut self,
        preferred_zone: MemoryZoneKind,
        order: usize,
        allow_reserve: bool,
    ) -> Option<(MemoryZoneKind, usize)> {
        // Fallback priority: HighMem -> Normal -> Dma
        for zone in self.zones.iter_mut().rev() {
            if zone.kind() <= preferred_zone {
                if let Some(pfn) = zone.alloc_pages(order, allow_reserve) {
                    return Some((zone.kind(), pfn));
                }
            }
        }
        None
    }

    /// Frees `2^order` pages starting at `pfn` into whichever zone owns `pfn`.
    pub fn free_to_owning_zone(&mut self, pfn: usize, order: usize) -> bool {
        for zone in &mut self.zones {
            if pfn >= zone.start_pfn && pfn < zone.end_pfn {
                return zone.free_pages(pfn, order);
            }
        }
        false
    }

    /// Returns total free pages across all zones.
    pub fn total_free_pages(&self) -> usize {
        self.zones.iter().map(MemoryZone::free_page_count).sum()
    }

    /// Borrows the underlying zones slice.
    pub fn zones(&self) -> &[MemoryZone] {
        &self.zones
    }
}
