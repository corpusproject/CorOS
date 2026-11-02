//! Virtual Memory Area (`VmArea`, `VmaFlags`, `VmaType`) Interval Manager.
//!
//! Manages ordered process virtual address space intervals (`[start, end)`),
//! supporting top-down and bottom-up `find_unmapped_area`, adjacent VMA merging
//! (`can_merge`), boundary splitting on partial `munmap`/`mprotect`, and stack
//! guard page enforcement.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Base page alignment (4 KiB) for all VMA boundaries.
pub const VMA_PAGE_SIZE: u64 = 4096;

/// Access permissions and behavior flags for a `VmArea`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaFlags(u32);

impl VmaFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const SHARED: Self = Self(1 << 3);
    pub const GROWS_DOWN: Self = Self(1 << 4);
    pub const LOCKED: Self = Self(1 << 5);
    pub const DONTDUMP: Self = Self(1 << 6);

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Semantic backing classification of a `VmArea`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaType {
    /// Anonymous zero-filled memory (`mmap(MAP_ANONYMOUS)` / `brk`).
    Anonymous,
    /// File-backed mapping with an inode identifier.
    FileBacked { inode_id: u64 },
    /// User thread stack with automatic downward guard page protection.
    UserStack,
    /// Shared POSIX / SysV IPC segment.
    SharedMemory,
    /// Device MMIO aperture mapping.
    DeviceMmio,
}

/// Contiguous Virtual Memory Area covering `[start_vaddr, end_vaddr)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmArea {
    pub start_vaddr: u64,
    pub end_vaddr: u64,
    pub flags: VmaFlags,
    pub vma_type: VmaType,
    /// Backing file offset in bytes (`0` for anonymous mappings).
    pub file_offset: u64,
    /// Number of guard pages reserved at the low end of a `UserStack` VMA.
    pub guard_pages: u32,
}

impl VmArea {
    /// Creates a new page-aligned `VmArea`.
    pub const fn new(
        start_vaddr: u64,
        end_vaddr: u64,
        flags: VmaFlags,
        vma_type: VmaType,
        file_offset: u64,
        guard_pages: u32,
    ) -> Self {
        Self {
            start_vaddr,
            end_vaddr,
            flags,
            vma_type,
            file_offset,
            guard_pages,
        }
    }

    /// Length of the VMA in bytes (including any leading stack guard pages).
    pub const fn size_bytes(&self) -> u64 {
        self.end_vaddr.saturating_sub(self.start_vaddr)
    }

    /// Returns `true` if `vaddr` falls within `[start_vaddr, end_vaddr)`.
    pub const fn contains_addr(&self, vaddr: u64) -> bool {
        vaddr >= self.start_vaddr && vaddr < self.end_vaddr
    }

    /// Returns `true` if `vaddr` hits the protected stack guard region at the bottom of a stack VMA.
    pub const fn is_in_stack_guard(&self, vaddr: u64) -> bool {
        if self.guard_pages == 0 {
            return false;
        }
        let guard_end = self.start_vaddr + (self.guard_pages as u64) * VMA_PAGE_SIZE;
        vaddr >= self.start_vaddr && vaddr < guard_end
    }

    /// Checks whether `self` and `right` are immediately adjacent and have compatible
    /// attributes so they can be coalesced into a single `VmArea`.
    pub fn can_merge(&self, right: &VmArea) -> bool {
        if self.end_vaddr != right.start_vaddr {
            return false;
        }
        if self.flags != right.flags
            || self.vma_type != right.vma_type
            || self.guard_pages != 0
            || right.guard_pages != 0
        {
            return false;
        }
        match self.vma_type {
            VmaType::Anonymous | VmaType::SharedMemory => true,
            VmaType::FileBacked { .. } => self.file_offset + self.size_bytes() == right.file_offset,
            VmaType::UserStack | VmaType::DeviceMmio => false,
        }
    }
}

/// Ordered Virtual Address Space manager (`mm_struct` VMA tree equivalent).
#[derive(Debug, Clone)]
pub struct VmaIntervalTree {
    mmap_min_addr: u64,
    mmap_max_addr: u64,
    areas: BTreeMap<u64, VmArea>,
}

impl VmaIntervalTree {
    /// Creates a new VMA manager spanning `[mmap_min_addr, mmap_max_addr)`.
    pub fn new(mmap_min_addr: u64, mmap_max_addr: u64) -> Self {
        Self {
            mmap_min_addr: mmap_min_addr & !(VMA_PAGE_SIZE - 1),
            mmap_max_addr: mmap_max_addr & !(VMA_PAGE_SIZE - 1),
            areas: BTreeMap::new(),
        }
    }

    /// Bottom-up search for an unmapped gap of `len_bytes` starting at or above `hint_addr`.
    pub fn find_unmapped_area_bottom_up(&self, hint_addr: u64, len_bytes: u64) -> Option<u64> {
        let aligned_len = (len_bytes + VMA_PAGE_SIZE - 1) & !(VMA_PAGE_SIZE - 1);
        if aligned_len == 0 {
            return None;
        }
        let mut candidate = hint_addr.max(self.mmap_min_addr) & !(VMA_PAGE_SIZE - 1);

        for area in self.areas.values() {
            if candidate + aligned_len <= area.start_vaddr {
                return Some(candidate);
            }
            if candidate < area.end_vaddr {
                candidate = area.end_vaddr;
            }
        }

        if candidate.saturating_add(aligned_len) <= self.mmap_max_addr {
            Some(candidate)
        } else {
            None
        }
    }

    /// Top-down search for an unmapped gap of `len_bytes` below `high_limit`.
    pub fn find_unmapped_area_top_down(&self, high_limit: u64, len_bytes: u64) -> Option<u64> {
        let aligned_len = (len_bytes + VMA_PAGE_SIZE - 1) & !(VMA_PAGE_SIZE - 1);
        if aligned_len == 0 {
            return None;
        }
        let mut ceiling = high_limit.min(self.mmap_max_addr) & !(VMA_PAGE_SIZE - 1);
        if ceiling < self.mmap_min_addr + aligned_len {
            return None;
        }

        for area in self.areas.values().rev() {
            if area.end_vaddr <= ceiling {
                if ceiling - area.end_vaddr >= aligned_len {
                    return Some(ceiling - aligned_len);
                }
                ceiling = area.start_vaddr;
            } else if area.start_vaddr < ceiling {
                ceiling = area.start_vaddr;
            }
            if ceiling < self.mmap_min_addr + aligned_len {
                return None;
            }
        }

        if ceiling - self.mmap_min_addr >= aligned_len {
            Some(ceiling - aligned_len)
        } else {
            None
        }
    }

    /// Inserts a `VmArea` (failing if it overlaps any existing VMA) and merges with
    /// left and/or right adjacent neighbors when `can_merge` holds.
    pub fn insert_and_merge(&mut self, mut new_vma: VmArea) -> Result<VmArea, &'static str> {
        if new_vma.start_vaddr >= new_vma.end_vaddr
            || (new_vma.start_vaddr & (VMA_PAGE_SIZE - 1)) != 0
            || (new_vma.end_vaddr & (VMA_PAGE_SIZE - 1)) != 0
        {
            return Err("Invalid or unaligned VMA bounds");
        }
        if new_vma.start_vaddr < self.mmap_min_addr || new_vma.end_vaddr > self.mmap_max_addr {
            return Err("VMA outside address space bounds");
        }

        // Overlap check
        for existing in self.areas.values() {
            if new_vma.start_vaddr < existing.end_vaddr && existing.start_vaddr < new_vma.end_vaddr
            {
                return Err("VMA overlaps an existing mapping");
            }
        }

        // Check left neighbor for merge
        if let Some((&left_start, left_vma)) = self.areas.range(..new_vma.start_vaddr).next_back() {
            if left_vma.can_merge(&new_vma) {
                let mut merged = left_vma.clone();
                merged.end_vaddr = new_vma.end_vaddr;
                self.areas.remove(&left_start);
                new_vma = merged;
            }
        }

        // Check right neighbor for merge
        if let Some((&right_start, right_vma)) = self.areas.range(new_vma.end_vaddr..).next() {
            if new_vma.can_merge(right_vma) {
                new_vma.end_vaddr = right_vma.end_vaddr;
                self.areas.remove(&right_start);
            }
        }

        self.areas.insert(new_vma.start_vaddr, new_vma.clone());
        Ok(new_vma)
    }

    /// Unmaps `[unmap_start, unmap_end)`, truncating or splitting any VMA that straddles
    /// the boundary (`munmap` semantics).
    pub fn munmap_range(&mut self, unmap_start: u64, unmap_end: u64) -> usize {
        if unmap_start >= unmap_end {
            return 0;
        }
        let affected_keys: Vec<u64> = self
            .areas
            .values()
            .filter(|vma| vma.start_vaddr < unmap_end && unmap_start < vma.end_vaddr)
            .map(|vma| vma.start_vaddr)
            .collect();

        let mut modified = 0usize;
        for key in affected_keys {
            if let Some(vma) = self.areas.remove(&key) {
                modified += 1;
                // Left remainder
                if vma.start_vaddr < unmap_start {
                    let mut left = vma.clone();
                    left.end_vaddr = unmap_start;
                    self.areas.insert(left.start_vaddr, left);
                }
                // Right remainder
                if vma.end_vaddr > unmap_end {
                    let mut right = vma.clone();
                    let delta = unmap_end - vma.start_vaddr;
                    right.start_vaddr = unmap_end;
                    if matches!(right.vma_type, VmaType::FileBacked { .. }) {
                        right.file_offset += delta;
                    }
                    right.guard_pages = 0;
                    self.areas.insert(right.start_vaddr, right);
                }
            }
        }
        modified
    }

    /// Changes protection flags on `[prot_start, prot_end)`, splitting VMAs at boundaries
    /// and coalescing adjacent compatible regions (`mprotect` semantics).
    pub fn mprotect_range(
        &mut self,
        prot_start: u64,
        prot_end: u64,
        new_flags: VmaFlags,
    ) -> Result<usize, &'static str> {
        if prot_start >= prot_end {
            return Err("Empty mprotect range");
        }
        let affected_keys: Vec<u64> = self
            .areas
            .values()
            .filter(|vma| vma.start_vaddr < prot_end && prot_start < vma.end_vaddr)
            .map(|vma| vma.start_vaddr)
            .collect();

        let mut new_pieces = Vec::new();
        for key in &affected_keys {
            if let Some(vma) = self.areas.remove(key) {
                if vma.start_vaddr < prot_start {
                    let mut left = vma.clone();
                    left.end_vaddr = prot_start;
                    new_pieces.push(left);
                }
                let mid_start = vma.start_vaddr.max(prot_start);
                let mid_end = vma.end_vaddr.min(prot_end);
                let mut mid = vma.clone();
                mid.start_vaddr = mid_start;
                mid.end_vaddr = mid_end;
                mid.flags = new_flags;
                if mid_start > vma.start_vaddr
                    && matches!(mid.vma_type, VmaType::FileBacked { .. })
                {
                    mid.file_offset += mid_start - vma.start_vaddr;
                }
                new_pieces.push(mid);

                if vma.end_vaddr > prot_end {
                    let mut right = vma.clone();
                    right.start_vaddr = prot_end;
                    if matches!(right.vma_type, VmaType::FileBacked { .. }) {
                        right.file_offset += prot_end - vma.start_vaddr;
                    }
                    new_pieces.push(right);
                }
            }
        }

        for piece in new_pieces {
            let _ = self.insert_and_merge(piece)?;
        }
        Ok(affected_keys.len())
    }

    /// Looks up the `VmArea` containing `vaddr`.
    pub fn find_vma(&self, vaddr: u64) -> Option<&VmArea> {
        let (_, vma) = self.areas.range(..=vaddr).next_back()?;
        if vma.contains_addr(vaddr) {
            Some(vma)
        } else {
            None
        }
    }

    /// Returns the number of distinct VMAs currently in the address space.
    pub fn vma_count(&self) -> usize {
        self.areas.len()
    }
}
