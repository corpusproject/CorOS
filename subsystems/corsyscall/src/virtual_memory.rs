//! CorOS Syscall Domain Module: `virtual_memory`
//! Virtual memory management: `mmap`, `munmap`, `mprotect`, `brk`, `mremap`, `madvise`, `mlock`, `msync`, and page fault classification.

use alloc::vec::Vec;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

pub const EINVAL: i64 = -22;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EEXIST: i64 = -17;
pub const EFAULT: i64 = -14;

/// Memory protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmProt(pub u32);

impl VmProt {
    pub const NONE: Self = Self(0x0);
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    pub const EXEC: Self = Self(0x4);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn is_valid(self) -> bool {
        (self.0 & !0x7) == 0
    }
}

/// Memory mapping flags (`MAP_SHARED`, `MAP_PRIVATE`, `MAP_FIXED`, `MAP_ANONYMOUS`, etc.).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapFlags(pub u32);

impl MmapFlags {
    pub const SHARED: Self = Self(0x01);
    pub const PRIVATE: Self = Self(0x02);
    pub const FIXED: Self = Self(0x10);
    pub const ANONYMOUS: Self = Self(0x20);
    pub const GROWSDOWN: Self = Self(0x0100);
    pub const LOCKED: Self = Self(0x2000);
    pub const POPULATE: Self = Self(0x8000);
    pub const FIXED_NOREPLACE: Self = Self(0x10_0000);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// `madvise` behavior hints.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadviseBehavior {
    Normal = 0,
    Random = 1,
    Sequential = 2,
    WillNeed = 3,
    DontNeed = 4,
    Free = 8,
    DontFork = 10,
    DoFork = 11,
    HugePage = 14,
    NoHugePage = 15,
}

impl MadviseBehavior {
    pub const fn from_raw(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Normal),
            1 => Some(Self::Random),
            2 => Some(Self::Sequential),
            3 => Some(Self::WillNeed),
            4 => Some(Self::DontNeed),
            8 => Some(Self::Free),
            10 => Some(Self::DontFork),
            11 => Some(Self::DoFork),
            14 => Some(Self::HugePage),
            15 => Some(Self::NoHugePage),
            _ => None,
        }
    }
}

/// Hardware page fault resolution action returned by the VMA fault classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFaultResolution {
    DemandZeroAllocate { vaddr_page: u64, prot: VmProt },
    CopyOnWriteBreak { vaddr_page: u64, prot: VmProt },
    FilePageIn { vaddr_page: u64, fd: i32, file_offset: u64 },
    SegmentationViolation,
    ProtectionViolation,
}

/// Contiguous Virtual Memory Area (VMA) descriptor inside a process `AddressSpace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub prot: VmProt,
    pub flags: MmapFlags,
    pub backing_fd: i32,
    pub file_offset: u64,
    pub locked: bool,
    pub advise: MadviseBehavior,
    pub dirty_pages: u32,
}

impl VmArea {
    #[inline]
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    #[inline]
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

#[inline]
pub const fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}

#[inline]
pub const fn is_page_aligned(val: u64) -> bool {
    (val & (PAGE_SIZE - 1)) == 0
}

/// Per-process Virtual Address Space managing VMAs, program break (`brk`), and page locks.
pub struct AddressSpace {
    vmas: Vec<VmArea>,
    pub brk_start: u64,
    pub brk_current: u64,
    pub brk_limit: u64,
    pub mmap_base: u64,
    pub locked_pages: u64,
    pub max_locked_pages: u64,
}

impl AddressSpace {
    pub fn new(brk_start: u64, brk_limit: u64, mmap_base: u64, max_locked_pages: u64) -> Self {
        Self {
            vmas: Vec::new(),
            brk_start: page_align_up(brk_start),
            brk_current: page_align_up(brk_start),
            brk_limit: page_align_up(brk_limit),
            mmap_base: page_align_up(mmap_base),
            locked_pages: 0,
            max_locked_pages,
        }
    }

    pub fn vma_count(&self) -> usize {
        self.vmas.len()
    }

    pub fn find_vma(&self, addr: u64) -> Option<&VmArea> {
        self.vmas.iter().find(|v| addr >= v.start && addr < v.end)
    }

    fn find_free_gap(&self, len: u64) -> u64 {
        let mut candidate = self.mmap_base;
        loop {
            let candidate_end = candidate + len;
            let mut conflict = None;
            for vma in &self.vmas {
                if vma.overlaps(candidate, candidate_end) {
                    conflict = Some(vma.end);
                    break;
                }
            }
            match conflict {
                Some(next_addr) => candidate = page_align_up(next_addr),
                None => return candidate,
            }
        }
    }

    /// `sys_mmap`: Maps anonymous or file-backed virtual memory pages.
    pub fn sys_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: VmProt,
        flags: MmapFlags,
        fd: i32,
        offset: u64,
    ) -> i64 {
        if len == 0 || !prot.is_valid() || !is_page_aligned(offset) {
            return EINVAL;
        }
        let shared = flags.contains(MmapFlags::SHARED);
        let private = flags.contains(MmapFlags::PRIVATE);
        if shared == private {
            return EINVAL; // Must specify exactly one of MAP_SHARED or MAP_PRIVATE
        }

        let aligned_len = page_align_up(len);
        let map_start = if flags.contains(MmapFlags::FIXED) || flags.contains(MmapFlags::FIXED_NOREPLACE) {
            if !is_page_aligned(addr) || addr == 0 {
                return EINVAL;
            }
            let map_end = addr + aligned_len;
            let has_overlap = self.vmas.iter().any(|v| v.overlaps(addr, map_end));
            if has_overlap {
                if flags.contains(MmapFlags::FIXED_NOREPLACE) {
                    return EEXIST;
                }
                let _ = self.sys_munmap(addr, aligned_len);
            }
            addr
        } else if addr != 0 && is_page_aligned(addr) {
            let map_end = addr + aligned_len;
            if !self.vmas.iter().any(|v| v.overlaps(addr, map_end)) {
                addr
            } else {
                self.find_free_gap(aligned_len)
            }
        } else {
            self.find_free_gap(aligned_len)
        };

        let locked = flags.contains(MmapFlags::LOCKED);
        if locked {
            let pages = aligned_len / PAGE_SIZE;
            if self.locked_pages + pages > self.max_locked_pages {
                return ENOMEM;
            }
            self.locked_pages += pages;
        }

        let vma = VmArea {
            start: map_start,
            end: map_start + aligned_len,
            prot,
            flags,
            backing_fd: if flags.contains(MmapFlags::ANONYMOUS) { -1 } else { fd },
            file_offset: if flags.contains(MmapFlags::ANONYMOUS) { 0 } else { offset },
            locked,
            advise: MadviseBehavior::Normal,
            dirty_pages: 0,
        };

        self.vmas.push(vma);
        self.vmas.sort_by_key(|v| v.start);
        map_start as i64
    }

    /// `sys_munmap`: Unmaps virtual pages across `[addr, addr + len)`, splitting VMAs if needed.
    pub fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        if !is_page_aligned(addr) || len == 0 {
            return EINVAL;
        }
        let unmap_start = addr;
        let unmap_end = addr + page_align_up(len);
        let mut updated = Vec::with_capacity(self.vmas.len());

        for vma in self.vmas.drain(..) {
            if !vma.overlaps(unmap_start, unmap_end) {
                updated.push(vma);
                continue;
            }
            // Account for unlocked pages in the unmapped overlap
            let overlap_start = vma.start.max(unmap_start);
            let overlap_end = vma.end.min(unmap_end);
            if vma.locked && overlap_end > overlap_start {
                let freed_pages = (overlap_end - overlap_start) / PAGE_SIZE;
                self.locked_pages = self.locked_pages.saturating_sub(freed_pages);
            }

            if vma.start < unmap_start {
                let mut left = vma;
                left.end = unmap_start;
                updated.push(left);
            }
            if vma.end > unmap_end {
                let mut right = vma;
                let shift = unmap_end - vma.start;
                right.start = unmap_end;
                if right.backing_fd >= 0 {
                    right.file_offset += shift;
                }
                updated.push(right);
            }
        }

        self.vmas = updated;
        0
    }

    /// `sys_mprotect`: Changes protection flags on `[addr, addr + len)`, splitting VMAs at boundaries.
    pub fn sys_mprotect(&mut self, addr: u64, len: u64, new_prot: VmProt) -> i64 {
        if !is_page_aligned(addr) || len == 0 || !new_prot.is_valid() {
            return EINVAL;
        }
        let prot_start = addr;
        let prot_end = addr + page_align_up(len);

        let mut covered = false;
        let mut updated = Vec::with_capacity(self.vmas.len() + 2);

        for vma in self.vmas.drain(..) {
            if !vma.overlaps(prot_start, prot_end) {
                updated.push(vma);
                continue;
            }
            covered = true;
            if vma.start < prot_start {
                let mut left = vma;
                left.end = prot_start;
                updated.push(left);
            }
            let mid_start = vma.start.max(prot_start);
            let mid_end = vma.end.min(prot_end);
            let mut mid = vma;
            mid.start = mid_start;
            mid.end = mid_end;
            mid.prot = new_prot;
            if mid.backing_fd >= 0 {
                mid.file_offset += mid_start - vma.start;
            }
            updated.push(mid);

            if vma.end > prot_end {
                let mut right = vma;
                right.start = prot_end;
                if right.backing_fd >= 0 {
                    right.file_offset += prot_end - vma.start;
                }
                updated.push(right);
            }
        }

        self.vmas = updated;
        if covered { 0 } else { ENOMEM }
    }

    /// `sys_brk`: Queries or adjusts the program data segment break.
    pub fn sys_brk(&mut self, new_brk: u64) -> u64 {
        if new_brk == 0 || new_brk < self.brk_start || new_brk > self.brk_limit {
            return self.brk_current;
        }
        self.brk_current = page_align_up(new_brk);
        self.brk_current
    }

    /// `sys_mremap`: Expands or shrinks an existing mapping in place or relocates if allowed.
    pub fn sys_mremap(&mut self, old_addr: u64, old_size: u64, new_size: u64, may_move: bool) -> i64 {
        if !is_page_aligned(old_addr) || old_size == 0 || new_size == 0 {
            return EINVAL;
        }
        let aligned_old = page_align_up(old_size);
        let aligned_new = page_align_up(new_size);

        let idx = match self.vmas.iter().position(|v| v.start == old_addr && v.size() == aligned_old) {
            Some(i) => i,
            None => return EFAULT,
        };

        if aligned_new <= aligned_old {
            self.vmas[idx].end = old_addr + aligned_new;
            return old_addr as i64;
        }

        let target_end = old_addr + aligned_new;
        let in_place_conflict = self
            .vmas
            .iter()
            .enumerate()
            .any(|(i, v)| i != idx && v.overlaps(old_addr, target_end));

        if !in_place_conflict {
            self.vmas[idx].end = target_end;
            old_addr as i64
        } else if may_move {
            let mut moved = self.vmas.remove(idx);
            let new_start = self.find_free_gap(aligned_new);
            moved.start = new_start;
            moved.end = new_start + aligned_new;
            self.vmas.push(moved);
            self.vmas.sort_by_key(|v| v.start);
            new_start as i64
        } else {
            ENOMEM
        }
    }

    /// `sys_madvise`: Applies paging behavior advice to overlapping VMAs.
    pub fn sys_madvise(&mut self, addr: u64, len: u64, raw_behavior: u32) -> i64 {
        if !is_page_aligned(addr) || len == 0 {
            return EINVAL;
        }
        let behavior = match MadviseBehavior::from_raw(raw_behavior) {
            Some(b) => b,
            None => return EINVAL,
        };
        let end = addr + page_align_up(len);
        let mut matched = false;
        for vma in &mut self.vmas {
            if vma.overlaps(addr, end) {
                vma.advise = behavior;
                if behavior == MadviseBehavior::DontNeed || behavior == MadviseBehavior::Free {
                    vma.dirty_pages = 0;
                }
                matched = true;
            }
        }
        if matched { 0 } else { ENOMEM }
    }

    /// `sys_mlock`: Pins pages of overlapping VMAs in physical RAM.
    pub fn sys_mlock(&mut self, addr: u64, len: u64) -> i64 {
        if !is_page_aligned(addr) || len == 0 {
            return EINVAL;
        }
        let end = addr + page_align_up(len);
        for vma in &mut self.vmas {
            if vma.overlaps(addr, end) && !vma.locked {
                let pages = vma.size() / PAGE_SIZE;
                if self.locked_pages + pages > self.max_locked_pages {
                    return ENOMEM;
                }
                vma.locked = true;
                self.locked_pages += pages;
            }
        }
        0
    }

    /// `sys_msync`: Flushes dirty pages in shared file-backed mappings.
    pub fn sys_msync(&mut self, addr: u64, len: u64) -> i64 {
        if !is_page_aligned(addr) || len == 0 {
            return EINVAL;
        }
        let end = addr + page_align_up(len);
        let mut found = false;
        for vma in &mut self.vmas {
            if vma.overlaps(addr, end) {
                vma.dirty_pages = 0;
                found = true;
            }
        }
        if found { 0 } else { ENOMEM }
    }

    /// Classifies a hardware page fault at `fault_addr` for the given access type.
    pub fn classify_page_fault(&mut self, fault_addr: u64, is_write: bool, is_exec: bool) -> PageFaultResolution {
        let page_addr = fault_addr & PAGE_MASK;
        let vma = match self.vmas.iter_mut().find(|v| fault_addr >= v.start && fault_addr < v.end) {
            Some(v) => v,
            None => return PageFaultResolution::SegmentationViolation,
        };

        if is_exec && !vma.prot.contains(VmProt::EXEC) {
            return PageFaultResolution::ProtectionViolation;
        }
        if is_write {
            if !vma.prot.contains(VmProt::WRITE) {
                if vma.flags.contains(MmapFlags::PRIVATE) && vma.prot.contains(VmProt::READ) {
                    return PageFaultResolution::CopyOnWriteBreak {
                        vaddr_page: page_addr,
                        prot: vma.prot.union(VmProt::WRITE),
                    };
                }
                return PageFaultResolution::ProtectionViolation;
            }
            vma.dirty_pages = vma.dirty_pages.saturating_add(1);
        } else if !vma.prot.contains(VmProt::READ) {
            return PageFaultResolution::ProtectionViolation;
        }

        if vma.backing_fd >= 0 {
            let offset = vma.file_offset + (page_addr - vma.start);
            PageFaultResolution::FilePageIn {
                vaddr_page: page_addr,
                fd: vma.backing_fd,
                file_offset: offset,
            }
        } else {
            PageFaultResolution::DemandZeroAllocate {
                vaddr_page: page_addr,
                prot: vma.prot,
            }
        }
    }
}

/// Runs comprehensive self-tests on `virtual_memory` structs and VMA algorithms.
pub fn verify_domain_virtual_memory() -> u32 {
    let mut passed = 0u32;
    let mut aspace = AddressSpace::new(0x0040_0000, 0x0100_0000, 0x7000_0000, 128);

    // 1. Test brk expansion
    let new_brk = aspace.sys_brk(0x0040_3500);
    if new_brk == 0x0040_4000 {
        passed += 1;
    }

    // 2. Test anonymous mmap of 4 pages (16 KiB)
    let rw_prot = VmProt::READ.union(VmProt::WRITE);
    let anon_flags = MmapFlags::PRIVATE.union(MmapFlags::ANONYMOUS);
    let addr = aspace.sys_mmap(0, 4 * PAGE_SIZE, rw_prot, anon_flags, -1, 0);
    if addr == 0x7000_0000 {
        passed += 1;
    }

    // 3. Test mprotect splitting the middle 2 pages into READ-only
    if aspace.sys_mprotect(0x7000_1000, 2 * PAGE_SIZE, VmProt::READ) == 0 && aspace.vma_count() == 3 {
        passed += 1;
    }

    // 4. Test page fault classification on COW private read-only VMA vs RW VMA
    let cow_fault = aspace.classify_page_fault(0x7000_1500, true, false);
    if matches!(cow_fault, PageFaultResolution::CopyOnWriteBreak { vaddr_page: 0x7000_1000, .. }) {
        passed += 1;
    }
    let demand_fault = aspace.classify_page_fault(0x7000_0200, true, false);
    if matches!(demand_fault, PageFaultResolution::DemandZeroAllocate { vaddr_page: 0x7000_0000, .. }) {
        passed += 1;
    }

    // 5. Test mlock accounting and msync clearing dirty pages
    if aspace.sys_mlock(0x7000_0000, PAGE_SIZE) == 0 && aspace.locked_pages == 1 {
        passed += 1;
    }
    if aspace.sys_msync(0x7000_0000, PAGE_SIZE) == 0 {
        passed += 1;
    }

    // 6. Test madvise DONTNEED
    if aspace.sys_madvise(0x7000_0000, PAGE_SIZE, MadviseBehavior::DontNeed as u32) == 0 {
        passed += 1;
    }

    // 7. Test munmap of the entire 4-page region
    if aspace.sys_munmap(0x7000_0000, 4 * PAGE_SIZE) == 0 && aspace.vma_count() == 0 && aspace.locked_pages == 0 {
        passed += 1;
    }

    passed
}
