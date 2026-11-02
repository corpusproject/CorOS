//! Linux SLUB-style Object Slab Allocator (`KmemCache`, `SlabPage`, `KmallocSizeClass`).
//!
//! Implements unqueued slab allocation with embedded freelist indices, object size
//! alignment, partial/full slab tracking, and general `kmalloc` size classes from
//! `8` bytes up to `2048` bytes.

use alloc::vec;
use alloc::vec::Vec;

/// Standard 4 KiB slab backing page size.
pub const SLAB_PAGE_BYTES: usize = 4096;

/// Sentinel value marking the end of an embedded slab freelist chain.
pub const FREELIST_END: u16 = u16::MAX;

/// General-purpose `kmalloc` power-of-two size classes (`8..=2048` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KmallocSizeClass {
    Bytes8,
    Bytes16,
    Bytes32,
    Bytes64,
    Bytes128,
    Bytes256,
    Bytes512,
    Bytes1024,
    Bytes2048,
}

impl KmallocSizeClass {
    /// All 9 `kmalloc` size classes in ascending order.
    pub const ALL: [KmallocSizeClass; 9] = [
        Self::Bytes8,
        Self::Bytes16,
        Self::Bytes32,
        Self::Bytes64,
        Self::Bytes128,
        Self::Bytes256,
        Self::Bytes512,
        Self::Bytes1024,
        Self::Bytes2048,
    ];

    /// Size in bytes of a slot in this class.
    pub const fn object_size(self) -> usize {
        match self {
            Self::Bytes8 => 8,
            Self::Bytes16 => 16,
            Self::Bytes32 => 32,
            Self::Bytes64 => 64,
            Self::Bytes128 => 128,
            Self::Bytes256 => 256,
            Self::Bytes512 => 512,
            Self::Bytes1024 => 1024,
            Self::Bytes2048 => 2048,
        }
    }

    /// Selects the smallest `KmallocSizeClass` capable of holding `requested_bytes`.
    pub const fn for_size(requested_bytes: usize) -> Option<Self> {
        if requested_bytes == 0 || requested_bytes > 2048 {
            return None;
        }
        if requested_bytes <= 8 {
            Some(Self::Bytes8)
        } else if requested_bytes <= 16 {
            Some(Self::Bytes16)
        } else if requested_bytes <= 32 {
            Some(Self::Bytes32)
        } else if requested_bytes <= 64 {
            Some(Self::Bytes64)
        } else if requested_bytes <= 128 {
            Some(Self::Bytes128)
        } else if requested_bytes <= 256 {
            Some(Self::Bytes256)
        } else if requested_bytes <= 512 {
            Some(Self::Bytes512)
        } else if requested_bytes <= 1024 {
            Some(Self::Bytes1024)
        } else {
            Some(Self::Bytes2048)
        }
    }
}

/// Aligns `size` upwards to `align` (where `align` is a power of two).
#[inline]
pub const fn align_up(size: usize, align: usize) -> usize {
    let mask = align.saturating_sub(1);
    (size + mask) & !mask
}

/// Lifecycle residency state of a `SlabPage` inside a `KmemCache`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabState {
    /// Currently bound as the active per-CPU fastpath slab.
    ActiveCpu,
    /// Partially allocated slab sitting on the node partial list.
    Partial,
    /// Completely full slab with zero free objects.
    Full,
}

/// Handle identifying an allocated SLUB object (`slab_id`, `slot_index`, and virtual address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlubObjectHandle {
    pub slab_id: u32,
    pub slot_index: u16,
    pub object_vaddr: u64,
}

/// Single 4 KiB SLUB page containing fixed-size object slots and an index freelist chain.
#[derive(Debug, Clone)]
pub struct SlabPage {
    slab_id: u32,
    base_vaddr: u64,
    object_stride: usize,
    capacity: u16,
    inuse_count: u16,
    freelist_head: u16,
    next_free_chain: Vec<u16>,
    allocated_bitmap: Vec<bool>,
    state: SlabState,
}

impl SlabPage {
    /// Initializes a new `SlabPage` with `object_stride` bytes per slot.
    pub fn new(slab_id: u32, base_vaddr: u64, object_stride: usize) -> Self {
        let capacity = (SLAB_PAGE_BYTES / object_stride.max(8)) as u16;
        let mut next_free_chain = Vec::with_capacity(capacity as usize);
        for idx in 0..capacity {
            let next = if idx + 1 < capacity {
                idx + 1
            } else {
                FREELIST_END
            };
            next_free_chain.push(next);
        }
        let allocated_bitmap = vec![false; capacity as usize];
        Self {
            slab_id,
            base_vaddr,
            object_stride,
            capacity,
            inuse_count: 0,
            freelist_head: if capacity > 0 { 0 } else { FREELIST_END },
            next_free_chain,
            allocated_bitmap,
            state: SlabState::Partial,
        }
    }

    /// Pops one object from the embedded freelist chain.
    pub fn allocate_slot(&mut self) -> Option<SlubObjectHandle> {
        if self.freelist_head == FREELIST_END {
            return None;
        }
        let slot = self.freelist_head;
        self.freelist_head = self.next_free_chain[slot as usize];
        self.allocated_bitmap[slot as usize] = true;
        self.inuse_count += 1;
        let object_vaddr = self.base_vaddr + (slot as u64) * (self.object_stride as u64);
        Some(SlubObjectHandle {
            slab_id: self.slab_id,
            slot_index: slot,
            object_vaddr,
        })
    }

    /// Pushes a previously allocated object slot back onto the freelist head.
    pub fn free_slot(&mut self, slot_index: u16) -> bool {
        let idx = slot_index as usize;
        if idx >= self.capacity as usize || !self.allocated_bitmap[idx] {
            return false;
        }
        self.allocated_bitmap[idx] = false;
        self.next_free_chain[idx] = self.freelist_head;
        self.freelist_head = slot_index;
        self.inuse_count = self.inuse_count.saturating_sub(1);
        true
    }

    /// Returns whether all slots in this slab are currently allocated.
    pub const fn is_full(&self) -> bool {
        self.inuse_count == self.capacity
    }

    /// Returns whether zero slots in this slab are currently allocated.
    pub const fn is_empty(&self) -> bool {
        self.inuse_count == 0
    }

    /// Returns the number of allocated objects in this slab.
    pub const fn inuse_count(&self) -> u16 {
        self.inuse_count
    }

    /// Returns total object capacity of this slab.
    pub const fn capacity(&self) -> u16 {
        self.capacity
    }

    /// Returns the current residency state of this slab.
    pub const fn state(&self) -> SlabState {
        self.state
    }
}

/// Dedicated SLUB object cache (`kmem_cache`) for a specific object size and alignment.
#[derive(Debug, Clone)]
pub struct KmemCache {
    name: &'static str,
    raw_object_size: usize,
    object_align: usize,
    object_stride: usize,
    objects_per_slab: u16,
    slabs: Vec<SlabPage>,
    active_cpu_slab: Option<usize>,
    partial_slab_indices: Vec<usize>,
    full_slab_indices: Vec<usize>,
    next_slab_base_vaddr: u64,
    total_allocations: u64,
    total_frees: u64,
}

impl KmemCache {
    /// Creates a new `KmemCache` for objects of `raw_object_size` aligned to `object_align`.
    pub fn new(
        name: &'static str,
        raw_object_size: usize,
        object_align: usize,
        vaddr_region_base: u64,
    ) -> Self {
        let effective_align = object_align.max(8).next_power_of_two();
        let object_stride = align_up(raw_object_size.max(8), effective_align);
        let objects_per_slab = (SLAB_PAGE_BYTES / object_stride) as u16;
        Self {
            name,
            raw_object_size,
            object_align: effective_align,
            object_stride,
            objects_per_slab,
            slabs: Vec::new(),
            active_cpu_slab: None,
            partial_slab_indices: Vec::new(),
            full_slab_indices: Vec::new(),
            next_slab_base_vaddr: vaddr_region_base,
            total_allocations: 0,
            total_frees: 0,
        }
    }

    /// Allocates an object from the active CPU slab, promoting a partial slab or
    /// growing a fresh slab page if needed.
    pub fn alloc_object(&mut self) -> Option<SlubObjectHandle> {
        if self.objects_per_slab == 0 {
            return None;
        }

        if self.active_cpu_slab.is_none() {
            if let Some(partial_idx) = self.partial_slab_indices.pop() {
                self.slabs[partial_idx].state = SlabState::ActiveCpu;
                self.active_cpu_slab = Some(partial_idx);
            } else {
                let new_idx = self.slabs.len();
                let mut slab = SlabPage::new(
                    new_idx as u32,
                    self.next_slab_base_vaddr,
                    self.object_stride,
                );
                self.next_slab_base_vaddr += SLAB_PAGE_BYTES as u64;
                slab.state = SlabState::ActiveCpu;
                self.slabs.push(slab);
                self.active_cpu_slab = Some(new_idx);
            }
        }

        let cpu_idx = self.active_cpu_slab?;
        let handle = self.slabs[cpu_idx].allocate_slot()?;
        self.total_allocations += 1;

        if self.slabs[cpu_idx].is_full() {
            self.slabs[cpu_idx].state = SlabState::Full;
            self.full_slab_indices.push(cpu_idx);
            self.active_cpu_slab = None;
        }

        Some(handle)
    }

    /// Frees an object back to its owning `SlabPage` and transitions full slabs
    /// back onto the partial list.
    pub fn free_object(&mut self, handle: SlubObjectHandle) -> bool {
        let slab_idx = handle.slab_id as usize;
        if slab_idx >= self.slabs.len() {
            return false;
        }

        let was_full = self.slabs[slab_idx].is_full();
        if !self.slabs[slab_idx].free_slot(handle.slot_index) {
            return false;
        }

        self.total_frees += 1;

        if was_full && self.slabs[slab_idx].state == SlabState::Full {
            if let Some(pos) = self
                .full_slab_indices
                .iter()
                .position(|&idx| idx == slab_idx)
            {
                self.full_slab_indices.swap_remove(pos);
            }
            self.slabs[slab_idx].state = SlabState::Partial;
            self.partial_slab_indices.push(slab_idx);
        }

        true
    }

    /// Returns the aligned stride in bytes of each object in this cache.
    pub const fn object_stride(&self) -> usize {
        self.object_stride
    }

    /// Returns how many objects fit in each 4 KiB slab page.
    pub const fn objects_per_slab(&self) -> u16 {
        self.objects_per_slab
    }

    /// Returns the cache name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns raw unaligned object size.
    pub const fn raw_object_size(&self) -> usize {
        self.raw_object_size
    }

    /// Returns object alignment in bytes.
    pub const fn object_align(&self) -> usize {
        self.object_align
    }

    /// Returns the total number of live allocated objects across all slabs.
    pub fn active_objects(&self) -> usize {
        self.slabs.iter().map(|s| s.inuse_count() as usize).sum()
    }

    /// Returns the number of slabs currently on the partial list.
    pub fn partial_slab_count(&self) -> usize {
        self.partial_slab_indices.len()
    }

    /// Returns the number of slabs currently on the full list.
    pub fn full_slab_count(&self) -> usize {
        self.full_slab_indices.len()
    }
}

/// Receipt returned by `SlubAllocator::kmalloc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KmallocAllocation {
    pub size_class: KmallocSizeClass,
    pub handle: SlubObjectHandle,
}

/// Top-level SLUB General `kmalloc` Allocator managing `8..=2048` byte size classes.
#[derive(Debug, Clone)]
pub struct SlubAllocator {
    caches: [KmemCache; 9],
}

impl SlubAllocator {
    /// Creates a new `SlubAllocator` with all 9 `KmallocSizeClass` caches initialized.
    pub fn new(base_vaddr: u64) -> Self {
        let names: [&'static str; 9] = [
            "kmalloc-8",
            "kmalloc-16",
            "kmalloc-32",
            "kmalloc-64",
            "kmalloc-128",
            "kmalloc-256",
            "kmalloc-512",
            "kmalloc-1024",
            "kmalloc-2048",
        ];
        let caches = core::array::from_fn(|idx| {
            let class = KmallocSizeClass::ALL[idx];
            let sz = class.object_size();
            let region = base_vaddr + (idx as u64) * 0x0100_0000;
            KmemCache::new(names[idx], sz, sz, region)
        });
        Self { caches }
    }

    /// Allocates memory from the matching `KmallocSizeClass` cache.
    pub fn kmalloc(&mut self, bytes: usize) -> Option<KmallocAllocation> {
        let size_class = KmallocSizeClass::for_size(bytes)?;
        let idx = size_class as usize;
        let handle = self.caches[idx].alloc_object()?;
        Some(KmallocAllocation { size_class, handle })
    }

    /// Frees an allocation returned by `kmalloc`.
    pub fn kfree(&mut self, allocation: KmallocAllocation) -> bool {
        let idx = allocation.size_class as usize;
        self.caches[idx].free_object(allocation.handle)
    }

    /// Borrows the cache for a given `KmallocSizeClass`.
    pub fn cache(&self, class: KmallocSizeClass) -> &KmemCache {
        &self.caches[class as usize]
    }
}
