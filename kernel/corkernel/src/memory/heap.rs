//! Early no_std heap over exclusively mapped pages. The provider must obtain
//! frames from CorOS and map them through the inactive/active page mapper.
//! This is intentionally not registered as GlobalAlloc until runtime proofs exist.
use core::{alloc::Layout, ptr};

/// # Safety
/// Implementations must return exclusive, valid, page-aligned mapped storage
/// backed by owned physical frames and keep it mapped for the heap lifetime.
pub unsafe trait HeapPageProvider {
    /// Returns a page-aligned, writable virtual range backed by exclusively
    /// owned frames, with length at least `minimum_bytes`.
    fn grow(&mut self, minimum_bytes: usize) -> Option<(*mut u8, usize)>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError { InvalidLayout, OutOfMemory, ProviderReturnedInvalidRange }
#[repr(C)]
struct FreeBlock { size: usize, next: *mut FreeBlock }
#[repr(C)]
struct AllocationHeader { base: *mut u8, size: usize }

/// First-fit heap with page-provider growth and whole-block reuse. A freed
/// block can be reused by any smaller compatible allocation; coalescing is
/// deliberately omitted until the kernel has a virtual-region ownership map.
pub struct KernelHeap<P: HeapPageProvider> { provider: P, free: *mut FreeBlock }
impl<P: HeapPageProvider> KernelHeap<P> {
    pub const fn new(provider: P) -> Self { Self { provider, free: ptr::null_mut() } }

    pub fn allocate(&mut self, layout: Layout) -> Result<*mut u8, HeapError> {
        // Null is the explicit zero-sized sentinel; deallocate treats it as a no-op.
        if layout.size() == 0 { return Ok(ptr::null_mut()); }
        let align = layout.align().max(core::mem::align_of::<AllocationHeader>());
        let needed = layout.size().checked_add(align - 1).and_then(|n| n.checked_add(core::mem::size_of::<AllocationHeader>())).ok_or(HeapError::InvalidLayout)?;
        let mut link = &mut self.free as *mut *mut FreeBlock;
        unsafe {
            while !(*link).is_null() {
                let block = *link;
                if (*block).size >= needed {
                    *link = (*block).next;
                    return unsafe { Self::commit_block(block as *mut u8, (*block).size, layout) }.ok_or(HeapError::ProviderReturnedInvalidRange);
                }
                link = &mut (*block).next;
            }
            let (base, size) = self.provider.grow(needed).ok_or(HeapError::OutOfMemory)?;
            if base.is_null() || (base as usize) % 4096 != 0 || size % 4096 != 0 || size < needed || (base as usize).checked_add(size).is_none() {
                return Err(HeapError::ProviderReturnedInvalidRange);
            }
            Self::commit_block(base, size, layout).ok_or(HeapError::ProviderReturnedInvalidRange)
        }
    }

    unsafe fn commit_block(base: *mut u8, size: usize, layout: Layout) -> Option<*mut u8> {
        let align = layout.align().max(core::mem::align_of::<AllocationHeader>());
        let limit = (base as usize).checked_add(size)?;
        let start = (base as usize).checked_add(core::mem::size_of::<AllocationHeader>())?;
        let user = start.checked_add(align - 1)? & !(align - 1);
        if user.checked_add(layout.size())? > limit { return None; }
        let header = (user - core::mem::size_of::<AllocationHeader>()) as *mut AllocationHeader;
        unsafe { header.write(AllocationHeader { base, size }); }
        Some(user as *mut u8)
    }

    /// # Safety
    /// `pointer` must be a live pointer returned by this heap and freed exactly once.
    pub unsafe fn deallocate(&mut self, pointer: *mut u8) -> Result<(), HeapError> {
        if pointer.is_null() { return Ok(()); }
        let header = unsafe { pointer.sub(core::mem::size_of::<AllocationHeader>()).cast::<AllocationHeader>().read() };
        if header.base.is_null() || header.size < core::mem::size_of::<FreeBlock>() { return Err(HeapError::ProviderReturnedInvalidRange); }
        let block = header.base.cast::<FreeBlock>();
        unsafe { block.write(FreeBlock { size: header.size, next: self.free }); }
        self.free = block;
        Ok(())
    }
}

unsafe impl<P: HeapPageProvider + Send> Send for KernelHeap<P> {}

pub const CACHE_LINE_SIZE: usize = 64;
pub const EARLY_HEAP_SIZE: usize = 1024 * 1024; // 1 MiB high-speed initial heap

#[repr(align(4096))]
struct EarlyHeapStorage([u8; EARLY_HEAP_SIZE]);

static mut EARLY_HEAP_MEMORY: EarlyHeapStorage = EarlyHeapStorage([0; EARLY_HEAP_SIZE]);

pub struct EarlyHeapProvider {
    consumed: usize,
    capacity: usize,
    base: *mut u8,
}

impl EarlyHeapProvider {
    pub const fn new() -> Self {
        Self { consumed: 0, capacity: EARLY_HEAP_SIZE, base: ptr::null_mut() }
    }
}

unsafe impl Send for EarlyHeapProvider {}

use core::sync::atomic::{AtomicUsize, Ordering};

pub static HEAP_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
pub static HEAP_TOTAL_CAPACITY: AtomicUsize = AtomicUsize::new(EARLY_HEAP_SIZE);

/// Returns (allocated_bytes, total_capacity_bytes) for live memory telemetry
pub fn heap_stats() -> (usize, usize) {
    (
        HEAP_ALLOCATED_BYTES.load(Ordering::Relaxed),
        HEAP_TOTAL_CAPACITY.load(Ordering::Relaxed),
    )
}

unsafe impl HeapPageProvider for EarlyHeapProvider {
    fn grow(&mut self, minimum_bytes: usize) -> Option<(*mut u8, usize)> {
        let aligned_needed = (minimum_bytes + 4095) & !4095;
        if self.base.is_null() {
            self.base = unsafe { ptr::addr_of_mut!(EARLY_HEAP_MEMORY.0).cast::<u8>() };
        }
        if self.consumed + aligned_needed <= self.capacity {
            let chunk_ptr = unsafe { self.base.add(self.consumed) };
            self.consumed += aligned_needed;
            HEAP_ALLOCATED_BYTES.fetch_add(aligned_needed, Ordering::Relaxed);
            return Some((chunk_ptr, aligned_needed));
        }

        // Dynamically scale beyond 1 MiB by requesting contiguous RAM frames from the OS frame allocator!
        let pages = (aligned_needed + 4095) / 4096;
        if let Some(frame) = crate::memory::allocate_contiguous_frames(pages) {
            let phys_addr = frame.start_address()?.0;
            let chunk_ptr = phys_addr as *mut u8;
            self.capacity += pages * 4096;
            self.consumed += pages * 4096;
            HEAP_ALLOCATED_BYTES.fetch_add(pages * 4096, Ordering::Relaxed);
            HEAP_TOTAL_CAPACITY.fetch_add(pages * 4096, Ordering::Relaxed);
            return Some((chunk_ptr, pages * 4096));
        }

        None
    }
}

#[repr(C)]
struct SlabNode {
    next: *mut SlabNode,
}

const SLAB_SIZES: [usize; 7] = [64, 128, 256, 512, 1024, 2048, 4096];

pub struct CorGlobalAlloc {
    heap: crate::sync::SpinLock<Option<KernelHeap<EarlyHeapProvider>>>,
    slabs: crate::sync::SpinLock<[*mut SlabNode; 7]>,
    cormm_slub: crate::sync::SpinLock<Option<cormm::slub_cache::SlubAllocator>>,
    cormm_buddy: crate::sync::SpinLock<Option<cormm::buddy_allocator::PhysicalBuddyAllocator>>,
}

unsafe impl Send for CorGlobalAlloc {}
unsafe impl Sync for CorGlobalAlloc {}

impl CorGlobalAlloc {
    pub const fn uninit() -> Self {
        Self {
            heap: crate::sync::SpinLock::new(None),
            slabs: crate::sync::SpinLock::new([ptr::null_mut(); 7]),
            cormm_slub: crate::sync::SpinLock::new(None),
            cormm_buddy: crate::sync::SpinLock::new(None),
        }
    }

    pub fn initialize(&self) {
        let mut guard = self.heap.lock_irqsave();
        if guard.is_none() {
            *guard = Some(KernelHeap::new(EarlyHeapProvider::new()));
        }
        drop(guard);

        let mut slub_guard = self.cormm_slub.lock_irqsave();
        if slub_guard.is_none() {
            *slub_guard = Some(cormm::slub_cache::SlubAllocator::new(0xFFFF_8880_0000_0000));
        }
        drop(slub_guard);

        let mut buddy_guard = self.cormm_buddy.lock_irqsave();
        if buddy_guard.is_none() {
            *buddy_guard = Some(cormm::buddy_allocator::PhysicalBuddyAllocator::new_standard_layout(1024, 8192, 0));
        }
    }

    fn slab_index(size: usize) -> Option<usize> {
        for (i, &s) in SLAB_SIZES.iter().enumerate() {
            if size <= s {
                return Some(i);
            }
        }
        None
    }

    /// Query live statistics from the cormm Buddy Allocator
    pub fn cormm_buddy_stats(&self) -> Option<cormm::buddy_allocator::BuddyZoneStats> {
        let guard = self.cormm_buddy.lock_irqsave();
        guard.as_ref().and_then(|b| {
            b.zones().iter().find(|z| z.kind() == cormm::buddy_allocator::MemoryZoneKind::ZoneNormal).map(|z| z.stats())
        })
    }

    /// Query live active object count from the cormm SLUB cache for a size class
    pub fn cormm_slub_active_objects(&self, class: cormm::slub_cache::KmallocSizeClass) -> usize {
        let guard = self.cormm_slub.lock_irqsave();
        guard.as_ref().map(|s| s.cache(class).active_objects()).unwrap_or(0)
    }
}

unsafe impl core::alloc::GlobalAlloc for CorGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);

        // Fast-path O(1) Slab allocation for requests <= 4096 bytes
        if let Some(idx) = Self::slab_index(size) {
            // Track with cormm SLUB allocator accounting
            if let Some(mut slub_guard) = self.cormm_slub.try_lock() {
                if let Some(slub) = slub_guard.as_mut() {
                    let _ = slub.kmalloc(size);
                }
            }

            let mut slabs = self.slabs.lock_irqsave();
            let head = slabs[idx];
            if !head.is_null() {
                slabs[idx] = (*head).next;
                return head as *mut u8;
            }
            drop(slabs);

            // Allocate a slab chunk aligned to 64 bytes
            let slab_size = SLAB_SIZES[idx];
            let Ok(slab_layout) = Layout::from_size_align(slab_size, CACHE_LINE_SIZE) else { return ptr::null_mut(); };
            let mut guard = self.heap.lock_irqsave();
            let Some(heap) = guard.as_mut() else { return ptr::null_mut(); };
            return heap.allocate(slab_layout).unwrap_or(ptr::null_mut());
        }

        // Standard page-backed heap path for large requests via cormm buddy orders
        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let bounded_order = order.min(cormm::buddy_allocator::MAX_ORDER - 1);
        if let Some(mut buddy_guard) = self.cormm_buddy.try_lock() {
            if let Some(buddy) = buddy_guard.as_mut() {
                let _ = buddy.alloc_from_zone(cormm::buddy_allocator::MemoryZoneKind::ZoneNormal, bounded_order, false);
            }
        }

        let align = layout.align().max(CACHE_LINE_SIZE);
        let Ok(aligned_layout) = Layout::from_size_align(size, align) else { return ptr::null_mut(); };
        let mut guard = self.heap.lock_irqsave();
        let Some(heap) = guard.as_mut() else { return ptr::null_mut(); };
        heap.allocate(aligned_layout).unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        let size = layout.size().max(1);

        // Fast-path O(1) Slab recycling
        if let Some(idx) = Self::slab_index(size) {
            let mut slabs = self.slabs.lock_irqsave();
            let node = ptr as *mut SlabNode;
            (*node).next = slabs[idx];
            slabs[idx] = node;
            return;
        }

        let pages = (size + 4095) / 4096;
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let bounded_order = order.min(cormm::buddy_allocator::MAX_ORDER - 1);
        if let Some(mut buddy_guard) = self.cormm_buddy.try_lock() {
            if let Some(buddy) = buddy_guard.as_mut() {
                let pfn = (ptr as usize) / 4096;
                let _ = buddy.free_to_owning_zone(pfn, bounded_order);
            }
        }

        let mut guard = self.heap.lock_irqsave();
        if let Some(heap) = guard.as_mut() {
            let _ = heap.deallocate(ptr);
        }
    }
}

#[global_allocator]
pub static ALLOCATOR: CorGlobalAlloc = CorGlobalAlloc::uninit();


#[cfg(test)]
mod tests {
    use super::*;
    #[repr(align(4096))]
    struct Page([u8; 4096]);
    struct OnePage { page: *mut u8, supplied: bool }
    unsafe impl HeapPageProvider for OnePage {
        fn grow(&mut self, minimum_bytes: usize) -> Option<(*mut u8, usize)> {
            if self.supplied || minimum_bytes > 4096 { return None; }
            self.supplied = true; Some((self.page, 4096))
        }
    }
    #[test]
    fn heap_honors_alignment_reuses_freed_blocks_and_reports_exhaustion() {
        let mut page = Page([0; 4096]);
        let provider = OnePage { page: page.0.as_mut_ptr(), supplied: false };
        let mut heap = KernelHeap::new(provider);
        let layout = Layout::from_size_align(64, 64).unwrap();
        let first = heap.allocate(layout).unwrap();
        assert_eq!((first as usize) % 64, 0);
        unsafe { heap.deallocate(first).unwrap(); }
        assert_eq!(heap.allocate(layout).unwrap(), first);
        let too_large = Layout::from_size_align(8192, 8).unwrap();
        assert_eq!(heap.allocate(too_large), Err(HeapError::OutOfMemory));
    }
}
