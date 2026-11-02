mod address;
mod frame;
mod physical;
mod region;
pub mod virtual_memory;
pub mod heap;
pub mod mmio;
pub mod vma;
pub mod slab;
pub mod swap;
pub mod numa;
pub mod page_fault;
pub mod aslr;
pub mod ksm;
pub mod thp;
pub mod zram;
pub mod dma;

pub use address::{align_down, align_up, is_canonical, page_containing, PhysicalAddress, VirtualAddress};
pub use frame::{Frame4KiB, Page4KiB};
pub use physical::{FrameAllocator, FrameError, MAX_TRACKED_FRAMES};
pub use region::{MemoryRegion, RegionType};
pub use vma::{AddressSpace, Vma, VmaType};
pub use slab::{SlabAllocator, KmemCache, Slab};
pub use swap::{SwapManager, OomKiller, ProcessMemoryProfile, SwapBackend, InMemorySwapBackend, verify_swap_subsystem};
pub use numa::{NumaManager, NumaNode, MemoryPolicy};
pub use page_fault::{PageFaultHandler, FaultAction, PageFaultErrorCode};
pub use aslr::{AslrEngine, ProcessAddressLayout};
pub use ksm::{KsmEngine, StablePageNode, PageFingerprint};
pub use thp::{ThpManager, HugePage2Mb, ThpMode, PAGE_SIZE_2MB, PAGE_SIZE_1GB};
pub use zram::{ZramDevice, ZramSlot, ZramStats, ZRAM_PAGE_SIZE};
pub use dma::{DmaBuffer, ScatterGatherList, ScatterGatherEntry, memory_barrier, read_barrier, write_barrier};

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::sync::SpinLock;

use corboot_info::{memory_map_from_boot_info, BootInfo};
pub const PAGE_SIZE: u64 = 4096;

const BITMAP_WORDS: usize = MAX_TRACKED_FRAMES / 64;
static mut MANAGED_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static mut ALLOCATED_BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];
static FRAME_ALLOCATOR: SpinLock<Option<FrameAllocator<'static>>> = SpinLock::new(None);
// The active UEFI page-table descendants have not been enumerated. Keep the
// live allocator fail-closed until a verified reservation audit can enable it.
static FRAME_ALLOCATION_SAFE: AtomicBool = AtomicBool::new(false);

/// Initializes the bounded frame allocator once from the final firmware map.
/// # Safety
/// The BootInfo memory-map range must remain readable for the entire initialization call.
pub unsafe fn initialize(info: &BootInfo) -> Result<(), FrameError> {
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    if slot.is_some() { return Err(FrameError::AlreadyInitialized); }
    // SAFETY: the lock guarantees one-time exclusive access; both arrays live for the kernel lifetime.
    let managed: &'static mut [u64] = unsafe { &mut *ptr::addr_of_mut!(MANAGED_BITMAP) };
    let allocated: &'static mut [u64] = unsafe { &mut *ptr::addr_of_mut!(ALLOCATED_BITMAP) };
    // SAFETY: caller guarantees BootInfo and the final map remain readable.
    let mut allocator = unsafe { FrameAllocator::from_boot_info(info, managed, allocated)? };
    // Reserve the active firmware CR3 root even if firmware unexpectedly placed
    // its page in a conventional descriptor. Descendant tables remain
    // unenumerated without a proven physical-table access mechanism.
    const CR3_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    allocator.reserve_physical_range(crate::arch::x86_64::cpu::read_cr3().0 & CR3_ADDRESS_MASK, PAGE_SIZE);
    *slot = Some(allocator);
    Ok(())
}

pub fn enable_allocation() {
    FRAME_ALLOCATION_SAFE.store(true, Ordering::Release);
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    if let Some(allocator) = slot.as_mut() {
        allocator.enable_allocation();
    }
}

pub fn with_frame_allocator<R, F: FnOnce(&mut FrameAllocator<'static>) -> R>(f: F) -> Option<R> {
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    slot.as_mut().map(f)
}

pub fn allocate_frame() -> Option<Frame4KiB> {
    if !FRAME_ALLOCATION_SAFE.load(Ordering::Acquire) { return None; }
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    slot.as_mut()?.allocate()
}

pub fn allocate_contiguous_frames(count: usize) -> Option<Frame4KiB> {
    if !FRAME_ALLOCATION_SAFE.load(Ordering::Acquire) { return None; }
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    slot.as_mut()?.allocate_contiguous(count)
}

pub fn free_frame(frame: Frame4KiB) -> Result<(), FrameError> {
    if !FRAME_ALLOCATION_SAFE.load(Ordering::Acquire) { return Err(FrameError::AllocationDisabled); }
    let mut slot = FRAME_ALLOCATOR.lock_irqsave();
    slot.as_mut().ok_or(FrameError::NotInitialized)?.free(frame)
}

pub struct MemorySummary { pub conventional_pages: u64 }
/// # Safety
/// The BootInfo memory-map range must be readable and live for the call.
pub unsafe fn summarize(info: &BootInfo) -> Option<MemorySummary> {
    // SAFETY: required by this function's caller contract.
    let map = unsafe { memory_map_from_boot_info(info) }.ok()?;
    let mut count = 0u64;
    for d in map.iter() {
        let region = MemoryRegion::from_uefi(d)?;
        if region.kind == RegionType::Usable { count = count.checked_add(region.frame_count)?; }
    }
    Some(MemorySummary { conventional_pages: count })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_frame_allocation_fails_closed_before_safety_prerequisites() {
        assert_eq!(allocate_frame(), None);
        assert_eq!(free_frame(Frame4KiB(1)), Err(FrameError::AllocationDisabled));
    }
}
