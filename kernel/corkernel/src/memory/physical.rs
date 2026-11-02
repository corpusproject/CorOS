//! Deterministic bitmap physical frame allocator. Only conventional UEFI RAM
//! enters the managed set; all other descriptors start reserved. Its address
//! model is u64; capacity is determined by caller-provided bitmap storage.
use super::{frame::Frame4KiB, region::{MemoryRegion, RegionType}};
use corboot_info::{memory_map_from_boot_info, BootInfo};
use crate::arch::x86_64::cpu;

pub const MAX_TRACKED_FRAMES: usize = 1_048_576; // first 4 GiB, 4 KiB frames
const WORD_BITS: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError { BitmapTooSmall, InvalidMap, OutOfRange, NotManaged, NotAllocated, AlreadyInitialized, NotInitialized, AllocationDisabled, PhysicalAddressWidthUnknown }

pub struct FrameAllocator<'a> { managed: &'a mut [u64], allocated: &'a mut [u64], frame_count: usize, cursor: usize, allocation_enabled: bool }
impl<'a> FrameAllocator<'a> {
    /// # Safety
    /// `info` must describe a readable, live UEFI memory-map buffer. Call only after validating the CorBoot handoff.
    pub unsafe fn from_boot_info(info: &BootInfo, managed: &'a mut [u64], allocated: &'a mut [u64]) -> Result<Self, FrameError> {
        let physical_bits = cpu::physical_address_bits().ok_or(FrameError::PhysicalAddressWidthUnknown)?;
        // SAFETY: the caller's map-lifetime contract is forwarded unchanged.
        unsafe { Self::from_boot_info_with_width(info, managed, allocated, physical_bits, false) }
    }

    /// Source-test seam; production must use the width discovered from CPUID.
    /// # Safety
    /// Same map-lifetime contract as `from_boot_info`.
    unsafe fn from_boot_info_with_width(
        info: &BootInfo,
        managed: &'a mut [u64],
        allocated: &'a mut [u64],
        physical_bits: u8,
        allocation_enabled: bool,
    ) -> Result<Self, FrameError> {
        if !(32..=52).contains(&physical_bits) { return Err(FrameError::PhysicalAddressWidthUnknown); }
        let words = managed.len().min(allocated.len());
        if words == 0 { return Err(FrameError::BitmapTooSmall); }
        let bitmap_frames = words.checked_mul(WORD_BITS).ok_or(FrameError::BitmapTooSmall)?;
        let cpu_frames = 1usize.checked_shl((physical_bits - 12) as u32).unwrap_or(usize::MAX);
        let frame_count = bitmap_frames.min(cpu_frames);
        managed[..words].fill(0);
        allocated[..words].fill(u64::MAX);
        // SAFETY: this constructor's caller guarantees a live, readable handoff map.
        let map = unsafe { memory_map_from_boot_info(info) }.map_err(|_| FrameError::InvalidMap)?;
        for d in map.iter() {
            let region = MemoryRegion::from_uefi(d).ok_or(FrameError::InvalidMap)?;
            if region.kind != RegionType::Usable { continue; }
            let start = usize::try_from(region.start.0 / 4096).unwrap_or(usize::MAX);
            let count = usize::try_from(region.frame_count).unwrap_or(usize::MAX);
            let end = start.saturating_add(count).min(frame_count);
            for frame in start.min(frame_count)..end {
                bit_set(&mut managed[..words], frame, true);
                bit_set(&mut allocated[..words], frame, false);
            }
        }
        // Apply every non-usable descriptor after usable ranges so an
        // overlapping/malformed map can never make reserved pages allocatable.
        for d in map.iter() {
            let region = MemoryRegion::from_uefi(d).ok_or(FrameError::InvalidMap)?;
            if region.kind == RegionType::Usable { continue; }
            reserve_range(&mut managed[..words], &mut allocated[..words], frame_count, region.start.0, region.frame_count.saturating_mul(4096));
        }
        // ImageBase values in BootInfo are EFI pointer values, not proven
        // physical addresses. EFI application code/data descriptors remain
        // non-usable and protect the images, BootInfo, stacks, and statics.
        reserve_range(&mut managed[..words], &mut allocated[..words], frame_count, info.framebuffer_address, info.framebuffer_size);
        // The ACPI configuration-table value is also a pointer, not used as a
        // physical range here. ACPI descriptors remain non-usable; no reclaim occurs.
        // Physical frame zero is never returned, even if firmware labels it usable.
        bit_set(&mut managed[..words], 0, false);
        bit_set(&mut allocated[..words], 0, true);
        Ok(Self { managed: &mut managed[..words], allocated: &mut allocated[..words], frame_count, cursor: 1, allocation_enabled })
    }

    #[cfg(test)]
    pub(super) unsafe fn from_boot_info_for_test(
        info: &BootInfo,
        managed: &'a mut [u64],
        allocated: &'a mut [u64],
        physical_bits: u8,
    ) -> Result<Self, FrameError> {
        // SAFETY: caller carries the same live-map obligation as test setup.
        unsafe { Self::from_boot_info_with_width(info, managed, allocated, physical_bits, true) }
    }
    pub fn allocate(&mut self) -> Option<Frame4KiB> {
        if !self.allocation_enabled { return None; }
        for step in 0..self.frame_count.saturating_sub(1) {
            let i = 1 + (self.cursor.saturating_sub(1) + step) % (self.frame_count - 1);
            if bit_get(self.managed, i) && !bit_get(self.allocated, i) {
                bit_set(self.allocated, i, true);
                self.cursor = if i + 1 == self.frame_count { 1 } else { i + 1 };
                return Some(Frame4KiB(i as u64));
            }
        }
        None
    }
    /// Allocates `count` contiguous 4 KiB physical frames from conventional memory.
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<Frame4KiB> {
        if !self.allocation_enabled || count == 0 { return None; }
        let mut run_start = 1;
        let mut run_length = 0;
        for i in 1..self.frame_count {
            if bit_get(self.managed, i) && !bit_get(self.allocated, i) {
                if run_length == 0 {
                    run_start = i;
                }
                run_length += 1;
                if run_length == count {
                    for f in run_start..run_start + count {
                        bit_set(self.allocated, f, true);
                    }
                    return Some(Frame4KiB(run_start as u64));
                }
            } else {
                run_length = 0;
            }
        }
        None
    }
    pub fn free(&mut self, frame: Frame4KiB) -> Result<(), FrameError> {
        if !self.allocation_enabled { return Err(FrameError::AllocationDisabled); }
        let i = usize::try_from(frame.0).map_err(|_| FrameError::OutOfRange)?;
        if i >= self.frame_count { return Err(FrameError::OutOfRange); }
        if !bit_get(self.managed, i) { return Err(FrameError::NotManaged); }
        if !bit_get(self.allocated, i) { return Err(FrameError::NotAllocated); }
        bit_set(self.allocated, i, false);
        self.cursor = self.cursor.min(i.max(1));
        Ok(())
    }
    pub fn enable_allocation(&mut self) {
        self.allocation_enabled = true;
    }
    pub fn reserve_physical_range(&mut self, start: u64, length: u64) {
        reserve_range(self.managed, self.allocated, self.frame_count, start, length);
    }
    pub fn is_managed(&self, frame: Frame4KiB) -> bool { usize::try_from(frame.0).ok().filter(|i| *i < self.frame_count).map(|i| bit_get(self.managed, i)).unwrap_or(false) }
}
fn reserve_range(managed: &mut [u64], allocated: &mut [u64], frame_count: usize, start: u64, length: u64) {
    if length == 0 { return; }
    let first = usize::try_from(start / 4096).unwrap_or(frame_count).min(frame_count);
    // Invalid overflowing reservations conservatively reserve the remainder
    // of the managed physical range instead of silently leaving frames free.
    let last = start.checked_add(length)
        .and_then(|end| end.checked_add(4095).map(|rounded| rounded / 4096))
        .and_then(|frame| usize::try_from(frame).ok())
        .unwrap_or(frame_count)
        .min(frame_count);
    for frame in first..last { bit_set(managed, frame, false); bit_set(allocated, frame, true); }
}
fn bit_get(map: &[u64], i: usize) -> bool { map[i / WORD_BITS] & (1u64 << (i % WORD_BITS)) != 0 }
fn bit_set(map: &mut [u64], i: usize, yes: bool) { let mask = 1u64 << (i % WORD_BITS); if yes { map[i / WORD_BITS] |= mask; } else { map[i / WORD_BITS] &= !mask; } }

#[cfg(test)]
mod tests {
    use super::*;
    use corboot_info::{MemoryDescriptor, BOOT_INFO_MAGIC, BOOT_INFO_VERSION, ARCH_X86_64};
    #[test]
    fn allocates_only_managed_frames_and_tracks_free_state() {
        let descriptors = [MemoryDescriptor { memory_type: 7, physical_start: 4096, number_of_pages: 4, ..MemoryDescriptor::default() }];
        let mut info = BootInfo::empty();
        info.magic = BOOT_INFO_MAGIC; info.version = BOOT_INFO_VERSION; info.architecture = ARCH_X86_64;
        info.memory_map_address = descriptors.as_ptr() as u64;
        info.memory_map_size = core::mem::size_of_val(&descriptors) as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let words = MAX_TRACKED_FRAMES / WORD_BITS;
        let mut managed = std::vec![0; words];
        let mut allocated = std::vec![0; words];
        let mut allocator = unsafe { FrameAllocator::from_boot_info_for_test(&info, &mut managed, &mut allocated, 48) }.unwrap();
        let a = allocator.allocate().unwrap();
        let b = allocator.allocate().unwrap();
        assert_eq!(a, Frame4KiB(1)); assert_eq!(b, Frame4KiB(2));
        assert!(allocator.free(a).is_ok());
        assert_eq!(allocator.allocate(), Some(a));
        assert_eq!(allocator.free(a), Ok(()));
        assert_eq!(allocator.free(a), Err(FrameError::NotAllocated));
        assert_eq!(allocator.free(Frame4KiB(0)), Err(FrameError::NotManaged));
        assert_eq!(allocator.allocate(), Some(a));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(3)));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(4)));
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn larger_bitmaps_can_allocate_frames_above_four_gib() {
        let descriptors = [MemoryDescriptor { memory_type: 7, physical_start: 0x1_0000_0000, number_of_pages: 2, ..MemoryDescriptor::default() }];
        let mut info = BootInfo::empty();
        info.magic = BOOT_INFO_MAGIC; info.version = BOOT_INFO_VERSION; info.architecture = ARCH_X86_64;
        info.memory_map_address = descriptors.as_ptr() as u64;
        info.memory_map_size = core::mem::size_of_val(&descriptors) as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let words = MAX_TRACKED_FRAMES / WORD_BITS + 1;
        let mut managed = std::vec![0; words];
        let mut allocated = std::vec![0; words];
        let mut allocator = unsafe { FrameAllocator::from_boot_info_for_test(&info, &mut managed, &mut allocated, 48) }.unwrap();
        assert_eq!(allocator.allocate(), Some(Frame4KiB(0x1_0000_0000 / 4096)));
    }

    #[test]
    fn overlapping_nonusable_descriptor_wins_over_conventional_range() {
        let descriptors = [
            MemoryDescriptor { memory_type: 7, physical_start: 0x1000, number_of_pages: 4, ..MemoryDescriptor::default() },
            MemoryDescriptor { memory_type: 11, physical_start: 0x2000, number_of_pages: 1, ..MemoryDescriptor::default() },
        ];
        let mut info = BootInfo::empty();
        info.memory_map_address = descriptors.as_ptr() as u64;
        info.memory_map_size = core::mem::size_of_val(&descriptors) as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let mut managed = [0u64; 1]; let mut allocated = [0u64; 1];
        let mut allocator = unsafe { FrameAllocator::from_boot_info_for_test(&info, &mut managed, &mut allocated, 48) }.unwrap();
        assert_eq!(allocator.allocate(), Some(Frame4KiB(1)));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(3)));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(4)));
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn explicit_unaligned_reservation_excludes_every_overlapping_frame() {
        let descriptor = MemoryDescriptor { memory_type: 7, physical_start: 0x1000, number_of_pages: 4, ..MemoryDescriptor::default() };
        let mut info = BootInfo::empty();
        info.memory_map_address = &descriptor as *const MemoryDescriptor as u64;
        info.memory_map_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let mut managed = [0u64; 1]; let mut allocated = [0u64; 1];
        let mut allocator = unsafe { FrameAllocator::from_boot_info_for_test(&info, &mut managed, &mut allocated, 48) }.unwrap();
        allocator.reserve_physical_range(0x2001, 1);
        allocator.reserve_physical_range(0x2001, 1); // duplicate reservation is idempotent
        assert_eq!(allocator.allocate(), Some(Frame4KiB(1)));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(3)));
        assert_eq!(allocator.allocate(), Some(Frame4KiB(4)));
        assert_eq!(allocator.allocate(), None);
    }

    #[test]
    fn overflowing_reservation_excludes_remaining_tracked_frames() {
        let mut managed = [u64::MAX; 1];
        let mut allocated = [0u64; 1];
        reserve_range(&mut managed, &mut allocated, 64, 0x1000, u64::MAX);
        assert!(!bit_get(&managed, 1));
        assert!(!bit_get(&managed, 2));
        assert!(bit_get(&allocated, 1));
        assert!(bit_get(&allocated, 2));
    }

    #[test]
    fn unknown_physical_width_fails_allocator_initialization() {
        let descriptor = MemoryDescriptor { memory_type: 7, physical_start: 0x1000, number_of_pages: 4, ..MemoryDescriptor::default() };
        let mut info = BootInfo::empty();
        info.memory_map_address = &descriptor as *const MemoryDescriptor as u64;
        info.memory_map_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let mut managed = [0u64; 1];
        let mut allocated = [0u64; 1];
        assert_eq!(unsafe { FrameAllocator::from_boot_info_for_test(&info, &mut managed, &mut allocated, 0) }.err(), Some(FrameError::PhysicalAddressWidthUnknown));
    }

    #[test]
    fn production_allocator_instance_stays_disabled_after_map_parsing() {
        let descriptor = MemoryDescriptor { memory_type: 7, physical_start: 0x1000, number_of_pages: 4, ..MemoryDescriptor::default() };
        let mut info = BootInfo::empty();
        info.memory_map_address = &descriptor as *const MemoryDescriptor as u64;
        info.memory_map_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        let mut managed = [0u64; 1];
        let mut allocated = [0u64; 1];
        let mut allocator = unsafe { FrameAllocator::from_boot_info_with_width(&info, &mut managed, &mut allocated, 48, false) }.unwrap();
        assert_eq!(allocator.allocate(), None);
        assert_eq!(allocator.free(Frame4KiB(1)), Err(FrameError::AllocationDisabled));
    }
}
