//! Four-level page-table construction. The mapper edits an inactive root only;
//! activation is deliberately separate so callers must first preserve all live mappings.
use super::{address::{is_canonical, PhysicalAddress, VirtualAddress}, frame::Frame4KiB, physical::FrameAllocator, FrameError, PAGE_SIZE};
use crate::arch::mmu::{self, PagingMode, PagingSnapshot};

pub const ENTRY_COUNT: usize = 512;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const HUGE_PAGE: u64 = 1 << 7;
pub const NO_EXECUTE: u64 = 1 << 63;
pub const HUGE_PAGE_2M_SIZE: u64 = 2 * 1024 * 1024;
pub const CACHE_WRITE_BACK: u64 = 0;
pub const CACHE_WRITE_COMBINING: u64 = 1 << 3; // PWT=1 -> PAT index 1
pub const CACHE_UNCACHEABLE: u64 = (1 << 3) | (1 << 4); // PWT=1, PCD=1 -> PAT index 3

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const ALLOWED_FLAG_MASK: u64 = (0x0000_0000_0000_0fff & !HUGE_PAGE) | NO_EXECUTE | CACHE_UNCACHEABLE;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Classification for a validated entry encountered while inspecting a
/// four-level x86_64 hierarchy. `LargePage` is valid only at PDPT/PD levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind { NotPresent, Table, LargePage, Leaf, InvalidLargePage }

/// Current bootstrap-compatible layout. CorOS currently continues using the
/// firmware root; these ranges are reserved for the owned address space.
pub mod layout {
    pub const KERNEL_START: u64 = 0xffff_8000_0000_0000;
    pub const KERNEL_END: u64 = 0xffff_8800_0000_0000;
    pub const HEAP_START: u64 = 0xffff_9000_0000_0000;
    pub const HEAP_END: u64 = 0xffff_a000_0000_0000;
    pub const MMIO_START: u64 = 0xffff_c000_0000_0000;
    pub const MMIO_END: u64 = 0xffff_c100_0000_0000;
    pub const FRAMEBUFFER_START: u64 = 0xffff_d000_0000_0000;
    pub const FRAMEBUFFER_END: u64 = 0xffff_d100_0000_0000;
    pub const NULL_GUARD_END: u64 = 0x0000_0000_0001_0000;
    pub const USER_START: u64 = NULL_GUARD_END;
    pub const USER_END: u64 = 0x0000_7000_0000_0000;
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageTableEntry(pub u64);
impl PageTableEntry {
    pub const fn is_present(self) -> bool { self.0 & PRESENT != 0 }
    pub const fn is_writable(self) -> bool { self.0 & WRITABLE != 0 }
    pub const fn is_user(self) -> bool { self.0 & USER != 0 }
    pub const fn is_huge(self) -> bool { self.0 & HUGE_PAGE != 0 }
    pub const fn is_executable(self) -> bool { self.0 & NO_EXECUTE == 0 }
    pub const fn address(self) -> PhysicalAddress { PhysicalAddress(self.0 & ADDRESS_MASK) }
    pub const fn classify(self, level: usize) -> EntryKind {
        if !self.is_present() { EntryKind::NotPresent }
        // At the leaf, bit 7 is PAT rather than the large-page bit.
        else if level == 3 { EntryKind::Leaf }
        else if self.is_huge() && (level == 1 || level == 2) { EntryKind::LargePage }
        else if self.is_huge() { EntryKind::InvalidLargePage }
        else { EntryKind::Table }
    }
    pub const fn with_flags(address: PhysicalAddress, flags: u64) -> Option<Self> {
        if address.0 & !ADDRESS_MASK != 0 || flags & !ALLOWED_FLAG_MASK != 0 { None } else { Some(Self(address.0 | flags)) }
    }
}

/// Read-only access to physical page-table pages for future firmware-tree
/// inspection. This is deliberately separate from the writable mapper access.
/// # Safety
/// Implementations must return a stable readable view of exactly the requested
/// RAM frame, without aliasing a different frame or dereferencing unchecked
/// physical addresses. No implementation is currently proven for live UEFI CR3.
pub unsafe trait PageTableReadAccess {
    /// # Safety
    /// Caller must uphold the implementation contract above.
    unsafe fn table(&mut self, frame: Frame4KiB) -> Option<*const PageTable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionStop { Missing, LargePage, InvalidLargePage, Complete }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageWalk { pub entries: [PageTableEntry; 4], pub levels_read: u8, pub stop: InspectionStop }

/// Inspect one virtual address through at most four entries. This is not a
/// whole-tree enumeration. It validates the supplied root and address width,
/// stops at non-present entries, and never follows large-page entries.
/// A trusted read provider is still required before use against firmware CR3.
/// # Safety
/// `access` must uphold `PageTableReadAccess` for the full walk, `root` must be
/// a root frame belonging to the address space being read, and `paging` must
/// be an accurate snapshot of that address space's active paging controls.
pub unsafe fn inspect_path<A: PageTableReadAccess>(
    root: Frame4KiB, address: VirtualAddress, paging: PagingSnapshot, access: &mut A,
) -> Result<PageWalk, MapError> {
    if !address.is_canonical() { return Err(MapError::InvalidAddress); }
    if paging.mode != PagingMode::FourLevel { return Err(MapError::UnsupportedPagingMode); }
    let physical_bits = paging.physical_address_bits.ok_or(MapError::UnknownPhysicalWidth)?;
    let root_address = root.start_address().ok_or(MapError::InvalidFlags)?.0;
    if !(32..=52).contains(&physical_bits) || root_address >> physical_bits != 0 {
        return Err(MapError::InvalidFlags);
    }
    let mut walk = PageWalk { entries: [PageTableEntry(0); 4], levels_read: 0, stop: InspectionStop::Complete };
    let idx = indices(address);
    let mut frame = root;
    for level in 0..4 {
        let ptr = unsafe { access.table(frame) }.ok_or(MapError::AccessUnavailable)?;
        if ptr.is_null() { return Err(MapError::AccessUnavailable); }
        let entry = unsafe { (*ptr).entries[idx[level]] };
        walk.entries[level] = entry;
        walk.levels_read += 1;
        if entry.is_present() && entry.address().0 >> physical_bits != 0 {
            return Err(MapError::InvalidFlags);
        }
        if entry.is_present() {
            let is_leaf = level == 3 || entry.classify(level) == EntryKind::LargePage;
            const PKEY_MASK: u64 = 0x7800_0000_0000_0000;
            if entry.0 & NO_EXECUTE != 0 && !paging.nxe_enabled { return Err(MapError::InvalidFlags); }
            if entry.0 & PKEY_MASK != 0 && (!is_leaf || !paging.pke_enabled) { return Err(MapError::InvalidFlags); }
        }
        match entry.classify(level) {
            EntryKind::NotPresent => { walk.stop = InspectionStop::Missing; return Ok(walk); }
            EntryKind::InvalidLargePage => { walk.stop = InspectionStop::InvalidLargePage; return Ok(walk); }
            EntryKind::LargePage => {
                if level == 1 && !paging.page_1g_supported {
                    walk.stop = InspectionStop::InvalidLargePage;
                    return Ok(walk);
                }
                let page_shift = if level == 1 { 30 } else { 21 };
                // Bit 12 is the large-page PAT bit, not address bit 12.
                let alignment_mask = ((1u64 << page_shift) - 1) & !0x1000;
                if entry.address().0 & alignment_mask != 0 { walk.stop = InspectionStop::InvalidLargePage; }
                else { walk.stop = InspectionStop::LargePage; }
                return Ok(walk);
            }
            EntryKind::Leaf => return Ok(walk),
            EntryKind::Table => {
                let physical = entry.address().0;
                if physical >> physical_bits != 0 { return Err(MapError::InvalidFlags); }
                frame = Frame4KiB(physical / PAGE_SIZE);
            }
        }
    }
    Ok(walk)
}

#[repr(C, align(4096))]
pub struct PageTable { pub entries: [PageTableEntry; ENTRY_COUNT] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError { InvalidAddress, Unaligned, InvalidFlags, UnsupportedPagingMode, UnknownPhysicalWidth, AlreadyMapped, NotMapped, NotOwned, OutOfFrames, AccessUnavailable, OwnershipFull, Frame(FrameError) }

/// Maps physical frames into writable virtual access to page-table pages.
/// # Safety
/// Implementations must ensure returned pointers address exactly one live,
/// writable physical page and remain valid while borrowed. Implementations
/// must never alias distinct frames or expose non-RAM device pages as tables.
pub unsafe trait PageTableAccess {
    /// # Safety
    /// Caller must uphold the implementation contract above.
    unsafe fn table_mut(&mut self, frame: Frame4KiB) -> Option<*mut PageTable>;
}

/// Direct physical-to-virtual access valid during bootstrap and identity-mapped UEFI execution.
pub struct IdentityPageTableAccess;
unsafe impl PageTableAccess for IdentityPageTableAccess {
    unsafe fn table_mut(&mut self, frame: Frame4KiB) -> Option<*mut PageTable> {
        let addr = frame.start_address()?.0;
        if addr == 0 { return None; }
        Some(addr as *mut PageTable)
    }
}
unsafe impl PageTableReadAccess for IdentityPageTableAccess {
    unsafe fn table(&mut self, frame: Frame4KiB) -> Option<*const PageTable> {
        let addr = frame.start_address()?.0;
        if addr == 0 { return None; }
        Some(addr as *const PageTable)
    }
}

/// Owns every allocated table frame and constructs 4 KiB and 2 MiB leaf mappings.
/// It never activates CR3. Dropping it does not reclaim frames; explicitly call
/// `release_inactive` only while this root is not active.
pub struct PageTableMapper<'m, 'b, A: PageTableAccess> {
    allocator: &'m mut FrameAllocator<'b>, access: A, owned: &'m mut [Frame4KiB], count: usize, root: Frame4KiB,
}
impl<'m, 'b, A: PageTableAccess> PageTableMapper<'m, 'b, A> {
    pub fn new(allocator: &'m mut FrameAllocator<'b>, mut access: A, owned: &'m mut [Frame4KiB]) -> Result<Self, MapError> {
        if owned.is_empty() { return Err(MapError::OwnershipFull); }
        let root = allocator.allocate().ok_or(MapError::OutOfFrames)?;
        let ptr = unsafe { access.table_mut(root) }.ok_or_else(|| { let _ = allocator.free(root); MapError::AccessUnavailable })?;
        unsafe { ptr.write(PageTable { entries: [PageTableEntry(0); ENTRY_COUNT] }); }
        owned[0] = root;
        Ok(Self { allocator, access, owned, count: 1, root })
    }
    pub const fn root_frame(&self) -> Frame4KiB { self.root }
    fn table_ptr(&mut self, frame: Frame4KiB) -> Result<*mut PageTable, MapError> {
        unsafe { self.access.table_mut(frame) }.ok_or(MapError::AccessUnavailable)
    }
    fn new_table(&mut self) -> Result<Frame4KiB, MapError> {
        if self.count == self.owned.len() { return Err(MapError::OwnershipFull); }
        let f = self.allocator.allocate().ok_or(MapError::OutOfFrames)?;
        let Some(p) = (unsafe { self.access.table_mut(f) }) else { let _ = self.allocator.free(f); return Err(MapError::AccessUnavailable); };
        unsafe { p.write(PageTable { entries: [PageTableEntry(0); ENTRY_COUNT] }); }
        self.owned[self.count] = f; self.count += 1; Ok(f)
    }
    /// Maps a caller-owned physical page. The caller retains responsibility for
    /// that leaf frame; this mapper owns only page-table frames.
    pub fn map_page(&mut self, virtual_address: VirtualAddress, physical: PhysicalAddress, flags: u64) -> Result<(), MapError> {
        let physical_bits = mmu::physical_address_bits().ok_or(MapError::UnknownPhysicalWidth)?;
        self.map_page_with_width(virtual_address, physical, flags, physical_bits)
    }

    fn map_page_with_width(&mut self, virtual_address: VirtualAddress, physical: PhysicalAddress, flags: u64, physical_bits: u8) -> Result<(), MapError> {
        if !virtual_address.is_canonical() { return Err(MapError::InvalidAddress); }
        if !virtual_address.is_aligned(PAGE_SIZE) || !physical.is_aligned(PAGE_SIZE) { return Err(MapError::Unaligned); }
        if flags & !ALLOWED_FLAG_MASK != 0 { return Err(MapError::InvalidFlags); }
        if flags & NO_EXECUTE != 0 && !mmu::nx_enabled() { return Err(MapError::InvalidFlags); }
        if !(32..=52).contains(&physical_bits) { return Err(MapError::UnknownPhysicalWidth); }
        if physical.0 >> physical_bits != 0 { return Err(MapError::InvalidFlags); }
        let leaf = PageTableEntry::with_flags(physical, flags | PRESENT).ok_or(MapError::InvalidFlags)?;
        let idx = indices(virtual_address); let mut frame = self.root;
        let mut path = [self.root; 4];
        for i in 0..3 {
            let p = self.table_ptr(frame)?;
            let entry = unsafe { (*p).entries[idx[i]] };
            if entry.is_present() {
                if entry.is_huge() { return Err(MapError::AlreadyMapped); }
                frame = Frame4KiB(entry.address().0 / PAGE_SIZE);
            } else {
                let child = self.new_table()?;
                let parent_flags = PRESENT | WRITABLE;
                let child_address = child.start_address().ok_or(MapError::InvalidFlags)?;
                unsafe { (*p).entries[idx[i]] = PageTableEntry::with_flags(child_address, parent_flags).ok_or(MapError::InvalidFlags)?; }
                frame = child;
            }
            path[i + 1] = frame;
        }
        let p = self.table_ptr(frame)?;
        if unsafe { (*p).entries[idx[3]].is_present() } { return Err(MapError::AlreadyMapped); }
        if flags & USER != 0 {
            let mut parents = [core::ptr::null_mut(); 3];
            for i in 0..3 {
                parents[i] = self.table_ptr(path[i])?;
            }
            for i in 0..3 {
                unsafe { (*parents[i]).entries[idx[i]].0 |= USER; }
            }
        }
        unsafe { (*p).entries[idx[3]] = leaf; }
        Ok(())
    }

    /// High-performance 2 MiB Huge Page mapping. Drastically reduces TLB pressure
    /// by eliminating an entire level of page table lookups.
    pub fn map_huge_2m_page(&mut self, virtual_address: VirtualAddress, physical: PhysicalAddress, flags: u64) -> Result<(), MapError> {
        let physical_bits = mmu::physical_address_bits().ok_or(MapError::UnknownPhysicalWidth)?;
        self.map_huge_2m_page_with_width(virtual_address, physical, flags, physical_bits)
    }

    pub fn map_huge_2m_page_with_width(&mut self, virtual_address: VirtualAddress, physical: PhysicalAddress, flags: u64, physical_bits: u8) -> Result<(), MapError> {
        if !virtual_address.is_canonical() { return Err(MapError::InvalidAddress); }
        if !virtual_address.is_aligned(HUGE_PAGE_2M_SIZE) || !physical.is_aligned(HUGE_PAGE_2M_SIZE) { return Err(MapError::Unaligned); }
        if flags & !ALLOWED_FLAG_MASK != 0 { return Err(MapError::InvalidFlags); }
        if flags & NO_EXECUTE != 0 && !mmu::nx_enabled() { return Err(MapError::InvalidFlags); }
        if !(32..=52).contains(&physical_bits) { return Err(MapError::UnknownPhysicalWidth); }
        if physical.0 >> physical_bits != 0 { return Err(MapError::InvalidFlags); }

        let idx = indices(virtual_address);
        let mut frame = self.root;
        for i in 0..2 {
            let p = self.table_ptr(frame)?;
            let entry = unsafe { (*p).entries[idx[i]] };
            if entry.is_present() {
                if entry.is_huge() { return Err(MapError::AlreadyMapped); }
                frame = Frame4KiB(entry.address().0 / PAGE_SIZE);
            } else {
                let child = self.new_table()?;
                let parent_flags = PRESENT | WRITABLE;
                let child_address = child.start_address().ok_or(MapError::InvalidFlags)?;
                unsafe { (*p).entries[idx[i]] = PageTableEntry::with_flags(child_address, parent_flags).ok_or(MapError::InvalidFlags)?; }
                frame = child;
            }
        }
        let p = self.table_ptr(frame)?;
        if unsafe { (*p).entries[idx[2]].is_present() } { return Err(MapError::AlreadyMapped); }
        let huge_flags = (flags & !(PAGE_SIZE - 1)) | PRESENT | HUGE_PAGE;
        unsafe { (*p).entries[idx[2]] = PageTableEntry(physical.0 | huge_flags); }
        Ok(())
    }

    /// Allocate a leaf frame from the CorOS allocator and map it. On failure the
    /// leaf frame is returned to the allocator; any successfully-created empty
    /// intermediate tables remain owned by this mapper.
    pub fn map_allocated_page(&mut self, address: VirtualAddress, flags: u64) -> Result<Frame4KiB, MapError> {
        let frame = self.allocator.allocate().ok_or(MapError::OutOfFrames)?;
        let Some(physical) = frame.start_address() else { let _ = self.allocator.free(frame); return Err(MapError::InvalidFlags); };
        if let Err(error) = self.map_page(address, physical, flags) {
            let _ = self.allocator.free(frame);
            return Err(error);
        }
        Ok(frame)
    }
    pub fn translate(&mut self, address: VirtualAddress) -> Result<Option<PhysicalAddress>, MapError> {
        if !address.is_canonical() { return Err(MapError::InvalidAddress); }
        let idx = indices(address); let mut frame = self.root;
        for (level, index) in idx.iter().enumerate() {
            let p = self.table_ptr(frame)?; let e = unsafe { (*p).entries[*index] };
            if !e.is_present() { return Ok(None); }
            if e.is_huge() && level != 3 {
                let shift = [39, 30, 21, 12][level];
                if level == 1 || level == 2 { let mask = (1u64 << shift) - 1; return Ok(Some(PhysicalAddress((e.address().0 & !mask) | (address.0 & mask)))); }
                return Err(MapError::InvalidFlags);
            }
            if level == 3 { return Ok(Some(PhysicalAddress(e.address().0 | (address.0 & (PAGE_SIZE - 1))))); }
            frame = Frame4KiB(e.address().0 / PAGE_SIZE);
        }
        Ok(None)
    }
    pub fn inspect_page(&mut self, address: VirtualAddress) -> Result<Option<PageTableEntry>, MapError> {
        if !address.is_canonical() { return Err(MapError::InvalidAddress); }
        let idx = indices(address); let mut frame = self.root;
        for (level, index) in idx.iter().enumerate() {
            let p = self.table_ptr(frame)?; let entry = unsafe { (*p).entries[*index] };
            if !entry.is_present() { return Ok(None); }
            if entry.is_huge() && level != 3 { return Err(MapError::InvalidFlags); }
            if level == 3 { return Ok(Some(entry)); }
            frame = Frame4KiB(entry.address().0 / PAGE_SIZE);
        }
        Ok(None)
    }
    pub fn is_mapped(&mut self, address: VirtualAddress) -> Result<bool, MapError> { Ok(self.translate(address)?.is_some()) }
    /// Removes a leaf mapping and returns its physical address without freeing
    /// the caller-owned leaf frame.
    pub fn unmap_page(&mut self, address: VirtualAddress) -> Result<PhysicalAddress, MapError> {
        if !address.is_canonical() { return Err(MapError::InvalidAddress); }
        if !address.is_aligned(PAGE_SIZE) { return Err(MapError::Unaligned); }
        let idx = indices(address); let mut frame = self.root;
        let mut path = [self.root; 4];
        for (level, index) in idx.iter().take(3).enumerate() {
            let p = self.table_ptr(frame)?; let e = unsafe { (*p).entries[*index] };
            if !e.is_present() || e.is_huge() { return Err(MapError::NotMapped); }
            frame = Frame4KiB(e.address().0 / PAGE_SIZE);
            path[level + 1] = frame;
        }
        let p = self.table_ptr(frame)?; let e = unsafe { (*p).entries[idx[3]] };
        if !e.is_present() { return Err(MapError::NotMapped); }
        unsafe { (*p).entries[idx[3]] = PageTableEntry(0); }
        // Reclaim empty owned intermediate tables from leaf upward. The root is
        // retained, and foreign tables cannot be reclaimed by this ownership list.
        for level in (1..=3).rev() {
            let child_ptr = self.table_ptr(path[level])?;
            let empty = unsafe { (*child_ptr).entries.iter().all(|entry| !entry.is_present()) };
            if !empty { break; }
            let parent_ptr = self.table_ptr(path[level - 1])?;
            unsafe { (*parent_ptr).entries[idx[level - 1]] = PageTableEntry(0); }
            self.release_owned_table(path[level])?;
        }
        Ok(e.address())
    }
    pub fn protect_page(&mut self, address: VirtualAddress, flags: u64) -> Result<(), MapError> {
        if flags & !ALLOWED_FLAG_MASK != 0 { return Err(MapError::InvalidFlags); }
        if flags & NO_EXECUTE != 0 && !mmu::nx_enabled() { return Err(MapError::InvalidFlags); }
        if !address.is_canonical() { return Err(MapError::InvalidAddress); }
        if !address.is_aligned(PAGE_SIZE) { return Err(MapError::Unaligned); }
        let idx = indices(address); let mut frame = self.root;
        let mut path = [self.root; 4];
        for (level, index) in idx.iter().take(3).enumerate() {
            let p = self.table_ptr(frame)?; let e = unsafe { (*p).entries[*index] };
            if !e.is_present() || e.is_huge() { return Err(MapError::NotMapped); }
            frame = Frame4KiB(e.address().0 / PAGE_SIZE);
            path[level + 1] = frame;
        }
        let p = self.table_ptr(frame)?; let old = unsafe { (*p).entries[idx[3]] };
        if !old.is_present() { return Err(MapError::NotMapped); }
        let replacement = PageTableEntry::with_flags(old.address(), flags | PRESENT).ok_or(MapError::InvalidFlags)?;
        if flags & USER != 0 {
            let mut parents = [core::ptr::null_mut(); 3];
            for i in 0..3 {
                parents[i] = self.table_ptr(path[i])?;
            }
            for i in 0..3 {
                unsafe { (*parents[i]).entries[idx[i]].0 |= USER; }
            }
        }
        let p = self.table_ptr(frame)?;
        unsafe { (*p).entries[idx[3]] = replacement; }
        Ok(())
    }
    fn release_owned_table(&mut self, frame: Frame4KiB) -> Result<(), MapError> {
        let Some(index) = self.owned[1..self.count].iter().position(|owned| *owned == frame).map(|i| i + 1) else { return Err(MapError::NotOwned); };
        self.allocator.free(frame).map_err(MapError::Frame)?;
        self.count -= 1;
        self.owned[index] = self.owned[self.count];
        Ok(())
    }
    /// # Safety
    /// This mapper's root must never have been loaded into CR3.
    pub unsafe fn release_inactive(self) -> Result<(), MapError> {
        for f in self.owned[..self.count].iter().rev() { self.allocator.free(*f).map_err(MapError::Frame)?; }
        Ok(())
    }
}

pub fn current_root_frame() -> PhysicalAddress { PhysicalAddress(mmu::current_page_table_root() & ADDRESS_MASK) }

pub fn indices(address: VirtualAddress) -> [usize; 4] {
    let a = address.0;
    [((a >> 39) & 0x1ff) as usize, ((a >> 30) & 0x1ff) as usize, ((a >> 21) & 0x1ff) as usize, ((a >> 12) & 0x1ff) as usize]
}

/// Bridge connecting cormm PageTableMapper trait to live CR3 paging hardware.
pub struct CormmPageTableBridge {
    pt: cormm::page_table_x86::AddressSpacePageTable,
    cr3_root: u64,
}

impl CormmPageTableBridge {
    pub fn new(asid: u16) -> Self {
        let cr3 = mmu::current_page_table_root();
        Self {
            pt: cormm::page_table_x86::AddressSpacePageTable::new(cormm::page_table_x86::PagingMode::FourLevel, asid),
            cr3_root: cr3,
        }
    }

    pub fn cr3_root(&self) -> u64 {
        self.cr3_root
    }

    /// Switches live CPU hardware CR3 to this address space root and flushes the entire TLB
    pub unsafe fn activate_live_cr3(&mut self) {
        crate::arch::x86_64::mmu::switch_page_table(self.cr3_root);
        crate::arch::x86_64::mmu::flush_tlb_all();
    }
}

impl cormm::PageTableMapper for CormmPageTableBridge {
    type Entry = cormm::page_table_x86::PageTableEntry;
    type Flags = cormm::page_table_x86::PageTableFlags;

    fn map_page(&mut self, vaddr: u64, paddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str> {
        let entry = self.pt.map_page(vaddr, paddr, flags)?;
        crate::arch::x86_64::mmu::flush_tlb(vaddr);
        Ok(entry)
    }

    fn unmap_page(&mut self, vaddr: u64) -> Option<Self::Entry> {
        let entry = self.pt.unmap_page(vaddr)?;
        crate::arch::x86_64::mmu::flush_tlb(vaddr);
        Some(entry)
    }

    fn protect_page(&mut self, vaddr: u64, flags: Self::Flags) -> Result<Self::Entry, &'static str> {
        let entry = self.pt.protect_page(vaddr, flags)?;
        crate::arch::x86_64::mmu::flush_tlb(vaddr);
        Ok(entry)
    }

    fn translate(&self, vaddr: u64) -> Option<(u64, Self::Flags)> {
        self.pt.translate(vaddr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corboot_info::{BootInfo, MemoryDescriptor};
    fn test_paging() -> PagingSnapshot {
        PagingSnapshot { mode: PagingMode::FourLevel, physical_address_bits: Some(48), nxe_enabled: true, pke_enabled: false, page_1g_supported: true }
    }
    #[repr(C, align(4096))]
    struct TestTables([PageTable; 64]);
    struct TestAccess(*mut TestTables);
    unsafe impl PageTableAccess for TestAccess {
        unsafe fn table_mut(&mut self, frame: Frame4KiB) -> Option<*mut PageTable> {
            let index = usize::try_from(frame.0).ok()?;
            if index >= 64 { return None; }
            Some(unsafe { core::ptr::addr_of_mut!((*self.0).0[index]) })
        }
    }
    unsafe impl PageTableReadAccess for TestAccess {
        unsafe fn table(&mut self, frame: Frame4KiB) -> Option<*const PageTable> {
            unsafe { <Self as PageTableAccess>::table_mut(self, frame) }.map(|p| p as *const PageTable)
        }
    }
    fn test_allocator<'a>(managed: &'a mut [u64], allocated: &'a mut [u64], descriptor: &MemoryDescriptor) -> FrameAllocator<'a> {
        let mut info = BootInfo::empty();
        info.memory_map_address = descriptor as *const MemoryDescriptor as u64;
        info.memory_map_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u64;
        info.memory_descriptor_version = 1;
        unsafe { FrameAllocator::from_boot_info_for_test(&info, managed, allocated, 48) }.unwrap()
    }

    #[test] fn maps_translates_protects_rejects_duplicate_and_unmaps() {
        let descriptor = MemoryDescriptor { memory_type: 7, physical_start: 0x1000, number_of_pages: 48, ..MemoryDescriptor::default() };
        let mut managed = [0u64; 1]; let mut allocated = [0u64; 1];
        let mut allocator = test_allocator(&mut managed, &mut allocated, &descriptor);
        let mut tables = TestTables(core::array::from_fn(|_| PageTable { entries: [PageTableEntry(0); ENTRY_COUNT] }));
        let mut owned = [Frame4KiB(0); 16];
        let mut mapper = PageTableMapper::new(&mut allocator, TestAccess(&mut tables), &mut owned).unwrap();
        let virtual_page = VirtualAddress(0x0000_0000_4000_1000);
        mapper.map_page_with_width(virtual_page, PhysicalAddress(0x8000), WRITABLE, 48).unwrap();
        assert_eq!(mapper.translate(VirtualAddress(virtual_page.0 + 0xabc)).unwrap(), Some(PhysicalAddress(0x8abc)));
        assert_eq!(mapper.map_page_with_width(virtual_page, PhysicalAddress(0x9000), WRITABLE, 48), Err(MapError::AlreadyMapped));
        mapper.protect_page(virtual_page, 0).unwrap();
        assert!(!mapper.inspect_page(virtual_page).unwrap().unwrap().is_writable());
        assert_eq!(mapper.unmap_page(virtual_page), Ok(PhysicalAddress(0x8000)));
        assert_eq!(mapper.translate(virtual_page), Ok(None));
        assert_eq!(mapper.owned.len(), 16);
        assert_eq!(mapper.count, 1);
    }

    #[test] fn four_level_indices_cover_low_and_high_canonical_halves() {
        assert_eq!(indices(VirtualAddress(0x0000_0000_0000_1000)), [0, 0, 0, 1]);
        assert_eq!(indices(VirtualAddress(0xffff_8000_0000_0000)), [256, 0, 0, 0]);
        assert_eq!(indices(VirtualAddress(0x0000_7fff_ffff_f000)), [255, 511, 511, 511]);
    }
    #[test] fn decodes_entry_bits_and_rejects_unaddressable_alignment() {
        let entry = PageTableEntry::with_flags(PhysicalAddress(0x1234_5000), PRESENT | WRITABLE | NO_EXECUTE).unwrap();
        assert!(entry.is_present()); assert!(entry.is_writable()); assert!(!entry.is_user());
        assert!(!entry.is_executable()); assert_eq!(entry.address(), PhysicalAddress(0x1234_5000));
        assert!(PageTableEntry::with_flags(PhysicalAddress(0x1234_5001), PRESENT).is_none());
    }

    #[test] fn classifies_absent_table_leaf_and_large_page_entries() {
        assert_eq!(PageTableEntry(0).classify(0), EntryKind::NotPresent);
        assert_eq!(PageTableEntry(PRESENT | 0x2000).classify(0), EntryKind::Table);
        assert_eq!(PageTableEntry(PRESENT | 0x2000).classify(3), EntryKind::Leaf);
        assert_eq!(PageTableEntry(PRESENT | HUGE_PAGE).classify(3), EntryKind::Leaf); // PTE PAT bit
        assert_eq!(PageTableEntry(PRESENT | HUGE_PAGE | 0x20_0000).classify(2), EntryKind::LargePage);
        assert_eq!(PageTableEntry(PRESENT | HUGE_PAGE).classify(0), EntryKind::InvalidLargePage);
    }

    #[test] fn bounded_read_walk_stops_at_absent_and_large_pages() {
        let mut tables = TestTables(core::array::from_fn(|_| PageTable { entries: [PageTableEntry(0); ENTRY_COUNT] }));
        let mut access = TestAccess(&mut tables);
        let address = VirtualAddress(0x4000_1000);
        let absent = unsafe { inspect_path(Frame4KiB(1), address, test_paging(), &mut access) }.unwrap();
        assert_eq!(absent.levels_read, 1);
        assert_eq!(absent.stop, InspectionStop::Missing);
        unsafe {
            (*access.table_mut(Frame4KiB(1)).unwrap()).entries[0] = PageTableEntry(PRESENT | 0x2000);
            (*access.table_mut(Frame4KiB(2)).unwrap()).entries[1] = PageTableEntry(PRESENT | HUGE_PAGE | 0x4000_0000);
        }
        let large = unsafe { inspect_path(Frame4KiB(1), address, test_paging(), &mut access) }.unwrap();
        assert_eq!(large.levels_read, 2);
        assert_eq!(large.stop, InspectionStop::LargePage);
        let mut paging = test_paging();
        paging.page_1g_supported = false;
        let unsupported = unsafe { inspect_path(Frame4KiB(1), address, paging, &mut access) }.unwrap();
        assert_eq!(unsupported.stop, InspectionStop::InvalidLargePage);
    }

    struct NoPhysicalAccess;
    unsafe impl PageTableReadAccess for NoPhysicalAccess {
        unsafe fn table(&mut self, _frame: Frame4KiB) -> Option<*const PageTable> { None }
    }

    #[test]
    fn inspection_rejects_unknown_mode_width_and_unprovided_frames() {
        let address = VirtualAddress(0x1000);
        let mut reader = NoPhysicalAccess;
        let mut unknown = test_paging();
        unknown.mode = PagingMode::Unknown;
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, unknown, &mut reader) }, Err(MapError::UnsupportedPagingMode));
        let mut five_level = test_paging();
        five_level.mode = PagingMode::FiveLevel;
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, five_level, &mut reader) }, Err(MapError::UnsupportedPagingMode));
        let mut unknown = test_paging();
        unknown.physical_address_bits = None;
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, unknown, &mut reader) }, Err(MapError::UnknownPhysicalWidth));
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, test_paging(), &mut reader) }, Err(MapError::AccessUnavailable));
    }

    #[test]
    fn inspection_rejects_nx_without_nxe_and_pkeys_without_pke() {
        let mut tables = TestTables(core::array::from_fn(|_| PageTable { entries: [PageTableEntry(0); ENTRY_COUNT] }));
        let mut access = TestAccess(&mut tables);
        let address = VirtualAddress(0x4000_1000);
        unsafe {
            (*access.table_mut(Frame4KiB(1)).unwrap()).entries[0] = PageTableEntry(PRESENT | 0x2000);
            (*access.table_mut(Frame4KiB(2)).unwrap()).entries[1] = PageTableEntry(PRESENT | 0x3000);
            (*access.table_mut(Frame4KiB(3)).unwrap()).entries[0] = PageTableEntry(PRESENT | 0x4000);
            (*access.table_mut(Frame4KiB(4)).unwrap()).entries[1] = PageTableEntry(PRESENT | NO_EXECUTE | 0x8000);
        }
        let mut paging = test_paging();
        paging.nxe_enabled = false;
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, paging, &mut access) }, Err(MapError::InvalidFlags));
        paging.nxe_enabled = true;
        unsafe { (*access.table_mut(Frame4KiB(4)).unwrap()).entries[1] = PageTableEntry(PRESENT | 0x0800_0000_0000_8000); }
        assert_eq!(unsafe { inspect_path(Frame4KiB(1), address, paging, &mut access) }, Err(MapError::InvalidFlags));
    }
}
