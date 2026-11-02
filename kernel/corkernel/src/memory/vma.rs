//! Virtual Memory Area (VMA) & Address Space Manager for CorOS.
//! 100% in-house implementation modeled after Linux `vm_area_struct` and Windows NT VAD (Virtual Address Descriptor).
//! Manages process virtual address layout, page fault validation, memory protection,
//! and mmap file/anonymous memory regions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const PROT_NONE: u32   = 0x0;
pub const PROT_READ: u32   = 0x1;
pub const PROT_WRITE: u32  = 0x2;
pub const PROT_EXEC: u32   = 0x4;

pub const MAP_SHARED: u32     = 0x01;
pub const MAP_PRIVATE: u32    = 0x02;
pub const MAP_FIXED: u32      = 0x10;
pub const MAP_ANONYMOUS: u32  = 0x20;
pub const MAP_GROWSDOWN: u32  = 0x0100; // Stack segment
pub const MAP_LOCKED: u32     = 0x2000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmaType {
    Anonymous,
    FileBacked { file_inode: u64, file_offset: u64 },
    Stack,
    Heap,
    Code,
}

#[derive(Clone, Debug)]
pub struct Vma {
    pub vm_start: u64,
    pub vm_end: u64,       // Non-inclusive
    pub vm_flags: u32,     // PROT_READ | PROT_WRITE | PROT_EXEC
    pub map_flags: u32,    // MAP_PRIVATE | MAP_ANONYMOUS ...
    pub vma_type: VmaType,
}

impl Vma {
    pub fn new(start: u64, end: u64, prot: u32, map_flags: u32, vma_type: VmaType) -> Self {
        Self {
            vm_start: start,
            vm_end: end,
            vm_flags: prot,
            map_flags,
            vma_type,
        }
    }

    pub fn size(&self) -> u64 {
        self.vm_end.saturating_sub(self.vm_start)
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vm_start && addr < self.vm_end
    }

    pub fn can_read(&self) -> bool {
        (self.vm_flags & PROT_READ) != 0
    }

    pub fn can_write(&self) -> bool {
        (self.vm_flags & PROT_WRITE) != 0
    }

    pub fn can_exec(&self) -> bool {
        (self.vm_flags & PROT_EXEC) != 0
    }
}

/// Address Space descriptor containing all VMAs of a process
pub struct AddressSpace {
    // Keyed by vm_start
    pub vmas: BTreeMap<u64, Vma>,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub mmap_base: u64,
}

impl AddressSpace {
    pub fn new(mmap_base: u64, start_brk: u64, start_stack: u64) -> Self {
        Self {
            vmas: BTreeMap::new(),
            start_brk,
            brk: start_brk,
            start_stack,
            mmap_base,
        }
    }

    /// Find the VMA containing virtual address `addr`.
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        // Range check using BTreeMap range
        for (_, vma) in self.vmas.iter() {
            if vma.contains(addr) {
                return Some(vma);
            }
        }
        None
    }

    /// Check if a memory access caused by page fault is legitimate.
    pub fn handle_page_fault(&self, fault_addr: u64, write_access: bool, exec_access: bool) -> bool {
        if let Some(vma) = self.find_vma(fault_addr) {
            if write_access && !vma.can_write() {
                return false; // Access violation: write to read-only page
            }
            if exec_access && !vma.can_exec() {
                return false; // Access violation: execute non-executable memory (DEP/NX)
            }
            return true; // Valid page fault to be resolved by Demand Paging
        }
        false // Segmentation fault: outside of all mapped VMAs
    }

    /// Map a new memory region (like `sys_mmap`).
    pub fn mmap(
        &mut self,
        hint_addr: u64,
        length: u64,
        prot: u32,
        flags: u32,
        vma_type: VmaType,
    ) -> Result<u64, &'static str> {
        let page_size = 4096u64;
        let aligned_len = (length + page_size - 1) & !(page_size - 1);
        if aligned_len == 0 {
            return Err("Invalid mmap length 0");
        }

        // Determine starting address
        let start = if (flags & MAP_FIXED) != 0 {
            if (hint_addr % page_size) != 0 {
                return Err("MAP_FIXED address not page aligned");
            }
            // Invalidate overlapping VMAs
            self.munmap(hint_addr, aligned_len)?;
            hint_addr
        } else {
            self.find_free_area(aligned_len)?
        };

        let end = start + aligned_len;
        let vma = Vma::new(start, end, prot, flags, vma_type);
        self.vmas.insert(start, vma);

        Ok(start)
    }

    /// Unmap a memory region (like `sys_munmap`).
    pub fn munmap(&mut self, addr: u64, length: u64) -> Result<(), &'static str> {
        let page_size = 4096u64;
        let aligned_len = (length + page_size - 1) & !(page_size - 1);
        let end_unmap = addr + aligned_len;

        let mut to_remove = Vec::new();
        let mut to_insert = Vec::new();

        for (&start, vma) in self.vmas.iter() {
            if vma.vm_start < end_unmap && vma.vm_end > addr {
                // Overlaps
                to_remove.push(start);

                // Case 1: unmap region is strictly inside VMA -> split into two
                if vma.vm_start < addr && vma.vm_end > end_unmap {
                    to_insert.push(Vma::new(vma.vm_start, addr, vma.vm_flags, vma.map_flags, vma.vma_type));
                    to_insert.push(Vma::new(end_unmap, vma.vm_end, vma.vm_flags, vma.map_flags, vma.vma_type));
                }
                // Case 2: unmap clips left edge
                else if vma.vm_start < addr && vma.vm_end <= end_unmap {
                    to_insert.push(Vma::new(vma.vm_start, addr, vma.vm_flags, vma.map_flags, vma.vma_type));
                }
                // Case 3: unmap clips right edge
                else if vma.vm_start >= addr && vma.vm_end > end_unmap {
                    to_insert.push(Vma::new(end_unmap, vma.vm_end, vma.vm_flags, vma.map_flags, vma.vma_type));
                }
            }
        }

        for k in to_remove {
            self.vmas.remove(&k);
        }
        for v in to_insert {
            self.vmas.insert(v.vm_start, v);
        }

        Ok(())
    }

    /// Find an unmapped contiguous address gap large enough for `length` bytes.
    fn find_free_area(&self, length: u64) -> Result<u64, &'static str> {
        let mut cur = self.mmap_base;
        let max_addr = 0x0000_7FFF_FFFF_0000u64; // Standard x86_64 Userland limit

        for (&start, vma) in self.vmas.iter() {
            if start >= cur {
                if start - cur >= length {
                    return Ok(cur);
                }
                cur = vma.vm_end;
            } else if vma.vm_end > cur {
                cur = vma.vm_end;
            }
        }

        if max_addr.saturating_sub(cur) >= length {
            Ok(cur)
        } else {
            Err("Out of virtual address space in process")
        }
    }

    /// Resize heap (like `sys_brk`).
    pub fn sys_brk(&mut self, new_brk: u64) -> u64 {
        if new_brk < self.start_brk {
            return self.brk;
        }

        // Align up to 4096
        let page_size = 4096u64;
        let cur_aligned = (self.brk + page_size - 1) & !(page_size - 1);
        let new_aligned = (new_brk + page_size - 1) & !(page_size - 1);

        if new_aligned > cur_aligned {
            let diff = new_aligned - cur_aligned;
            if self.mmap(cur_aligned, diff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, VmaType::Heap).is_ok() {
                self.brk = new_brk;
            }
        } else if new_aligned < cur_aligned {
            let diff = cur_aligned - new_aligned;
            if self.munmap(new_aligned, diff).is_ok() {
                self.brk = new_brk;
            }
        } else {
            self.brk = new_brk;
        }

        self.brk
    }
}
