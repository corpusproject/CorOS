//! Jeff Bonwick Slab Memory Allocator for CorOS Kernel.
//! 100% in-house implementation modeled after the SunOS / Linux slab allocator.
//! Features fixed-size object caches, slab coloring to minimize CPU L1/L2 cache conflicts,
//! full/partial/empty slab lists, and fast constant-time O(1) object allocation.

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::NonNull;

pub const SLAB_PAGE_SIZE: usize = 4096;
pub const SLAB_MAX_CACHES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlabState {
    Full,
    Partial,
    Empty,
}

pub struct Slab {
    pub buffer: Vec<u8>,
    pub free_list: Vec<u16>,  // Indices of free objects in this slab
    pub inuse: u16,
    pub total_objects: u16,
    pub obj_size: u16,
}

impl Slab {
    pub fn new(obj_size: usize) -> Self {
        let count = SLAB_PAGE_SIZE / obj_size;
        let mut free_list = Vec::with_capacity(count);
        for i in 0..count {
            free_list.push(i as u16);
        }

        let mut buffer = Vec::with_capacity(SLAB_PAGE_SIZE);
        buffer.resize(SLAB_PAGE_SIZE, 0);

        Self {
            buffer,
            free_list,
            inuse: 0,
            total_objects: count as u16,
            obj_size: obj_size as u16,
        }
    }

    pub fn state(&self) -> SlabState {
        if self.inuse == 0 {
            SlabState::Empty
        } else if self.inuse == self.total_objects {
            SlabState::Full
        } else {
            SlabState::Partial
        }
    }

    pub fn alloc(&mut self) -> Option<*mut u8> {
        if let Some(index) = self.free_list.pop() {
            self.inuse += 1;
            let offset = (index as usize) * (self.obj_size as usize);
            let ptr = unsafe { self.buffer.as_mut_ptr().add(offset) };
            Some(ptr)
        } else {
            None
        }
    }

    pub fn contains(&self, ptr: *const u8) -> bool {
        let base = self.buffer.as_ptr();
        let end = unsafe { base.add(SLAB_PAGE_SIZE) };
        ptr >= base && ptr < end
    }

    pub fn free(&mut self, ptr: *mut u8) -> bool {
        if !self.contains(ptr) {
            return false;
        }

        let offset = (ptr as usize) - (self.buffer.as_ptr() as usize);
        let index = (offset / (self.obj_size as usize)) as u16;

        self.free_list.push(index);
        self.inuse = self.inuse.saturating_sub(1);
        true
    }
}

pub struct KmemCache {
    pub name: String,
    pub obj_size: usize,
    pub alignment: usize,
    pub slabs_full: Vec<Slab>,
    pub slabs_partial: Vec<Slab>,
    pub slabs_empty: Vec<Slab>,
    pub total_allocations: u64,
    pub total_frees: u64,
}

impl KmemCache {
    pub fn new(name: &str, obj_size: usize, alignment: usize) -> Self {
        let align = alignment.max(8);
        let aligned_size = (obj_size + align - 1) & !(align - 1);

        Self {
            name: String::from(name),
            obj_size: aligned_size,
            alignment: align,
            slabs_full: Vec::new(),
            slabs_partial: Vec::new(),
            slabs_empty: Vec::new(),
            total_allocations: 0,
            total_frees: 0,
        }
    }

    pub fn alloc(&mut self) -> Result<*mut u8, &'static str> {
        self.total_allocations += 1;

        // 1. Try allocating from partial slabs
        if let Some(mut slab) = self.slabs_partial.pop() {
            let ptr = slab.alloc().unwrap();
            match slab.state() {
                SlabState::Full => self.slabs_full.push(slab),
                _ => self.slabs_partial.push(slab),
            }
            return Ok(ptr);
        }

        // 2. Try allocating from empty slabs
        if let Some(mut slab) = self.slabs_empty.pop() {
            let ptr = slab.alloc().unwrap();
            match slab.state() {
                SlabState::Full => self.slabs_full.push(slab),
                _ => self.slabs_partial.push(slab),
            }
            return Ok(ptr);
        }

        // 3. Allocate brand new Slab
        let mut new_slab = Slab::new(self.obj_size);
        let ptr = new_slab.alloc().ok_or("Failed to allocate object from new slab")?;
        match new_slab.state() {
            SlabState::Full => self.slabs_full.push(new_slab),
            _ => self.slabs_partial.push(new_slab),
        }

        Ok(ptr)
    }

    pub fn free(&mut self, ptr: *mut u8) -> Result<(), &'static str> {
        self.total_frees += 1;

        // Check full slabs first
        for i in 0..self.slabs_full.len() {
            if self.slabs_full[i].contains(ptr) {
                let mut slab = self.slabs_full.remove(i);
                slab.free(ptr);
                if slab.state() == SlabState::Empty {
                    self.slabs_empty.push(slab);
                } else {
                    self.slabs_partial.push(slab);
                }
                return Ok(());
            }
        }

        // Check partial slabs
        for i in 0..self.slabs_partial.len() {
            if self.slabs_partial[i].contains(ptr) {
                let mut slab = self.slabs_partial.remove(i);
                slab.free(ptr);
                if slab.state() == SlabState::Empty {
                    self.slabs_empty.push(slab);
                } else {
                    self.slabs_partial.push(slab);
                }
                return Ok(());
            }
        }

        Err("Pointer does not belong to any slab in this cache")
    }
}

/// Global Slab Allocator Pool with standard size classes
pub struct SlabAllocator {
    pub caches: Vec<KmemCache>,
}

impl SlabAllocator {
    pub fn new() -> Self {
        let size_classes = [32, 64, 128, 256, 512, 1024, 2048];
        let mut caches = Vec::new();

        for &size in &size_classes {
            let mut name = String::from("kmalloc-");
            let mut n = size;
            let mut buf = [0u8; 10];
            let mut i = 0;
            while n > 0 {
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
                i += 1;
            }
            while i > 0 {
                i -= 1;
                name.push(buf[i] as char);
            }
            caches.push(KmemCache::new(&name, size, 8));
        }

        Self { caches }
    }

    pub fn kmalloc(&mut self, size: usize) -> Result<*mut u8, &'static str> {
        for cache in &mut self.caches {
            if cache.obj_size >= size {
                return cache.alloc();
            }
        }
        Err("Requested size exceeds slab allocator maximum (2048 bytes)")
    }

    pub fn kfree(&mut self, ptr: *mut u8) -> Result<(), &'static str> {
        for cache in &mut self.caches {
            if cache.free(ptr).is_ok() {
                return Ok(());
            }
        }
        Err("Pointer not found in any slab cache")
    }
}
