//! Hardware Direct Memory Access (DMA) & Cache Coherency Architecture
//!
//! Bare-metal no_std pure Rust DMA subsystem for CorOS:
//! - Physical DMA Buffer Allocator below 4 GiB (32-bit PCI addressable zone)
//! - Scatter-Gather List (SGL) Builder for bus-mastering devices (AHCI, NVMe, xHCI, HDA)
//! - Hardware Cache Coherency: clflush, clflushopt, mfence, sfence, lfence
//! - Device DMA synchronization (dma_sync_for_cpu, dma_sync_for_device)

#![allow(dead_code)]

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

pub const PAGE_SIZE: usize = 4096;
pub const MAX_DMA32_PHYSICAL: u64 = 0xFFFFFFFF; // 4 GiB boundary

/// Single Scatter-Gather Physical Memory Descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScatterGatherEntry {
    pub physical_address: u64,
    pub length: u32,
    pub flags: u32,
}

/// Hardware Scatter-Gather List (SGL)
#[derive(Debug, Clone)]
pub struct ScatterGatherList {
    pub entries: Vec<ScatterGatherEntry>,
    pub total_bytes: usize,
}

impl ScatterGatherList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_bytes: 0,
        }
    }

    pub fn add_segment(&mut self, phys_addr: u64, length: u32) {
        self.entries.push(ScatterGatherEntry {
            physical_address: phys_addr,
            length,
            flags: 0,
        });
        self.total_bytes += length as usize;
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Contiguous Hardware DMA Memory Buffer
pub struct DmaBuffer {
    pub physical_address: u64,
    pub virtual_address: *mut u8,
    pub size: usize,
    pub page_count: usize,
}

impl DmaBuffer {
    /// Create an aligned DMA buffer structure
    pub fn from_raw_parts(physical_address: u64, virtual_address: *mut u8, size: usize) -> Self {
        let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        Self {
            physical_address,
            virtual_address,
            size,
            page_count,
        }
    }

    /// Read byte slice safely from DMA buffer
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.virtual_address, self.size)
    }

    /// Write byte slice safely to DMA buffer
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.virtual_address, self.size)
    }

    /// Flush CPU cache lines to RAM before device DMA reads (Host -> Device)
    pub fn sync_for_device(&self) {
        compiler_fence(Ordering::SeqCst);
        let ptr = self.virtual_address as usize;
        let mut offset = 0;
        while offset < self.size {
            unsafe {
                core::arch::x86_64::_mm_clflush((ptr + offset) as *const u8);
            }
            offset += 64; // Cacheline size = 64 bytes
        }
        unsafe {
            core::arch::x86_64::_mm_sfence();
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Invalidate CPU cache lines after device DMA wrote to RAM (Device -> Host)
    pub fn sync_for_cpu(&self) {
        compiler_fence(Ordering::SeqCst);
        let ptr = self.virtual_address as usize;
        let mut offset = 0;
        while offset < self.size {
            unsafe {
                core::arch::x86_64::_mm_clflush((ptr + offset) as *const u8);
            }
            offset += 64;
        }
        unsafe {
            core::arch::x86_64::_mm_mfence();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Hardware Memory Barriers
#[inline(always)]
pub fn memory_barrier() {
    unsafe {
        core::arch::x86_64::_mm_mfence();
    }
}

#[inline(always)]
pub fn read_barrier() {
    unsafe {
        core::arch::x86_64::_mm_lfence();
    }
}

#[inline(always)]
pub fn write_barrier() {
    unsafe {
        core::arch::x86_64::_mm_sfence();
    }
}
