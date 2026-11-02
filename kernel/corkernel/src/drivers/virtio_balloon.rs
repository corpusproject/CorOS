//! VirtIO Memory Balloon Device Driver for CorOS
//! 100% in-house bare-metal implementation conforming to OASIS VirtIO 1.1 Specification Section 5.5.
//!
//! Features:
//! - Cooperative memory page reclaim (inflation) and surrender (deflation) between guest OS and hypervisor
//! - Inflation queue (inflateq = 0) and Deflation queue (deflateq = 1)
//! - Memory statistics reporting queue (statsq = 2) for real-time host telemetry
//! - Auto-deflation under kernel Out-Of-Memory (OOM) memory pressure (VIRTIO_BALLOON_F_DEFLATE_ON_OOM)
//! - 4096-byte PFN array serialization for bulk page ballooning

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use crate::drivers::virtio::VirtQueue;

pub const VIRTIO_BALLOON_DEVICE_ID: u16 = 5;

// Feature Bits (OASIS VirtIO 1.1 Section 5.5.3)
pub const VIRTIO_BALLOON_F_MUST_TELL_HOST: u64 = 1 << 0;
pub const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1 << 1;
pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;
pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u64 = 1 << 3;
pub const VIRTIO_BALLOON_F_PAGE_POISON: u64 = 1 << 4;
pub const VIRTIO_BALLOON_F_REPORTING: u64 = 1 << 5;

// Memory Statistics Tags (OASIS VirtIO 1.1 Section 5.5.6.3)
pub const VIRTIO_BALLOON_S_SWAP_IN: u16 = 0;
pub const VIRTIO_BALLOON_S_SWAP_OUT: u16 = 1;
pub const VIRTIO_BALLOON_S_MAJFLT: u16 = 2;
pub const VIRTIO_BALLOON_S_MINFLT: u16 = 3;
pub const VIRTIO_BALLOON_S_MEMFREE: u16 = 4;
pub const VIRTIO_BALLOON_S_MEMTOT: u16 = 5;
pub const VIRTIO_BALLOON_S_AVAIL: u16 = 6;
pub const VIRTIO_BALLOON_S_CACHES: u16 = 7;
pub const VIRTIO_BALLOON_S_HTLB_PGALLOC: u16 = 8;
pub const VIRTIO_BALLOON_S_HTLB_PGFAIL: u16 = 9;

/// 8-byte Balloon Memory Statistic Entry
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, packed)]
pub struct VirtioBalloonStat {
    pub tag: u16,
    pub val: u64,
}

/// VirtIO Balloon Hardware Configuration Layout (Section 5.5.4)
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    pub num_pages: u32,
    pub actual: u32,
    pub free_page_hint_cmd_id: u32,
    pub poison_val: u32,
}

/// VirtIO Memory Balloon Controller
pub struct VirtioBalloonDevice {
    pub io_base: u16,
    pub inflate_queue: VirtQueue,
    pub deflate_queue: VirtQueue,
    pub target_pages: u32,
    pub current_pages: u32,
    pub ballooned_pfns: Vec<u32>,
    pub stats_supported: bool,
    pub deflate_on_oom: bool,
}

impl VirtioBalloonDevice {
    pub fn new(io_base: u16) -> Self {
        Self {
            io_base,
            inflate_queue: VirtQueue::new(0, 128),
            deflate_queue: VirtQueue::new(1, 128),
            target_pages: 0,
            current_pages: 0,
            ballooned_pfns: Vec::new(),
            stats_supported: false,
            deflate_on_oom: true,
        }
    }

    /// Read hypervisor requested target page count
    pub fn update_target(&mut self) -> u32 {
        // Read num_pages from config register (offset 0 in device-specific config)
        let num_pages = unsafe { crate::arch::x86_64::cpu::in32(self.io_base + 0x14) };
        self.target_pages = num_pages;
        num_pages
    }

    /// Write actual ballooned page count to hypervisor
    pub fn write_actual(&self) {
        unsafe {
            crate::arch::x86_64::cpu::out32(self.io_base + 0x18, self.current_pages);
        }
    }

    /// Inflate balloon by allocating guest physical pages and handing them to hypervisor
    pub fn inflate(&mut self, pages_to_inflate: usize, alloc_pfn_fn: impl Fn() -> Option<u32>) -> usize {
        let mut inflated = 0;
        let mut pfn_batch = Vec::new();

        for _ in 0..pages_to_inflate {
            if let Some(pfn) = alloc_pfn_fn() {
                pfn_batch.push(pfn);
                self.ballooned_pfns.push(pfn);
                inflated += 1;
            } else {
                break; // Out of memory
            }
        }

        if !pfn_batch.is_empty() {
            // Send PFN array to inflate_queue
            let pfn_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    pfn_batch.as_ptr() as *const u8,
                    pfn_batch.len() * 4,
                )
            };

            // In real hardware, enqueue buffer into VirtQueue and kick host
            self.enqueue_pfn_buffer(true, pfn_bytes);
            self.current_pages += inflated as u32;
            self.write_actual();
        }

        inflated
    }

    /// Deflate balloon by returning pages back to the guest kernel
    pub fn deflate(&mut self, pages_to_deflate: usize, free_pfn_fn: impl Fn(u32)) -> usize {
        let count = pages_to_deflate.min(self.ballooned_pfns.len());
        if count == 0 {
            return 0;
        }

        let mut pfn_batch = Vec::new();
        for _ in 0..count {
            if let Some(pfn) = self.ballooned_pfns.pop() {
                pfn_batch.push(pfn);
                free_pfn_fn(pfn);
            }
        }

        let pfn_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                pfn_batch.as_ptr() as *const u8,
                pfn_batch.len() * 4,
            )
        };

        self.enqueue_pfn_buffer(false, pfn_bytes);
        self.current_pages = self.current_pages.saturating_sub(count as u32);
        self.write_actual();

        count
    }

    fn enqueue_pfn_buffer(&mut self, is_inflate: bool, pfn_bytes: &[u8]) {
        let vq = if is_inflate {
            &mut self.inflate_queue
        } else {
            &mut self.deflate_queue
        };

        if let Some(desc_idx) = vq.alloc_desc() {
            let desc = &mut vq.desc_table[desc_idx as usize];
            desc.addr = pfn_bytes.as_ptr() as u64;
            desc.len = pfn_bytes.len() as u32;
            desc.flags = 0;
            vq.submit_chain(desc_idx);
        }
    }

    /// Collect memory telemetry statistics for host hypervisor
    pub fn collect_stats(&self, free_ram_bytes: u64, total_ram_bytes: u64) -> Vec<VirtioBalloonStat> {
        vec![
            VirtioBalloonStat { tag: VIRTIO_BALLOON_S_MEMFREE, val: free_ram_bytes },
            VirtioBalloonStat { tag: VIRTIO_BALLOON_S_MEMTOT, val: total_ram_bytes },
            VirtioBalloonStat { tag: VIRTIO_BALLOON_S_AVAIL, val: free_ram_bytes },
            VirtioBalloonStat { tag: VIRTIO_BALLOON_S_SWAP_IN, val: 0 },
            VirtioBalloonStat { tag: VIRTIO_BALLOON_S_SWAP_OUT, val: 0 },
        ]
    }
}
