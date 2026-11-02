//! Virtual Memory Swap Engine & OOM (Out Of Memory) Killer for CorOS.
//! 100% in-house implementation modeled after the Linux page reclamation subsystem (`mm/vmscan.c`)
//! and Windows NT Pagefile Manager.
//! Features Active/Inactive dual-list LRU page aging, swap slot allocation, and OOM scoring.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const SWAP_SLOT_SIZE: usize = 4096;
pub const MAX_SWAP_SLOTS: usize = 65536; // 256 MiB Swap partition capacity

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageLruState {
    Active,
    Inactive,
    Unreferenced,
}

#[derive(Clone, Debug)]
pub struct LruPage {
    pub pfn: u64,
    pub task_id: u64,
    pub virt_addr: u64,
    pub state: PageLruState,
    pub referenced: bool,
    pub is_dirty: bool,
}

pub struct SwapManager {
    pub swap_map: Vec<u8>,               // Slot refcount: 0 = free, >0 = in use
    pub swap_cache: BTreeMap<u64, u32>,   // (task_id, virt_addr) -> swap_slot_index
    pub active_list: Vec<LruPage>,       // Hot pages
    pub inactive_list: Vec<LruPage>,     // Cold pages candidate for swap out
    pub total_slots: usize,
    pub free_slots: usize,
}

impl SwapManager {
    pub fn new(total_slots: usize) -> Self {
        let slots = total_slots.min(MAX_SWAP_SLOTS);
        let mut map = Vec::with_capacity(slots);
        map.resize(slots, 0);

        Self {
            swap_map: map,
            swap_cache: BTreeMap::new(),
            active_list: Vec::new(),
            inactive_list: Vec::new(),
            total_slots: slots,
            free_slots: slots,
        }
    }

    /// Allocate a free swap slot.
    pub fn alloc_swap_slot(&mut self) -> Option<u32> {
        for (i, count) in self.swap_map.iter_mut().enumerate() {
            if *count == 0 {
                *count = 1;
                self.free_slots = self.free_slots.saturating_sub(1);
                return Some(i as u32);
            }
        }
        None
    }

    /// Free an allocated swap slot.
    pub fn free_swap_slot(&mut self, slot: u32) {
        let idx = slot as usize;
        if idx < self.swap_map.len() && self.swap_map[idx] > 0 {
            self.swap_map[idx] -= 1;
            if self.swap_map[idx] == 0 {
                self.free_slots += 1;
            }
        }
    }

    /// Register page in the active LRU list.
    pub fn add_page(&mut self, page: LruPage) {
        self.active_list.push(page);
    }

    /// Periodic page reclamation scan (simulates `kswapd`).
    /// Deactivates unreferenced pages from Active to Inactive list.
    /// Evicts cold pages from Inactive list to Swap.
    pub fn scan_and_reclaim(&mut self) -> Vec<LruPage> {
        let mut to_evict = Vec::new();

        // 1. Scan active list: demote unreferenced pages to inactive
        let mut still_active = Vec::new();
        for mut page in self.active_list.drain(..) {
            if page.referenced {
                page.referenced = false;
                still_active.push(page);
            } else {
                page.state = PageLruState::Inactive;
                self.inactive_list.push(page);
            }
        }
        self.active_list = still_active;

        // 2. Scan inactive list: evict candidates
        let mut still_inactive = Vec::new();
        for mut page in self.inactive_list.drain(..) {
            if page.referenced {
                page.referenced = false;
                page.state = PageLruState::Active;
                self.active_list.push(page);
            } else {
                // Candidate for swap
                to_evict.push(page);
            }
        }
        self.inactive_list = still_inactive;

        to_evict
    }

    /// Evicts an inactive cold page to swap backend and records it in swap_cache.
    pub fn evict_page_to_swap(
        &mut self,
        backend: &mut dyn SwapBackend,
        page: LruPage,
        data: &[u8; SWAP_SLOT_SIZE],
    ) -> Result<u32, i32> {
        let slot = self.alloc_swap_slot().ok_or(-28)?; // -ENOSPC (swap exhausted)
        if let Err(e) = backend.write_page(slot, data) {
            self.free_swap_slot(slot);
            return Err(e);
        }
        self.swap_cache.insert(page.virt_addr, slot);
        Ok(slot)
    }

    /// Reads swapped-out page from swap backend and frees the swap slot.
    pub fn fault_in_page_from_swap(
        &mut self,
        backend: &dyn SwapBackend,
        slot: u32,
        virt_addr: u64,
        data: &mut [u8; SWAP_SLOT_SIZE],
    ) -> Result<(), i32> {
        backend.read_page(slot, data)?;
        self.free_swap_slot(slot);
        self.swap_cache.remove(&virt_addr);
        Ok(())
    }

    /// When swap allocation fails (exhausted), select the highest badness victim to kill.
    pub fn check_oom_on_exhaustion<'a>(
        &self,
        candidates: &'a [ProcessMemoryProfile],
        total_ram_pages: u64,
    ) -> Option<&'a ProcessMemoryProfile> {
        if self.free_slots == 0 {
            OomKiller::select_victim(candidates, total_ram_pages)
        } else {
            None
        }
    }
}

/// Abstract block backend for page swapping (e.g., in-memory buffer, NVMe, AHCI, or zram).
pub trait SwapBackend {
    fn read_page(&self, slot: u32, buf: &mut [u8; SWAP_SLOT_SIZE]) -> Result<(), i32>;
    fn write_page(&mut self, slot: u32, buf: &[u8; SWAP_SLOT_SIZE]) -> Result<(), i32>;
    fn total_slots(&self) -> usize;
}

/// In-Memory Swap Partition / Block Device implementing `SwapBackend`.
pub struct InMemorySwapBackend {
    pub slots: BTreeMap<u32, [u8; SWAP_SLOT_SIZE]>,
    pub capacity: usize,
}

impl InMemorySwapBackend {
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: BTreeMap::new(),
            capacity: capacity.min(MAX_SWAP_SLOTS),
        }
    }
}

impl SwapBackend for InMemorySwapBackend {
    fn read_page(&self, slot: u32, buf: &mut [u8; SWAP_SLOT_SIZE]) -> Result<(), i32> {
        if let Some(page) = self.slots.get(&slot) {
            *buf = *page;
            Ok(())
        } else {
            Err(-5) // -EIO
        }
    }

    fn write_page(&mut self, slot: u32, buf: &[u8; SWAP_SLOT_SIZE]) -> Result<(), i32> {
        if slot as usize >= self.capacity {
            return Err(-28); // -ENOSPC
        }
        self.slots.insert(slot, *buf);
        Ok(())
    }

    fn total_slots(&self) -> usize {
        self.capacity
    }
}

// -----------------------------------------------------------------------------
// Linux-Compatible Out-Of-Memory (OOM) Killer Engine
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct ProcessMemoryProfile {
    pub pid: u64,
    pub name: [u8; 16],
    pub rss_pages: u64,     // Resident Set Size (RAM pages held)
    pub swap_pages: u64,    // Swapped out pages
    pub oom_score_adj: i16, // -1000 (immune, e.g. corinit) to +1000
    pub is_kernel_task: bool,
}

pub struct OomKiller;

impl OomKiller {
    /// Calculate the badness score of a process according to Linux `oom_badness` rules:
    /// score = (rss + swap) * 1000 / total_ram + oom_score_adj
    pub fn calculate_badness(proc: &ProcessMemoryProfile, total_ram_pages: u64) -> i64 {
        // Root / init tasks with score -1000 are immune from termination
        if proc.oom_score_adj <= -1000 || proc.is_kernel_task || proc.pid == 1 {
            return -1;
        }

        let total_mem = proc.rss_pages + proc.swap_pages;
        let mut points = if total_ram_pages > 0 {
            (total_mem as i64 * 1000) / (total_ram_pages as i64)
        } else {
            total_mem as i64
        };

        points += proc.oom_score_adj as i64;
        points.max(0)
    }

    /// Select the highest-scoring victim process to terminate when system memory is exhausted.
    pub fn select_victim<'a>(candidates: &'a [ProcessMemoryProfile], total_ram_pages: u64) -> Option<&'a ProcessMemoryProfile> {
        let mut highest_score: i64 = -1;
        let mut victim = None;

        for proc in candidates {
            let score = Self::calculate_badness(proc, total_ram_pages);
            if score > highest_score {
                highest_score = score;
                victim = Some(proc);
            }
        }

        victim
    }
}

/// Verification self-tests for swap engine, in-memory backend, and OOM killer heuristics.
pub fn verify_swap_subsystem() -> u32 {
    let mut passed = 0u32;

    // 1. SwapManager slot allocation, eviction, and fault-in
    let mut mgr = SwapManager::new(16);
    let mut backend = InMemorySwapBackend::new(16);
    let test_data = [0x5Au8; SWAP_SLOT_SIZE];

    let lru = LruPage {
        pfn: 0x1000,
        task_id: 1,
        virt_addr: 0x4000_0000,
        state: PageLruState::Inactive,
        referenced: false,
        is_dirty: true,
    };

    if let Ok(slot) = mgr.evict_page_to_swap(&mut backend, lru, &test_data) {
        passed += 1;

        let mut read_buf = [0u8; SWAP_SLOT_SIZE];
        if mgr.fault_in_page_from_swap(&backend, slot, 0x4000_0000, &mut read_buf).is_ok() {
            if read_buf[0] == 0x5A && read_buf[SWAP_SLOT_SIZE - 1] == 0x5A {
                passed += 1;
            }
        }
    }

    // 2. OOM killer victim selection
    let candidates = [
        ProcessMemoryProfile {
            pid: 1,
            name: *b"init\0\0\0\0\0\0\0\0\0\0\0\0",
            rss_pages: 50,
            swap_pages: 0,
            oom_score_adj: -1000,
            is_kernel_task: false,
        },
        ProcessMemoryProfile {
            pid: 200,
            name: *b"normal_app\0\0\0\0\0\0",
            rss_pages: 100,
            swap_pages: 50,
            oom_score_adj: 0,
            is_kernel_task: false,
        },
        ProcessMemoryProfile {
            pid: 300,
            name: *b"memory_hog\0\0\0\0\0\0",
            rss_pages: 500,
            swap_pages: 200,
            oom_score_adj: 200,
            is_kernel_task: false,
        },
    ];

    if let Some(victim) = OomKiller::select_victim(&candidates, 1000) {
        if victim.pid == 300 {
            passed += 1;
        }
    }

    passed
}

