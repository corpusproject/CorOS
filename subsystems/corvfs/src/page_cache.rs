//! CorOS VFS Module: `page_cache`
//!
//! Block buffer & page cache (`CachedPage`, radix/index lookup by `(inode_id, page_index)`,
//! dirty page tracking, writeback flush queue ordered by block LBA, and sequential
//! read-ahead window predictor).

use alloc::vec::Vec;

/// Standard VFS page cache frame size (4096 bytes).
pub const PAGE_CACHE_FRAME_SIZE: usize = 4096;

/// Lifecycle state of a cached 4 KiB page frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    Clean,
    Dirty,
    WritebackInFlight,
}

/// 4 KiB cached file page indexed by `(inode_id, page_index)`.
#[derive(Clone, Debug)]
pub struct CachedPage {
    pub inode_id: u64,
    pub page_index: u64,
    pub disk_block_lba: u64,
    pub state: PageState,
    pub pin_count: u32,
    pub last_access_tick: u64,
    pub data: [u8; PAGE_CACHE_FRAME_SIZE],
}

/// Sequential read-ahead window tracker for a file stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadAheadWindow {
    pub last_page_index: u64,
    pub sequential_hits: u32,
    pub window_pages: u32,
    pub max_window_pages: u32,
}

impl ReadAheadWindow {
    pub const fn new(max_window_pages: u32) -> Self {
        Self {
            last_page_index: u64::MAX,
            sequential_hits: 0,
            window_pages: 2,
            max_window_pages,
        }
    }

    /// Observes an access to `page_index` and returns the recommended read-ahead range `(start_page, count)`.
    pub fn observe_access(&mut self, page_index: u64) -> (u64, u32) {
        if self.last_page_index != u64::MAX && page_index == self.last_page_index + 1 {
            self.sequential_hits = self.sequential_hits.saturating_add(1);
            self.window_pages = (self.window_pages * 2).min(self.max_window_pages);
        } else if page_index != self.last_page_index {
            self.sequential_hits = 0;
            self.window_pages = 2;
        }
        self.last_page_index = page_index;
        (page_index + 1, self.window_pages)
    }
}

/// Writeback batch descriptor ordered by physical LBA for elevator disk scheduling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritebackRequest {
    pub inode_id: u64,
    pub page_index: u64,
    pub disk_block_lba: u64,
}

/// Unified VFS Page Cache & Writeback Flush Queue.
pub struct VfsPageCache {
    pages: Vec<CachedPage>,
    max_pages: usize,
    clock_tick: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub writebacks_completed: u64,
}

impl VfsPageCache {
    pub fn new(max_pages: usize) -> Self {
        Self {
            pages: Vec::with_capacity(max_pages),
            max_pages: max_pages.max(4),
            clock_tick: 1,
            cache_hits: 0,
            cache_misses: 0,
            writebacks_completed: 0,
        }
    }

    #[inline]
    fn next_tick(&mut self) -> u64 {
        let t = self.clock_tick;
        self.clock_tick = self.clock_tick.wrapping_add(1);
        t
    }

    /// Binary search index by `(inode_id, page_index)`.
    fn find_slot_index(&self, inode_id: u64, page_index: u64) -> Result<usize, usize> {
        self.pages
            .binary_search_by_key(&(inode_id, page_index), |p| (p.inode_id, p.page_index))
    }

    /// Evicts the least-recently-used clean, unpinned page frame.
    fn evict_clean_lru(&mut self) -> bool {
        let victim = self
            .pages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == PageState::Clean && p.pin_count == 0)
            .min_by_key(|(_, p)| p.last_access_tick)
            .map(|(idx, _)| idx);

        if let Some(idx) = victim {
            self.pages.remove(idx);
            true
        } else {
            false
        }
    }

    /// Inserts or updates a 4 KiB page frame in the sorted index.
    pub fn insert_page(
        &mut self,
        inode_id: u64,
        page_index: u64,
        disk_block_lba: u64,
        initial_data: &[u8],
        dirty: bool,
    ) -> bool {
        let tick = self.next_tick();
        if let Ok(idx) = self.find_slot_index(inode_id, page_index) {
            let p = &mut self.pages[idx];
            let copy_len = initial_data.len().min(PAGE_CACHE_FRAME_SIZE);
            p.data[..copy_len].copy_from_slice(&initial_data[..copy_len]);
            if dirty {
                p.state = PageState::Dirty;
            }
            p.last_access_tick = tick;
            return true;
        }

        if self.pages.len() >= self.max_pages && !self.evict_clean_lru() {
            return false;
        }

        let ins_idx = match self.find_slot_index(inode_id, page_index) {
            Ok(i) | Err(i) => i,
        };

        let mut frame = [0u8; PAGE_CACHE_FRAME_SIZE];
        let copy_len = initial_data.len().min(PAGE_CACHE_FRAME_SIZE);
        frame[..copy_len].copy_from_slice(&initial_data[..copy_len]);

        self.pages.insert(
            ins_idx,
            CachedPage {
                inode_id,
                page_index,
                disk_block_lba,
                state: if dirty { PageState::Dirty } else { PageState::Clean },
                pin_count: 0,
                last_access_tick: tick,
                data: frame,
            },
        );
        true
    }

    /// Reads a slice of a cached page if resident.
    pub fn read_cached(&mut self, inode_id: u64, page_index: u64, offset_in_page: usize, out: &mut [u8]) -> Option<usize> {
        let tick = self.next_tick();
        match self.find_slot_index(inode_id, page_index) {
            Ok(idx) => {
                let p = &mut self.pages[idx];
                p.last_access_tick = tick;
                self.cache_hits += 1;
                if offset_in_page >= PAGE_CACHE_FRAME_SIZE {
                    return Some(0);
                }
                let avail = (PAGE_CACHE_FRAME_SIZE - offset_in_page).min(out.len());
                out[..avail].copy_from_slice(&p.data[offset_in_page..offset_in_page + avail]);
                Some(avail)
            }
            Err(_) => {
                self.cache_misses += 1;
                None
            }
        }
    }

    /// Modifies a resident page in-place and transitions its state to `PageState::Dirty`.
    pub fn write_cached(&mut self, inode_id: u64, page_index: u64, offset_in_page: usize, src: &[u8]) -> Option<usize> {
        let tick = self.next_tick();
        let idx = self.find_slot_index(inode_id, page_index).ok()?;
        let p = &mut self.pages[idx];
        if offset_in_page >= PAGE_CACHE_FRAME_SIZE {
            return Some(0);
        }
        let n = (PAGE_CACHE_FRAME_SIZE - offset_in_page).min(src.len());
        p.data[offset_in_page..offset_in_page + n].copy_from_slice(&src[..n]);
        p.state = PageState::Dirty;
        p.last_access_tick = tick;
        Some(n)
    }

    /// Collects all dirty pages, sorts them by physical `disk_block_lba` (elevator order), and marks them `Clean`.
    pub fn flush_writeback_queue(&mut self) -> Vec<WritebackRequest> {
        let mut queue = Vec::new();
        for p in &mut self.pages {
            if p.state == PageState::Dirty {
                p.state = PageState::Clean;
                queue.push(WritebackRequest {
                    inode_id: p.inode_id,
                    page_index: p.page_index,
                    disk_block_lba: p.disk_block_lba,
                });
                self.writebacks_completed += 1;
            }
        }
        queue.sort_by_key(|r| r.disk_block_lba);
        queue
    }
}

/// Self-test suite for `page_cache`.
pub fn verify_vfs_page_cache() -> u32 {
    let mut passed = 0u32;
    let mut pc = VfsPageCache::new(4);

    if pc.insert_page(10, 0, 500, b"PAGE_ZERO_HEADER", false)
        && pc.insert_page(10, 1, 480, b"PAGE_ONE_DIRTY", true)
        && pc.insert_page(10, 2, 420, b"PAGE_TWO_DIRTY", true)
    {
        passed += 1;
    }

    let mut rbuf = [0u8; 16];
    if pc.read_cached(10, 0, 0, &mut rbuf) == Some(16) && &rbuf == b"PAGE_ZERO_HEADER" {
        passed += 1;
    }

    // Flush dirty pages and verify LBA-sorted elevator ordering (420 before 480)
    let wb = pc.flush_writeback_queue();
    if wb.len() == 2 && wb[0].disk_block_lba == 420 && wb[1].disk_block_lba == 480 {
        passed += 1;
    }

    // Verify exponential sequential read-ahead window expansion
    let mut ra = ReadAheadWindow::new(32);
    let _ = ra.observe_access(0);
    let _ = ra.observe_access(1);
    let (next_pg, win_len) = ra.observe_access(2);
    if next_pg == 3 && win_len == 8 {
        passed += 1;
    }

    passed
}
