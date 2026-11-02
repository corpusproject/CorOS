//! Two-List Active/Inactive LRU Page Reclaim (`kswapd`) & Working-Set Shadow Detector.
//!
//! Manages the 4 Linux LRU lists (`ActiveAnon`, `InactiveAnon`, `ActiveFile`,
//! `InactiveFile`), implements the second-chance clock-hand scanner (`shrink_node`),
//! dirty page writeback watermarks, and shadow-entry refault distance detection
//! (`workingset_refault`).

use alloc::collections::{BTreeMap, VecDeque};

/// The four primary Linux LRU page reclaim lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LruListKind {
    InactiveAnon,
    ActiveAnon,
    InactiveFile,
    ActiveFile,
}

/// Descriptor for a physical page frame tracked on an LRU list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LruPageFrame {
    pub pfn: usize,
    pub is_anon: bool,
    pub referenced: bool,
    pub dirty: bool,
}

/// Summary of a single `kswapd` reclaim scan pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReclaimScanReport {
    pub scanned_pages: usize,
    pub demoted_to_inactive: usize,
    pub promoted_to_active: usize,
    pub writeback_queued: usize,
    pub reclaimed_pages: usize,
    pub refault_activations: usize,
}

/// Two-List Active/Inactive LRU Reclaim Engine (`kswapd`) with working-set shadow tracking.
#[derive(Debug, Clone)]
pub struct PageReclaimScanner {
    inactive_anon: VecDeque<LruPageFrame>,
    active_anon: VecDeque<LruPageFrame>,
    inactive_file: VecDeque<LruPageFrame>,
    active_file: VecDeque<LruPageFrame>,
    /// Monotonically increasing eviction clock (`nonresident_age`) for refault distance.
    eviction_age_clock: u64,
    /// Shadow entries mapping evicted `pfn` -> `eviction_age_clock` at eviction time.
    shadow_entries: BTreeMap<usize, u64>,
    /// Dirty page writeback threshold (number of dirty pages that triggers flusher wakeup).
    dirty_writeback_threshold: usize,
}

impl PageReclaimScanner {
    /// Creates a new `PageReclaimScanner` with the specified `dirty_writeback_threshold`.
    pub fn new(dirty_writeback_threshold: usize) -> Self {
        Self {
            inactive_anon: VecDeque::new(),
            active_anon: VecDeque::new(),
            inactive_file: VecDeque::new(),
            active_file: VecDeque::new(),
            eviction_age_clock: 0,
            shadow_entries: BTreeMap::new(),
            dirty_writeback_threshold,
        }
    }

    /// Inserts a newly faulted page onto the appropriate Inactive LRU list.
    pub fn add_new_page(&mut self, frame: LruPageFrame) {
        if frame.is_anon {
            self.inactive_anon.push_back(frame);
        } else {
            self.inactive_file.push_back(frame);
        }
    }

    /// Handles a page refault on `pfn` (`workingset_refault`): if the shadow eviction
    /// distance is smaller than the current active list size, the page is immediately
    /// promoted to the Active LRU list to protect the thrashing working set.
    pub fn handle_page_refault(&mut self, mut frame: LruPageFrame) -> bool {
        let active_window = (self.active_anon.len() + self.active_file.len()).max(4) as u64;
        if let Some(evicted_at) = self.shadow_entries.remove(&frame.pfn) {
            let refault_distance = self.eviction_age_clock.saturating_sub(evicted_at);
            if refault_distance <= active_window {
                frame.referenced = false;
                if frame.is_anon {
                    self.active_anon.push_back(frame);
                } else {
                    self.active_file.push_back(frame);
                }
                return true;
            }
        }
        self.add_new_page(frame);
        false
    }

    /// Runs a `kswapd` clock-hand scan pass aiming to reclaim `nr_to_reclaim` pages.
    pub fn shrink_lists(&mut self, nr_to_reclaim: usize) -> ReclaimScanReport {
        let mut report = ReclaimScanReport::default();

        // 1. Balance Active -> Inactive lists using second-chance clock sweep
        Self::age_active_list(
            &mut self.active_file,
            &mut self.inactive_file,
            &mut report,
        );
        Self::age_active_list(
            &mut self.active_anon,
            &mut self.inactive_anon,
            &mut report,
        );

        // 2. Scan Inactive File list first, then Inactive Anon list
        Self::scan_inactive_list(
            &mut self.inactive_file,
            &mut self.active_file,
            &mut self.shadow_entries,
            &mut self.eviction_age_clock,
            nr_to_reclaim,
            &mut report,
        );

        if report.reclaimed_pages < nr_to_reclaim {
            let remaining = nr_to_reclaim - report.reclaimed_pages;
            Self::scan_inactive_list(
                &mut self.inactive_anon,
                &mut self.active_anon,
                &mut self.shadow_entries,
                &mut self.eviction_age_clock,
                remaining,
                &mut report,
            );
        }

        report
    }

    fn age_active_list(
        active: &mut VecDeque<LruPageFrame>,
        inactive: &mut VecDeque<LruPageFrame>,
        report: &mut ReclaimScanReport,
    ) {
        let scan_count = active.len();
        for _ in 0..scan_count {
            if let Some(mut page) = active.pop_front() {
                report.scanned_pages += 1;
                if page.referenced {
                    // Second chance on Active list: clear referenced bit and rotate to tail
                    page.referenced = false;
                    active.push_back(page);
                } else {
                    // Demote cold active page to Inactive list
                    inactive.push_back(page);
                    report.demoted_to_inactive += 1;
                }
            }
        }
    }

    fn scan_inactive_list(
        inactive: &mut VecDeque<LruPageFrame>,
        active: &mut VecDeque<LruPageFrame>,
        shadow_entries: &mut BTreeMap<usize, u64>,
        eviction_clock: &mut u64,
        target: usize,
        report: &mut ReclaimScanReport,
    ) {
        let initial_len = inactive.len();
        let mut reclaimed_here = 0usize;

        for _ in 0..initial_len {
            if reclaimed_here >= target {
                break;
            }
            let Some(mut page) = inactive.pop_front() else {
                break;
            };
            report.scanned_pages += 1;

            if page.referenced {
                page.referenced = false;
                active.push_back(page);
                report.promoted_to_active += 1;
            } else if page.dirty {
                // Dirty page cannot be freed immediately; launder via writeback and rotate
                page.dirty = false;
                inactive.push_back(page);
                report.writeback_queued += 1;
            } else {
                // Evict clean cold page and record working-set shadow entry
                *eviction_clock += 1;
                shadow_entries.insert(page.pfn, *eviction_clock);
                reclaimed_here += 1;
                report.reclaimed_pages += 1;
            }
        }
    }

    /// Returns the number of pages currently residing on `list`.
    pub fn list_len(&self, list: LruListKind) -> usize {
        match list {
            LruListKind::InactiveAnon => self.inactive_anon.len(),
            LruListKind::ActiveAnon => self.active_anon.len(),
            LruListKind::InactiveFile => self.inactive_file.len(),
            LruListKind::ActiveFile => self.active_file.len(),
        }
    }

    /// Returns whether dirty pages across all lists exceed `dirty_writeback_threshold`.
    pub fn needs_dirty_writeback(&self) -> bool {
        let dirty_count = self
            .inactive_file
            .iter()
            .chain(self.active_file.iter())
            .filter(|p| p.dirty)
            .count();
        dirty_count >= self.dirty_writeback_threshold
    }
}
