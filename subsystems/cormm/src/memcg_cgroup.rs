//! Memory Control Group (`MemCgroup` / cgroup v2) Hierarchical Accounting & Enforcement.
//!
//! Tracks per-category memory usage (`anon`, `file`, `kernel_stack`, `slab`, `sock`),
//! propagates page charges up parent cgroups, enforces `memory.min`, `memory.low`,
//! `memory.high` throttling, and `memory.max` hard OOM limits.

use alloc::collections::BTreeMap;

/// Categories of memory accounted inside a `MemCgroup` (`memory.stat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemCgStatKind {
    /// Anonymous user memory (`rss`).
    Anon,
    /// Page cache / file-backed pages.
    File,
    /// Kernel thread stacks allocated on behalf of tasks in this cgroup.
    KernelStack,
    /// Kernel SLUB slab objects (`kmem`) charged to this cgroup.
    Slab,
    /// Network socket buffers (`TCP`/`UDP` skb memory).
    Sock,
}

/// Per-category page counters inside a `MemCgroup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemCgPageCounters {
    pub anon_pages: u64,
    pub file_pages: u64,
    pub kernel_stack_pages: u64,
    pub slab_pages: u64,
    pub sock_pages: u64,
}

impl MemCgPageCounters {
    /// Total pages charged across all 5 categories.
    pub const fn total_pages(&self) -> u64 {
        self.anon_pages
            .saturating_add(self.file_pages)
            .saturating_add(self.kernel_stack_pages)
            .saturating_add(self.slab_pages)
            .saturating_add(self.sock_pages)
    }

    /// Adds `pages` to the specified `kind`.
    pub fn add(&mut self, kind: MemCgStatKind, pages: u64) {
        match kind {
            MemCgStatKind::Anon => self.anon_pages = self.anon_pages.saturating_add(pages),
            MemCgStatKind::File => self.file_pages = self.file_pages.saturating_add(pages),
            MemCgStatKind::KernelStack => {
                self.kernel_stack_pages = self.kernel_stack_pages.saturating_add(pages)
            }
            MemCgStatKind::Slab => self.slab_pages = self.slab_pages.saturating_add(pages),
            MemCgStatKind::Sock => self.sock_pages = self.sock_pages.saturating_add(pages),
        }
    }

    /// Subtracts `pages` from the specified `kind`.
    pub fn sub(&mut self, kind: MemCgStatKind, pages: u64) {
        match kind {
            MemCgStatKind::Anon => self.anon_pages = self.anon_pages.saturating_sub(pages),
            MemCgStatKind::File => self.file_pages = self.file_pages.saturating_sub(pages),
            MemCgStatKind::KernelStack => {
                self.kernel_stack_pages = self.kernel_stack_pages.saturating_sub(pages)
            }
            MemCgStatKind::Slab => self.slab_pages = self.slab_pages.saturating_sub(pages),
            MemCgStatKind::Sock => self.sock_pages = self.sock_pages.saturating_sub(pages),
        }
    }
}

/// Cgroup v2 memory watermark and enforcement limits (in 4 KiB pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemCgLimits {
    /// Hard protection guarantee (`memory.min`); never reclaimed.
    pub min_pages: u64,
    /// Soft protection threshold (`memory.low`); reclaimed only under severe pressure.
    pub low_pages: u64,
    /// Throttle limit (`memory.high`); tasks are throttled and forced to reclaim excess pages.
    pub high_pages: u64,
    /// Hard OOM limit (`memory.max`); charges exceeding this trigger cgroup reclaim/OOM.
    pub max_pages: u64,
}

/// Result of charging pages to a `MemCgroup` hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// Charge succeeded cleanly below `memory.high`.
    Allowed { current_total_pages: u64 },
    /// Charge succeeded, but `memory.high` was exceeded in `throttled_cgroup_id`;
    /// caller must reclaim `reclaim_target_pages` before returning to user mode.
    ThrottledHigh {
        throttled_cgroup_id: u32,
        reclaim_target_pages: u64,
    },
    /// Charge rejected because `limiting_cgroup_id` would exceed `memory.max`.
    RejectedMaxOom { limiting_cgroup_id: u32 },
}

/// Single cgroup v2 memory controller node (`MemCgroup`).
#[derive(Debug, Clone)]
pub struct MemCgroup {
    pub cgroup_id: u32,
    pub parent_id: Option<u32>,
    pub name: &'static str,
    pub limits: MemCgLimits,
    pub counters: MemCgPageCounters,
    pub high_throttle_events: u64,
    pub max_oom_events: u64,
}

impl MemCgroup {
    /// Computes how many pages can be reclaimed from this cgroup without violating `memory.min`.
    pub const fn reclaimable_pages(&self) -> u64 {
        self.counters
            .total_pages()
            .saturating_sub(self.limits.min_pages)
    }

    /// Computes the number of pages above `memory.high` that must be reclaimed to lift throttling.
    pub const fn high_reclaim_target(&self) -> u64 {
        self.counters
            .total_pages()
            .saturating_sub(self.limits.high_pages)
    }
}

/// Hierarchical Memory Control Group tree managing parent-child charge propagation.
#[derive(Debug, Clone)]
pub struct MemCgroupHierarchy {
    nodes: BTreeMap<u32, MemCgroup>,
}

impl MemCgroupHierarchy {
    /// Creates a new hierarchy initialized with a root cgroup (`id = 0`).
    pub fn new(root_max_pages: u64) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            0,
            MemCgroup {
                cgroup_id: 0,
                parent_id: None,
                name: "root",
                limits: MemCgLimits {
                    min_pages: 0,
                    low_pages: 0,
                    high_pages: root_max_pages,
                    max_pages: root_max_pages,
                },
                counters: MemCgPageCounters::default(),
                high_throttle_events: 0,
                max_oom_events: 0,
            },
        );
        Self { nodes }
    }

    /// Creates a child `MemCgroup` under `parent_id`.
    pub fn create_cgroup(
        &mut self,
        cgroup_id: u32,
        parent_id: u32,
        name: &'static str,
        limits: MemCgLimits,
    ) -> Result<(), &'static str> {
        if !self.nodes.contains_key(&parent_id) {
            return Err("Parent cgroup does not exist");
        }
        if self.nodes.contains_key(&cgroup_id) {
            return Err("Cgroup ID already exists");
        }
        self.nodes.insert(
            cgroup_id,
            MemCgroup {
                cgroup_id,
                parent_id: Some(parent_id),
                name,
                limits,
                counters: MemCgPageCounters::default(),
                high_throttle_events: 0,
                max_oom_events: 0,
            },
        );
        Ok(())
    }

    /// Attempts to charge `pages` of `kind` to `cgroup_id` and all of its ancestors.
    /// If any ancestor would exceed `memory.max`, the entire charge is rolled back.
    pub fn try_charge(&mut self, cgroup_id: u32, kind: MemCgStatKind, pages: u64) -> ChargeOutcome {
        // Collect ancestor chain from leaf up to root
        let mut chain = alloc::vec::Vec::new();
        let mut cursor = Some(cgroup_id);
        while let Some(id) = cursor {
            let Some(node) = self.nodes.get(&id) else {
                return ChargeOutcome::RejectedMaxOom {
                    limiting_cgroup_id: cgroup_id,
                };
            };
            chain.push(id);
            cursor = node.parent_id;
        }

        // First pass: check `memory.max` along the entire ancestor chain
        for &id in &chain {
            let node = self.nodes.get_mut(&id).unwrap();
            if node.counters.total_pages().saturating_add(pages) > node.limits.max_pages {
                node.max_oom_events += 1;
                return ChargeOutcome::RejectedMaxOom {
                    limiting_cgroup_id: id,
                };
            }
        }

        // Second pass: commit charge and check `memory.high` throttling
        let mut throttle_report: Option<(u32, u64)> = None;
        for &id in &chain {
            let node = self.nodes.get_mut(&id).unwrap();
            node.counters.add(kind, pages);
            let excess = node.high_reclaim_target();
            if excess > 0 && throttle_report.is_none() {
                node.high_throttle_events += 1;
                throttle_report = Some((id, excess));
            }
        }

        if let Some((throttled_cgroup_id, reclaim_target_pages)) = throttle_report {
            ChargeOutcome::ThrottledHigh {
                throttled_cgroup_id,
                reclaim_target_pages,
            }
        } else {
            let leaf_total = self.nodes[&cgroup_id].counters.total_pages();
            ChargeOutcome::Allowed {
                current_total_pages: leaf_total,
            }
        }
    }

    /// Uncharges `pages` of `kind` from `cgroup_id` and all of its ancestors.
    pub fn uncharge(&mut self, cgroup_id: u32, kind: MemCgStatKind, pages: u64) {
        let mut cursor = Some(cgroup_id);
        while let Some(id) = cursor {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.counters.sub(kind, pages);
                cursor = node.parent_id;
            } else {
                break;
            }
        }
    }

    /// Borrows a `MemCgroup` by ID.
    pub fn get(&self, cgroup_id: u32) -> Option<&MemCgroup> {
        self.nodes.get(&cgroup_id)
    }
}
