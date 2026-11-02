//! ACPI SRAT / SLIT NUMA Node Topology & Allocation Policy Engine.
//!
//! Models Non-Uniform Memory Access (`NumaNode`) physical PFN spans, the ACPI SLIT
//! inter-node relative distance matrix (where local = `10` and remote = `20+`),
//! distance-ordered fallback zonelists, and Linux `mpol` (`Default`, `Bind`,
//! `Preferred`, `Interleave`) allocation policies.

use alloc::vec::Vec;

/// ACPI SLIT standard local node distance (`10`).
pub const NUMA_LOCAL_DISTANCE: u8 = 10;

/// ACPI SLIT default single-hop remote node distance (`20`).
pub const NUMA_REMOTE_DISTANCE: u8 = 20;

/// Descriptor for a single NUMA Node (`pglist_data` / `pg_data_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaNode {
    pub node_id: usize,
    pub start_pfn: usize,
    pub end_pfn: usize,
    pub free_pages: usize,
    pub cpu_mask: u64,
}

impl NumaNode {
    /// Creates a new `NumaNode` covering `[start_pfn, end_pfn)`.
    pub const fn new(
        node_id: usize,
        start_pfn: usize,
        end_pfn: usize,
        free_pages: usize,
        cpu_mask: u64,
    ) -> Self {
        Self {
            node_id,
            start_pfn,
            end_pfn,
            free_pages,
            cpu_mask,
        }
    }
}

/// Linux `set_mempolicy` NUMA allocation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumaPolicy {
    /// Allocate on the node running the current CPU, falling back by SLIT distance.
    Default,
    /// Strictly restrict allocations to nodes present in `nodemask` (`MPOL_BIND`).
    Bind { nodemask: u64 },
    /// Prefer `preferred_node` first, falling back to other nodes by SLIT distance (`MPOL_PREFERRED`).
    Preferred { preferred_node: usize },
    /// Round-robin interleave page allocations across nodes set in `nodemask` (`MPOL_INTERLEAVE`).
    Interleave { nodemask: u64 },
}

/// ACPI SRAT + SLIT NUMA Topology and Policy Allocator.
#[derive(Debug, Clone)]
pub struct NumaTopology {
    nodes: Vec<NumaNode>,
    /// Flattened `N x N` ACPI SLIT distance matrix (`distances[src * n + dst]`).
    distances: Vec<u8>,
    interleave_cursor: usize,
}

impl NumaTopology {
    /// Creates a new `NumaTopology` with `nodes` and initializes diagonal SLIT
    /// distances to `10` (`NUMA_LOCAL_DISTANCE`) and off-diagonal to `20`.
    pub fn new(nodes: Vec<NumaNode>) -> Self {
        let count = nodes.len();
        let mut distances = alloc::vec![NUMA_REMOTE_DISTANCE; count * count];
        for idx in 0..count {
            distances[idx * count + idx] = NUMA_LOCAL_DISTANCE;
        }
        Self {
            nodes,
            distances,
            interleave_cursor: 0,
        }
    }

    /// Sets the symmetric or asymmetric ACPI SLIT distance between `from_node` and `to_node`.
    pub fn set_distance(&mut self, from_node: usize, to_node: usize, distance: u8) -> bool {
        let n = self.nodes.len();
        if from_node >= n || to_node >= n || distance < NUMA_LOCAL_DISTANCE {
            return false;
        }
        self.distances[from_node * n + to_node] = distance;
        true
    }

    /// Queries the ACPI SLIT distance from `from_node` to `to_node`.
    pub fn distance(&self, from_node: usize, to_node: usize) -> Option<u8> {
        let n = self.nodes.len();
        if from_node >= n || to_node >= n {
            return None;
        }
        Some(self.distances[from_node * n + to_node])
    }

    /// Builds the fallback node zonelist for `home_node` sorted in ascending order
    /// of ACPI SLIT distance (breaking ties by node ID).
    pub fn build_zonelist(&self, home_node: usize) -> Vec<usize> {
        let n = self.nodes.len();
        if home_node >= n {
            return Vec::new();
        }
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            let da = self.distances[home_node * n + a];
            let db = self.distances[home_node * n + b];
            da.cmp(&db).then_with(|| a.cmp(&b))
        });
        order
    }

    /// Allocates `pages` from the topology according to `policy` and `executing_node`,
    /// returning the selected `node_id`.
    pub fn allocate_on_policy(
        &mut self,
        policy: &NumaPolicy,
        executing_node: usize,
        pages: usize,
    ) -> Option<usize> {
        let n = self.nodes.len();
        if n == 0 || pages == 0 {
            return None;
        }

        match policy {
            NumaPolicy::Default => {
                for candidate in self.build_zonelist(executing_node.min(n - 1)) {
                    if self.nodes[candidate].free_pages >= pages {
                        self.nodes[candidate].free_pages -= pages;
                        return Some(candidate);
                    }
                }
                None
            }
            NumaPolicy::Preferred { preferred_node } => {
                for candidate in self.build_zonelist((*preferred_node).min(n - 1)) {
                    if self.nodes[candidate].free_pages >= pages {
                        self.nodes[candidate].free_pages -= pages;
                        return Some(candidate);
                    }
                }
                None
            }
            NumaPolicy::Bind { nodemask } => {
                for candidate in self.build_zonelist(executing_node.min(n - 1)) {
                    if (nodemask & (1u64 << candidate)) != 0
                        && self.nodes[candidate].free_pages >= pages
                    {
                        self.nodes[candidate].free_pages -= pages;
                        return Some(candidate);
                    }
                }
                None
            }
            NumaPolicy::Interleave { nodemask } => {
                for _ in 0..n {
                    let candidate = self.interleave_cursor % n;
                    self.interleave_cursor = (self.interleave_cursor + 1) % n;
                    if (nodemask & (1u64 << candidate)) != 0
                        && self.nodes[candidate].free_pages >= pages
                    {
                        self.nodes[candidate].free_pages -= pages;
                        return Some(candidate);
                    }
                }
                None
            }
        }
    }

    /// Borrows the slice of NUMA nodes.
    pub fn nodes(&self) -> &[NumaNode] {
        &self.nodes
    }
}
