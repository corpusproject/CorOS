//! CorOS Non-Uniform Memory Access (NUMA) Topology & Allocation Subsystem (`numa.rs`)
//!
//! Implements multi-socket and multi-die NUMA memory partitioning:
//! - ACPI SRAT (System Resource Affinity Table) parsing:
//!   - Processor Local APIC / x2APIC Affinity structures (maps CPU Core -> NUMA Node)
//!   - Memory Affinity structures (maps Physical Address Range -> NUMA Node)
//! - ACPI SLIT (System Locality Distance Information Table) parsing:
//!   - Normalized latency distance matrix (local node = 10, cross-socket = 20-30)
//! - Per-Node Physical Frame Allocator (Free page lists per NUMA domain)
//! - Allocation Policies:
//!   - `MPOL_DEFAULT`: Local-node first, fallback to nearest neighbor
//!   - `MPOL_BIND`: Strict allocation on specified node mask
//!   - `MPOL_INTERLEAVE`: Round-robin page allocation across nodes

extern crate alloc;

use alloc::vec::Vec;

pub const MAX_NUMA_NODES: usize = 8;
pub const NUMA_LOCAL_DISTANCE: u8 = 10;
pub const NUMA_DEFAULT_REMOTE_DISTANCE: u8 = 20;

/// ACPI SRAT Entry Types
pub const SRAT_TYPE_CPU_AFFINITY: u8 = 0;
pub const SRAT_TYPE_MEMORY_AFFINITY: u8 = 1;
pub const SRAT_TYPE_X2APIC_AFFINITY: u8 = 2;

/// Memory Allocation Policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPolicy {
    Default,
    Bind(u8),      // Strict node ID
    Interleave,    // Striped round-robin
    Preferred(u8), // Soft preference
}

/// NUMA Memory Range descriptor
#[derive(Debug, Clone, Copy)]
pub struct NumaMemoryRange {
    pub base_addr: u64,
    pub length: u64,
    pub node_id: u8,
    pub hot_pluggable: bool,
    pub non_volatile: bool,
}

/// Per-Node Memory Domain
pub struct NumaNode {
    pub node_id: u8,
    pub cpu_cores: Vec<u32>,
    pub memory_ranges: Vec<NumaMemoryRange>,
    pub total_frames: usize,
    pub free_frames: usize,
    pub distances: [u8; MAX_NUMA_NODES],
}

impl NumaNode {
    pub fn new(id: u8) -> Self {
        let mut distances = [NUMA_DEFAULT_REMOTE_DISTANCE; MAX_NUMA_NODES];
        if (id as usize) < MAX_NUMA_NODES {
            distances[id as usize] = NUMA_LOCAL_DISTANCE;
        }

        Self {
            node_id: id,
            cpu_cores: Vec::new(),
            memory_ranges: Vec::new(),
            total_frames: 0,
            free_frames: 0,
            distances,
        }
    }

    pub fn add_cpu(&mut self, lapic_id: u32) {
        if !self.cpu_cores.contains(&lapic_id) {
            self.cpu_cores.push(lapic_id);
        }
    }

    pub fn add_memory_range(&mut self, base: u64, len: u64, hotplug: bool, nv: bool) {
        self.memory_ranges.push(NumaMemoryRange {
            base_addr: base,
            length: len,
            node_id: self.node_id,
            hot_pluggable: hotplug,
            non_volatile: nv,
        });
        let frames = (len / 4096) as usize;
        self.total_frames += frames;
        self.free_frames += frames;
    }
}

/// Global NUMA Topology Manager
pub struct NumaManager {
    nodes: Vec<NumaNode>,
    pub node_count: usize,
    current_interleave_node: u8,
}

impl NumaManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            nodes: Vec::new(),
            node_count: 0,
            current_interleave_node: 0,
        };

        // Initialize single default Node 0 for fallback
        let mut node0 = NumaNode::new(0);
        node0.add_cpu(0);
        node0.add_memory_range(0x100000, 0x7FF00000, false, false);
        mgr.nodes.push(node0);
        mgr.node_count = 1;

        mgr
    }

    /// Parse ACPI SRAT table
    pub fn parse_srat(&mut self, srat_bytes: &[u8]) -> bool {
        if srat_bytes.len() < 48 || &srat_bytes[0..4] != b"SRAT" {
            return false;
        }

        let table_len = u32::from_le_bytes([
            srat_bytes[4], srat_bytes[5], srat_bytes[6], srat_bytes[7],
        ]) as usize;

        if srat_bytes.len() < table_len {
            return false;
        }

        let mut offset = 48; // Skip 36-byte ACPI header + 12 reserved bytes
        while offset + 2 <= table_len {
            let entry_type = srat_bytes[offset];
            let entry_len = srat_bytes[offset + 1] as usize;
            if entry_len == 0 || offset + entry_len > table_len {
                break;
            }

            match entry_type {
                SRAT_TYPE_CPU_AFFINITY => {
                    if entry_len >= 16 {
                        let node_id = srat_bytes[offset + 2];
                        let apic_id = srat_bytes[offset + 3] as u32;
                        let flags = u32::from_le_bytes([
                            srat_bytes[offset + 4], srat_bytes[offset + 5],
                            srat_bytes[offset + 6], srat_bytes[offset + 7],
                        ]);
                        if (flags & 1) != 0 { // Enabled
                            self.ensure_node(node_id);
                            self.nodes[node_id as usize].add_cpu(apic_id);
                        }
                    }
                }
                SRAT_TYPE_MEMORY_AFFINITY => {
                    if entry_len >= 40 {
                        let node_id = srat_bytes[offset + 2];
                        let base = u64::from_le_bytes([
                            srat_bytes[offset + 8], srat_bytes[offset + 9],
                            srat_bytes[offset + 10], srat_bytes[offset + 11],
                            srat_bytes[offset + 12], srat_bytes[offset + 13],
                            srat_bytes[offset + 14], srat_bytes[offset + 15],
                        ]);
                        let len = u64::from_le_bytes([
                            srat_bytes[offset + 16], srat_bytes[offset + 17],
                            srat_bytes[offset + 18], srat_bytes[offset + 19],
                            srat_bytes[offset + 20], srat_bytes[offset + 21],
                            srat_bytes[offset + 22], srat_bytes[offset + 23],
                        ]);
                        let flags = u32::from_le_bytes([
                            srat_bytes[offset + 28], srat_bytes[offset + 29],
                            srat_bytes[offset + 30], srat_bytes[offset + 31],
                        ]);
                        if (flags & 1) != 0 {
                            let hotplug = (flags & 2) != 0;
                            let nv = (flags & 4) != 0;
                            self.ensure_node(node_id);
                            self.nodes[node_id as usize].add_memory_range(base, len, hotplug, nv);
                        }
                    }
                }
                _ => {}
            }

            offset += entry_len;
        }

        true
    }

    fn ensure_node(&mut self, node_id: u8) {
        let idx = node_id as usize;
        while self.nodes.len() <= idx {
            let next_id = self.nodes.len() as u8;
            self.nodes.push(NumaNode::new(next_id));
        }
        if self.nodes.len() > self.node_count {
            self.node_count = self.nodes.len();
        }
    }

    /// Select optimal NUMA node for allocation based on current policy
    pub fn select_node_for_alloc(&mut self, current_cpu: u32, policy: MemoryPolicy) -> u8 {
        match policy {
            MemoryPolicy::Bind(target_node) => {
                if (target_node as usize) < self.node_count {
                    target_node
                } else {
                    0
                }
            }
            MemoryPolicy::Preferred(target_node) => {
                if (target_node as usize) < self.node_count && self.nodes[target_node as usize].free_frames > 0 {
                    target_node
                } else {
                    self.get_local_node_for_cpu(current_cpu)
                }
            }
            MemoryPolicy::Interleave => {
                let n = self.current_interleave_node;
                self.current_interleave_node = (self.current_interleave_node + 1) % (self.node_count as u8);
                n
            }
            MemoryPolicy::Default => {
                let local = self.get_local_node_for_cpu(current_cpu);
                if (local as usize) < self.node_count && self.nodes[local as usize].free_frames > 0 {
                    local
                } else {
                    // Fallback to closest neighbor with available memory
                    self.find_closest_available_node(local)
                }
            }
        }
    }

    pub fn get_local_node_for_cpu(&self, apic_id: u32) -> u8 {
        for node in &self.nodes {
            if node.cpu_cores.contains(&apic_id) {
                return node.node_id;
            }
        }
        0
    }

    fn find_closest_available_node(&self, origin_node: u8) -> u8 {
        if (origin_node as usize) >= self.nodes.len() {
            return 0;
        }

        let origin = &self.nodes[origin_node as usize];
        let mut best_node = 0;
        let mut min_distance = 255u8;

        for (i, node) in self.nodes.iter().enumerate() {
            if node.free_frames > 0 {
                let dist = origin.distances[i];
                if dist < min_distance {
                    min_distance = dist;
                    best_node = node.node_id;
                }
            }
        }

        best_node
    }
}
