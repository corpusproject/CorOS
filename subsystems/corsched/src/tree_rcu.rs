//! Tree RCU (Read-Copy Update) Grace-Period State Machine.
//!
//! Implements hierarchical Tree RCU with:
//! - Multi-level tree topology aggregating CPU quiescent state bitmasks
//! - Grace-period state machine ($gp\_seq$, quiescent state barrier)
//! - Per-CPU segmented callback queues (next, wait, done)
//! - Batched callback invocation upon grace period completion

extern crate alloc;

use alloc::vec::Vec;

/// Maximum number of CPUs per leaf RCU node.
pub const RCU_CPUS_PER_LEAF: usize = 8;

/// RCU Grace Period State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcuGpState {
    Idle,
    Starting,
    WaitingForQuiescentStates,
    CleaningUp,
    Completed,
}

/// Hierarchical RCU tree node.
#[derive(Debug, Clone)]
pub struct RcuNode {
    pub level: usize,
    /// CPU or child bitmask belonging to this subtree.
    pub span_mask: u64,
    /// Bitmask of CPUs or children that have NOT yet reported a quiescent state for current GP.
    pub qs_mask: u64,
    pub parent_idx: Option<usize>,
    pub child_indices: Vec<usize>,
}

/// RCU deferred callback function and argument.
#[derive(Debug, Clone)]
pub struct RcuCallback {
    pub id: u64,
    pub func: fn(u64),
    pub arg: u64,
    pub gp_seq: u64,
}

/// Per-CPU RCU queue state.
#[derive(Debug, Clone)]
pub struct PerCpuRcuState {
    pub cpu_id: u32,
    /// Callbacks registered but not yet assigned to an active grace period.
    pub next_callbacks: Vec<RcuCallback>,
    /// Callbacks waiting for current grace period to complete.
    pub wait_callbacks: Vec<RcuCallback>,
    /// Callbacks whose grace period has completed and are ready to execute.
    pub done_callbacks: Vec<RcuCallback>,
    /// CPU nesting depth for rcu_read_lock().
    pub read_lock_nesting: u32,
    /// Total callbacks executed on this CPU.
    pub total_callbacks_invoked: u64,
}

impl PerCpuRcuState {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            next_callbacks: Vec::new(),
            wait_callbacks: Vec::new(),
            done_callbacks: Vec::new(),
            read_lock_nesting: 0,
            total_callbacks_invoked: 0,
        }
    }
}

/// Hierarchical Tree RCU controller.
pub struct TreeRcu {
    pub nodes: Vec<RcuNode>,
    pub root_idx: usize,
    pub leaf_indices: Vec<usize>,
    pub cpu_states: Vec<PerCpuRcuState>,
    /// GP sequence counter: lowest bit 0 indicates active GP; higher bits track completed GPs.
    pub gp_seq: u64,
    pub state: RcuGpState,
}

impl TreeRcu {
    /// Build a Tree RCU instance for the given number of CPUs.
    pub fn new(num_cpus: u32) -> Self {
        let cpu_count = (num_cpus as usize).clamp(1, 64);
        let mut cpu_states = Vec::with_capacity(cpu_count);
        for i in 0..cpu_count {
            cpu_states.push(PerCpuRcuState::new(i as u32));
        }

        let mut nodes = Vec::new();
        let mut leaf_indices = Vec::new();

        let num_leaves = (cpu_count + RCU_CPUS_PER_LEAF - 1) / RCU_CPUS_PER_LEAF;

        if num_leaves <= 1 {
            // Single node (both root and leaf)
            let mut span_mask = 0u64;
            for i in 0..cpu_count {
                span_mask |= 1u64 << i;
            }
            nodes.push(RcuNode {
                level: 0,
                span_mask,
                qs_mask: 0,
                parent_idx: None,
                child_indices: Vec::new(),
            });
            leaf_indices.push(0);
            return Self {
                nodes,
                root_idx: 0,
                leaf_indices,
                cpu_states,
                gp_seq: 0,
                state: RcuGpState::Idle,
            };
        }

        // Multiple leaves: create leaves then root
        let root_idx = num_leaves;
        for leaf_i in 0..num_leaves {
            let start_cpu = leaf_i * RCU_CPUS_PER_LEAF;
            let end_cpu = (start_cpu + RCU_CPUS_PER_LEAF).min(cpu_count);
            let mut span_mask = 0u64;
            for c in start_cpu..end_cpu {
                span_mask |= 1u64 << c;
            }

            nodes.push(RcuNode {
                level: 1,
                span_mask,
                qs_mask: 0,
                parent_idx: Some(root_idx),
                child_indices: Vec::new(),
            });
            leaf_indices.push(leaf_i);
        }

        // Create root node
        let mut root_span = 0u64;
        let mut child_indices = Vec::new();
        for i in 0..num_leaves {
            root_span |= 1u64 << i;
            child_indices.push(i);
        }
        nodes.push(RcuNode {
            level: 0,
            span_mask: root_span,
            qs_mask: 0,
            parent_idx: None,
            child_indices,
        });

        Self {
            nodes,
            root_idx,
            leaf_indices,
            cpu_states,
            gp_seq: 0,
            state: RcuGpState::Idle,
        }
    }

    /// Enter RCU read-side critical section on given CPU.
    pub fn rcu_read_lock(&mut self, cpu_id: u32) {
        if let Some(state) = self.cpu_states.get_mut(cpu_id as usize) {
            state.read_lock_nesting += 1;
        }
    }

    /// Exit RCU read-side critical section on given CPU.
    pub fn rcu_read_unlock(&mut self, cpu_id: u32) {
        if let Some(state) = self.cpu_states.get_mut(cpu_id as usize) {
            state.read_lock_nesting = state.read_lock_nesting.saturating_sub(1);
        }
    }

    /// Queue a callback to be executed after a subsequent grace period.
    pub fn call_rcu(&mut self, cpu_id: u32, callback: RcuCallback) {
        if let Some(state) = self.cpu_states.get_mut(cpu_id as usize) {
            state.next_callbacks.push(callback);
        }
    }

    /// Start a new RCU Grace Period if none is currently active.
    pub fn start_grace_period(&mut self) -> bool {
        if self.state == RcuGpState::WaitingForQuiescentStates {
            return false;
        }

        // Advance gp_seq: bit 0 indicates active GP
        self.gp_seq = (self.gp_seq & !1) + 2 | 1;
        self.state = RcuGpState::Starting;

        // Advance callback queues across all CPUs
        for state in &mut self.cpu_states {
            // Move next_callbacks into wait_callbacks stamped with current gp_seq
            while let Some(mut cb) = state.next_callbacks.pop() {
                cb.gp_seq = self.gp_seq;
                state.wait_callbacks.push(cb);
            }
        }

        // Arm the quiescent state masks across the tree
        // 1. Arm leaf nodes
        for (leaf_idx_in_vec, &node_idx) in self.leaf_indices.iter().enumerate() {
            let span = self.nodes[node_idx].span_mask;
            self.nodes[node_idx].qs_mask = span;

            // Arm root mask bit for this leaf
            if let Some(parent_idx) = self.nodes[node_idx].parent_idx {
                self.nodes[parent_idx].qs_mask |= 1u64 << leaf_idx_in_vec;
            }
        }

        // If single root node, arm root qs_mask directly
        if self.leaf_indices.len() == 1 && self.leaf_indices[0] == self.root_idx {
            let span = self.nodes[self.root_idx].span_mask;
            self.nodes[self.root_idx].qs_mask = span;
        }

        self.state = RcuGpState::WaitingForQuiescentStates;
        true
    }

    /// Report a quiescent state for a CPU (e.g. on context switch or idle).
    pub fn report_quiescent_state(&mut self, cpu_id: u32) {
        if self.state != RcuGpState::WaitingForQuiescentStates {
            return;
        }

        // Locate corresponding leaf node
        let leaf_idx = (cpu_id as usize) / RCU_CPUS_PER_LEAF;
        if leaf_idx >= self.leaf_indices.len() {
            return;
        }
        let node_idx = self.leaf_indices[leaf_idx];

        // Clear CPU bit in leaf qs_mask
        let cpu_bit = 1u64 << cpu_id;
        self.nodes[node_idx].qs_mask &= !cpu_bit;

        // If leaf qs_mask is zero, propagate to parent
        if self.nodes[node_idx].qs_mask == 0 {
            if let Some(parent_idx) = self.nodes[node_idx].parent_idx {
                let leaf_bit = 1u64 << leaf_idx;
                self.nodes[parent_idx].qs_mask &= !leaf_bit;

                // Check if root qs_mask is completely cleared
                if self.nodes[self.root_idx].qs_mask == 0 {
                    self.complete_grace_period();
                }
            } else if node_idx == self.root_idx {
                self.complete_grace_period();
            }
        }
    }

    /// Internal completion handler when all CPUs have reported quiescent state.
    fn complete_grace_period(&mut self) {
        // Clear active bit in gp_seq
        self.gp_seq &= !1;
        self.state = RcuGpState::Completed;

        // Move wait_callbacks to done_callbacks on all CPUs
        for state in &mut self.cpu_states {
            while let Some(cb) = state.wait_callbacks.pop() {
                state.done_callbacks.push(cb);
            }
        }

        self.state = RcuGpState::Idle;
    }

    /// Execute ready callbacks in batch on the specified CPU.
    pub fn do_batch(&mut self, cpu_id: u32, max_batch: usize) -> usize {
        let mut executed = 0;
        if let Some(state) = self.cpu_states.get_mut(cpu_id as usize) {
            while executed < max_batch && !state.done_callbacks.is_empty() {
                let cb = state.done_callbacks.remove(0);
                (cb.func)(cb.arg);
                state.total_callbacks_invoked += 1;
                executed += 1;
            }
        }
        executed
    }
}
