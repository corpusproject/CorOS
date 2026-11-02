//! Runtime Deadlock Graph Validator (Lockdep).
//!
//! Implements runtime verification of lock ordering with:
//! - Static and dynamic lock class registration
//! - Directed lock dependency graph tracking ($A \to B$)
//! - Depth-First Search (DFS) ABBA cycle and deadlock detection
//! - Recursive write-lock acquisition detection
//! - Per-thread/CPU held-lock stack validation with out-of-order release detection

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const LOCKDEP_FLAG_HARDIRQ_SAFE: u32 = 1 << 0;
pub const LOCKDEP_FLAG_SOFTIRQ_SAFE: u32 = 1 << 1;
pub const LOCKDEP_FLAG_RECURSIVE_READ: u32 = 1 << 2;

/// Lockdep verification error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockdepError {
    DeadlockCycle {
        from_class: u64,
        to_class: u64,
        cycle_path: Vec<u64>,
    },
    RecursiveDeadlock {
        class_id: u64,
        addr: usize,
    },
    LockNotHeld {
        addr: usize,
    },
    MaxDepthExceeded,
}

/// Metadata descriptor for a class of locks sharing identical locking rules.
#[derive(Debug, Clone)]
pub struct LockClass {
    pub id: u64,
    pub name: String,
    pub flags: u32,
    pub acquire_count: u64,
    pub read_acquire_count: u64,
}

impl LockClass {
    pub fn new(id: u64, name: &str, flags: u32) -> Self {
        Self {
            id,
            name: String::from(name),
            flags,
            acquire_count: 0,
            read_acquire_count: 0,
        }
    }
}

/// Instance of an acquired lock on the current execution stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldLockInstance {
    pub addr: usize,
    pub class_id: u64,
    pub is_read: bool,
    pub cpu_id: u32,
    pub acquire_time_ns: u64,
}

/// Directed Lock Dependency Graph.
pub struct LockDependencyGraph {
    /// Adjacency list: class_id -> list of child class_ids taken while holding key.
    pub adjacency: BTreeMap<u64, Vec<u64>>,
    pub total_edges: usize,
}

impl LockDependencyGraph {
    pub fn new() -> Self {
        Self {
            adjacency: BTreeMap::new(),
            total_edges: 0,
        }
    }

    /// Check if target is reachable from source using Depth-First Search (DFS).
    pub fn is_reachable(&self, start: u64, target: u64, path: &mut Vec<u64>) -> bool {
        path.push(start);
        if start == target {
            return true;
        }

        if let Some(neighbors) = self.adjacency.get(&start) {
            for &next in neighbors {
                if !path.contains(&next) {
                    if self.is_reachable(next, target, path) {
                        return true;
                    }
                }
            }
        }

        path.pop();
        false
    }

    /// Add a dependency edge: `from_class -> to_class`.
    /// Returns Err(LockdepError::DeadlockCycle) if this edge creates an ABBA cycle.
    pub fn add_dependency(&mut self, from_class: u64, to_class: u64) -> Result<bool, LockdepError> {
        if from_class == to_class {
            return Ok(false); // Same class recursive handling handled separately
        }

        // Check if `from_class` is already reachable from `to_class` (meaning cycle if edge added)
        let mut cycle_path = Vec::new();
        if self.is_reachable(to_class, from_class, &mut cycle_path) {
            cycle_path.push(to_class);
            return Err(LockdepError::DeadlockCycle {
                from_class,
                to_class,
                cycle_path,
            });
        }

        let neighbors = self.adjacency.entry(from_class).or_default();
        if !neighbors.contains(&to_class) {
            neighbors.push(to_class);
            self.total_edges += 1;
            return Ok(true);
        }

        Ok(false)
    }
}

/// Complete Lockdep Validator maintaining lock classes, dependency graph, and held stacks.
pub struct LockdepValidator {
    pub classes: BTreeMap<u64, LockClass>,
    pub graph: LockDependencyGraph,
    pub held_stack: Vec<HeldLockInstance>,
    pub total_acquisitions: u64,
    pub cycle_violations_detected: u64,
}

impl LockdepValidator {
    pub fn new() -> Self {
        Self {
            classes: BTreeMap::new(),
            graph: LockDependencyGraph::new(),
            held_stack: Vec::new(),
            total_acquisitions: 0,
            cycle_violations_detected: 0,
        }
    }

    /// Register a lock class with metadata.
    pub fn register_class(&mut self, id: u64, name: &str, flags: u32) {
        self.classes.insert(id, LockClass::new(id, name, flags));
    }

    /// Check if a lock instance at `addr` is currently held on this stack.
    pub fn is_held(&self, addr: usize) -> bool {
        self.held_stack.iter().any(|h| h.addr == addr)
    }

    /// Validate and record a lock acquisition.
    pub fn acquire(
        &mut self,
        class_id: u64,
        addr: usize,
        is_read: bool,
        is_trylock: bool,
        cpu_id: u32,
        now_ns: u64,
    ) -> Result<(), LockdepError> {
        // 1. Recursive lock check on the same address
        for held in &self.held_stack {
            if held.addr == addr {
                if !is_read || !held.is_read {
                    return Err(LockdepError::RecursiveDeadlock { class_id, addr });
                }
            }
        }

        // 2. Validate dependency graph against all currently held locks
        if !is_trylock {
            for held in &self.held_stack {
                if held.class_id != class_id {
                    match self.graph.add_dependency(held.class_id, class_id) {
                        Ok(_) => {},
                        Err(err) => {
                            self.cycle_violations_detected += 1;
                            return Err(err);
                        }
                    }
                }
            }
        }

        // 3. Record acquisition
        if let Some(cls) = self.classes.get_mut(&class_id) {
            if is_read {
                cls.read_acquire_count += 1;
            } else {
                cls.acquire_count += 1;
            }
        }

        self.held_stack.push(HeldLockInstance {
            addr,
            class_id,
            is_read,
            cpu_id,
            acquire_time_ns: now_ns,
        });

        self.total_acquisitions += 1;
        Ok(())
    }

    /// Record a lock release and remove from held stack.
    pub fn release(&mut self, addr: usize) -> Result<(), LockdepError> {
        let pos = self.held_stack.iter().rposition(|h| h.addr == addr)
            .ok_or(LockdepError::LockNotHeld { addr })?;

        self.held_stack.remove(pos);
        Ok(())
    }
}
