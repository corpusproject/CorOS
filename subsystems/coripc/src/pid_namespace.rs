//! Hierarchical nested PID Namespaces (`MAX_PID_NS_DEPTH = 32`), `NamespacedPid`
//! multi-level virtual PID chains, `translate_pid` cross-namespace PID visibility,
//! and namespace `init` (virtual PID 1) termination cascading `SIGKILL` to all
//! descendant member tasks.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Maximum nesting depth of PID namespaces (matches Linux `MAX_PID_NS_LEVEL = 32`).
pub const MAX_PID_NS_DEPTH: usize = 32;

/// Signal number delivered to all member tasks when a PID namespace's `init` (PID 1) exits.
pub const SIGKILL_SIGNAL: u32 = 9;

/// Errors returned by PID namespace operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidNsError {
    /// Specified namespace ID does not exist.
    NamespaceNotFound,
    /// Creating a child namespace would exceed `MAX_PID_NS_DEPTH`.
    MaxDepthExceeded,
    /// Namespace has been terminated because its `init` (PID 1) exited; new forks are forbidden (`ENOMEM`/`EINVAL`).
    NamespaceTerminated,
    /// Task not found.
    TaskNotFound,
}

/// Multi-level virtual PID representation across a task's ancestor PID namespaces.
/// Level `0` is always the root (global) PID namespace, and `level == depth` is the
/// task's active (innermost) PID namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespacedPid {
    /// Depth of the innermost namespace (`0..MAX_PID_NS_DEPTH`).
    pub depth: usize,
    /// Namespace IDs at each level `0..=depth`.
    pub ns_chain: [u32; MAX_PID_NS_DEPTH],
    /// Virtual PID assigned at each level `0..=depth`.
    pub vpid_chain: [u32; MAX_PID_NS_DEPTH],
}

impl NamespacedPid {
    /// Return the global PID (level 0 root PID namespace).
    #[inline]
    pub const fn global_pid(&self) -> u32 {
        self.vpid_chain[0]
    }

    /// Return the virtual PID seen by the task inside its own innermost namespace.
    #[inline]
    pub const fn local_vpid(&self) -> u32 {
        self.vpid_chain[self.depth]
    }

    /// Return the innermost namespace ID.
    #[inline]
    pub const fn active_ns_id(&self) -> u32 {
        self.ns_chain[self.depth]
    }

    /// Return the virtual PID of this task as seen from `observer_ns_id`, or `0` (`None`)
    /// if this task does not reside within `observer_ns_id` or one of its descendants.
    pub fn vpid_in_namespace(&self, observer_ns_id: u32, observer_depth: usize) -> Option<u32> {
        if observer_depth <= self.depth && self.ns_chain[observer_depth] == observer_ns_id {
            Some(self.vpid_chain[observer_depth])
        } else {
            None
        }
    }
}

/// State of a single PID Namespace node.
#[derive(Clone, Debug)]
pub struct PidNamespace {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub depth: usize,
    /// Ancestor namespace ID chain from level `0` down to `depth`.
    pub ns_chain: [u32; MAX_PID_NS_DEPTH],
    /// Next virtual PID cursor to allocate within this namespace (starts at 1 for namespace init).
    pub next_vpid: u32,
    /// Global PID of the namespace's `init` process (the task assigned virtual PID 1).
    pub init_global_pid: Option<u32>,
    /// True once the namespace's `init` process has terminated, disabling further allocations.
    pub terminated: bool,
    /// Mapping from virtual PID in this namespace to global PID.
    pub vpid_to_global: BTreeMap<u32, u32>,
}

/// Task entry tracked by the PID Namespace manager.
#[derive(Clone, Debug)]
pub struct NamespacedTask {
    pub pid: NamespacedPid,
    pub alive: bool,
    pub pending_signals: u32,
}

/// Hierarchical PID Namespace Manager.
pub struct PidNamespaceManager {
    namespaces: BTreeMap<u32, PidNamespace>,
    tasks: BTreeMap<u32, NamespacedTask>,
    next_ns_id: u32,
}

impl Default for PidNamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PidNamespaceManager {
    pub const ROOT_NS_ID: u32 = 1;

    pub fn new() -> Self {
        let mut ns_chain = [0u32; MAX_PID_NS_DEPTH];
        ns_chain[0] = Self::ROOT_NS_ID;
        let root_ns = PidNamespace {
            id: Self::ROOT_NS_ID,
            parent_id: None,
            depth: 0,
            ns_chain,
            next_vpid: 1,
            init_global_pid: None,
            terminated: false,
            vpid_to_global: BTreeMap::new(),
        };
        let mut namespaces = BTreeMap::new();
        namespaces.insert(Self::ROOT_NS_ID, root_ns);
        Self {
            namespaces,
            tasks: BTreeMap::new(),
            next_ns_id: 2,
        }
    }

    /// Create a nested child PID namespace under `parent_ns_id`.
    pub fn create_child_namespace(&mut self, parent_ns_id: u32) -> Result<u32, PidNsError> {
        let (parent_depth, parent_chain, parent_terminated) = {
            let parent = self
                .namespaces
                .get(&parent_ns_id)
                .ok_or(PidNsError::NamespaceNotFound)?;
            (parent.depth, parent.ns_chain, parent.terminated)
        };

        if parent_terminated {
            return Err(PidNsError::NamespaceTerminated);
        }
        let child_depth = parent_depth + 1;
        if child_depth >= MAX_PID_NS_DEPTH {
            return Err(PidNsError::MaxDepthExceeded);
        }

        let ns_id = self.next_ns_id;
        self.next_ns_id += 1;

        let mut ns_chain = parent_chain;
        ns_chain[child_depth] = ns_id;

        let child_ns = PidNamespace {
            id: ns_id,
            parent_id: Some(parent_ns_id),
            depth: child_depth,
            ns_chain,
            next_vpid: 1,
            init_global_pid: None,
            terminated: false,
            vpid_to_global: BTreeMap::new(),
        };
        self.namespaces.insert(ns_id, child_ns);
        Ok(ns_id)
    }

    /// Allocate a new task inside `target_ns_id`, assigning a virtual PID at every
    /// ancestor namespace level from `0` down to `target_ns.depth`.
    /// The very first task created in a namespace receives virtual PID `1` and becomes
    /// that namespace's `init` reaper process.
    pub fn allocate_task(&mut self, target_ns_id: u32) -> Result<NamespacedPid, PidNsError> {
        let (depth, ns_chain) = {
            let ns = self
                .namespaces
                .get(&target_ns_id)
                .ok_or(PidNsError::NamespaceNotFound)?;
            if ns.terminated {
                return Err(PidNsError::NamespaceTerminated);
            }
            (ns.depth, ns.ns_chain)
        };

        // Verify no ancestor namespace is terminated.
        for level in 0..=depth {
            let anc_id = ns_chain[level];
            let anc = self
                .namespaces
                .get(&anc_id)
                .ok_or(PidNsError::NamespaceNotFound)?;
            if anc.terminated {
                return Err(PidNsError::NamespaceTerminated);
            }
        }

        let mut vpid_chain = [0u32; MAX_PID_NS_DEPTH];
        for level in 0..=depth {
            let anc_id = ns_chain[level];
            let anc = self
                .namespaces
                .get_mut(&anc_id)
                .ok_or(PidNsError::NamespaceNotFound)?;
            let vpid = anc.next_vpid;
            anc.next_vpid += 1;
            vpid_chain[level] = vpid;
        }

        let global_pid = vpid_chain[0];
        for level in 0..=depth {
            let anc_id = ns_chain[level];
            let vpid = vpid_chain[level];
            if let Some(anc) = self.namespaces.get_mut(&anc_id) {
                anc.vpid_to_global.insert(vpid, global_pid);
                if vpid == 1 && anc.init_global_pid.is_none() {
                    anc.init_global_pid = Some(global_pid);
                }
            }
        }

        let nspid = NamespacedPid {
            depth,
            ns_chain,
            vpid_chain,
        };
        self.tasks.insert(
            global_pid,
            NamespacedTask {
                pid: nspid,
                alive: true,
                pending_signals: 0,
            },
        );
        Ok(nspid)
    }

    /// Translate a task's PID (`source_vpid` in `source_ns_id`) into the virtual PID
    /// visible inside `observer_ns_id`. Returns `None` if the target task is outside
    /// `observer_ns_id`'s subtree (isolation boundary).
    pub fn translate_pid(
        &self,
        source_ns_id: u32,
        source_vpid: u32,
        observer_ns_id: u32,
    ) -> Result<Option<u32>, PidNsError> {
        let source_ns = self
            .namespaces
            .get(&source_ns_id)
            .ok_or(PidNsError::NamespaceNotFound)?;
        let observer_ns = self
            .namespaces
            .get(&observer_ns_id)
            .ok_or(PidNsError::NamespaceNotFound)?;

        let global_pid = match source_ns.vpid_to_global.get(&source_vpid) {
            Some(&g) => g,
            None => return Ok(None),
        };
        let task = match self.tasks.get(&global_pid) {
            Some(t) if t.alive => t,
            _ => return Ok(None),
        };
        Ok(task
            .pid
            .vpid_in_namespace(observer_ns_id, observer_ns.depth))
    }

    /// Handle exit of `global_pid`. If `global_pid` is virtual PID `1` (`init`) in any
    /// namespace, that namespace and all descendant namespaces are marked terminated and
    /// `SIGKILL` is cascaded to all member tasks in that subtree.
    /// Returns the list of global PIDs that received `SIGKILL` due to `init` exit.
    pub fn exit_task(&mut self, global_pid: u32) -> Result<Vec<u32>, PidNsError> {
        let task_pid = {
            let task = self
                .tasks
                .get_mut(&global_pid)
                .ok_or(PidNsError::TaskNotFound)?;
            task.alive = false;
            task.pid
        };

        // Remove vpid mappings for the exiting task.
        for level in 0..=task_pid.depth {
            let anc_id = task_pid.ns_chain[level];
            let vpid = task_pid.vpid_chain[level];
            if let Some(ns) = self.namespaces.get_mut(&anc_id) {
                ns.vpid_to_global.remove(&vpid);
            }
        }

        // Check if this task was PID 1 (`init`) in any namespace along its chain.
        let mut init_ns_level: Option<(usize, u32)> = None;
        for level in 0..=task_pid.depth {
            if task_pid.vpid_chain[level] == 1 {
                init_ns_level = Some((level, task_pid.ns_chain[level]));
                break;
            }
        }

        let mut killed_global_pids = Vec::new();
        if let Some((level, dying_ns_id)) = init_ns_level {
            // Mark all namespaces whose chain has `dying_ns_id` at `level` as terminated.
            for ns in self.namespaces.values_mut() {
                if ns.depth >= level && ns.ns_chain[level] == dying_ns_id {
                    ns.terminated = true;
                }
            }

            // Deliver SIGKILL and terminate every live task belonging to `dying_ns_id` or its descendants.
            for (&gpid, t) in self.tasks.iter_mut() {
                if t.alive && t.pid.depth >= level && t.pid.ns_chain[level] == dying_ns_id {
                    t.pending_signals |= 1 << SIGKILL_SIGNAL;
                    t.alive = false;
                    killed_global_pids.push(gpid);
                }
            }

            // Purge vpid_to_global mappings for all killed tasks.
            for &kpid in &killed_global_pids {
                if let Some(ktask) = self.tasks.get(&kpid) {
                    let k_nspid = ktask.pid;
                    for l in 0..=k_nspid.depth {
                        if let Some(ns) = self.namespaces.get_mut(&k_nspid.ns_chain[l]) {
                            ns.vpid_to_global.remove(&k_nspid.vpid_chain[l]);
                        }
                    }
                }
            }
        }

        Ok(killed_global_pids)
    }
}

/// Self-test verifying nested PID namespaces, cross-namespace `translate_pid`, isolation,
/// and cascading `SIGKILL` when a child namespace's `init` (PID 1) exits.
pub fn self_test() -> bool {
    let mut mgr = PidNamespaceManager::new();

    // Allocate host init (PID 1 in root namespace).
    let host_init = match mgr.allocate_task(PidNamespaceManager::ROOT_NS_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if host_init.global_pid() != 1 || host_init.local_vpid() != 1 {
        return false;
    }

    // Create container namespace (level 1) and nested sub-container namespace (level 2).
    let container_ns = match mgr.create_child_namespace(PidNamespaceManager::ROOT_NS_ID) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let sub_ns = match mgr.create_child_namespace(container_ns) {
        Ok(id) => id,
        Err(_) => return false,
    };

    // First task in container_ns gets global PID 2, container vPID 1 (container init).
    let c_init = match mgr.allocate_task(container_ns) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if c_init.global_pid() != 2 || c_init.local_vpid() != 1 {
        return false;
    }

    // First task in sub_ns gets global PID 3, container vPID 2, sub_ns vPID 1.
    let sub_task = match mgr.allocate_task(sub_ns) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if sub_task.global_pid() != 3
        || sub_task.vpid_chain[1] != 2
        || sub_task.local_vpid() != 1
    {
        return false;
    }

    // Translate sub_task (vPID 1 in sub_ns) as seen from container_ns -> Some(2).
    match mgr.translate_pid(sub_ns, 1, container_ns) {
        Ok(Some(2)) => {}
        _ => return false,
    }

    // Translate host_init (vPID 1 in root) as seen from container_ns -> None (isolated!).
    match mgr.translate_pid(PidNamespaceManager::ROOT_NS_ID, 1, container_ns) {
        Ok(None) => {}
        _ => return false,
    }

    // Exiting c_init (global PID 2, which is vPID 1 in container_ns) must cascade SIGKILL to sub_task (global PID 3).
    let killed = match mgr.exit_task(c_init.global_pid()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if killed.as_slice() != [sub_task.global_pid()] {
        return false;
    }

    // Further task allocations in container_ns or sub_ns must fail with NamespaceTerminated.
    mgr.allocate_task(container_ns) == Err(PidNsError::NamespaceTerminated)
}
