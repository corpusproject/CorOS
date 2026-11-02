//! Yama `ptrace_scope` enforcement engine, process ancestry walker, and `PR_SET_PTRACER` table.
//!
//! Enforces the four Yama ptrace modes:
//! - `Classic = 0`: Standard same-UID or `CAP_SYS_PTRACE` checks.
//! - `RestrictedDescendant = 1`: Tracer must be an ancestor of tracee, explicitly authorized via
//!   `PR_SET_PTRACER`, or hold `CAP_SYS_PTRACE`.
//! - `AdminOnly = 2`: Only tasks holding `CAP_SYS_PTRACE` may attach.
//! - `NoAttach = 3`: Irrevocably disables all `ptrace` attachment system-wide.

use alloc::vec::Vec;

/// Wildcard PID constant (`PR_SET_PTRACER_ANY`) permitting any process of the same UID to trace the target.
pub const PR_SET_PTRACER_ANY: u32 = u32::MAX;

/// Yama `kernel.yama.ptrace_scope` sysctl level.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum YamaPtraceScope {
    Classic = 0,
    RestrictedDescendant = 1,
    AdminOnly = 2,
    NoAttach = 3,
}

/// Process lineage and credential descriptor used by the Yama ancestry evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YamaProcessNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub euid: u32,
    pub dumpable: bool,
    pub has_cap_sys_ptrace: bool,
}

/// Explicit tracer exception registered by a tracee via `prctl(PR_SET_PTRACER, tracer_pid)`.
#[derive(Debug, Clone, Copy)]
struct PtracerException {
    tracee_pid: u32,
    allowed_tracer_pid: u32,
}

/// Denial reason returned when Yama blocks a `ptrace` attach or `process_vm_readv` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YamaError {
    ProcessNotFound,
    NotDumpable,
    UidMismatch,
    NotAncestorOrAuthorized,
    AdminCapabilityRequired,
    PtraceLockedOut,
    ScopeLockedIrrevocably,
}

/// Yama `ptrace_scope` security engine with process tree lineage walker and `PR_SET_PTRACER` exception table.
pub struct YamaPtraceEngine {
    scope: YamaPtraceScope,
    processes: Vec<YamaProcessNode>,
    exceptions: Vec<PtracerException>,
}

impl YamaPtraceEngine {
    pub fn new(initial_scope: YamaPtraceScope) -> Self {
        Self {
            scope: initial_scope,
            processes: Vec::new(),
            exceptions: Vec::new(),
        }
    }

    pub fn current_scope(&self) -> YamaPtraceScope {
        self.scope
    }

    /// Updates `ptrace_scope`. Once set to `NoAttach` (3), the scope can never be lowered.
    pub fn set_scope(&mut self, new_scope: YamaPtraceScope) -> Result<(), YamaError> {
        if self.scope == YamaPtraceScope::NoAttach && new_scope != YamaPtraceScope::NoAttach {
            return Err(YamaError::ScopeLockedIrrevocably);
        }
        self.scope = new_scope;
        Ok(())
    }

    /// Registers or updates a process in the lineage table.
    pub fn register_process(&mut self, node: YamaProcessNode) {
        for p in self.processes.iter_mut() {
            if p.pid == node.pid {
                *p = node;
                return;
            }
        }
        self.processes.push(node);
    }

    /// Removes a terminated process and cleans up any `PR_SET_PTRACER` exceptions referencing it.
    pub fn remove_process(&mut self, pid: u32) {
        self.processes.retain(|p| p.pid != pid);
        self.exceptions
            .retain(|e| e.tracee_pid != pid && e.allowed_tracer_pid != pid);
    }

    /// Implements `prctl(PR_SET_PTRACER, allowed_tracer_pid)` called by `tracee_pid`.
    /// Passing `0` clears any existing exception for `tracee_pid`.
    pub fn set_ptracer_exception(&mut self, tracee_pid: u32, allowed_tracer_pid: u32) {
        if allowed_tracer_pid == 0 {
            self.exceptions.retain(|e| e.tracee_pid != tracee_pid);
            return;
        }
        for exc in self.exceptions.iter_mut() {
            if exc.tracee_pid == tracee_pid {
                exc.allowed_tracer_pid = allowed_tracer_pid;
                return;
            }
        }
        self.exceptions.push(PtracerException {
            tracee_pid,
            allowed_tracer_pid,
        });
    }

    /// Walks up the process tree from `descendant_pid` to determine if `ancestor_pid` is in its lineage.
    pub fn is_ancestor(&self, ancestor_pid: u32, descendant_pid: u32) -> bool {
        if ancestor_pid == descendant_pid {
            return false;
        }
        let mut cursor_pid = descendant_pid;
        let max_steps = self.processes.len().saturating_add(1);

        for _ in 0..max_steps {
            let Some(node) = self.find_process(cursor_pid) else {
                return false;
            };
            if node.parent_pid == ancestor_pid {
                return true;
            }
            if node.parent_pid == 0 || node.parent_pid == cursor_pid {
                return false;
            }
            cursor_pid = node.parent_pid;
        }
        false
    }

    /// Checks whether `tracer_pid` has been granted an explicit exception by `tracee_pid`
    /// (either directly or via an ancestor of `tracer_pid`, or via `PR_SET_PTRACER_ANY`).
    pub fn has_ptracer_exception(&self, tracer_pid: u32, tracee_pid: u32) -> bool {
        for exc in &self.exceptions {
            if exc.tracee_pid == tracee_pid {
                if exc.allowed_tracer_pid == PR_SET_PTRACER_ANY
                    || exc.allowed_tracer_pid == tracer_pid
                    || self.is_ancestor(exc.allowed_tracer_pid, tracer_pid)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Evaluates whether `tracer_pid` is permitted to `PTRACE_ATTACH` to `tracee_pid`.
    pub fn check_ptrace_access(&self, tracer_pid: u32, tracee_pid: u32) -> Result<(), YamaError> {
        let tracer = self
            .find_process(tracer_pid)
            .ok_or(YamaError::ProcessNotFound)?;
        let tracee = self
            .find_process(tracee_pid)
            .ok_or(YamaError::ProcessNotFound)?;

        if self.scope == YamaPtraceScope::NoAttach {
            return Err(YamaError::PtraceLockedOut);
        }

        // Standard base ptrace check: unless tracer has CAP_SYS_PTRACE, tracee must be dumpable and share UID
        if !tracer.has_cap_sys_ptrace {
            if !tracee.dumpable {
                return Err(YamaError::NotDumpable);
            }
            if tracer.euid != tracee.uid || tracer.uid != tracee.euid {
                return Err(YamaError::UidMismatch);
            }
        }

        match self.scope {
            YamaPtraceScope::Classic => Ok(()),
            YamaPtraceScope::RestrictedDescendant => {
                if tracer.has_cap_sys_ptrace
                    || self.is_ancestor(tracer_pid, tracee_pid)
                    || self.has_ptracer_exception(tracer_pid, tracee_pid)
                {
                    Ok(())
                } else {
                    Err(YamaError::NotAncestorOrAuthorized)
                }
            }
            YamaPtraceScope::AdminOnly => {
                if tracer.has_cap_sys_ptrace {
                    Ok(())
                } else {
                    Err(YamaError::AdminCapabilityRequired)
                }
            }
            YamaPtraceScope::NoAttach => Err(YamaError::PtraceLockedOut),
        }
    }

    fn find_process(&self, pid: u32) -> Option<&YamaProcessNode> {
        self.processes.iter().find(|p| p.pid == pid)
    }
}
