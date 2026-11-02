//! CorOS Syscall Domain Module: `process_lifecycle`
//! Process creation, fork, clone, execve, exit, wait4, credentials, and process groups.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const ESRCH: i64 = -3;
pub const EPERM: i64 = -1;
pub const ECHILD: i64 = -10;
pub const ENOMEM: i64 = -12;
pub const EAGAIN: i64 = -11;

pub const WNOHANG: u32 = 0x0000_0001;
pub const WUNTRACED: u32 = 0x0000_0002;
pub const WCONTINUED: u32 = 0x0000_0008;

/// Process execution state within the CorOS scheduler and process table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running(u16), // CPU core index
    SleepingInterruptible,
    SleepingUninterruptible,
    Stopped(u8),  // Stop signal number
    Zombie(i32),  // Exit code
    Dead,
}

/// Bitmask flags controlling resource sharing during `sys_clone`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloneFlags(pub u64);

impl CloneFlags {
    pub const VM: Self = Self(0x0000_0100);
    pub const FS: Self = Self(0x0000_0200);
    pub const FILES: Self = Self(0x0000_0400);
    pub const SIGHAND: Self = Self(0x0000_0800);
    pub const PIDFD: Self = Self(0x0000_1000);
    pub const PTRACE: Self = Self(0x0000_2000);
    pub const VFORK: Self = Self(0x0000_4000);
    pub const PARENT: Self = Self(0x0000_8000);
    pub const THREAD: Self = Self(0x0001_0000);
    pub const NEWNS: Self = Self(0x0002_0000);
    pub const SYSVSEM: Self = Self(0x0004_0000);
    pub const SETTLS: Self = Self(0x0008_0000);
    pub const PARENT_SETTID: Self = Self(0x0010_0000);
    pub const CHILD_CLEARTID: Self = Self(0x0020_0000);
    pub const CLONE_CHILD_SETTID: Self = Self(0x0100_0000);
    pub const NEWCGROUP: Self = Self(0x0200_0000);
    pub const NEWUTS: Self = Self(0x0400_0000);
    pub const NEWIPC: Self = Self(0x0800_0000);
    pub const NEWUSER: Self = Self(0x1000_0000);
    pub const NEWPID: Self = Self(0x2000_0000);
    pub const NEWNET: Self = Self(0x4000_0000);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates POSIX / Linux clone flag constraints (e.g., THREAD requires SIGHAND, SIGHAND requires VM).
    pub const fn is_valid(self) -> bool {
        if self.contains(Self::THREAD) && !self.contains(Self::SIGHAND) {
            return false;
        }
        if self.contains(Self::SIGHAND) && !self.contains(Self::VM) {
            return false;
        }
        if self.contains(Self::NEWPID) && self.contains(Self::THREAD) {
            return false;
        }
        true
    }
}

/// Real, effective, saved, and filesystem UID/GID credentials for a task.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessCredentials {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
}

impl ProcessCredentials {
    pub const fn root() -> Self {
        Self {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
        }
    }

    pub const fn user(uid: u32, gid: u32) -> Self {
        Self {
            ruid: uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }

    #[inline]
    pub const fn is_privileged(&self) -> bool {
        self.euid == 0
    }
}

/// Resource accounting statistics returned by `wait4` and `getrusage`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    pub user_time_usec: u64,
    pub sys_time_usec: u64,
    pub max_rss_kb: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub block_inputs: u64,
    pub block_outputs: u64,
    pub voluntary_ctx_switches: u64,
    pub involuntary_ctx_switches: u64,
}

impl ResourceUsage {
    pub fn accumulate(&mut self, child: &Self) {
        self.user_time_usec = self.user_time_usec.saturating_add(child.user_time_usec);
        self.sys_time_usec = self.sys_time_usec.saturating_add(child.sys_time_usec);
        if child.max_rss_kb > self.max_rss_kb {
            self.max_rss_kb = child.max_rss_kb;
        }
        self.minor_faults = self.minor_faults.saturating_add(child.minor_faults);
        self.major_faults = self.major_faults.saturating_add(child.major_faults);
        self.block_inputs = self.block_inputs.saturating_add(child.block_inputs);
        self.block_outputs = self.block_outputs.saturating_add(child.block_outputs);
        self.voluntary_ctx_switches = self.voluntary_ctx_switches.saturating_add(child.voluntary_ctx_switches);
        self.involuntary_ctx_switches = self.involuntary_ctx_switches.saturating_add(child.involuntary_ctx_switches);
    }
}

/// Maximum nesting depth of PID namespaces (matches Linux MAX_PID_NS_LEVEL = 32).
pub const MAX_PID_NS_DEPTH: usize = 32;

/// Multi-level virtual PID representation across ancestor namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespacedPid {
    pub depth: usize,
    pub ns_chain: [u32; MAX_PID_NS_DEPTH],
    pub vpid_chain: [u32; MAX_PID_NS_DEPTH],
}

impl Default for NamespacedPid {
    fn default() -> Self {
        let mut ns_chain = [0u32; MAX_PID_NS_DEPTH];
        let mut vpid_chain = [0u32; MAX_PID_NS_DEPTH];
        ns_chain[0] = 1;
        vpid_chain[0] = 1;
        Self {
            depth: 0,
            ns_chain,
            vpid_chain,
        }
    }
}

impl NamespacedPid {
    #[inline]
    pub const fn global_pid(&self) -> u32 {
        self.vpid_chain[0]
    }

    #[inline]
    pub const fn local_vpid(&self) -> u32 {
        self.vpid_chain[self.depth]
    }

    #[inline]
    pub const fn active_ns_id(&self) -> u32 {
        self.ns_chain[self.depth]
    }

    pub fn vpid_in_namespace(&self, observer_ns_id: u32, observer_depth: usize) -> Option<u32> {
        if observer_depth <= self.depth && self.ns_chain[observer_depth] == observer_ns_id {
            Some(self.vpid_chain[observer_depth])
        } else {
            None
        }
    }
}

/// Linux-grade Container Namespace Proxy held by each process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceProxy {
    pub pid_ns_id: u32,
    pub mnt_ns_id: u32,
    pub net_ns_id: u32,
    pub uts_ns_id: u64,
    pub ipc_ns_id: u64,
    pub user_ns_id: u64,
    pub cgroup_node_id: u64,
    pub root_dir: String, // Per-process chroot jail
    pub cwd_dir: String,
}

impl Default for NamespaceProxy {
    fn default() -> Self {
        Self {
            pid_ns_id: 1,
            mnt_ns_id: 1,
            net_ns_id: 1,
            uts_ns_id: 1,
            ipc_ns_id: 1,
            user_ns_id: 1,
            cgroup_node_id: 1,
            root_dir: String::from("/"),
            cwd_dir: String::from("/"),
        }
    }
}

/// Process Control Block (PCB) stored in the kernel process table.
#[derive(Clone, Debug)]
pub struct ProcessDescriptor {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub state: ProcessState,
    pub creds: ProcessCredentials,
    pub comm: String,
    pub argv: Vec<String>,
    pub user_stack_ptr: u64,
    pub tls_base: u64,
    pub clear_child_tid_addr: u64,
    pub rusage: ResourceUsage,
    pub children_rusage: ResourceUsage,
    pub shares_vm: bool,
    pub shares_files: bool,
    pub ns_proxy: Arc<NamespaceProxy>,
    pub namespaced_pid: NamespacedPid,
}

/// Kernel process table managing PID allocation and process lifecycle system calls.
pub struct ProcessTable {
    processes: Vec<ProcessDescriptor>,
    next_pid: u32,
    max_processes: usize,
    pub next_ns_id: u64,
    pub pid_ns_next_vpid: BTreeMap<u32, u32>,
}

impl ProcessTable {
    pub fn new(max_processes: usize) -> Self {
        let mut table = Self {
            processes: Vec::new(),
            next_pid: 2,
            max_processes,
            next_ns_id: 2,
            pid_ns_next_vpid: BTreeMap::new(),
        };
        // Bootstrap PID 1 (init)
        table.processes.push(ProcessDescriptor {
            pid: 1,
            tgid: 1,
            ppid: 0,
            pgid: 1,
            sid: 1,
            state: ProcessState::Running(0),
            creds: ProcessCredentials::root(),
            comm: String::from("corinit"),
            argv: alloc::vec![String::from("/sbin/corinit")],
            user_stack_ptr: 0x0000_7FFF_FFFF_E000,
            tls_base: 0,
            clear_child_tid_addr: 0,
            rusage: ResourceUsage::default(),
            children_rusage: ResourceUsage::default(),
            shares_vm: false,
            shares_files: false,
            ns_proxy: Arc::new(NamespaceProxy::default()),
            namespaced_pid: NamespacedPid::default(),
        });
        table
    }

    pub fn register_process(&mut self, proc: ProcessDescriptor) -> bool {
        if self.processes.len() >= self.max_processes {
            return false;
        }
        self.processes.push(proc);
        true
    }

    pub fn get_process(&self, pid: u32) -> Option<&ProcessDescriptor> {
        self.processes.iter().find(|p| p.pid == pid && p.state != ProcessState::Dead)
    }

    pub fn get_process_mut(&mut self, pid: u32) -> Option<&mut ProcessDescriptor> {
        self.processes.iter_mut().find(|p| p.pid == pid && p.state != ProcessState::Dead)
    }

    /// `sys_getpid`: Returns thread group ID (POSIX PID) of caller.
    pub fn sys_getpid(&self, caller_pid: u32) -> i64 {
        match self.get_process(caller_pid) {
            Some(proc) => proc.namespaced_pid.local_vpid() as i64,
            None => ESRCH,
        }
    }

    /// `sys_gettid`: Returns global/kernel thread ID of caller.
    pub fn sys_gettid(&self, caller_pid: u32) -> i64 {
        match self.get_process(caller_pid) {
            Some(proc) => proc.pid as i64,
            None => ESRCH,
        }
    }

    /// `sys_getppid`: Returns parent PID of caller.
    pub fn sys_getppid(&self, caller_pid: u32) -> i64 {
        match self.get_process(caller_pid) {
            Some(proc) => proc.ppid as i64,
            None => ESRCH,
        }
    }

    /// `sys_clone`: Creates a new child task or thread according to `CloneFlags`.
    pub fn sys_clone(
        &mut self,
        caller_pid: u32,
        flags: CloneFlags,
        child_stack: u64,
        tls: u64,
        clear_tid_addr: u64,
    ) -> i64 {
        if !flags.is_valid() {
            return EINVAL;
        }
        if self.processes.len() >= self.max_processes {
            return EAGAIN;
        }
        let parent = match self.get_process(caller_pid) {
            Some(p) => p.clone(),
            None => return ESRCH,
        };

        let new_pid = self.next_pid;
        self.next_pid = self.next_pid.wrapping_add(1).max(2);

        let is_thread = flags.contains(CloneFlags::THREAD);
        let tgid = if is_thread { parent.tgid } else { new_pid };
        let ppid = if is_thread || flags.contains(CloneFlags::PARENT) {
            parent.ppid
        } else {
            parent.pid
        };

        let stack = if child_stack != 0 {
            child_stack
        } else {
            parent.user_stack_ptr
        };

        let tls_base = if flags.contains(CloneFlags::SETTLS) {
            tls
        } else {
            parent.tls_base
        };

        let clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) {
            clear_tid_addr
        } else {
            0
        };

        // Evaluate Namespace Flags
        let has_new_ns = flags.contains(CloneFlags::NEWNS);
        let has_new_uts = flags.contains(CloneFlags::NEWUTS);
        let has_new_ipc = flags.contains(CloneFlags::NEWIPC);
        let has_new_user = flags.contains(CloneFlags::NEWUSER);
        let has_new_pid = flags.contains(CloneFlags::NEWPID);
        let has_new_net = flags.contains(CloneFlags::NEWNET);
        let has_new_cgroup = flags.contains(CloneFlags::NEWCGROUP);

        let (child_ns_proxy, child_nspid) = if has_new_ns || has_new_uts || has_new_ipc || has_new_user || has_new_pid || has_new_net || has_new_cgroup {
            let mut proxy = (*parent.ns_proxy).clone();
            let mut nspid = parent.namespaced_pid;

            if has_new_ns {
                proxy.mnt_ns_id = self.next_ns_id as u32;
                self.next_ns_id += 1;
            }
            if has_new_uts {
                proxy.uts_ns_id = self.next_ns_id;
                self.next_ns_id += 1;
            }
            if has_new_ipc {
                proxy.ipc_ns_id = self.next_ns_id;
                self.next_ns_id += 1;
            }
            if has_new_user {
                proxy.user_ns_id = self.next_ns_id;
                self.next_ns_id += 1;
            }
            if has_new_net {
                proxy.net_ns_id = self.next_ns_id as u32;
                self.next_ns_id += 1;
            }
            if has_new_cgroup {
                proxy.cgroup_node_id = self.next_ns_id;
                self.next_ns_id += 1;
            }
            if has_new_pid {
                if nspid.depth + 1 >= MAX_PID_NS_DEPTH {
                    return EINVAL;
                }
                let new_pid_ns = self.next_ns_id as u32;
                self.next_ns_id += 1;
                proxy.pid_ns_id = new_pid_ns;

                nspid.depth += 1;
                nspid.ns_chain[nspid.depth] = new_pid_ns;
                nspid.vpid_chain[nspid.depth] = 1; // init in child PID namespace
                nspid.vpid_chain[0] = new_pid;
                for d in 1..nspid.depth {
                    let ancestor_ns = nspid.ns_chain[d];
                    let next_vpid = self.pid_ns_next_vpid.entry(ancestor_ns).or_insert(2);
                    nspid.vpid_chain[d] = *next_vpid;
                    *next_vpid += 1;
                }
                self.pid_ns_next_vpid.insert(new_pid_ns, 2);
            } else {
                nspid.vpid_chain[0] = new_pid;
                for d in 1..=nspid.depth {
                    let ns = nspid.ns_chain[d];
                    let next_vpid = self.pid_ns_next_vpid.entry(ns).or_insert(2);
                    nspid.vpid_chain[d] = *next_vpid;
                    *next_vpid += 1;
                }
                if is_thread {
                    nspid.vpid_chain[nspid.depth] = parent.namespaced_pid.local_vpid();
                }
            }

            (Arc::new(proxy), nspid)
        } else {
            let mut nspid = parent.namespaced_pid;
            nspid.vpid_chain[0] = new_pid;
            for d in 1..=nspid.depth {
                let ns = nspid.ns_chain[d];
                let next_vpid = self.pid_ns_next_vpid.entry(ns).or_insert(2);
                nspid.vpid_chain[d] = *next_vpid;
                *next_vpid += 1;
            }
            if is_thread {
                nspid.vpid_chain[nspid.depth] = parent.namespaced_pid.local_vpid();
            }
            (parent.ns_proxy.clone(), nspid)
        };

        let child = ProcessDescriptor {
            pid: new_pid,
            tgid,
            ppid,
            pgid: parent.pgid,
            sid: parent.sid,
            state: ProcessState::Runnable,
            creds: parent.creds,
            comm: parent.comm.clone(),
            argv: parent.argv.clone(),
            user_stack_ptr: stack,
            tls_base,
            clear_child_tid_addr: clear_child_tid,
            rusage: ResourceUsage::default(),
            children_rusage: ResourceUsage::default(),
            shares_vm: flags.contains(CloneFlags::VM),
            shares_files: flags.contains(CloneFlags::FILES),
            ns_proxy: child_ns_proxy,
            namespaced_pid: child_nspid,
        };

        self.processes.push(child);
        new_pid as i64
    }

    /// `sys_unshare`: Disassociates parts of the process execution context.
    pub fn sys_unshare(&mut self, caller_pid: u32, flags: CloneFlags) -> i64 {
        if !flags.is_valid() {
            return EINVAL;
        }
        let old_proxy = match self.get_process(caller_pid) {
            Some(p) => (*p.ns_proxy).clone(),
            None => return ESRCH,
        };

        let mut proxy = old_proxy;
        if flags.contains(CloneFlags::NEWNS) {
            proxy.mnt_ns_id = self.next_ns_id as u32;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWUTS) {
            proxy.uts_ns_id = self.next_ns_id;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWIPC) {
            proxy.ipc_ns_id = self.next_ns_id;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWUSER) {
            proxy.user_ns_id = self.next_ns_id;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWNET) {
            proxy.net_ns_id = self.next_ns_id as u32;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWCGROUP) {
            proxy.cgroup_node_id = self.next_ns_id;
            self.next_ns_id += 1;
        }
        if flags.contains(CloneFlags::NEWPID) {
            proxy.pid_ns_id = self.next_ns_id as u32;
            self.next_ns_id += 1;
            self.pid_ns_next_vpid.insert(proxy.pid_ns_id, 1);
        }

        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        proc.ns_proxy = Arc::new(proxy);
        0
    }

    /// `sys_setns`: Reassociates the calling thread with a target namespace.
    pub fn sys_setns(&mut self, caller_pid: u32, target_pid: u32, nstype: CloneFlags) -> i64 {
        let target_proxy = match self.get_process(target_pid) {
            Some(t) => (*t.ns_proxy).clone(),
            None => return ESRCH,
        };
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        if !proc.creds.is_privileged() && !nstype.contains(CloneFlags::NEWUSER) {
            return EPERM;
        }

        let mut current_proxy = (*proc.ns_proxy).clone();
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWNS) {
            current_proxy.mnt_ns_id = target_proxy.mnt_ns_id;
            current_proxy.root_dir = target_proxy.root_dir.clone();
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWUTS) {
            current_proxy.uts_ns_id = target_proxy.uts_ns_id;
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWIPC) {
            current_proxy.ipc_ns_id = target_proxy.ipc_ns_id;
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWUSER) {
            current_proxy.user_ns_id = target_proxy.user_ns_id;
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWNET) {
            current_proxy.net_ns_id = target_proxy.net_ns_id;
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWPID) {
            current_proxy.pid_ns_id = target_proxy.pid_ns_id;
        }
        if nstype.0 == 0 || nstype.contains(CloneFlags::NEWCGROUP) {
            current_proxy.cgroup_node_id = target_proxy.cgroup_node_id;
        }

        proc.ns_proxy = Arc::new(current_proxy);
        0
    }

    /// `sys_chroot`: Sets the per-process root directory for path resolution.
    pub fn sys_chroot(&mut self, caller_pid: u32, new_root: &str) -> i64 {
        if new_root.is_empty() || !new_root.starts_with('/') {
            return EINVAL;
        }
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        if !proc.creds.is_privileged() {
            return EPERM;
        }
        let mut proxy = (*proc.ns_proxy).clone();
        proxy.root_dir = String::from(new_root);
        proc.ns_proxy = Arc::new(proxy);
        0
    }

    /// `sys_pivot_root`: Moves the root mount to put_old and makes new_root the new root directory.
    pub fn sys_pivot_root(&mut self, caller_pid: u32, new_root: &str, put_old: &str) -> i64 {
        if !new_root.starts_with('/') || !put_old.starts_with('/') || new_root == "/" {
            return EINVAL;
        }
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        if !proc.creds.is_privileged() {
            return EPERM;
        }
        let mut proxy = (*proc.ns_proxy).clone();
        proxy.root_dir = String::from(new_root);
        proc.ns_proxy = Arc::new(proxy);
        0
    }

    /// Resolves a path under the caller's active chroot jail, rigorously normalizing '.' and '..'
    /// path segments to guarantee containment and prevent jail escape.
    pub fn resolve_process_path(&self, caller_pid: u32, path: &str) -> Result<String, i64> {
        let proc = self.get_process(caller_pid).ok_or(ESRCH)?;
        let root = &proc.ns_proxy.root_dir;

        // Build the un-normalized virtual path relative to the jail root
        let mut raw_vpath = String::new();
        if path.starts_with('/') {
            raw_vpath.push_str(path);
        } else {
            raw_vpath.push('/');
            raw_vpath.push_str(proc.ns_proxy.cwd_dir.trim_matches('/'));
            if !raw_vpath.ends_with('/') {
                raw_vpath.push('/');
            }
            raw_vpath.push_str(path);
        }

        // Canonicalize path segments within the jail:
        // Clamping '..' so it cannot escape above the jail root ('/')
        let mut components: Vec<&str> = Vec::new();
        for seg in raw_vpath.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            } else if seg == ".." {
                components.pop(); // Clamped at jail root if empty
            } else {
                components.push(seg);
            }
        }

        let mut normalized_in_jail = String::from("/");
        for (i, comp) in components.iter().enumerate() {
            if i > 0 {
                normalized_in_jail.push('/');
            }
            normalized_in_jail.push_str(comp);
        }

        if root == "/" {
            Ok(normalized_in_jail)
        } else {
            let base_root = root.trim_end_matches('/');
            if normalized_in_jail == "/" {
                Ok(String::from(base_root))
            } else {
                let mut full = String::from(base_root);
                full.push_str(&normalized_in_jail);
                Ok(full)
            }
        }
    }

    /// `sys_fork`: Standard fork wrapper over `sys_clone` with isolated address space.
    pub fn sys_fork(&mut self, caller_pid: u32) -> i64 {
        self.sys_clone(caller_pid, CloneFlags(0), 0, 0, 0)
    }

    /// `sys_execve`: Replaces current process image, resets signal dispositions and stack, handles setuid.
    pub fn sys_execve(
        &mut self,
        caller_pid: u32,
        path: &str,
        argv: &[&str],
        setuid_bit: Option<u32>,
    ) -> i64 {
        if path.is_empty() || !path.starts_with('/') {
            return EINVAL;
        }
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };

        let basename = path.rsplit('/').next().unwrap_or(path);
        proc.comm = String::from(basename);
        proc.argv = argv.iter().map(|s| String::from(*s)).collect();
        proc.user_stack_ptr = 0x0000_7FFF_FFFF_F000;
        proc.tls_base = 0;
        proc.shares_vm = false;

        if let Some(new_euid) = setuid_bit {
            proc.creds.euid = new_euid;
            proc.creds.suid = new_euid;
            proc.creds.fsuid = new_euid;
        }
        0
    }

    /// `sys_exit`: Terminates a process, reparents orphans to PID 1, and transitions to Zombie.
    pub fn sys_exit(&mut self, caller_pid: u32, exit_code: i32) -> i64 {
        if caller_pid == 1 {
            return EPERM; // Init cannot exit
        }
        let found = self.processes.iter().any(|p| p.pid == caller_pid && p.state != ProcessState::Dead);
        if !found {
            return ESRCH;
        }

        // Reparent any living children to PID 1
        for p in self.processes.iter_mut() {
            if p.ppid == caller_pid && p.state != ProcessState::Dead {
                p.ppid = 1;
            }
        }

        if let Some(proc) = self.get_process_mut(caller_pid) {
            proc.state = ProcessState::Zombie(exit_code & 0xFF);
            proc.clear_child_tid_addr = 0;
        }
        0
    }

    /// `sys_wait4`: Reaps a Zombie child (or reports Stopped child), returning `(reaped_pid, wstatus, rusage)`.
    pub fn sys_wait4(
        &mut self,
        caller_pid: u32,
        target_pid: i32,
        options: u32,
    ) -> Result<(u32, i32, ResourceUsage), i64> {
        let caller_pgid = match self.get_process(caller_pid) {
            Some(p) => p.pgid,
            None => return Err(ESRCH),
        };

        let mut matching_children = false;
        let mut zombie_idx = None;
        let mut stopped_info = None;

        for (idx, p) in self.processes.iter().enumerate() {
            if p.ppid != caller_pid || p.state == ProcessState::Dead {
                continue;
            }
            let pid_matches = if target_pid > 0 {
                p.pid == target_pid as u32
            } else if target_pid == -1 {
                true
            } else if target_pid == 0 {
                p.pgid == caller_pgid
            } else {
                p.pgid == (-target_pid) as u32
            };

            if !pid_matches {
                continue;
            }
            matching_children = true;

            match p.state {
                ProcessState::Zombie(_) => {
                    zombie_idx = Some(idx);
                    break;
                }
                ProcessState::Stopped(sig) if (options & WUNTRACED) != 0 => {
                    stopped_info = Some((p.pid, ((sig as i32) << 8) | 0x7F, p.rusage));
                }
                _ => {}
            }
        }

        if !matching_children {
            return Err(ECHILD);
        }

        if let Some(idx) = zombie_idx {
            let child_pid = self.processes[idx].pid;
            let code = match self.processes[idx].state {
                ProcessState::Zombie(c) => c,
                _ => 0,
            };
            let mut total_usage = self.processes[idx].rusage;
            let child_sub_usage = self.processes[idx].children_rusage;
            total_usage.accumulate(&child_sub_usage);

            self.processes[idx].state = ProcessState::Dead;
            self.processes.remove(idx);

            if let Some(parent) = self.get_process_mut(caller_pid) {
                parent.children_rusage.accumulate(&total_usage);
            }
            let wstatus = (code & 0xFF) << 8;
            return Ok((child_pid, wstatus, total_usage));
        }

        if let Some(info) = stopped_info {
            return Ok(info);
        }

        if (options & WNOHANG) != 0 {
            Ok((0, 0, ResourceUsage::default()))
        } else {
            Err(EAGAIN)
        }
    }

    /// `sys_setuid`: POSIX UID transition semantics for privileged vs unprivileged callers.
    pub fn sys_setuid(&mut self, caller_pid: u32, uid: u32) -> i64 {
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        if proc.creds.is_privileged() {
            proc.creds.ruid = uid;
            proc.creds.euid = uid;
            proc.creds.suid = uid;
            proc.creds.fsuid = uid;
            0
        } else if uid == proc.creds.ruid || uid == proc.creds.suid {
            proc.creds.euid = uid;
            proc.creds.fsuid = uid;
            0
        } else {
            EPERM
        }
    }

    /// `sys_setgid`: POSIX GID transition semantics.
    pub fn sys_setgid(&mut self, caller_pid: u32, gid: u32) -> i64 {
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        if proc.creds.is_privileged() {
            proc.creds.rgid = gid;
            proc.creds.egid = gid;
            proc.creds.sgid = gid;
            proc.creds.fsgid = gid;
            0
        } else if gid == proc.creds.rgid || gid == proc.creds.sgid {
            proc.creds.egid = gid;
            proc.creds.fsgid = gid;
            0
        } else {
            EPERM
        }
    }

    /// `sys_setsid`: Creates a new session if the caller is not already a process group leader.
    pub fn sys_setsid(&mut self, caller_pid: u32) -> i64 {
        let is_pg_leader = self
            .processes
            .iter()
            .any(|p| p.pgid == caller_pid && p.state != ProcessState::Dead);
        if is_pg_leader {
            return EPERM;
        }
        let proc = match self.get_process_mut(caller_pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        proc.sid = caller_pid;
        proc.pgid = caller_pid;
        caller_pid as i64
    }

    /// `sys_setpgid`: Sets process group ID for `target_pid` (or caller if 0).
    pub fn sys_setpgid(&mut self, caller_pid: u32, target_pid: u32, pgid: u32) -> i64 {
        let actual_pid = if target_pid == 0 { caller_pid } else { target_pid };
        let actual_pgid = if pgid == 0 { actual_pid } else { pgid };

        let caller_sid = match self.get_process(caller_pid) {
            Some(p) => p.sid,
            None => return ESRCH,
        };

        let target = match self.get_process_mut(actual_pid) {
            Some(p) => p,
            None => return ESRCH,
        };

        if target.pid != caller_pid && target.ppid != caller_pid {
            return ESRCH;
        }
        if target.sid != caller_sid {
            return EPERM;
        }
        target.pgid = actual_pgid;
        0
    }
}

/// Runs comprehensive self-tests on `process_lifecycle` structs and state machines.
pub fn verify_domain_process_lifecycle() -> u32 {
    let mut passed = 0u32;
    let mut table = ProcessTable::new(64);

    if table.sys_getpid(1) == 1 {
        passed += 1;
    }
    if table.sys_getppid(1) == 0 {
        passed += 1;
    }

    // Fork a child from init (PID 1 -> PID 2)
    let child_pid = table.sys_fork(1);
    if child_pid == 2 {
        passed += 1;
    }
    if table.sys_getppid(2) == 1 {
        passed += 1;
    }

    // Reject invalid CloneFlags (THREAD without SIGHAND)
    if table.sys_clone(1, CloneFlags::THREAD, 0, 0, 0) == EINVAL {
        passed += 1;
    }

    // Valid thread clone (THREAD | SIGHAND | VM)
    let thread_flags = CloneFlags::THREAD
        .union(CloneFlags::SIGHAND)
        .union(CloneFlags::VM);
    let tid = table.sys_clone(2, thread_flags, 0x7FFF_0000, 0x4000, 0);
    if tid == 3 && table.sys_getpid(3) == 2 {
        passed += 1;
    }

    // Execve on PID 2 and drop privileges via setuid(1000)
    if table.sys_execve(2, "/bin/corsh", &["corsh", "-i"], None) == 0 {
        passed += 1;
    }
    if table.sys_setgid(2, 1000) == 0 && table.sys_setuid(2, 1000) == 0 {
        passed += 1;
    }
    // Unprivileged process cannot escalate back to root (0)
    if table.sys_setuid(2, 0) == EPERM {
        passed += 1;
    }

    // Create a new session in PID 2
    if table.sys_setsid(2) == 2 {
        passed += 1;
    }

    // Exit PID 2 with status 42 and reap from PID 1 via wait4
    if table.sys_exit(2, 42) == 0 {
        passed += 1;
    }
    if let Ok((reaped, wstatus, _)) = table.sys_wait4(1, 2, 0) {
        if reaped == 2 && (wstatus >> 8) == 42 {
            passed += 1;
        }
    }

    // 12. Test sys_clone with NEWPID namespace isolation
    let pid_ns_child = table.sys_clone(1, CloneFlags::NEWPID, 0, 0, 0);
    if pid_ns_child > 0 {
        if let Some(child_proc) = table.get_process(pid_ns_child as u32) {
            // In its own namespace, its local virtual PID is 1 (init)
            if child_proc.namespaced_pid.local_vpid() == 1
                && child_proc.namespaced_pid.depth == 1
                && table.sys_getpid(pid_ns_child as u32) == 1
            {
                passed += 1;
            }
        }
    }

    // 13. Test sys_unshare for Mount & Net namespaces
    if table.sys_unshare(1, CloneFlags::NEWNS.union(CloneFlags::NEWNET)) == 0 {
        if let Some(init_proc) = table.get_process(1) {
            if init_proc.ns_proxy.mnt_ns_id != 1 && init_proc.ns_proxy.net_ns_id != 1 {
                passed += 1;
            }
        }
    }

    // 14. Test per-process chroot jail & path resolution
    if table.sys_chroot(1, "/jail") == 0 {
        if let Ok(resolved) = table.resolve_process_path(1, "/etc/passwd") {
            if resolved == "/jail/etc/passwd" {
                passed += 1;
            }
        }
    }

    // Reset root for init
    let _ = table.sys_chroot(1, "/");

    // 15. Test sys_setns between processes
    let target_child = table.sys_clone(1, CloneFlags::NEWUTS, 0, 0, 0);
    if target_child > 0 {
        let child_uts = table.get_process(target_child as u32).unwrap().ns_proxy.uts_ns_id;
        if table.sys_setns(1, target_child as u32, CloneFlags::NEWUTS) == 0 {
            if table.get_process(1).unwrap().ns_proxy.uts_ns_id == child_uts {
                passed += 1;
            }
        }
    }

    passed
}
