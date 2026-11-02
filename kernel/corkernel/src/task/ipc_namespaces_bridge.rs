//! CorOS IPC & Namespaces Subsystem Bridge (`ipc_namespaces_bridge.rs`)
//!
//! Integrates:
//! - `coripc::unix_domain::{UnixDomainEngine, UnixSocketType, UnixSocketAddr, Ucred, UnixMessage, UnixSocketError}`
//! - `coripc::ring_channel::{ShmRingHeader, RingChannelError}`
//! - `coripc::pid_namespace::{PidNamespaceManager, NamespacedPid, PidNsError}`
//! - `coripc::cgroup_v2::{CgroupHierarchy, CgroupControllers}`

extern crate alloc;

use alloc::vec::Vec;
use crate::sync::SpinLock;
use coripc::cgroup_v2::CgroupHierarchy;
use coripc::pid_namespace::{NamespacedPid, PidNamespaceManager, PidNsError};
use coripc::ring_channel::{RingChannelError, ShmRingHeader};
use coripc::unix_domain::{Ucred, UnixDomainEngine, UnixMessage, UnixSocketAddr, UnixSocketError, UnixSocketType};

pub struct IpcNamespacesBridge {
    unix_engine: SpinLock<Option<UnixDomainEngine>>,
    pid_ns_mgr: SpinLock<Option<PidNamespaceManager>>,
    cgroup_tree: SpinLock<Option<CgroupHierarchy>>,
}

unsafe impl Send for IpcNamespacesBridge {}
unsafe impl Sync for IpcNamespacesBridge {}

impl IpcNamespacesBridge {
    pub const fn uninit() -> Self {
        Self {
            unix_engine: SpinLock::new(None),
            pid_ns_mgr: SpinLock::new(None),
            cgroup_tree: SpinLock::new(None),
        }
    }

    /// Initializes IPC engines, root PID namespace, and Cgroups v2 root hierarchy.
    pub fn initialize(&self) {
        let mut u_guard = self.unix_engine.lock_irqsave();
        if u_guard.is_none() {
            *u_guard = Some(UnixDomainEngine::new());
        }
        drop(u_guard);

        let mut p_guard = self.pid_ns_mgr.lock_irqsave();
        if p_guard.is_none() {
            *p_guard = Some(PidNamespaceManager::new());
        }
        drop(p_guard);

        let mut c_guard = self.cgroup_tree.lock_irqsave();
        if c_guard.is_none() {
            *c_guard = Some(CgroupHierarchy::new());
        }
    }

    /// Creates a new `AF_UNIX` socket endpoint.
    pub fn create_unix_socket(&self, sock_type: UnixSocketType, pid: u32, uid: u32, gid: u32) -> u32 {
        self.initialize();
        let mut engine = self.unix_engine.lock_irqsave();
        let cred = Ucred { pid, uid, gid };
        if let Some(ref mut eng) = *engine {
            eng.socket(sock_type, cred)
        } else {
            0
        }
    }

    /// Binds an `AF_UNIX` socket to a filesystem path.
    pub fn bind_unix_socket(&self, sock_id: u32, path: &[u8]) -> Result<(), UnixSocketError> {
        self.initialize();
        let addr = UnixSocketAddr::from_raw_sun_path(path).ok_or(UnixSocketError::AddressNotFound)?;
        let mut engine = self.unix_engine.lock_irqsave();
        if let Some(ref mut eng) = *engine {
            eng.bind(sock_id, addr)
        } else {
            Err(UnixSocketError::SocketNotFound)
        }
    }

    /// Connects an `AF_UNIX` socket to a listening server path.
    pub fn connect_unix_socket(&self, client_id: u32, path: &[u8]) -> Result<(), UnixSocketError> {
        self.initialize();
        let addr = UnixSocketAddr::from_raw_sun_path(path).ok_or(UnixSocketError::AddressNotFound)?;
        let mut engine = self.unix_engine.lock_irqsave();
        if let Some(ref mut eng) = *engine {
            eng.connect(client_id, &addr)
        } else {
            Err(UnixSocketError::SocketNotFound)
        }
    }

    /// Sends data across an `AF_UNIX` connection.
    pub fn send_unix_message(&self, sock_id: u32, data: &[u8]) -> Result<usize, UnixSocketError> {
        self.initialize();
        let mut engine = self.unix_engine.lock_irqsave();
        if let Some(ref mut eng) = *engine {
            eng.sendmsg(sock_id, None, data, None)
        } else {
            Err(UnixSocketError::SocketNotFound)
        }
    }

    /// Receives queued data from an `AF_UNIX` socket.
    pub fn recv_unix_message(&self, sock_id: u32) -> Result<UnixMessage, UnixSocketError> {
        self.initialize();
        let mut engine = self.unix_engine.lock_irqsave();
        if let Some(ref mut eng) = *engine {
            eng.recvmsg(sock_id)
        } else {
            Err(UnixSocketError::SocketNotFound)
        }
    }

    /// Creates a nested child PID namespace.
    pub fn create_pid_namespace(&self, parent_ns_id: u32) -> Result<u32, PidNsError> {
        self.initialize();
        let mut p_mgr = self.pid_ns_mgr.lock_irqsave();
        if let Some(ref mut mgr) = *p_mgr {
            mgr.create_child_namespace(parent_ns_id)
        } else {
            Err(PidNsError::NamespaceNotFound)
        }
    }

    /// Allocates a new task in `target_ns_id`, returning its multi-level `NamespacedPid`.
    pub fn allocate_namespaced_task(&self, target_ns_id: u32) -> Result<NamespacedPid, PidNsError> {
        self.initialize();
        let mut p_mgr = self.pid_ns_mgr.lock_irqsave();
        if let Some(ref mut mgr) = *p_mgr {
            mgr.allocate_task(target_ns_id)
        } else {
            Err(PidNsError::NamespaceNotFound)
        }
    }

    /// Creates a lockless shared-memory IPC ring channel.
    pub fn create_shm_ring_channel(&self, capacity: usize) -> Result<ShmRingHeader, RingChannelError> {
        ShmRingHeader::new(capacity)
    }
}

pub static GLOBAL_IPC_NAMESPACES_BRIDGE: IpcNamespacesBridge = IpcNamespacesBridge::uninit();
