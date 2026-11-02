//! Linux Kernel Namespaces Subsystem for OS-Level Containerization
//!
//! Implements isolation boundaries identical to Linux `clone()` / `unshare()` flags:
//! - Mount Namespace (`CLONE_NEWNS`): Isolated filesystem mount hierarchy and pivot_root
//! - PID Namespace (`CLONE_NEWPID`): Independent process tree starting at PID 1
//! - Network Namespace (`CLONE_NEWNET`): Isolated loopback, interfaces, routing tables, and socket spaces
//! - IPC Namespace (`CLONE_NEWIPC`): System V IPC and POSIX message queue isolation
//! - UTS Namespace (`CLONE_NEWUTS`): Independent hostname and NIS domain name
//! - User Namespace (`CLONE_NEWUSER`): UID/GID mappings enabling rootless containers
//! - Cgroup Namespace (`CLONE_NEWCGROUP`): Virtualized cgroup directory view

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;

static NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);

/// UTS (Unix Timesharing System) Namespace
#[derive(Debug, Clone)]
pub struct UtsNamespace {
    pub id: u64,
    pub hostname: String,
    pub domainname: String,
}

impl UtsNamespace {
    pub fn new(hostname: &str, domainname: &str) -> Self {
        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            hostname: String::from(hostname),
            domainname: String::from(domainname),
        }
    }
}

/// UID / GID Mapping entry for User Namespaces
#[derive(Debug, Clone, Copy)]
pub struct IdMapEntry {
    pub inside_id: u32,
    pub outside_id: u32,
    pub count: u32,
}

/// User Namespace (Enables rootless containers)
#[derive(Debug, Clone)]
pub struct UserNamespace {
    pub id: u64,
    pub owner_uid: u32,
    pub uid_maps: Vec<IdMapEntry>,
    pub gid_maps: Vec<IdMapEntry>,
}

impl UserNamespace {
    pub fn new(owner_uid: u32) -> Self {
        let mut uid_maps = Vec::new();
        uid_maps.push(IdMapEntry { inside_id: 0, outside_id: owner_uid, count: 1 });

        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            owner_uid,
            uid_maps,
            gid_maps: Vec::new(),
        }
    }

    /// Map container internal UID to host real UID
    pub fn map_uid_to_host(&self, internal_uid: u32) -> u32 {
        for map in &self.uid_maps {
            if internal_uid >= map.inside_id && internal_uid < map.inside_id + map.count {
                return map.outside_id + (internal_uid - map.inside_id);
            }
        }
        65534 // nobody
    }

    /// Map host real UID into container internal UID
    pub fn map_uid_to_ns(&self, host_uid: u32) -> u32 {
        for map in &self.uid_maps {
            if host_uid >= map.outside_id && host_uid < map.outside_id + map.count {
                return map.inside_id + (host_uid - map.outside_id);
            }
        }
        65534 // nobody
    }
}

/// Process Tree in PID Namespace
#[derive(Debug, Clone)]
pub struct PidNamespace {
    pub id: u64,
    pub parent_ns_id: Option<u64>,
    pub level: u32,
    pub pids: Vec<(u32, u32)>, // (internal_pid, host_pid)
    pub next_internal_pid: u32,
}

impl PidNamespace {
    pub fn new(parent_id: Option<u64>, level: u32) -> Self {
        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            parent_ns_id: parent_id,
            level,
            pids: Vec::new(),
            next_internal_pid: 1, // PID 1 (init)
        }
    }

    /// Allocate new PID within this isolated namespace
    pub fn alloc_pid(&mut self, host_pid: u32) -> u32 {
        let internal = self.next_internal_pid;
        self.next_internal_pid += 1;
        self.pids.push((internal, host_pid));
        internal
    }

    pub fn host_to_internal(&self, host_pid: u32) -> Option<u32> {
        self.pids.iter().find(|(_, h)| *h == host_pid).map(|(i, _)| *i)
    }

    pub fn internal_to_host(&self, internal_pid: u32) -> Option<u32> {
        self.pids.iter().find(|(i, _)| *i == internal_pid).map(|(_, h)| *h)
    }
}

/// Network Interface isolated inside Net Namespace
#[derive(Debug, Clone)]
pub struct NetNsInterface {
    pub name: String,
    pub ipv4: [u8; 4],
    pub netmask: [u8; 4],
    pub is_up: bool,
}

/// Network Namespace
#[derive(Debug, Clone)]
pub struct NetNamespace {
    pub id: u64,
    pub interfaces: Vec<NetNsInterface>,
    pub default_gateway: Option<[u8; 4]>,
}

impl NetNamespace {
    pub fn new() -> Self {
        let mut ifaces = Vec::new();
        // Always include loopback
        ifaces.push(NetNsInterface {
            name: String::from("lo"),
            ipv4: [127, 0, 0, 1],
            netmask: [255, 0, 0, 0],
            is_up: true,
        });

        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            interfaces: ifaces,
            default_gateway: None,
        }
    }

    pub fn add_veth(&mut self, name: &str, ip: [u8; 4], mask: [u8; 4]) {
        self.interfaces.push(NetNsInterface {
            name: String::from(name),
            ipv4: ip,
            netmask: mask,
            is_up: true,
        });
    }
}

/// Mount entry in Mount Namespace
#[derive(Debug, Clone)]
pub struct NsMount {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub flags: u32,
}

/// Mount Namespace
#[derive(Debug, Clone)]
pub struct MountNamespace {
    pub id: u64,
    pub root_path: String,
    pub mounts: Vec<NsMount>,
}

impl MountNamespace {
    pub fn new(root: &str) -> Self {
        Self {
            id: NEXT_NS_ID.fetch_add(1, Ordering::SeqCst),
            root_path: String::from(root),
            mounts: Vec::new(),
        }
    }

    pub fn add_mount(&mut self, source: &str, target: &str, fstype: &str, flags: u32) {
        self.mounts.push(NsMount {
            source: String::from(source),
            target: String::from(target),
            fstype: String::from(fstype),
            flags,
        });
    }
}

/// Container / Namespace Aggregation Context
#[derive(Debug, Clone)]
pub struct ContainerNamespaceContext {
    pub name: String,
    pub uts: UtsNamespace,
    pub user: UserNamespace,
    pub pid: PidNamespace,
    pub net: NetNamespace,
    pub mnt: MountNamespace,
}

impl ContainerNamespaceContext {
    pub fn new(name: &str, hostname: &str, root_path: &str, owner_uid: u32) -> Self {
        Self {
            name: String::from(name),
            uts: UtsNamespace::new(hostname, "localdomain"),
            user: UserNamespace::new(owner_uid),
            pid: PidNamespace::new(None, 0),
            net: NetNamespace::new(),
            mnt: MountNamespace::new(root_path),
        }
    }
}
