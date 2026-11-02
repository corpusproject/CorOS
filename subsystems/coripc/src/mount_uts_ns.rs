//! Mount Namespace propagation graph (`MountPropagation`: `Shared`, `Private`, `Slave`,
//! `Unbindable` peer-group event propagation), UTS Namespace (`sysname`, `nodename`,
//! `release`, `domainname`), and User Namespace UID/GID extent mapper (`UidGidExtent`,
//! `map_id_up`, `map_id_down`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Mount propagation mode (Linux MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountPropagation {
    /// Mount/unmount events propagate bidirectionally across all members of `peer_group_id`
    /// and one-way downward to any slave mounts whose `master_group_id == Some(peer_group_id)`.
    Shared,
    /// Mount/unmount events do not propagate into or out of this mount point.
    Private,
    /// Receives mount/unmount events one-way from `master_group_id`, but does not propagate upward.
    Slave,
    /// Private mount that additionally forbids bind-mounting (`EINVAL` on bind).
    Unbindable,
}

/// Errors returned by Mount, UTS, and User namespace operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NsManageError {
    MountNotFound,
    CannotBindUnbindable,
    InvalidHostnameLength,
    TooManyUidGidExtents,
    OverlappingExtent,
}

/// A single mount entry inside a Mount Namespace.
#[derive(Clone, Debug)]
pub struct MountPoint {
    pub id: u32,
    pub mount_ns_id: u32,
    pub path: String,
    pub source_fs: String,
    pub propagation: MountPropagation,
    /// Shared peer group ID if `propagation == Shared`.
    pub peer_group_id: Option<u32>,
    /// Master peer group ID if `propagation == Slave` (or a `Shared` mount that is also a slave).
    pub master_group_id: Option<u32>,
    /// Child submounts mounted underneath this mount point (`(subpath, source_fs)`).
    pub submounts: Vec<(String, String)>,
}

/// Mount propagation graph across Mount Namespaces.
pub struct MountPropagationGraph {
    mounts: BTreeMap<u32, MountPoint>,
    next_mount_id: u32,
    next_peer_group_id: u32,
}

impl Default for MountPropagationGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl MountPropagationGraph {
    pub fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
            next_mount_id: 1,
            next_peer_group_id: 1,
        }
    }

    pub fn allocate_peer_group(&mut self) -> u32 {
        let g = self.next_peer_group_id;
        self.next_peer_group_id += 1;
        g
    }

    /// Create a root/base mount in `mount_ns_id`.
    pub fn create_mount(
        &mut self,
        mount_ns_id: u32,
        path: &str,
        source_fs: &str,
        propagation: MountPropagation,
    ) -> u32 {
        let id = self.next_mount_id;
        self.next_mount_id += 1;
        let peer_group_id = if propagation == MountPropagation::Shared {
            Some(self.allocate_peer_group())
        } else {
            None
        };
        self.mounts.insert(
            id,
            MountPoint {
                id,
                mount_ns_id,
                path: String::from(path),
                source_fs: String::from(source_fs),
                propagation,
                peer_group_id,
                master_group_id: None,
                submounts: Vec::new(),
            },
        );
        id
    }

    /// Clone/bind `src_mount_id` into `target_ns_id`. Fails if `src_mount_id` is `Unbindable`.
    /// If `src_mount_id` is `Shared`, the new mount joins the same `peer_group_id`.
    pub fn bind_clone_mount(
        &mut self,
        src_mount_id: u32,
        target_ns_id: u32,
        target_path: &str,
    ) -> Result<u32, NsManageError> {
        let src = self
            .mounts
            .get(&src_mount_id)
            .ok_or(NsManageError::MountNotFound)?
            .clone();
        if src.propagation == MountPropagation::Unbindable {
            return Err(NsManageError::CannotBindUnbindable);
        }

        let id = self.next_mount_id;
        self.next_mount_id += 1;
        self.mounts.insert(
            id,
            MountPoint {
                id,
                mount_ns_id: target_ns_id,
                path: String::from(target_path),
                source_fs: src.source_fs,
                propagation: src.propagation,
                peer_group_id: src.peer_group_id,
                master_group_id: src.master_group_id,
                submounts: src.submounts,
            },
        );
        Ok(id)
    }

    /// Transition propagation mode (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`) on `mount_id`.
    pub fn set_propagation(
        &mut self,
        mount_id: u32,
        new_mode: MountPropagation,
    ) -> Result<(), NsManageError> {
        let new_group = if new_mode == MountPropagation::Shared {
            Some(self.allocate_peer_group())
        } else {
            None
        };
        let m = self
            .mounts
            .get_mut(&mount_id)
            .ok_or(NsManageError::MountNotFound)?;
        match new_mode {
            MountPropagation::Shared => {
                if m.peer_group_id.is_none() {
                    m.peer_group_id = new_group;
                }
            }
            MountPropagation::Slave => {
                // If previously Shared, its old peer_group becomes its master_group_id.
                if let Some(pg) = m.peer_group_id.take() {
                    m.master_group_id = Some(pg);
                }
            }
            MountPropagation::Private | MountPropagation::Unbindable => {
                m.peer_group_id = None;
                m.master_group_id = None;
            }
        }
        m.propagation = new_mode;
        Ok(())
    }

    /// Mount `(subpath, source_fs)` under `origin_mount_id` and propagate across its
    /// shared peer group and downstream slave mounts. Returns the number of mounts updated.
    pub fn trigger_submount_event(
        &mut self,
        origin_mount_id: u32,
        subpath: &str,
        source_fs: &str,
    ) -> Result<usize, NsManageError> {
        let (origin_prop, origin_peer_group) = {
            let m = self
                .mounts
                .get(&origin_mount_id)
                .ok_or(NsManageError::MountNotFound)?;
            (m.propagation, m.peer_group_id)
        };

        let mut affected_ids = alloc::vec![origin_mount_id];
        if origin_prop == MountPropagation::Shared {
            if let Some(pg) = origin_peer_group {
                // Propagate to all peers in `pg` and all slaves whose `master_group_id == Some(pg)`.
                for (&id, m) in &self.mounts {
                    if id != origin_mount_id
                        && (m.peer_group_id == Some(pg) || m.master_group_id == Some(pg))
                    {
                        affected_ids.push(id);
                    }
                }
            }
        }

        for &id in &affected_ids {
            if let Some(m) = self.mounts.get_mut(&id) {
                m.submounts
                    .push((String::from(subpath), String::from(source_fs)));
            }
        }
        Ok(affected_ids.len())
    }

    pub fn get_mount(&self, mount_id: u32) -> Option<&MountPoint> {
        self.mounts.get(&mount_id)
    }
}

/// UTS Namespace (`CLONE_NEWUTS`) isolating `sysname`, `nodename`, `release`, and `domainname`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtsNamespace {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub domainname: String,
}

impl UtsNamespace {
    pub const MAX_UTS_LEN: usize = 64;

    pub fn new_default() -> Self {
        Self {
            sysname: String::from("CorOS"),
            nodename: String::from("coros-host"),
            release: String::from("6.12.0-coros"),
            domainname: String::from("(none)"),
        }
    }

    pub fn clone_ns(&self) -> Self {
        self.clone()
    }

    pub fn set_nodename(&mut self, name: &str) -> Result<(), NsManageError> {
        if name.is_empty() || name.len() > Self::MAX_UTS_LEN {
            return Err(NsManageError::InvalidHostnameLength);
        }
        self.nodename = String::from(name);
        Ok(())
    }

    pub fn set_domainname(&mut self, domain: &str) -> Result<(), NsManageError> {
        if domain.len() > Self::MAX_UTS_LEN {
            return Err(NsManageError::InvalidHostnameLength);
        }
        self.domainname = String::from(domain);
        Ok(())
    }
}

/// Single contiguous UID or GID mapping extent (`child_first..child_first+count` <-> `parent_first..parent_first+count`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UidGidExtent {
    pub child_first: u32,
    pub parent_first: u32,
    pub count: u32,
}

/// User Namespace (`CLONE_NEWUSER`) UID and GID extent mapper (`uid_map`, `gid_map`).
#[derive(Clone, Debug, Default)]
pub struct UserNamespaceMapper {
    pub uid_extents: Vec<UidGidExtent>,
    pub gid_extents: Vec<UidGidExtent>,
}

impl UserNamespaceMapper {
    pub const MAX_EXTENTS: usize = 340;
    pub const OVERFLOW_ID: u32 = 65534; // nobody / nogroup

    pub fn new() -> Self {
        Self::default()
    }

    fn validate_and_insert(
        extents: &mut Vec<UidGidExtent>,
        new_ext: UidGidExtent,
    ) -> Result<(), NsManageError> {
        if extents.len() >= Self::MAX_EXTENTS {
            return Err(NsManageError::TooManyUidGidExtents);
        }
        if new_ext.count == 0 {
            return Err(NsManageError::OverlappingExtent);
        }
        let c_end = new_ext.child_first.saturating_add(new_ext.count);
        let p_end = new_ext.parent_first.saturating_add(new_ext.count);

        for ext in extents.iter() {
            let ec_end = ext.child_first.saturating_add(ext.count);
            let ep_end = ext.parent_first.saturating_add(ext.count);
            let child_overlaps = new_ext.child_first < ec_end && ext.child_first < c_end;
            let parent_overlaps = new_ext.parent_first < ep_end && ext.parent_first < p_end;
            if child_overlaps || parent_overlaps {
                return Err(NsManageError::OverlappingExtent);
            }
        }
        extents.push(new_ext);
        Ok(())
    }

    pub fn add_uid_extent(&mut self, extent: UidGidExtent) -> Result<(), NsManageError> {
        Self::validate_and_insert(&mut self.uid_extents, extent)
    }

    pub fn add_gid_extent(&mut self, extent: UidGidExtent) -> Result<(), NsManageError> {
        Self::validate_and_insert(&mut self.gid_extents, extent)
    }

    /// Translate a child-namespace ID up into the parent (host) namespace (`kuid_t` resolution).
    pub fn map_id_up(extents: &[UidGidExtent], child_id: u32) -> Option<u32> {
        for ext in extents {
            if child_id >= ext.child_first
                && child_id < ext.child_first.saturating_add(ext.count)
            {
                let offset = child_id - ext.child_first;
                return Some(ext.parent_first + offset);
            }
        }
        None
    }

    /// Translate a parent (host) ID down into the child user namespace (returns `OVERFLOW_ID` if unmapped).
    pub fn map_id_down(extents: &[UidGidExtent], parent_id: u32) -> u32 {
        for ext in extents {
            if parent_id >= ext.parent_first
                && parent_id < ext.parent_first.saturating_add(ext.count)
            {
                let offset = parent_id - ext.parent_first;
                return ext.child_first + offset;
            }
        }
        Self::OVERFLOW_ID
    }
}

/// Self-test exercising Mount Namespace shared/slave/private/unbindable propagation,
/// UTS namespace isolation, and User Namespace UID/GID extent mapping.
pub fn self_test() -> bool {
    let mut graph = MountPropagationGraph::new();
    let host_mnt = graph.create_mount(1, "/mnt/shared", "tmpfs", MountPropagation::Shared);
    let peer_mnt = match graph.bind_clone_mount(host_mnt, 2, "/mnt/shared") {
        Ok(id) => id,
        Err(_) => return false,
    };
    let slave_mnt = match graph.bind_clone_mount(host_mnt, 3, "/mnt/shared") {
        Ok(id) => id,
        Err(_) => return false,
    };
    if graph
        .set_propagation(slave_mnt, MountPropagation::Slave)
        .is_err()
    {
        return false;
    }

    // Event on host_mnt propagates to peer_mnt and slave_mnt (3 mounts total).
    if graph.trigger_submount_event(host_mnt, "/data", "overlayfs") != Ok(3) {
        return false;
    }

    // Event on slave_mnt stays local to slave_mnt (1 mount total, does not propagate upstream to host_mnt).
    if graph.trigger_submount_event(slave_mnt, "/local_only", "ramfs") != Ok(1) {
        return false;
    }
    let host_state = match graph.get_mount(host_mnt) {
        Some(m) => m,
        None => return false,
    };
    let peer_state = match graph.get_mount(peer_mnt) {
        Some(m) => m,
        None => return false,
    };
    if host_state.submounts.len() != 1 || peer_state.submounts.len() != 1 {
        return false;
    }

    // UTS Namespace test.
    let host_uts = UtsNamespace::new_default();
    let mut container_uts = host_uts.clone_ns();
    if container_uts.set_nodename("container-alpha").is_err() {
        return false;
    }
    if host_uts.nodename == container_uts.nodename {
        return false;
    }

    // User Namespace rootless mapping test: container UID 0 -> host UID 100_000 (count 65536).
    let mut user_ns = UserNamespaceMapper::new();
    if user_ns
        .add_uid_extent(UidGidExtent {
            child_first: 0,
            parent_first: 100_000,
            count: 65536,
        })
        .is_err()
    {
        return false;
    }
    let host_uid = UserNamespaceMapper::map_id_up(&user_ns.uid_extents, 0);
    let back_to_child = UserNamespaceMapper::map_id_down(&user_ns.uid_extents, 100_500);
    let unmapped = UserNamespaceMapper::map_id_down(&user_ns.uid_extents, 0);

    host_uid == Some(100_000)
        && back_to_child == 500
        && unmapped == UserNamespaceMapper::OVERFLOW_ID
}
