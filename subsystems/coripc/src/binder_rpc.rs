//! Capability-oriented object RPC engine (`BinderNode`, `BinderHandle`,
//! `BinderTransactionData`, handle-to-node capability translation across processes,
//! synchronous call stack validation, and `DeathNotification` delivery on process exit).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Errors returned by Binder capability RPC operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinderError {
    ProcessNotFound,
    InvalidHandle,
    NodeNotFound,
    TargetProcessDead,
    EmptyReplyStack,
    ReplyCallerMismatch,
}

/// Capability object exported in kernel space on behalf of a server process (`binder_node`).
#[derive(Clone, Debug)]
pub struct BinderNode {
    pub node_id: u64,
    pub owner_pid: u32,
    /// User-space pointer/cookie identifying the local object in `owner_pid`.
    pub ptr_cookie: u64,
    /// Strong reference count held by client process handles.
    pub strong_refs: u32,
    /// Processes subscribed to `BC_REQUEST_DEATH_NOTIFICATION` when `owner_pid` exits.
    pub death_subscribers: Vec<(u32, u64)>,
}

/// Process-local capability descriptor (`binder_ref`) referencing a kernel `BinderNode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinderHandle {
    pub handle_id: u32,
    pub node_id: u64,
    pub strong_refs: u32,
}

/// Object reference embedded inside a `BinderTransactionData` payload (`flat_binder_object`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferredObject {
    /// Sender exports a local object `(ptr_cookie)` -> translated into a `BinderHandle` in the receiver.
    LocalBinder { ptr_cookie: u64 },
    /// Sender passes an existing capability handle -> translated into a `BinderHandle` (or local `BinderNode` if receiver is owner).
    RemoteHandle { handle_id: u32 },
}

/// Translated object delivered to the receiving process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredObject {
    /// Target process is the owner of the `BinderNode` itself.
    LocalObject { node_id: u64, ptr_cookie: u64 },
    /// Target process received a capability handle installed in its handle table.
    InstalledHandle { handle_id: u32, node_id: u64 },
}

/// Transaction payload (`binder_transaction_data`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinderTransactionData {
    pub code: u32,
    pub flags: u32,
    pub sender_pid: u32,
    pub sender_euid: u32,
    pub target_node_id: u64,
    pub target_ptr_cookie: u64,
    pub data_bytes: Vec<u8>,
    pub delivered_objects: Vec<DeliveredObject>,
}

/// Delivered death notification (`BR_DEAD_BINDER`) queued when a `BinderNode` owner process dies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeathNotification {
    pub dead_node_id: u64,
    pub dead_owner_pid: u32,
    pub client_cookie: u64,
}

/// Per-process Binder state (`binder_proc`).
pub struct BinderProcess {
    pub pid: u32,
    pub euid: u32,
    pub alive: bool,
    pub handles: BTreeMap<u32, BinderHandle>,
    pub next_handle_id: u32,
    pub inbox_transactions: Vec<BinderTransactionData>,
    pub inbox_replies: Vec<Vec<u8>>,
    pub death_notifications: Vec<DeathNotification>,
}

/// Capability-oriented Binder RPC Engine.
pub struct BinderRpcEngine {
    processes: BTreeMap<u32, BinderProcess>,
    nodes: BTreeMap<u64, BinderNode>,
    /// Synchronous call stack entries `(caller_pid, callee_pid, node_id)`.
    call_stack: Vec<(u32, u32, u64)>,
    next_node_id: u64,
}

impl Default for BinderRpcEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BinderRpcEngine {
    /// Handle `0` is universally reserved for the context manager (`servicemanager`).
    pub const CONTEXT_MGR_HANDLE: u32 = 0;

    pub fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            nodes: BTreeMap::new(),
            call_stack: Vec::new(),
            next_node_id: 1,
        }
    }

    pub fn register_process(&mut self, pid: u32, euid: u32) {
        self.processes.insert(
            pid,
            BinderProcess {
                pid,
                euid,
                alive: true,
                handles: BTreeMap::new(),
                next_handle_id: 1,
                inbox_transactions: Vec::new(),
                inbox_replies: Vec::new(),
                death_notifications: Vec::new(),
            },
        );
    }

    /// Register `pid` as the global context manager (`handle == 0`).
    pub fn set_context_manager(&mut self, pid: u32, ptr_cookie: u64) -> Result<u64, BinderError> {
        let proc_entry = self
            .processes
            .get(&pid)
            .ok_or(BinderError::ProcessNotFound)?;
        if !proc_entry.alive {
            return Err(BinderError::TargetProcessDead);
        }
        let node_id = self.find_or_create_node(pid, ptr_cookie);
        // Install handle 0 in all existing processes.
        let pids: Vec<u32> = self.processes.keys().copied().collect();
        for p in pids {
            if p != pid {
                self.install_handle_for_process(p, node_id, Some(Self::CONTEXT_MGR_HANDLE));
            }
        }
        Ok(node_id)
    }

    fn find_or_create_node(&mut self, owner_pid: u32, ptr_cookie: u64) -> u64 {
        for (&id, node) in &self.nodes {
            if node.owner_pid == owner_pid && node.ptr_cookie == ptr_cookie {
                return id;
            }
        }
        let id = self.next_node_id;
        self.next_node_id += 1;
        self.nodes.insert(
            id,
            BinderNode {
                node_id: id,
                owner_pid,
                ptr_cookie,
                strong_refs: 1,
                death_subscribers: Vec::new(),
            },
        );
        id
    }

    fn install_handle_for_process(
        &mut self,
        proc_pid: u32,
        node_id: u64,
        fixed_handle: Option<u32>,
    ) -> u32 {
        let proc_state = match self.processes.get_mut(&proc_pid) {
            Some(p) => p,
            None => return 0,
        };
        for (&hid, h) in &proc_state.handles {
            if h.node_id == node_id {
                let mut h_mut = *h;
                h_mut.strong_refs += 1;
                proc_state.handles.insert(hid, h_mut);
                return hid;
            }
        }
        let hid = match fixed_handle {
            Some(fh) => fh,
            None => {
                let h = proc_state.next_handle_id;
                proc_state.next_handle_id += 1;
                h
            }
        };
        proc_state.handles.insert(
            hid,
            BinderHandle {
                handle_id: hid,
                node_id,
                strong_refs: 1,
            },
        );
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.strong_refs += 1;
        }
        hid
    }

    /// Execute a capability-mediated RPC transaction (`BC_TRANSACTION`) from `sender_pid`
    /// targeting `target_handle`, translating any embedded `TransferredObject`s across
    /// process boundaries.
    pub fn transact(
        &mut self,
        sender_pid: u32,
        target_handle: u32,
        code: u32,
        flags: u32,
        data: &[u8],
        objects: &[TransferredObject],
    ) -> Result<(), BinderError> {
        let (sender_euid, target_node_id) = {
            let sender = self
                .processes
                .get(&sender_pid)
                .ok_or(BinderError::ProcessNotFound)?;
            let handle = sender
                .handles
                .get(&target_handle)
                .ok_or(BinderError::InvalidHandle)?;
            (sender.euid, handle.node_id)
        };

        let (receiver_pid, target_cookie) = {
            let node = self
                .nodes
                .get(&target_node_id)
                .ok_or(BinderError::NodeNotFound)?;
            (node.owner_pid, node.ptr_cookie)
        };

        let receiver_alive = self
            .processes
            .get(&receiver_pid)
            .ok_or(BinderError::ProcessNotFound)?
            .alive;
        if !receiver_alive {
            return Err(BinderError::TargetProcessDead);
        }

        // Translate transferred objects across the process boundary.
        let mut delivered = Vec::with_capacity(objects.len());
        for obj in objects {
            let resolved_node_id = match *obj {
                TransferredObject::LocalBinder { ptr_cookie } => {
                    self.find_or_create_node(sender_pid, ptr_cookie)
                }
                TransferredObject::RemoteHandle { handle_id } => {
                    let sender = self
                        .processes
                        .get(&sender_pid)
                        .ok_or(BinderError::ProcessNotFound)?;
                    sender
                        .handles
                        .get(&handle_id)
                        .ok_or(BinderError::InvalidHandle)?
                        .node_id
                }
            };

            let (node_owner, node_cookie) = {
                let n = self
                    .nodes
                    .get(&resolved_node_id)
                    .ok_or(BinderError::NodeNotFound)?;
                (n.owner_pid, n.ptr_cookie)
            };

            if node_owner == receiver_pid {
                delivered.push(DeliveredObject::LocalObject {
                    node_id: resolved_node_id,
                    ptr_cookie: node_cookie,
                });
            } else {
                let installed_hid =
                    self.install_handle_for_process(receiver_pid, resolved_node_id, None);
                delivered.push(DeliveredObject::InstalledHandle {
                    handle_id: installed_hid,
                    node_id: resolved_node_id,
                });
            }
        }

        self.call_stack
            .push((sender_pid, receiver_pid, target_node_id));

        if let Some(recv_proc) = self.processes.get_mut(&receiver_pid) {
            recv_proc.inbox_transactions.push(BinderTransactionData {
                code,
                flags,
                sender_pid,
                sender_euid,
                target_node_id,
                target_ptr_cookie: target_cookie,
                data_bytes: Vec::from(data),
                delivered_objects: delivered,
            });
        }
        Ok(())
    }

    /// Pop the next incoming `BinderTransactionData` queued for `pid`.
    pub fn pop_transaction(&mut self, pid: u32) -> Option<BinderTransactionData> {
        self.processes
            .get_mut(&pid)
            .and_then(|p| if p.inbox_transactions.is_empty() { None } else { Some(p.inbox_transactions.remove(0)) })
    }

    /// Send a synchronous reply (`BC_REPLY`) validating the top of the synchronous call stack.
    pub fn send_reply(&mut self, replier_pid: u32, reply_bytes: &[u8]) -> Result<u32, BinderError> {
        let (caller_pid, callee_pid, _node_id) =
            self.call_stack.pop().ok_or(BinderError::EmptyReplyStack)?;
        if callee_pid != replier_pid {
            self.call_stack.push((caller_pid, callee_pid, _node_id));
            return Err(BinderError::ReplyCallerMismatch);
        }
        let caller = self
            .processes
            .get_mut(&caller_pid)
            .ok_or(BinderError::ProcessNotFound)?;
        caller.inbox_replies.push(Vec::from(reply_bytes));
        Ok(caller_pid)
    }

    /// Subscribe `subscriber_pid` to receive a `DeathNotification` if the owner of `handle_id` exits.
    pub fn request_death_notification(
        &mut self,
        subscriber_pid: u32,
        handle_id: u32,
        client_cookie: u64,
    ) -> Result<(), BinderError> {
        let node_id = {
            let sub = self
                .processes
                .get(&subscriber_pid)
                .ok_or(BinderError::ProcessNotFound)?;
            sub.handles
                .get(&handle_id)
                .ok_or(BinderError::InvalidHandle)?
                .node_id
        };
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(BinderError::NodeNotFound)?;
        node.death_subscribers.push((subscriber_pid, client_cookie));
        Ok(())
    }

    /// Handle process termination: mark `exiting_pid` dead and deliver `DeathNotification`s
    /// (`BR_DEAD_BINDER`) to all subscribed clients of nodes owned by `exiting_pid`.
    pub fn on_process_exit(&mut self, exiting_pid: u32) -> Result<usize, BinderError> {
        {
            let proc_state = self
                .processes
                .get_mut(&exiting_pid)
                .ok_or(BinderError::ProcessNotFound)?;
            proc_state.alive = false;
        }

        let mut pending_deliveries = Vec::new();
        for (&node_id, node) in &self.nodes {
            if node.owner_pid == exiting_pid {
                for &(sub_pid, cookie) in &node.death_subscribers {
                    pending_deliveries.push((
                        sub_pid,
                        DeathNotification {
                            dead_node_id: node_id,
                            dead_owner_pid: exiting_pid,
                            client_cookie: cookie,
                        },
                    ));
                }
            }
        }

        let count = pending_deliveries.len();
        for (sub_pid, notif) in pending_deliveries {
            if let Some(sub_proc) = self.processes.get_mut(&sub_pid) {
                sub_proc.death_notifications.push(notif);
            }
        }
        Ok(count)
    }

    pub fn get_process(&self, pid: u32) -> Option<&BinderProcess> {
        self.processes.get(&pid)
    }
}

/// Self-test exercising Binder context manager registration, capability handle transfer
/// across three processes, synchronous call-stack reply validation, and `DeathNotification` delivery.
pub fn self_test() -> bool {
    let mut binder = BinderRpcEngine::new();
    let pid_svcmgr = 100;
    let pid_service = 200;
    let pid_client = 300;

    binder.register_process(pid_svcmgr, 0);
    binder.register_process(pid_service, 1001);
    binder.register_process(pid_client, 1002);

    if binder.set_context_manager(pid_svcmgr, 0xCAFE_0000).is_err() {
        return false;
    }

    // pid_service registers its local binder object (ptr_cookie = 0xABCD_1234) with pid_svcmgr via handle 0.
    if binder
        .transact(
            pid_service,
            BinderRpcEngine::CONTEXT_MGR_HANDLE,
            1,
            0,
            b"ADD_SERVICE:audio",
            &[TransferredObject::LocalBinder {
                ptr_cookie: 0xABCD_1234,
            }],
        )
        .is_err()
    {
        return false;
    }

    let svcmgr_tx = match binder.pop_transaction(pid_svcmgr) {
        Some(tx) => tx,
        None => return false,
    };
    let service_handle_in_svcmgr = match svcmgr_tx.delivered_objects.first() {
        Some(&DeliveredObject::InstalledHandle { handle_id, .. }) => handle_id,
        _ => return false,
    };
    if binder.send_reply(pid_svcmgr, b"OK").is_err() {
        return false;
    }

    // pid_svcmgr forwards that remote handle to pid_client? First let pid_client call pid_svcmgr,
    // and let pid_service also send its handle directly or via svcmgr.
    // Let's test pid_svcmgr passing `RemoteHandle { handle_id: service_handle_in_svcmgr }` to pid_client:
    // First give svcmgr a handle to client or let client receive it via a transaction.
    if binder
        .transact(
            pid_client,
            BinderRpcEngine::CONTEXT_MGR_HANDLE,
            2,
            0,
            b"GET_SERVICE:audio",
            &[TransferredObject::LocalBinder {
                ptr_cookie: 0x9999,
            }],
        )
        .is_err()
    {
        return false;
    }
    let client_tx = match binder.pop_transaction(pid_svcmgr) {
        Some(tx) => tx,
        None => return false,
    };
    let client_handle_in_svcmgr = match client_tx.delivered_objects.first() {
        Some(&DeliveredObject::InstalledHandle { handle_id, .. }) => handle_id,
        _ => return false,
    };
    if binder.send_reply(pid_svcmgr, b"GRANTED").is_err() {
        return false;
    }

    // svcmgr transfers `service_handle_in_svcmgr` to `pid_client`!
    if binder
        .transact(
            pid_svcmgr,
            client_handle_in_svcmgr,
            3,
            0,
            b"CAPABILITY_GRANT",
            &[TransferredObject::RemoteHandle {
                handle_id: service_handle_in_svcmgr,
            }],
        )
        .is_err()
    {
        return false;
    }
    let grant_tx = match binder.pop_transaction(pid_client) {
        Some(tx) => tx,
        None => return false,
    };
    let service_handle_in_client = match grant_tx.delivered_objects.first() {
        Some(&DeliveredObject::InstalledHandle { handle_id, .. }) => handle_id,
        _ => return false,
    };
    if binder.send_reply(pid_client, b"ACK").is_err() {
        return false;
    }

    // pid_client subscribes to death notification on `service_handle_in_client`.
    if binder
        .request_death_notification(pid_client, service_handle_in_client, 0xFEED_FACE)
        .is_err()
    {
        return false;
    }

    // When pid_service exits, pid_client must receive the DeathNotification with cookie 0xFEED_FACE.
    if binder.on_process_exit(pid_service) != Ok(1) {
        return false;
    }

    match binder.get_process(pid_client) {
        Some(p) => {
            p.death_notifications.len() == 1
                && p.death_notifications[0].client_cookie == 0xFEED_FACE
                && p.death_notifications[0].dead_owner_pid == pid_service
        }
        None => false,
    }
}
