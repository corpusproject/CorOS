//! `AF_UNIX` (`AF_LOCAL`) stream & datagram socket engine supporting filesystem
//! paths and Linux abstract namespace (`\0name`), `SCM_RIGHTS` file descriptor array
//! passing, and `SCM_CREDENTIALS` (`Ucred { pid, uid, gid }`) peer authentication.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

/// Standard POSIX AF_UNIX address family constant.
pub const AF_UNIX: u16 = 1;
/// Maximum length of sun_path in sockaddr_un (108 bytes per Linux ABI).
pub const UNIX_PATH_MAX: usize = 108;
/// POSIX file mode bit for Unix domain socket inodes (0o140000).
pub const S_IFSOCK: u32 = 0o140000;

/// Maximum number of file descriptors carried in a single `SCM_RIGHTS` ancillary message (`SCM_MAX_FD`).
pub const SCM_MAX_FD: usize = 253;

/// POSIX `struct sockaddr_un` representing an `AF_UNIX` endpoint address.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; UNIX_PATH_MAX],
}

impl SockAddrUn {
    pub const fn new() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0u8; UNIX_PATH_MAX],
        }
    }

    pub fn from_pathname(path: &str) -> Self {
        let mut addr = Self::new();
        let bytes = path.as_bytes();
        let len = if bytes.len() < UNIX_PATH_MAX { bytes.len() } else { UNIX_PATH_MAX - 1 };
        let mut i = 0;
        while i < len {
            addr.sun_path[i] = bytes[i];
            i += 1;
        }
        addr
    }

    pub fn from_abstract(name: &[u8]) -> Self {
        let mut addr = Self::new();
        addr.sun_path[0] = 0;
        let len = if name.len() < UNIX_PATH_MAX - 1 { name.len() } else { UNIX_PATH_MAX - 2 };
        let mut i = 0;
        while i < len {
            addr.sun_path[1 + i] = name[i];
            i += 1;
        }
        addr
    }

    pub fn to_socket_addr(&self) -> Option<UnixSocketAddr> {
        UnixSocketAddr::from_raw_sun_path(&self.sun_path)
    }

    pub fn is_abstract(&self) -> bool {
        self.sun_path[0] == 0 && self.sun_path[1] != 0
    }

    pub fn is_pathname(&self) -> bool {
        self.sun_path[0] != 0
    }
}

/// `AF_UNIX` socket type (`SOCK_STREAM` vs `SOCK_DGRAM`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnixSocketType {
    Stream,
    Datagram,
}

/// `AF_UNIX` address (`sun_path`): either a VFS pathname or a Linux abstract namespace name (`\0...`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixSocketAddr {
    /// Filesystem pathname (e.g. `b"/run/dbus/system_bus_socket"`).
    Pathname(Vec<u8>),
    /// Linux abstract socket namespace (`sun_path[0] == 0`, independent of filesystem mount namespaces).
    Abstract(Vec<u8>),
}

impl UnixSocketAddr {
    /// Parse a raw `sun_path` byte slice: a leading `0x00` byte selects the Linux abstract namespace.
    pub fn from_raw_sun_path(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        if raw[0] == 0 {
            if raw.len() < 2 {
                return None;
            }
            Some(Self::Abstract(Vec::from(&raw[1..])))
        } else {
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            if end == 0 {
                return None;
            }
            Some(Self::Pathname(Vec::from(&raw[..end])))
        }
    }
}

/// Peer credentials structure (`struct ucred`) passed via `SCM_CREDENTIALS` / `SO_PEERCRED`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Ancillary control message (`cmsghdr`) attached to an `AF_UNIX` message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixControlMsg {
    /// `SCM_RIGHTS`: open file descriptor numbers duplicated into the receiving process.
    pub scm_rights_fds: Vec<u32>,
    /// `SCM_CREDENTIALS`: kernel-verified sender `Ucred { pid, uid, gid }`.
    pub scm_credentials: Option<Ucred>,
}

/// A payload packet + optional ancillary data queued inside an `AF_UNIX` socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixMessage {
    pub data: Vec<u8>,
    pub control: Option<UnixControlMsg>,
    pub sender_addr: Option<UnixSocketAddr>,
}

/// Errors returned by `AF_UNIX` socket operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnixSocketError {
    SocketNotFound,
    AddressInUse,
    AddressNotFound,
    NotListening,
    SocketTypeMismatch,
    AlreadyConnected,
    NotConnected,
    WouldBlock,
    TooManyFdsInScmRights,
    CredentialsMismatch,
}

/// Internal state of a single `AF_UNIX` socket endpoint.
pub struct UnixSocketEndpoint {
    pub id: u32,
    pub sock_type: UnixSocketType,
    pub bound_addr: Option<UnixSocketAddr>,
    pub listening: bool,
    pub backlog_limit: usize,
    pub pending_accept_queue: VecDeque<u32>,
    pub peer_socket_id: Option<u32>,
    pub owner_cred: Ucred,
    pub peer_cred: Option<Ucred>,
    pub passcred_enabled: bool,
    pub recv_queue: VecDeque<UnixMessage>,
}

/// `AF_UNIX` Socket Subsystem Engine.
pub struct UnixDomainEngine {
    sockets: BTreeMap<u32, UnixSocketEndpoint>,
    bound_table: BTreeMap<UnixSocketAddr, u32>,
    next_sock_id: u32,
    /// Monotonic kernel file-table token allocator used when duplicating `SCM_RIGHTS` descriptors.
    next_duplicated_fd_base: u32,
}

impl Default for UnixDomainEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixDomainEngine {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            bound_table: BTreeMap::new(),
            next_sock_id: 1,
            next_duplicated_fd_base: 1000,
        }
    }

    /// Create a new `AF_UNIX` socket owned by `cred`.
    pub fn socket(&mut self, sock_type: UnixSocketType, cred: Ucred) -> u32 {
        let id = self.next_sock_id;
        self.next_sock_id += 1;
        self.sockets.insert(
            id,
            UnixSocketEndpoint {
                id,
                sock_type,
                bound_addr: None,
                listening: false,
                backlog_limit: 128,
                pending_accept_queue: VecDeque::new(),
                peer_socket_id: None,
                owner_cred: cred,
                peer_cred: None,
                passcred_enabled: false,
                recv_queue: VecDeque::new(),
            },
        );
        id
    }

    /// Enable or disable `SO_PASSCRED` on `sock_id`.
    pub fn set_passcred(&mut self, sock_id: u32, enable: bool) -> Result<(), UnixSocketError> {
        let sock = self
            .sockets
            .get_mut(&sock_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        sock.passcred_enabled = enable;
        Ok(())
    }

    /// Bind `sock_id` to a filesystem path or Linux abstract namespace address (`\0name`).
    pub fn bind(&mut self, sock_id: u32, addr: UnixSocketAddr) -> Result<(), UnixSocketError> {
        if self.bound_table.contains_key(&addr) {
            return Err(UnixSocketError::AddressInUse);
        }
        let sock = self
            .sockets
            .get_mut(&sock_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        sock.bound_addr = Some(addr.clone());
        self.bound_table.insert(addr, sock_id);
        Ok(())
    }

    /// Mark a `SOCK_STREAM` socket as listening for incoming connections.
    pub fn listen(&mut self, sock_id: u32, backlog: usize) -> Result<(), UnixSocketError> {
        let sock = self
            .sockets
            .get_mut(&sock_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        if sock.sock_type != UnixSocketType::Stream {
            return Err(UnixSocketError::SocketTypeMismatch);
        }
        sock.listening = true;
        sock.backlog_limit = backlog.max(1);
        Ok(())
    }

    /// Connect `client_id` to a bound server address, exchanging `SO_PEERCRED` credentials.
    pub fn connect(
        &mut self,
        client_id: u32,
        target_addr: &UnixSocketAddr,
    ) -> Result<(), UnixSocketError> {
        let listener_id = *self
            .bound_table
            .get(target_addr)
            .ok_or(UnixSocketError::AddressNotFound)?;

        let (client_type, client_cred) = {
            let c = self
                .sockets
                .get(&client_id)
                .ok_or(UnixSocketError::SocketNotFound)?;
            if c.peer_socket_id.is_some() {
                return Err(UnixSocketError::AlreadyConnected);
            }
            (c.sock_type, c.owner_cred)
        };

        let (listener_type, listener_listening, listener_cred) = {
            let l = self
                .sockets
                .get(&listener_id)
                .ok_or(UnixSocketError::SocketNotFound)?;
            (l.sock_type, l.listening, l.owner_cred)
        };

        if client_type != listener_type {
            return Err(UnixSocketError::SocketTypeMismatch);
        }

        if client_type == UnixSocketType::Datagram {
            let c = self
                .sockets
                .get_mut(&client_id)
                .ok_or(UnixSocketError::SocketNotFound)?;
            c.peer_socket_id = Some(listener_id);
            c.peer_cred = Some(listener_cred);
            return Ok(());
        }

        if !listener_listening {
            return Err(UnixSocketError::NotListening);
        }

        // Allocate the server-side accepted socket endpoint and wire the pair.
        let server_peer_id = self.socket(UnixSocketType::Stream, listener_cred);
        if let Some(sp) = self.sockets.get_mut(&server_peer_id) {
            sp.peer_socket_id = Some(client_id);
            sp.peer_cred = Some(client_cred);
        }
        if let Some(c) = self.sockets.get_mut(&client_id) {
            c.peer_socket_id = Some(server_peer_id);
            c.peer_cred = Some(listener_cred);
        }
        if let Some(l) = self.sockets.get_mut(&listener_id) {
            l.pending_accept_queue.push_back(server_peer_id);
        }
        Ok(())
    }

    /// Accept the next pending stream connection on `listener_id`, returning `(accepted_sock_id, peer_cred)`.
    pub fn accept(&mut self, listener_id: u32) -> Result<(u32, Ucred), UnixSocketError> {
        let next_peer_id = {
            let l = self
                .sockets
                .get_mut(&listener_id)
                .ok_or(UnixSocketError::SocketNotFound)?;
            if !l.listening {
                return Err(UnixSocketError::NotListening);
            }
            l.pending_accept_queue
                .pop_front()
                .ok_or(UnixSocketError::WouldBlock)?
        };
        let peer_cred = self
            .sockets
            .get(&next_peer_id)
            .and_then(|s| s.peer_cred)
            .ok_or(UnixSocketError::SocketNotFound)?;
        Ok((next_peer_id, peer_cred))
    }

    /// Send data and optional `SCM_RIGHTS` / `SCM_CREDENTIALS` ancillary control message.
    /// Kernel validates `SCM_CREDENTIALS` against the sender's `owner_cred` (unless `uid == 0`)
    /// and duplicates passed file descriptors into the receiver's descriptor space.
    pub fn sendmsg(
        &mut self,
        sender_id: u32,
        dest_addr: Option<&UnixSocketAddr>,
        data: &[u8],
        control: Option<UnixControlMsg>,
    ) -> Result<usize, UnixSocketError> {
        let (sender_cred, sender_bound, connected_peer) = {
            let s = self
                .sockets
                .get(&sender_id)
                .ok_or(UnixSocketError::SocketNotFound)?;
            (s.owner_cred, s.bound_addr.clone(), s.peer_socket_id)
        };

        let target_id = match dest_addr {
            Some(addr) => *self
                .bound_table
                .get(addr)
                .ok_or(UnixSocketError::AddressNotFound)?,
            None => connected_peer.ok_or(UnixSocketError::NotConnected)?,
        };

        let receiver_passcred = self
            .sockets
            .get(&target_id)
            .ok_or(UnixSocketError::SocketNotFound)?
            .passcred_enabled;

        let mut translated_control = None;
        if let Some(ctrl) = control {
            if ctrl.scm_rights_fds.len() > SCM_MAX_FD {
                return Err(UnixSocketError::TooManyFdsInScmRights);
            }
            // Validate SCM_CREDENTIALS: non-root sender cannot spoof PID/UID/GID.
            let verified_cred = match ctrl.scm_credentials {
                Some(c) => {
                    if sender_cred.uid != 0 && c != sender_cred {
                        return Err(UnixSocketError::CredentialsMismatch);
                    }
                    Some(c)
                }
                None if receiver_passcred => Some(sender_cred),
                None => None,
            };

            // Duplicate file descriptors into receiver FD numbers.
            let mut dup_fds = Vec::with_capacity(ctrl.scm_rights_fds.len());
            for _src_fd in &ctrl.scm_rights_fds {
                let new_fd = self.next_duplicated_fd_base;
                self.next_duplicated_fd_base += 1;
                dup_fds.push(new_fd);
            }

            translated_control = Some(UnixControlMsg {
                scm_rights_fds: dup_fds,
                scm_credentials: verified_cred,
            });
        } else if receiver_passcred {
            translated_control = Some(UnixControlMsg {
                scm_rights_fds: Vec::new(),
                scm_credentials: Some(sender_cred),
            });
        }

        let target_sock = self
            .sockets
            .get_mut(&target_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        target_sock.recv_queue.push_back(UnixMessage {
            data: Vec::from(data),
            control: translated_control,
            sender_addr: sender_bound,
        });
        Ok(data.len())
    }

    /// Receive the next queued `UnixMessage` from `sock_id`.
    pub fn recvmsg(&mut self, sock_id: u32) -> Result<UnixMessage, UnixSocketError> {
        let sock = self
            .sockets
            .get_mut(&sock_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        sock.recv_queue
            .pop_front()
            .ok_or(UnixSocketError::WouldBlock)
    }

    /// Create an unnamed pair of connected UNIX domain sockets (`sys_socketpair`, vector 53).
    pub fn socketpair(
        &mut self,
        sock_type: UnixSocketType,
        cred: Ucred,
    ) -> (u32, u32) {
        let s1 = self.socket(sock_type, cred);
        let s2 = self.socket(sock_type, cred);

        if let Some(sock1) = self.sockets.get_mut(&s1) {
            sock1.peer_socket_id = Some(s2);
            sock1.peer_cred = Some(cred);
        }
        if let Some(sock2) = self.sockets.get_mut(&s2) {
            sock2.peer_socket_id = Some(s1);
            sock2.peer_cred = Some(cred);
        }
        (s1, s2)
    }

    /// Retrieve peer credentials for a connected socket (`SO_PEERCRED`).
    pub fn get_peercred(&self, sock_id: u32) -> Result<Ucred, UnixSocketError> {
        let sock = self
            .sockets
            .get(&sock_id)
            .ok_or(UnixSocketError::SocketNotFound)?;
        sock.peer_cred.ok_or(UnixSocketError::NotConnected)
    }

    /// Unlink a pathname socket from the bound address table.
    pub fn unlink_pathname(&mut self, path: &[u8]) -> Result<(), UnixSocketError> {
        let addr = UnixSocketAddr::Pathname(Vec::from(path));
        self.bound_table.remove(&addr).ok_or(UnixSocketError::AddressNotFound)?;
        Ok(())
    }
}

/// Self-test exercising Linux abstract namespace binding (`\0coros-ipc`), `SOCK_STREAM`
/// handshake, `SCM_RIGHTS` file descriptor passing, and `SCM_CREDENTIALS` verification.
pub fn self_test() -> bool {
    let mut engine = UnixDomainEngine::new();
    let server_cred = Ucred {
        pid: 100,
        uid: 0,
        gid: 0,
    };
    let client_cred = Ucred {
        pid: 450,
        uid: 1000,
        gid: 1000,
    };

    let listener = engine.socket(UnixSocketType::Stream, server_cred);
    let abstract_addr = match UnixSocketAddr::from_raw_sun_path(b"\0coros-ipc-bus") {
        Some(a) => a,
        None => return false,
    };
    if engine.bind(listener, abstract_addr.clone()).is_err()
        || engine.listen(listener, 16).is_err()
    {
        return false;
    }

    let client = engine.socket(UnixSocketType::Stream, client_cred);
    if engine.connect(client, &abstract_addr).is_err() {
        return false;
    }

    let (accepted, peer_ucred) = match engine.accept(listener) {
        Ok(res) => res,
        Err(_) => return false,
    };
    if peer_ucred != client_cred || engine.set_passcred(accepted, true).is_err() {
        return false;
    }

    // Attempt credential spoofing by unprivileged client -> must fail with CredentialsMismatch.
    let spoofed_ctrl = UnixControlMsg {
        scm_rights_fds: alloc::vec![3],
        scm_credentials: Some(Ucred {
            pid: 1,
            uid: 0,
            gid: 0,
        }),
    };
    if engine.sendmsg(client, None, b"evil", Some(spoofed_ctrl))
        != Err(UnixSocketError::CredentialsMismatch)
    {
        return false;
    }

    // Legitimate sendmsg passing 2 file descriptors + authentic credentials.
    let valid_ctrl = UnixControlMsg {
        scm_rights_fds: alloc::vec![4, 5],
        scm_credentials: Some(client_cred),
    };
    if engine
        .sendmsg(client, None, b"HELLO_SCM", Some(valid_ctrl))
        .is_err()
    {
        return false;
    }

    let msg = match engine.recvmsg(accepted) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let ctrl = match msg.control {
        Some(c) => c,
        None => return false,
    };

    let (pair1, pair2) = engine.socketpair(UnixSocketType::Stream, client_cred);
    if engine.sendmsg(pair1, None, b"PAIR_DATA", None).is_err() {
        return false;
    }
    let pair_msg = match engine.recvmsg(pair2) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if pair_msg.data != b"PAIR_DATA" || engine.get_peercred(pair1) != Ok(client_cred) {
        return false;
    }

    let sun = SockAddrUn::from_pathname("/tmp/test.sock");
    if sun.sun_family != AF_UNIX || sun.to_socket_addr() != Some(UnixSocketAddr::Pathname(alloc::vec::Vec::from(&b"/tmp/test.sock"[..]))) {
        return false;
    }
    if !sun.is_pathname() || sun.is_abstract() {
        return false;
    }
    let abs_sock = SockAddrUn::from_abstract(b"abstract_demo");
    if !abs_sock.is_abstract() || abs_sock.is_pathname() {
        return false;
    }

    // Verify Linux ABI data structure sizes
    if core::mem::size_of::<SockAddrUn>() != 110 || core::mem::size_of::<Ucred>() != 12 {
        return false;
    }

    // Exceeding SCM_MAX_FD (253) must return TooManyFdsInScmRights
    let oversized_ctrl = UnixControlMsg {
        scm_rights_fds: alloc::vec![1u32; 254],
        scm_credentials: None,
    };
    if engine.sendmsg(client, None, b"too_many", Some(oversized_ctrl)) != Err(UnixSocketError::TooManyFdsInScmRights) {
        return false;
    }

    msg.data == b"HELLO_SCM"
        && ctrl.scm_rights_fds.len() == 2
        && ctrl.scm_credentials == Some(client_cred)
}
