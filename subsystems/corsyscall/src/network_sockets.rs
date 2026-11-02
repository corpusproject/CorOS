//! CorOS Syscall Domain Module: `network_sockets`
//! BSD/POSIX Socket Layer (`socket`, `bind`, `listen`, `accept4`, `connect`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `shutdown`, `socketpair`).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const EBADF: i64 = -9;
pub const EINVAL: i64 = -22;
pub const EADDRINUSE: i64 = -98;
pub const ENOTCONN: i64 = -107;
pub const EISCONN: i64 = -106;
pub const ECONNREFUSED: i64 = -111;
pub const EAGAIN: i64 = -11;
pub const EPIPE: i64 = -32;
pub const EAFNOSUPPORT: i64 = -97;
pub const EMSGSIZE: i64 = -90;
pub const EPERM: i64 = -1;

pub const SCM_MAX_FD: usize = 253;
pub const S_IFSOCK: u32 = 0o140000;

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

/// Socket address families (`AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Unix = 1,
    Inet = 2,
    Inet6 = 10,
    Netlink = 16,
}

impl AddressFamily {
    pub const fn from_raw(af: u16) -> Option<Self> {
        match af {
            1 => Some(Self::Unix),
            2 => Some(Self::Inet),
            10 => Some(Self::Inet6),
            16 => Some(Self::Netlink),
            _ => None,
        }
    }
}

/// Socket transport types (`SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_RAW`, `SOCK_SEQPACKET`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketType {
    Stream = 1,
    Dgram = 2,
    Raw = 3,
    SeqPacket = 5,
}

impl SocketType {
    pub const fn from_raw(raw: u32) -> Option<(Self, bool, bool)> {
        let base = raw & 0xF;
        let nonblock = (raw & 0x0800) != 0;
        let cloexec = (raw & 0x0008_0000) != 0;
        let ty = match base {
            1 => Self::Stream,
            2 => Self::Dgram,
            3 => Self::Raw,
            5 => Self::SeqPacket,
            _ => return None,
        };
        Some((ty, nonblock, cloexec))
    }
}

/// IPv4 socket endpoint (`struct sockaddr_in`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16, // Network byte order or port id
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            sin_family: AddressFamily::Inet as u16,
            sin_port: port,
            sin_addr: ip,
            sin_zero: [0; 8],
        }
    }
}

/// IPv6 socket endpoint (`struct sockaddr_in6`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

/// Standard POSIX constants for socket options and ancillary messages.
pub const AF_UNIX: u16 = 1;
pub const UNIX_PATH_MAX: usize = 108;
pub const SO_PEERCRED: u32 = 17;
pub const SCM_RIGHTS: u32 = 1;
pub const SCM_CREDENTIALS: u32 = 2;

/// Unix Domain Socket endpoint address (`struct sockaddr_un`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; UNIX_PATH_MAX],
}

impl SockAddrUn {
    pub const fn new() -> Self {
        Self {
            sun_family: AddressFamily::Unix as u16,
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

    pub fn is_abstract(&self) -> bool {
        self.sun_path[0] == 0 && self.sun_path[1] != 0
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

/// Ancillary control message carrying passed file descriptors (`SCM_RIGHTS`) or credentials (`SCM_CREDENTIALS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AncillaryMsg {
    pub fds: Vec<usize>,
    pub cred: Option<Ucred>,
}

/// Message header used by `sendmsg` and `recvmsg`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgHdr {
    pub msg_name: u64,
    pub msg_namelen: u32,
    pub msg_iov: u64,
    pub msg_iovlen: usize,
    pub msg_control: u64,
    pub msg_controllen: usize,
    pub msg_flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connected(usize), // Peer socket ID
    Closed,
}

#[derive(Clone, Debug)]
pub struct SocketEntry {
    pub id: usize,
    pub family: AddressFamily,
    pub sock_type: SocketType,
    pub state: SocketState,
    pub local_addr: Option<SockAddrIn>,
    pub unix_addr: Option<SockAddrUn>,
    pub owner_cred: Ucred,
    pub peer_cred: Option<Ucred>,
    pub reuse_addr: bool,
    pub keep_alive: bool,
    pub rcv_buf_limit: usize,
    pub snd_buf_limit: usize,
    pub nonblock: bool,
    pub shut_rd: bool,
    pub shut_wr: bool,
    pub backlog_limit: usize,
    pub accept_queue: VecDeque<usize>,
    pub rx_queue: VecDeque<(Vec<u8>, Option<SockAddrIn>)>,
    pub ancillary_queue: VecDeque<AncillaryMsg>,
}

/// Kernel Socket Table managing TCP/UDP/UNIX state transitions and loopback packet routing.
pub struct SocketTable {
    sockets: Vec<SocketEntry>,
}

impl SocketTable {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }

    fn get_sock(&self, fd: usize) -> Result<&SocketEntry, i64> {
        self.sockets
            .get(fd)
            .filter(|s| s.state != SocketState::Closed)
            .ok_or(EBADF)
    }

    fn get_sock_mut(&mut self, fd: usize) -> Result<&mut SocketEntry, i64> {
        self.sockets
            .get_mut(fd)
            .filter(|s| s.state != SocketState::Closed)
            .ok_or(EBADF)
    }

    /// `sys_socket`: Creates a new communication endpoint.
    pub fn sys_socket(&mut self, domain: u16, raw_type: u32, protocol: u32) -> i64 {
        self.sys_socket_with_cred(domain, raw_type, protocol, Ucred { pid: 1, uid: 0, gid: 0 })
    }

    /// `sys_socket_with_cred`: Creates a new socket owned by the specified credentials.
    pub fn sys_socket_with_cred(&mut self, domain: u16, raw_type: u32, _protocol: u32, cred: Ucred) -> i64 {
        let family = match AddressFamily::from_raw(domain) {
            Some(f) => f,
            None => return EAFNOSUPPORT,
        };
        let (sock_type, nonblock, _cloexec) = match SocketType::from_raw(raw_type) {
            Some(t) => t,
            None => return EINVAL,
        };

        let id = self.sockets.len();
        self.sockets.push(SocketEntry {
            id,
            family,
            sock_type,
            state: SocketState::Unbound,
            local_addr: None,
            unix_addr: None,
            owner_cred: cred,
            peer_cred: None,
            reuse_addr: false,
            keep_alive: false,
            rcv_buf_limit: 65536,
            snd_buf_limit: 65536,
            nonblock,
            shut_rd: false,
            shut_wr: false,
            backlog_limit: 0,
            accept_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            ancillary_queue: VecDeque::new(),
        });
        id as i64
    }

    /// `sys_bind`: Binds a socket to a local IPv4 address and port.
    pub fn sys_bind(&mut self, sockfd: usize, addr: SockAddrIn) -> i64 {
        let reuse = match self.get_sock(sockfd) {
            Ok(s) => s.reuse_addr,
            Err(e) => return e,
        };

        let port_busy = self.sockets.iter().any(|s| {
            s.id != sockfd
                && s.state != SocketState::Closed
                && s.local_addr.map(|a| a.sin_port == addr.sin_port).unwrap_or(false)
                && !(reuse && s.reuse_addr)
        });
        if port_busy {
            return EADDRINUSE;
        }

        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if sock.state != SocketState::Unbound {
            return EINVAL;
        }
        sock.local_addr = Some(addr);
        sock.state = SocketState::Bound;
        0
    }

    /// `sys_listen`: Marks a bound stream socket as passive listener.
    pub fn sys_listen(&mut self, sockfd: usize, backlog: usize) -> i64 {
        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if sock.sock_type != SocketType::Stream || sock.state != SocketState::Bound {
            return EINVAL;
        }
        sock.backlog_limit = backlog.max(1);
        sock.state = SocketState::Listening;
        0
    }

    /// `sys_connect`: Connects a client socket to a listening stream server or datagram peer.
    pub fn sys_connect(&mut self, client_fd: usize, target_addr: SockAddrIn) -> i64 {
        let client_type = match self.get_sock(client_fd) {
            Ok(s) => {
                if matches!(s.state, SocketState::Connected(_)) {
                    return EISCONN;
                }
                s.sock_type
            }
            Err(e) => return e,
        };

        if client_type == SocketType::Stream {
            let listener_id = match self.sockets.iter().find(|s| {
                s.state == SocketState::Listening
                    && s.local_addr.map(|a| a.sin_port == target_addr.sin_port).unwrap_or(false)
            }) {
                Some(l) => {
                    if l.accept_queue.len() >= l.backlog_limit {
                        return ECONNREFUSED;
                    }
                    l.id
                }
                None => return ECONNREFUSED,
            };

            // Allocate server-side accepted socket and link client <-> server_child
            let server_child_id = self.sockets.len();
            self.sockets.push(SocketEntry {
                id: server_child_id,
                family: AddressFamily::Inet,
                sock_type: SocketType::Stream,
                state: SocketState::Connected(client_fd),
                local_addr: Some(target_addr),
                unix_addr: None,
                owner_cred: Ucred { pid: 1, uid: 0, gid: 0 },
                peer_cred: None,
                reuse_addr: true,
                keep_alive: false,
                rcv_buf_limit: 65536,
                snd_buf_limit: 65536,
                nonblock: false,
                shut_rd: false,
                shut_wr: false,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                ancillary_queue: VecDeque::new(),
            });

            self.sockets[client_fd].state = SocketState::Connected(server_child_id);
            self.sockets[listener_id].accept_queue.push_back(server_child_id);
            0
        } else {
            let peer_id = match self.sockets.iter().find(|s| {
                s.state != SocketState::Closed
                    && s.local_addr.map(|a| a.sin_port == target_addr.sin_port).unwrap_or(false)
            }) {
                Some(p) => p.id,
                None => return ECONNREFUSED,
            };
            self.sockets[client_fd].state = SocketState::Connected(peer_id);
            0
        }
    }

    /// `sys_accept4`: Dequeues a pending connected socket from a listening socket.
    pub fn sys_accept4(&mut self, listener_fd: usize, flags: u32) -> i64 {
        let child_id = {
            let listener = match self.get_sock_mut(listener_fd) {
                Ok(s) => s,
                Err(e) => return e,
            };
            if listener.state != SocketState::Listening {
                return EINVAL;
            }
            match listener.accept_queue.pop_front() {
                Some(id) => id,
                None => return EAGAIN,
            }
        };
        if (flags & 0x0800) != 0 {
            self.sockets[child_id].nonblock = true;
        }
        child_id as i64
    }

    /// `sys_sendto`: Transmits payload to a connected peer or explicit datagram destination.
    pub fn sys_sendto(
        &mut self,
        sockfd: usize,
        buf: &[u8],
        dest_addr: Option<SockAddrIn>,
    ) -> i64 {
        let (peer_id, src_addr) = {
            let sock = match self.get_sock(sockfd) {
                Ok(s) => s,
                Err(e) => return e,
            };
            if sock.shut_wr {
                return EPIPE;
            }
            match (sock.state, dest_addr) {
                (SocketState::Connected(peer), _) => (peer, sock.local_addr),
                (_, Some(target)) => {
                    let found = self
                        .sockets
                        .iter()
                        .find(|s| {
                            s.state != SocketState::Closed
                                && s.local_addr.map(|a| a.sin_port == target.sin_port).unwrap_or(false)
                        })
                        .map(|s| s.id);
                    match found {
                        Some(id) => (id, sock.local_addr),
                        None => return ECONNREFUSED,
                    }
                }
                _ => return ENOTCONN,
            }
        };

        let peer = match self.get_sock_mut(peer_id) {
            Ok(p) => p,
            Err(_) => return EPIPE,
        };
        peer.rx_queue.push_back((buf.to_vec(), src_addr));
        buf.len() as i64
    }

    /// `sys_recvfrom`: Receives payload and optional source address from `sockfd`.
    pub fn sys_recvfrom(
        &mut self,
        sockfd: usize,
        buf: &mut [u8],
    ) -> Result<(usize, Option<SockAddrIn>), i64> {
        let sock = self.get_sock_mut(sockfd)?;
        if sock.shut_rd && sock.rx_queue.is_empty() {
            return Ok((0, None));
        }
        match sock.rx_queue.pop_front() {
            Some((data, addr)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, addr))
            }
            None => Err(EAGAIN),
        }
    }

    /// `sys_setsockopt`: Configures socket-level options (`SO_REUSEADDR=2`, `SO_KEEPALIVE=9`).
    pub fn sys_setsockopt(&mut self, sockfd: usize, optname: u32, optval: u32) -> i64 {
        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match optname {
            2 => sock.reuse_addr = optval != 0,
            7 => sock.snd_buf_limit = (optval as usize).max(4096),
            8 => sock.rcv_buf_limit = (optval as usize).max(4096),
            9 => sock.keep_alive = optval != 0,
            _ => return EINVAL,
        }
        0
    }

    /// `sys_bind_unix`: Binds a UNIX domain socket to a pathname or abstract namespace.
    pub fn sys_bind_unix(&mut self, sockfd: usize, addr: SockAddrUn) -> i64 {
        if addr.sun_family != AddressFamily::Unix as u16 {
            return EINVAL;
        }
        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if sock.family != AddressFamily::Unix {
            return EINVAL;
        }
        if sock.state != SocketState::Unbound {
            return EINVAL;
        }

        let path_busy = self.sockets.iter().any(|s| {
            s.id != sockfd
                && s.state != SocketState::Closed
                && s.unix_addr.map(|a| a.sun_path == addr.sun_path).unwrap_or(false)
        });
        if path_busy {
            return EADDRINUSE;
        }

        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        sock.unix_addr = Some(addr);
        sock.state = SocketState::Bound;
        0
    }

    /// `sys_connect_unix`: Connects a UNIX domain socket to a listening server or peer.
    pub fn sys_connect_unix(&mut self, client_fd: usize, target_addr: SockAddrUn) -> i64 {
        let (client_type, client_cred) = match self.get_sock(client_fd) {
            Ok(s) => {
                if s.family != AddressFamily::Unix {
                    return EINVAL;
                }
                if matches!(s.state, SocketState::Connected(_)) {
                    return EISCONN;
                }
                (s.sock_type, s.owner_cred)
            }
            Err(e) => return e,
        };

        if client_type == SocketType::Stream {
            let (listener_id, listener_cred) = match self.sockets.iter().find(|s| {
                s.family == AddressFamily::Unix
                    && s.state == SocketState::Listening
                    && s.unix_addr.map(|a| a.sun_path == target_addr.sun_path).unwrap_or(false)
            }) {
                Some(l) => {
                    if l.accept_queue.len() >= l.backlog_limit {
                        return ECONNREFUSED;
                    }
                    (l.id, l.owner_cred)
                }
                None => return ECONNREFUSED,
            };

            let server_child_id = self.sockets.len();
            self.sockets.push(SocketEntry {
                id: server_child_id,
                family: AddressFamily::Unix,
                sock_type: SocketType::Stream,
                state: SocketState::Connected(client_fd),
                local_addr: None,
                unix_addr: Some(target_addr),
                owner_cred: listener_cred,
                peer_cred: Some(client_cred),
                reuse_addr: true,
                keep_alive: false,
                rcv_buf_limit: 65536,
                snd_buf_limit: 65536,
                nonblock: false,
                shut_rd: false,
                shut_wr: false,
                backlog_limit: 0,
                accept_queue: VecDeque::new(),
                rx_queue: VecDeque::new(),
                ancillary_queue: VecDeque::new(),
            });

            self.sockets[client_fd].state = SocketState::Connected(server_child_id);
            self.sockets[client_fd].peer_cred = Some(listener_cred);
            self.sockets[listener_id].accept_queue.push_back(server_child_id);
            0
        } else {
            let (peer_id, peer_cred) = match self.sockets.iter().find(|s| {
                s.family == AddressFamily::Unix
                    && s.state != SocketState::Closed
                    && s.unix_addr.map(|a| a.sun_path == target_addr.sun_path).unwrap_or(false)
            }) {
                Some(p) => (p.id, p.owner_cred),
                None => return ECONNREFUSED,
            };
            self.sockets[client_fd].state = SocketState::Connected(peer_id);
            self.sockets[client_fd].peer_cred = Some(peer_cred);
            0
        }
    }

    /// `sys_sendmsg_unix`: Transmits data and optional `SCM_RIGHTS` / `SCM_CREDENTIALS` ancillary message.
    pub fn sys_sendmsg_unix(
        &mut self,
        sockfd: usize,
        buf: &[u8],
        passed_fds: &[usize],
        cred: Option<Ucred>,
    ) -> i64 {
        if passed_fds.len() > SCM_MAX_FD {
            return EMSGSIZE;
        }

        let (peer_id, sender_cred) = match self.get_sock(sockfd) {
            Ok(s) => match s.state {
                SocketState::Connected(p) => (p, s.owner_cred),
                _ => return ENOTCONN,
            },
            Err(e) => return e,
        };

        // Anti-spoofing validation: unprivileged sender (uid != 0) cannot spoof pid/uid/gid
        if let Some(c) = cred {
            if sender_cred.uid != 0
                && (c.pid != sender_cred.pid || c.uid != sender_cred.uid || c.gid != sender_cred.gid)
            {
                return EPERM;
            }
        }

        let peer = match self.get_sock_mut(peer_id) {
            Ok(p) => p,
            Err(_) => return EPIPE,
        };
        peer.rx_queue.push_back((buf.to_vec(), None));
        if !passed_fds.is_empty() || cred.is_some() {
            peer.ancillary_queue.push_back(AncillaryMsg {
                fds: passed_fds.to_vec(),
                cred,
            });
        }
        buf.len() as i64
    }

    /// `sys_recvmsg_unix`: Receives data and dequeues ancillary message.
    pub fn sys_recvmsg_unix(
        &mut self,
        sockfd: usize,
        buf: &mut [u8],
    ) -> Result<(usize, Option<AncillaryMsg>), i64> {
        let sock = self.get_sock_mut(sockfd)?;
        let (n, _) = match sock.rx_queue.pop_front() {
            Some((data, addr)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                (n, addr)
            }
            None => return Err(EAGAIN),
        };
        let ancillary = sock.ancillary_queue.pop_front();
        Ok((n, ancillary))
    }

    /// `sys_getsockopt`: Queries socket-level option value.
    pub fn sys_getsockopt(&self, sockfd: usize, optname: u32) -> Result<u32, i64> {
        let sock = self.get_sock(sockfd)?;
        match optname {
            2 => Ok(u32::from(sock.reuse_addr)),
            7 => Ok(sock.snd_buf_limit as u32),
            8 => Ok(sock.rcv_buf_limit as u32),
            9 => Ok(u32::from(sock.keep_alive)),
            SO_PEERCRED => Ok(sock.peer_cred.map(|c| c.pid).unwrap_or(0)),
            _ => Err(EINVAL),
        }
    }

    /// `sys_getsockopt_ucred`: Queries full 12-byte `struct ucred { pid, uid, gid }` for connected peer.
    pub fn sys_getsockopt_ucred(&self, sockfd: usize) -> Result<Ucred, i64> {
        let sock = self.get_sock(sockfd)?;
        sock.peer_cred.ok_or(ENOTCONN)
    }

    /// `sys_getsockopt_slice`: Copies socket option buffer into `optval` slice.
    pub fn sys_getsockopt_slice(&self, sockfd: usize, optname: u32, optval: &mut [u8]) -> Result<usize, i64> {
        let sock = self.get_sock(sockfd)?;
        match optname {
            SO_PEERCRED => {
                let cred = sock.peer_cred.ok_or(ENOTCONN)?;
                if optval.len() < 12 {
                    return Err(EINVAL);
                }
                optval[0..4].copy_from_slice(&cred.pid.to_ne_bytes());
                optval[4..8].copy_from_slice(&cred.uid.to_ne_bytes());
                optval[8..12].copy_from_slice(&cred.gid.to_ne_bytes());
                Ok(12)
            }
            _ => Err(EINVAL),
        }
    }

    /// `sys_shutdown`: Shuts down read, write, or both halves of a full-duplex connection.
    pub fn sys_shutdown(&mut self, sockfd: usize, how: u32) -> i64 {
        let sock = match self.get_sock_mut(sockfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        match how {
            SHUT_RD => sock.shut_rd = true,
            SHUT_WR => sock.shut_wr = true,
            SHUT_RDWR => {
                sock.shut_rd = true;
                sock.shut_wr = true;
            }
            _ => return EINVAL,
        }
        0
    }

    /// `sys_socketpair`: Creates an unnamed pair of connected UNIX domain sockets.
    pub fn sys_socketpair(&mut self, domain: u16, raw_type: u32) -> Result<(usize, usize), i64> {
        self.sys_socketpair_with_cred(domain, raw_type, Ucred { pid: 100, uid: 1000, gid: 1000 })
    }

    /// `sys_socketpair_with_cred`: Creates connected socketpair inheriting explicit caller credentials.
    pub fn sys_socketpair_with_cred(&mut self, domain: u16, raw_type: u32, cred: Ucred) -> Result<(usize, usize), i64> {
        if domain != AddressFamily::Unix as u16 {
            return Err(EAFNOSUPPORT);
        }
        let a = self.sys_socket_with_cred(domain, raw_type, 0, cred);
        if a < 0 {
            return Err(a);
        }
        let b = self.sys_socket_with_cred(domain, raw_type, 0, cred);
        if b < 0 {
            return Err(b);
        }
        let ua = a as usize;
        let ub = b as usize;
        self.sockets[ua].state = SocketState::Connected(ub);
        self.sockets[ub].state = SocketState::Connected(ua);
        self.sockets[ua].peer_cred = Some(cred);
        self.sockets[ub].peer_cred = Some(cred);
        Ok((ua, ub))
    }
}

/// Runs comprehensive self-tests on `network_sockets` structs and TCP/Unix socket state machines.
pub fn verify_domain_network_sockets() -> u32 {
    let mut passed = 0u32;
    let mut net = SocketTable::new();

    // 1. Create server TCP socket, set SO_REUSEADDR, bind to 127.0.0.1:8080, and listen
    let srv = net.sys_socket(AddressFamily::Inet as u16, SocketType::Stream as u32, 0) as usize;
    let addr = SockAddrIn::new([127, 0, 0, 1], 8080);
    if net.sys_setsockopt(srv, 2, 1) == 0
        && net.sys_bind(srv, addr) == 0
        && net.sys_listen(srv, 16) == 0
    {
        passed += 1;
    }

    // 2. Create client socket and connect to server
    let cli = net.sys_socket(AddressFamily::Inet as u16, SocketType::Stream as u32, 0) as usize;
    if net.sys_connect(cli, addr) == 0 {
        passed += 1;
    }

    // 3. Accept connection on server
    let accepted = net.sys_accept4(srv, 0) as usize;
    if accepted > cli {
        passed += 1;
    }

    // 4. Send request from client and recvfrom on accepted server socket
    if net.sys_sendto(cli, b"GET /status", None) == 11 {
        let mut rx = [0u8; 32];
        if let Ok((n, _)) = net.sys_recvfrom(accepted, &mut rx) {
            if n == 11 && &rx[..11] == b"GET /status" {
                passed += 1;
            }
        }
    }

    // 5. Test socketpair bidirectional communication, SO_PEERCRED u32 and full 12-byte ucred
    if let Ok((s0, s1)) = net.sys_socketpair(AddressFamily::Unix as u16, SocketType::Stream as u32) {
        if net.sys_sendto(s0, b"ping", None) == 4 {
            let mut buf = [0u8; 8];
            if let Ok((n, _)) = net.sys_recvfrom(s1, &mut buf) {
                let mut cred_bytes = [0u8; 12];
                if n == 4
                    && &buf[..4] == b"ping"
                    && net.sys_getsockopt(s0, SO_PEERCRED) == Ok(100)
                    && net.sys_getsockopt_ucred(s0) == Ok(Ucred { pid: 100, uid: 1000, gid: 1000 })
                    && net.sys_getsockopt_slice(s0, SO_PEERCRED, &mut cred_bytes) == Ok(12)
                {
                    passed += 1;
                }
            }
        }
    }

    // 6. Test shutdown write prevents further sends with EPIPE
    if net.sys_shutdown(cli, SHUT_WR) == 0 && net.sys_sendto(cli, b"more", None) == EPIPE {
        passed += 1;
    }

    // 7. Test AF_UNIX pathname & abstract namespace bind/connect with SCM_RIGHTS FD passing
    let u_srv = net.sys_socket(AddressFamily::Unix as u16, SocketType::Stream as u32, 0) as usize;
    let u_addr = SockAddrUn::from_pathname("/tmp/test_domain.sock");
    if net.sys_bind_unix(u_srv, u_addr) == 0 && net.sys_listen(u_srv, 8) == 0 {
        let u_cli = net.sys_socket(AddressFamily::Unix as u16, SocketType::Stream as u32, 0) as usize;
        if net.sys_connect_unix(u_cli, u_addr) == 0 {
            let u_acc = net.sys_accept4(u_srv, 0) as usize;
            let cred = Ucred { pid: 200, uid: 1000, gid: 1000 };
            if net.sys_sendmsg_unix(u_cli, b"FD_PASS", &[4, 5], Some(cred)) == 7 {
                let mut rbuf = [0u8; 16];
                if let Ok((rn, anc)) = net.sys_recvmsg_unix(u_acc, &mut rbuf) {
                    if rn == 7 && &rbuf[..7] == b"FD_PASS" {
                        if let Some(a) = anc {
                            if a.fds == [4, 5] && a.cred == Some(cred) {
                                passed += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // 8. Test SCM_MAX_FD (> 253) boundary rejection with EMSGSIZE
    let u_pair = net.sys_socketpair(AddressFamily::Unix as u16, SocketType::Stream as u32);
    if let Ok((sp0, _sp1)) = u_pair {
        let too_many_fds = alloc::vec![10usize; 254];
        if net.sys_sendmsg_unix(sp0, b"OVERFLOW", &too_many_fds, None) == EMSGSIZE {
            passed += 1;
        }
    }

    // 9. Test SCM_CREDENTIALS anti-spoofing: non-root cannot spoof pid/uid/gid
    let non_root_cli = net.sys_socket_with_cred(
        AddressFamily::Unix as u16,
        SocketType::Stream as u32,
        0,
        Ucred { pid: 500, uid: 1000, gid: 1000 },
    ) as usize;
    let non_root_srv = net.sys_socket(AddressFamily::Unix as u16, SocketType::Stream as u32, 0) as usize;
    let abs_addr = SockAddrUn::from_abstract(b"sec_test");
    if net.sys_bind_unix(non_root_srv, abs_addr) == 0 && net.sys_listen(non_root_srv, 2) == 0 {
        if net.sys_connect_unix(non_root_cli, abs_addr) == 0 {
            // Attempt to spoof root UID (0) from non-root socket (uid 1000)
            let spoofed = Ucred { pid: 1, uid: 0, gid: 0 };
            if net.sys_sendmsg_unix(non_root_cli, b"SPOOF", &[], Some(spoofed)) == EPERM {
                passed += 1;
            }
        }
    }

    passed
}
