//! POSIX / BSD Socket Descriptor Table, Ring Buffers & System Call Primitives (`socket`, `bind`, `listen`, `connect`, `accept`, `send`, `recv`, `close`).

use crate::ipv4_routing::Ipv4Addr;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Socket file descriptor identifier.
pub type SocketFd = u32;

/// POSIX Socket Address Family / Domain (`AF_INET`, `AF_INET6`, `AF_UNIX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketDomain {
    /// IPv4 Internet protocols (`AF_INET = 2`).
    Inet,
    /// IPv6 Internet protocols (`AF_INET6 = 10`).
    Inet6,
    /// Local inter-process communication (`AF_UNIX = 1`).
    Unix,
}

/// POSIX Socket Type (`SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_RAW`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketKind {
    /// Sequenced, reliable, two-way connection-based byte streams (`SOCK_STREAM = 1`).
    Stream,
    /// Connectionless, unreliable datagrams (`SOCK_DGRAM = 2`).
    Datagram,
    /// Raw network protocol access (`SOCK_RAW = 3`).
    Raw,
}

/// Lifecycle state of a BSD socket descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connecting,
    Connected,
    Closed,
}

/// IPv4 Socket Endpoint (`sockaddr_in`: IPv4 address + 16-bit TCP/UDP port).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SocketAddrV4 {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl SocketAddrV4 {
    #[inline]
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// POSIX-style errno codes returned by BSD socket operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketError {
    /// `EBADF`: Bad socket descriptor.
    BadDescriptor,
    /// `EADDRINUSE`: Local address/port is already bound.
    AddressInUse,
    /// `EINVAL`: Invalid state or argument for this socket operation.
    InvalidOperation,
    /// `ENOTCONN`: Socket is not connected.
    NotConnected,
    /// `ECONNREFUSED`: No listening socket at remote endpoint or backlog full.
    ConnectionRefused,
    /// `EAGAIN` / `EWOULDBLOCK`: Non-blocking operation would block (no data or pending connections).
    WouldBlock,
    /// `ENOBUFS`: Socket send/receive ring buffer is full.
    BufferFull,
}

/// Bounded FIFO byte ring buffer backing a socket's send (`SO_SNDBUF`) or receive (`SO_RCVBUF`) queue.
#[derive(Clone, Debug)]
pub struct SocketBuffer {
    buf: VecDeque<u8>,
    capacity: usize,
}

impl SocketBuffer {
    /// Creates a new `SocketBuffer` with the specified maximum byte capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(capacity.min(4096)),
            capacity,
        }
    }

    /// Number of unread bytes currently buffered.
    #[inline]
    pub fn readable_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Remaining free space in bytes.
    #[inline]
    pub fn writable_bytes(&self) -> usize {
        self.capacity.saturating_sub(self.buf.len())
    }

    /// Writes up to `writable_bytes()` from `src`, returning the byte count written.
    pub fn write(&mut self, src: &[u8]) -> Result<usize, SocketError> {
        let avail = self.writable_bytes();
        if avail == 0 && !src.is_empty() {
            return Err(SocketError::BufferFull);
        }
        let n = src.len().min(avail);
        self.buf.extend(&src[..n]);
        Ok(n)
    }

    /// Reads and drains up to ` dst.len()` bytes into `dst`, returning the byte count read.
    pub fn read(&mut self, dst: &mut [u8]) -> Result<usize, SocketError> {
        if self.buf.is_empty() {
            return Err(SocketError::WouldBlock);
        }
        let n = dst.len().min(self.buf.len());
        for slot in dst.iter_mut().take(n) {
            *slot = self.buf.pop_front().unwrap_or(0);
        }
        Ok(n)
    }
}

/// Kernel representation of an open BSD socket entry.
#[derive(Clone, Debug)]
pub struct SocketEntry {
    pub fd: SocketFd,
    pub domain: SocketDomain,
    pub kind: SocketKind,
    pub state: SocketState,
    pub local_addr: Option<SocketAddrV4>,
    pub remote_addr: Option<SocketAddrV4>,
    pub backlog_limit: usize,
    pub accept_queue: VecDeque<SocketFd>,
    pub peer_fd: Option<SocketFd>,
    pub rx_buf: SocketBuffer,
    pub tx_buf: SocketBuffer,
}

/// Kernel-wide BSD Socket Handle Table supporting full POSIX lifecycle operations.
#[derive(Clone, Debug, Default)]
pub struct SocketHandleTable {
    next_fd: SocketFd,
    next_ephemeral_port: u16,
    sockets: Vec<SocketEntry>,
}

impl SocketHandleTable {
    /// Default per-socket buffer capacity (64 KiB).
    pub const DEFAULT_BUF_CAP: usize = 65_536;

    /// Creates an empty `SocketHandleTable` (allocating descriptors starting at `fd = 3`).
    pub const fn new() -> Self {
        Self {
            next_fd: 3,
            next_ephemeral_port: 49_152,
            sockets: Vec::new(),
        }
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if self.next_ephemeral_port == 65_535 {
            49_152
        } else {
            self.next_ephemeral_port + 1
        };
        port
    }

    fn get_index(&self, fd: SocketFd) -> Result<usize, SocketError> {
        self.sockets
            .iter()
            .position(|s| s.fd == fd && s.state != SocketState::Closed)
            .ok_or(SocketError::BadDescriptor)
    }

    /// Returns a slice of all active sockets in the table.
    #[inline]
    pub fn sockets(&self) -> &[SocketEntry] {
        &self.sockets
    }

    /// `socket(domain, type)` — Allocates a new unbound socket descriptor.
    pub fn socket(&mut self, domain: SocketDomain, kind: SocketKind) -> SocketFd {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.sockets.push(SocketEntry {
            fd,
            domain,
            kind,
            state: SocketState::Unbound,
            local_addr: None,
            remote_addr: None,
            backlog_limit: 0,
            accept_queue: VecDeque::new(),
            peer_fd: None,
            rx_buf: SocketBuffer::with_capacity(Self::DEFAULT_BUF_CAP),
            tx_buf: SocketBuffer::with_capacity(Self::DEFAULT_BUF_CAP),
        });
        fd
    }

    /// `bind(fd, addr)` — Binds a local `SocketAddrV4` to `fd`.
    pub fn bind(&mut self, fd: SocketFd, mut addr: SocketAddrV4) -> Result<(), SocketError> {
        if addr.port == 0 {
            addr.port = self.alloc_ephemeral_port();
        }
        let conflict = self.sockets.iter().any(|s| {
            s.fd != fd
                && s.state != SocketState::Closed
                && s.kind == self.sockets.iter().find(|x| x.fd == fd).map(|x| x.kind).unwrap_or(SocketKind::Stream)
                && s.local_addr.map(|a| a.port == addr.port && (a.ip == addr.ip || a.ip == Ipv4Addr::UNSPECIFIED || addr.ip == Ipv4Addr::UNSPECIFIED)).unwrap_or(false)
        });
        if conflict {
            return Err(SocketError::AddressInUse);
        }

        let idx = self.get_index(fd)?;
        if self.sockets[idx].state != SocketState::Unbound {
            return Err(SocketError::InvalidOperation);
        }
        self.sockets[idx].local_addr = Some(addr);
        self.sockets[idx].state = SocketState::Bound;
        Ok(())
    }

    /// `listen(fd, backlog)` — Marks a bound `SOCK_STREAM` socket as passive listening.
    pub fn listen(&mut self, fd: SocketFd, backlog: usize) -> Result<(), SocketError> {
        let idx = self.get_index(fd)?;
        if self.sockets[idx].kind != SocketKind::Stream
            || self.sockets[idx].state != SocketState::Bound
        {
            return Err(SocketError::InvalidOperation);
        }
        self.sockets[idx].backlog_limit = backlog.max(1);
        self.sockets[idx].state = SocketState::Listening;
        Ok(())
    }

    /// `connect(fd, remote)` — Connects `fd` to `remote`. If `remote` matches a local listening
    /// stream socket, spawns a connected server child descriptor and queues it in `accept_queue`.
    pub fn connect(&mut self, fd: SocketFd, remote: SocketAddrV4) -> Result<(), SocketError> {
        let idx = self.get_index(fd)?;
        let kind = self.sockets[idx].kind;
        let domain = self.sockets[idx].domain;

        if self.sockets[idx].local_addr.is_none() {
            let eph = self.alloc_ephemeral_port();
            let idx = self.get_index(fd)?;
            self.sockets[idx].local_addr = Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, eph));
        }
        let cli_local = self.sockets[self.get_index(fd)?].local_addr.unwrap();

        if kind == SocketKind::Datagram {
            let idx = self.get_index(fd)?;
            self.sockets[idx].remote_addr = Some(remote);
            self.sockets[idx].state = SocketState::Connected;
            return Ok(());
        }

        // Locate a matching listening SOCK_STREAM socket.
        let listener_pos = self.sockets.iter().position(|s| {
            s.state == SocketState::Listening
                && s.kind == SocketKind::Stream
                && s.local_addr
                    .map(|la| {
                        la.port == remote.port
                            && (la.ip == remote.ip || la.ip == Ipv4Addr::UNSPECIFIED)
                    })
                    .unwrap_or(false)
        });

        let Some(l_idx) = listener_pos else {
            return Err(SocketError::ConnectionRefused);
        };
        if self.sockets[l_idx].accept_queue.len() >= self.sockets[l_idx].backlog_limit {
            return Err(SocketError::ConnectionRefused);
        }

        // Allocate the accepted server-side peer socket.
        let srv_fd = self.next_fd;
        self.next_fd += 1;
        self.sockets.push(SocketEntry {
            fd: srv_fd,
            domain,
            kind: SocketKind::Stream,
            state: SocketState::Connected,
            local_addr: Some(remote),
            remote_addr: Some(cli_local),
            backlog_limit: 0,
            accept_queue: VecDeque::new(),
            peer_fd: Some(fd),
            rx_buf: SocketBuffer::with_capacity(Self::DEFAULT_BUF_CAP),
            tx_buf: SocketBuffer::with_capacity(Self::DEFAULT_BUF_CAP),
        });

        let l_idx = self
            .sockets
            .iter()
            .position(|s| s.state == SocketState::Listening && s.local_addr.map(|la| la.port == remote.port).unwrap_or(false))
            .unwrap();
        self.sockets[l_idx].accept_queue.push_back(srv_fd);

        let c_idx = self.get_index(fd)?;
        self.sockets[c_idx].remote_addr = Some(remote);
        self.sockets[c_idx].peer_fd = Some(srv_fd);
        self.sockets[c_idx].state = SocketState::Connected;
        Ok(())
    }

    /// `accept(listen_fd)` — Dequeues the next established connection from `listen_fd`'s accept queue.
    pub fn accept(&mut self, listen_fd: SocketFd) -> Result<(SocketFd, SocketAddrV4), SocketError> {
        let idx = self.get_index(listen_fd)?;
        if self.sockets[idx].state != SocketState::Listening {
            return Err(SocketError::InvalidOperation);
        }
        let Some(accepted_fd) = self.sockets[idx].accept_queue.pop_front() else {
            return Err(SocketError::WouldBlock);
        };
        let a_idx = self.get_index(accepted_fd)?;
        let peer_addr = self.sockets[a_idx]
            .remote_addr
            .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        Ok((accepted_fd, peer_addr))
    }

    /// `send(fd, data)` — Writes `data` into the connected socket's transmit buffer (and delivers
    /// into the local peer's receive buffer when locally connected).
    pub fn send(&mut self, fd: SocketFd, data: &[u8]) -> Result<usize, SocketError> {
        let idx = self.get_index(fd)?;
        if self.sockets[idx].state != SocketState::Connected {
            return Err(SocketError::NotConnected);
        }
        let peer_fd = self.sockets[idx].peer_fd;
        let written = self.sockets[idx].tx_buf.write(data)?;

        if let Some(pfd) = peer_fd {
            if let Ok(p_idx) = self.get_index(pfd) {
                let mut temp = alloc::vec![0u8; written];
                let idx = self.get_index(fd)?;
                let _ = self.sockets[idx].tx_buf.read(&mut temp);
                let _ = self.sockets[p_idx].rx_buf.write(&temp);
            }
        }
        Ok(written)
    }

    /// `recv(fd, buf)` — Reads available bytes from `fd`'s receive buffer into `buf`.
    pub fn recv(&mut self, fd: SocketFd, out: &mut [u8]) -> Result<usize, SocketError> {
        let idx = self.get_index(fd)?;
        if self.sockets[idx].state != SocketState::Connected
            && self.sockets[idx].kind == SocketKind::Stream
        {
            return Err(SocketError::NotConnected);
        }
        self.sockets[idx].rx_buf.read(out)
    }

    /// `close(fd)` — Marks the socket descriptor as `Closed` and releases its bound address.
    pub fn close(&mut self, fd: SocketFd) -> Result<(), SocketError> {
        let idx = self.get_index(fd)?;
        self.sockets[idx].state = SocketState::Closed;
        self.sockets[idx].local_addr = None;
        self.sockets[idx].peer_fd = None;
        Ok(())
    }
}

/// Runs self-tests for the `bsd_sockets` module.
pub fn verify_net_bsd_sockets() -> u32 {
    let mut passed = 0u32;
    let mut table = SocketHandleTable::new();

    // 1. Create listening server socket and bind to 127.0.0.1:8080.
    let srv_listen = table.socket(SocketDomain::Inet, SocketKind::Stream);
    let srv_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
    if table.bind(srv_listen, srv_addr).is_ok() && table.listen(srv_listen, 16).is_ok() {
        passed += 1;
    }

    // 2. Connect client socket and accept on server.
    let cli_fd = table.socket(SocketDomain::Inet, SocketKind::Stream);
    if table.connect(cli_fd, srv_addr).is_ok() {
        if let Ok((accepted_fd, cli_peer)) = table.accept(srv_listen) {
            if cli_peer.port >= 49_152 {
                passed += 1;
            }

            // 3. Bi-directional send() and recv() across the socket pair.
            let msg = b"PING cornet socket\n";
            if table.send(cli_fd, msg) == Ok(msg.len()) {
                let mut rx = [0u8; 32];
                if let Ok(n) = table.recv(accepted_fd, &mut rx) {
                    if &rx[..n] == msg {
                        passed += 1;
                    }
                }
            }
            let _ = table.close(accepted_fd);
        }
    }

    // 4. Verify close() invalidates subsequent operations on the descriptor.
    if table.close(cli_fd).is_ok()
        && table. close(srv_listen).is_ok()
        && table.send(cli_fd, b"x") == Err(SocketError::BadDescriptor)
    {
        passed += 1;
    }

    passed
}
