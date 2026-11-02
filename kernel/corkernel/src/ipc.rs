//! CorOS Linux IPC (Inter-Process Communication) Subsystem
//!
//! Implements POSIX-compatible unidirectional byte pipes, ring buffers,
//! Unix domain sockets (AF_UNIX), and message passing primitives.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::SpinLock;

pub const PIPE_BUFFER_SIZE: usize = 4096;

/// Status of pipe endpoints
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PipeStatus {
    Open,
    ReadClosed,
    WriteClosed,
    Closed,
}

/// Circular byte buffer for POSIX pipes
pub struct PipeBuffer {
    data: [u8; PIPE_BUFFER_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
    status: PipeStatus,
}

impl PipeBuffer {
    pub const fn new() -> Self {
        Self {
            data: [0; PIPE_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            status: PipeStatus::Open,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, &'static str> {
        if self.status == PipeStatus::ReadClosed || self.status == PipeStatus::Closed {
            return Err("EPIPE: Broken pipe");
        }

        let mut written = 0;
        for &byte in buf {
            if self.count >= PIPE_BUFFER_SIZE {
                break; // Buffer full (in preemptive multitasking would block)
            }
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % PIPE_BUFFER_SIZE;
            self.count += 1;
            written += 1;
        }

        Ok(written)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut read_bytes = 0;
        for byte in buf.iter_mut() {
            if self.count == 0 {
                break; // Buffer empty (or EOF if write end closed)
            }
            *byte = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUFFER_SIZE;
            self.count -= 1;
            read_bytes += 1;
        }
        read_bytes
    }

    pub fn available_read(&self) -> usize {
        self.count
    }

    pub fn available_write(&self) -> usize {
        PIPE_BUFFER_SIZE - self.count
    }

    pub fn close_read(&mut self) {
        if self.status == PipeStatus::WriteClosed {
            self.status = PipeStatus::Closed;
        } else {
            self.status = PipeStatus::ReadClosed;
        }
    }

    pub fn close_write(&mut self) {
        if self.status == PipeStatus::ReadClosed {
            self.status = PipeStatus::Closed;
        } else {
            self.status = PipeStatus::WriteClosed;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.status == PipeStatus::Closed
    }
}

/// Linux POSIX Pipe Channel
pub struct PipeChannel {
    pub id: usize,
    pub name: String,
    pub buffer: Arc<SpinLock<PipeBuffer>>,
    pub reader_pid: usize,
    pub writer_pid: usize,
}

/// Unix Domain Socket (AF_UNIX) stream
pub struct UnixSocket {
    pub id: usize,
    pub path: String,
    pub client_to_server: Arc<SpinLock<PipeBuffer>>,
    pub server_to_client: Arc<SpinLock<PipeBuffer>>,
    pub connected: bool,
}

pub struct IpcManager {
    pipes: BTreeMap<usize, PipeChannel>,
    sockets: BTreeMap<usize, UnixSocket>,
    next_id: usize,
}

impl IpcManager {
    pub const fn new() -> Self {
        Self {
            pipes: BTreeMap::new(),
            sockets: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Create POSIX anonymous pipe [read_fd, write_fd]
    pub fn create_pipe(&mut self, reader_pid: usize, writer_pid: usize) -> (usize, usize) {
        let id = self.next_id;
        self.next_id += 1;

        let channel = PipeChannel {
            id,
            name: format!("pipe:[{}]", id),
            buffer: Arc::new(SpinLock::new(PipeBuffer::new())),
            reader_pid,
            writer_pid,
        };

        self.pipes.insert(id, channel);
        (id * 2, id * 2 + 1) // read_fd, write_fd
    }

    /// Create Unix Domain Socket bound to path (e.g. /var/run/coros.sock)
    pub fn bind_unix_socket(&mut self, path: &str) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let sock = UnixSocket {
            id,
            path: String::from(path),
            client_to_server: Arc::new(SpinLock::new(PipeBuffer::new())),
            server_to_client: Arc::new(SpinLock::new(PipeBuffer::new())),
            connected: false,
        };

        self.sockets.insert(id, sock);
        id
    }

    /// Write data to pipe by pipe ID
    pub fn pipe_write(&self, pipe_id: usize, data: &[u8]) -> Result<usize, &'static str> {
        if let Some(pipe) = self.pipes.get(&pipe_id) {
            pipe.buffer.lock().write(data)
        } else {
            Err("EBADF: Invalid pipe descriptor")
        }
    }

    /// Read data from pipe by pipe ID
    pub fn pipe_read(&self, pipe_id: usize, buf: &mut [u8]) -> usize {
        if let Some(pipe) = self.pipes.get(&pipe_id) {
            pipe.buffer.lock().read(buf)
        } else {
            0
        }
    }

    /// Generate Linux /proc/ipc/summary output
    pub fn proc_summary(&self) -> String {
        let mut out = String::new();
        out.push_str("=== CorOS POSIX Inter-Process Communication (IPC) ===\n");
        out.push_str(&format!("Active Pipes   : {}\n", self.pipes.len()));
        out.push_str(&format!("Active Sockets : {}\n", self.sockets.len()));
        out.push_str("ID   TYPE       STATE      BUF_USED  NAME\n");
        out.push_str("---------------------------------------------------\n");

        for (id, pipe) in &self.pipes {
            let buf = pipe.buffer.lock();
            out.push_str(&format!(
                "{:<4} PIPE       OPEN       {:<9} {}\n",
                id,
                format!("{}/{}", buf.available_read(), PIPE_BUFFER_SIZE),
                pipe.name
            ));
        }

        for (id, sock) in &self.sockets {
            let state = if sock.connected { "CONNECTED" } else { "LISTENING" };
            out.push_str(&format!(
                "{:<4} AF_UNIX    {:<10} 0/{}     {}\n",
                id,
                state,
                PIPE_BUFFER_SIZE,
                sock.path
            ));
        }

        out
    }
}

pub static IPC_MANAGER: SpinLock<IpcManager> = SpinLock::new(IpcManager::new());
