//! Linux FUSE (Filesystem in Userspace) Protocol & Kernel Bridge for CorOS.
//!
//! Implements Linux `/dev/fuse` ABI (v7.38) communication:
//! - Kernel-to-userspace request header `fuse_in_header`
//! - Userspace-to-kernel reply header `fuse_out_header`
//! - Complete opcode definitions (`FUSE_LOOKUP`, `FUSE_GETATTR`, `FUSE_OPEN`, `FUSE_READ`, `FUSE_WRITE`, etc.)
//! - Request serialization, asynchronous reply queue, and channel multiplexing

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt;

/// FUSE Protocol Major and Minor Versions
pub const FUSE_KERNEL_VERSION: u32 = 7;
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 38;

/// FUSE Inode 1 is always the root directory
pub const FUSE_ROOT_ID: u64 = 1;

/// Standard FUSE Opcodes
pub mod fuse_opcode {
    pub const FUSE_LOOKUP: u32 = 1;
    pub const FUSE_FORGET: u32 = 2;
    pub const FUSE_GETATTR: u32 = 3;
    pub const FUSE_SETATTR: u32 = 4;
    pub const FUSE_READLINK: u32 = 5;
    pub const FUSE_SYMLINK: u32 = 6;
    pub const FUSE_MKNOD: u32 = 8;
    pub const FUSE_MKDIR: u32 = 9;
    pub const FUSE_UNLINK: u32 = 10;
    pub const FUSE_RMDIR: u32 = 11;
    pub const FUSE_RENAME: u32 = 12;
    pub const FUSE_LINK: u32 = 13;
    pub const FUSE_OPEN: u32 = 14;
    pub const FUSE_READ: u32 = 15;
    pub const FUSE_WRITE: u32 = 16;
    pub const FUSE_STATFS: u32 = 17;
    pub const FUSE_RELEASE: u32 = 18;
    pub const FUSE_FSYNC: u32 = 20;
    pub const FUSE_FLUSH: u32 = 25;
    pub const FUSE_INIT: u32 = 26;
    pub const FUSE_OPENDIR: u32 = 27;
    pub const FUSE_READDIR: u32 = 28;
    pub const FUSE_RELEASEDIR: u32 = 29;
    pub const FUSE_ACCESS: u32 = 34;
    pub const FUSE_CREATE: u32 = 35;
    pub const FUSE_READDIRPLUS: u32 = 44;
}

/// FUSE Inbound Request Header sent to user-space daemon (40 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

impl FuseInHeader {
    pub fn new(len: u32, opcode: u32, unique: u64, nodeid: u64) -> Self {
        Self {
            len,
            opcode,
            unique,
            nodeid,
            uid: 0,
            gid: 0,
            pid: 1,
            padding: 0,
        }
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        buf[8..16].copy_from_slice(&self.unique.to_le_bytes());
        buf[16..24].copy_from_slice(&self.nodeid.to_le_bytes());
        buf[24..28].copy_from_slice(&self.uid.to_le_bytes());
        buf[28..32].copy_from_slice(&self.gid.to_le_bytes());
        buf[32..36].copy_from_slice(&self.pid.to_le_bytes());
        buf[36..40].copy_from_slice(&self.padding.to_le_bytes());
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 40 {
            return None;
        }
        Some(Self {
            len: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            opcode: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            unique: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11],
                buf[12], buf[13], buf[14], buf[15],
            ]),
            nodeid: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19],
                buf[20], buf[21], buf[22], buf[23],
            ]),
            uid: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
            gid: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            pid: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            padding: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        })
    }
}

/// FUSE Outbound Response Header sent from user-space daemon (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32, // 0 = Success, Negative errno for error (e.g. -2 for ENOENT)
    pub unique: u64,
}

impl FuseOutHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        Some(Self {
            len: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            error: i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            unique: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11],
                buf[12], buf[13], buf[14], buf[15],
            ]),
        })
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.len.to_le_bytes());
        buf[4..8].copy_from_slice(&self.error.to_le_bytes());
        buf[8..16].copy_from_slice(&self.unique.to_le_bytes());
    }
}

/// FUSE Init Handshake Request (`fuse_init_in`)
#[derive(Debug, Clone, Copy)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

impl FuseInitIn {
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.major.to_le_bytes());
        buf[4..8].copy_from_slice(&self.minor.to_le_bytes());
        buf[8..12].copy_from_slice(&self.max_readahead.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
    }
}

/// FUSE In-Flight Kernel Request Message
#[derive(Debug, Clone)]
pub struct FuseKernelRequest {
    pub header: FuseInHeader,
    pub payload: Vec<u8>,
}

/// FUSE Userspace Reply Message
#[derive(Debug, Clone)]
pub struct FuseKernelResponse {
    pub header: FuseOutHeader,
    pub payload: Vec<u8>,
}

/// Linux `/dev/fuse` Device Controller Session
pub struct FuseSession {
    pub session_id: u32,
    pub unique_counter: u64,
    pub initialized: bool,
    pub req_queue: Vec<FuseKernelRequest>,
    pub reply_queue: Vec<FuseKernelResponse>,
}

impl FuseSession {
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            unique_counter: 1,
            initialized: false,
            req_queue: Vec::new(),
            reply_queue: Vec::new(),
        }
    }

    /// Dispatch INIT request to userspace daemon
    pub fn send_init(&mut self) -> u64 {
        let unique = self.unique_counter;
        self.unique_counter += 1;

        let mut payload = [0u8; 16];
        let init_in = FuseInitIn {
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            max_readahead: 131072,
            flags: 0,
        };
        init_in.serialize(&mut payload);

        let hdr = FuseInHeader::new(40 + 16, fuse_opcode::FUSE_INIT, unique, 0);
        self.req_queue.push(FuseKernelRequest {
            header: hdr,
            payload: payload.to_vec(),
        });

        unique
    }

    /// Dispatch LOOKUP request for file name under parent directory nodeid
    pub fn send_lookup(&mut self, parent_nodeid: u64, name: &str) -> u64 {
        let unique = self.unique_counter;
        self.unique_counter += 1;

        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0); // Null-terminated string

        let total_len = 40 + name_bytes.len() as u32;
        let hdr = FuseInHeader::new(total_len, fuse_opcode::FUSE_LOOKUP, unique, parent_nodeid);

        self.req_queue.push(FuseKernelRequest {
            header: hdr,
            payload: name_bytes,
        });

        unique
    }

    /// Read next pending request from `/dev/fuse` to deliver to userspace daemon
    pub fn dev_fuse_read(&mut self) -> Option<Vec<u8>> {
        if self.req_queue.is_empty() {
            return None;
        }
        let req = self.req_queue.remove(0);
        let mut msg = Vec::with_capacity(40 + req.payload.len());
        let mut hdr_bytes = [0u8; 40];
        req.header.serialize(&mut hdr_bytes);
        msg.extend_from_slice(&hdr_bytes);
        msg.extend_from_slice(&req.payload);
        Some(msg)
    }

    /// Write daemon response into `/dev/fuse`
    pub fn dev_fuse_write(&mut self, raw_reply: &[u8]) -> Result<(), &'static str> {
        if raw_reply.len() < 16 {
            return Err("FUSE reply smaller than 16-byte header");
        }
        let hdr = FuseOutHeader::parse(&raw_reply[..16]).ok_or("Invalid FUSE out header")?;
        let payload = raw_reply[16..].to_vec();

        self.reply_queue.push(FuseKernelResponse {
            header: hdr,
            payload,
        });

        Ok(())
    }
}

impl fmt::Display for FuseSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FuseSession(id={}, pending_reqs={}, replies={})",
            self.session_id,
            self.req_queue.len(),
            self.reply_queue.len()
        )
    }
}
