//! NFS (Network File System v3, RFC 1813) & ONC RPC Client for CorOS.
//!
//! Implements bare-metal Sun RPC / XDR data serialization and NFSv3 remote operations:
//! - RFC 1831 Open Network Computing (ONC) Remote Procedure Call framing
//! - RFC 1014 External Data Representation (XDR) 4-byte aligned encoders/decoders
//! - NFSv3 Procedure calls: `LOOKUP`, `GETATTR`, `READ`, `WRITE`, `CREATE`, `REMOVE`
//! - `nfs_fh3` opaque file handle management and `fattr3` remote file metadata parsing

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;

/// ONC RPC Program Numbers
pub const RPC_PROG_NFS: u32 = 100003;
pub const RPC_PROG_MOUNT: u32 = 100005;

/// NFS Version 3
pub const NFS_V3: u32 = 3;

/// RPC Message Types
pub const RPC_CALL: u32 = 0;
pub const RPC_REPLY: u32 = 1;

/// RPC Authentication Flavors
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;

/// NFSv3 Procedure Numbers (RFC 1813 Section 3.3)
pub mod nfs_proc {
    pub const NULL: u32 = 0;
    pub const GETATTR: u32 = 1;
    pub const SETATTR: u32 = 2;
    pub const LOOKUP: u32 = 3;
    pub const ACCESS: u32 = 4;
    pub const READ: u32 = 6;
    pub const WRITE: u32 = 7;
    pub const CREATE: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const REMOVE: u32 = 12;
    pub const RMDIR: u32 = 13;
    pub const RENAME: u32 = 14;
    pub const READDIR: u32 = 16;
    pub const READDIRPLUS: u32 = 17;
    pub const FSSTAT: u32 = 18;
}

/// NFSv3 File Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsFileType {
    Regular,
    Directory,
    BlockDevice,
    CharDevice,
    Symlink,
    Socket,
    Fifo,
    Unknown,
}

/// NFSv3 File Attributes (`fattr3`)
#[derive(Debug, Clone, Copy)]
pub struct NfsFattr3 {
    pub file_type: NfsFileType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub fileid: u64,
    pub atime_sec: u32,
    pub mtime_sec: u32,
    pub ctime_sec: u32,
}

impl NfsFattr3 {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 84 {
            return None;
        }
        let ftype_raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let file_type = match ftype_raw {
            1 => NfsFileType::Regular,
            2 => NfsFileType::Directory,
            3 => NfsFileType::BlockDevice,
            4 => NfsFileType::CharDevice,
            5 => NfsFileType::Symlink,
            6 => NfsFileType::Socket,
            7 => NfsFileType::Fifo,
            _ => NfsFileType::Unknown,
        };

        let mode = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let nlink = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let uid = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let gid = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let size = u64::from_be_bytes([
            buf[20], buf[21], buf[22], buf[23],
            buf[24], buf[25], buf[26], buf[27],
        ]);
        let used = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31],
            buf[32], buf[33], buf[34], buf[35],
        ]);
        let fileid = u64::from_be_bytes([
            buf[44], buf[45], buf[46], buf[47],
            buf[48], buf[49], buf[50], buf[51],
        ]);
        let atime_sec = u32::from_be_bytes([buf[52], buf[53], buf[54], buf[55]]);
        let mtime_sec = u32::from_be_bytes([buf[60], buf[61], buf[62], buf[63]]);
        let ctime_sec = u32::from_be_bytes([buf[68], buf[69], buf[70], buf[71]]);

        Some(Self {
            file_type,
            mode,
            nlink,
            uid,
            gid,
            size,
            used,
            fileid,
            atime_sec,
            mtime_sec,
            ctime_sec,
        })
    }
}

/// Opaque NFSv3 File Handle (`nfs_fh3`, up to 64 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfsFileHandle {
    pub data: Vec<u8>,
}

impl NfsFileHandle {
    pub fn new(bytes: &[u8]) -> Self {
        Self { data: bytes.to_vec() }
    }

    pub fn serialize_xdr(&self, out: &mut Vec<u8>) {
        let len = self.data.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.data);
        // XDR requires padding to 4-byte alignment
        let pad = (4 - (self.data.len() % 4)) % 4;
        for _ in 0..pad {
            out.push(0);
        }
    }

    pub fn parse_xdr(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let pad = (4 - (len % 4)) % 4;
        let total = 4 + len + pad;
        if buf.len() < total {
            return None;
        }
        let data = buf[4..4 + len].to_vec();
        Some((Self { data }, total))
    }
}

/// XDR Stream Encoder Helper
pub struct XdrEncoder;

impl XdrEncoder {
    pub fn encode_u32(val: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&val.to_be_bytes());
    }

    pub fn encode_u64(val: u64, out: &mut Vec<u8>) {
        out.extend_from_slice(&val.to_be_bytes());
    }

    pub fn encode_string(s: &str, out: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        let len = bytes.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        let pad = (4 - (bytes.len() % 4)) % 4;
        for _ in 0..pad {
            out.push(0);
        }
    }

    pub fn encode_opaque(bytes: &[u8], out: &mut Vec<u8>) {
        let len = bytes.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        let pad = (4 - (bytes.len() % 4)) % 4;
        for _ in 0..pad {
            out.push(0);
        }
    }
}

/// NFSv3 Client RPC Protocol Dispatcher
pub struct NfsClient {
    pub server_ip: [u8; 4],
    pub server_port: u16,
    pub xid_counter: u32,
    pub root_handle: Option<NfsFileHandle>,
}

impl NfsClient {
    pub fn new(server_ip: [u8; 4], server_port: u16) -> Self {
        Self {
            server_ip,
            server_port,
            xid_counter: 1000,
            root_handle: None,
        }
    }

    /// Build standard ONC RPC Header (RFC 1831)
    fn build_rpc_header(&mut self, proc_id: u32) -> (u32, Vec<u8>) {
        let xid = self.xid_counter;
        self.xid_counter += 1;

        let mut rpc = Vec::with_capacity(64);
        XdrEncoder::encode_u32(xid, &mut rpc);
        XdrEncoder::encode_u32(RPC_CALL, &mut rpc);
        XdrEncoder::encode_u32(2, &mut rpc); // RPC Version 2
        XdrEncoder::encode_u32(RPC_PROG_NFS, &mut rpc);
        XdrEncoder::encode_u32(NFS_V3, &mut rpc);
        XdrEncoder::encode_u32(proc_id, &mut rpc);

        // Auth Flavor: AUTH_NONE (0, 0)
        XdrEncoder::encode_u32(AUTH_NONE, &mut rpc);
        XdrEncoder::encode_u32(0, &mut rpc);
        // Verifier: AUTH_NONE (0, 0)
        XdrEncoder::encode_u32(AUTH_NONE, &mut rpc);
        XdrEncoder::encode_u32(0, &mut rpc);

        (xid, rpc)
    }

    /// Build NFSv3 LOOKUP request packet for child name under dir_fh
    pub fn build_lookup_request(&mut self, dir_fh: &NfsFileHandle, name: &str) -> (u32, Vec<u8>) {
        let (xid, mut packet) = self.build_rpc_header(nfs_proc::LOOKUP);
        dir_fh.serialize_xdr(&mut packet);
        XdrEncoder::encode_string(name, &mut packet);
        (xid, packet)
    }

    /// Build NFSv3 READ request packet
    pub fn build_read_request(&mut self, file_fh: &NfsFileHandle, offset: u64, count: u32) -> (u32, Vec<u8>) {
        let (xid, mut packet) = self.build_rpc_header(nfs_proc::READ);
        file_fh.serialize_xdr(&mut packet);
        XdrEncoder::encode_u64(offset, &mut packet);
        XdrEncoder::encode_u32(count, &mut packet);
        (xid, packet)
    }

    /// Build NFSv3 WRITE request packet (UNSTABLE = 0, DATA_SYNC = 1, FILE_SYNC = 2)
    pub fn build_write_request(&mut self, file_fh: &NfsFileHandle, offset: u64, data: &[u8]) -> (u32, Vec<u8>) {
        let (xid, mut packet) = self.build_rpc_header(nfs_proc::WRITE);
        file_fh.serialize_xdr(&mut packet);
        XdrEncoder::encode_u64(offset, &mut packet);
        XdrEncoder::encode_u32(data.len() as u32, &mut packet);
        XdrEncoder::encode_u32(2, &mut packet); // FILE_SYNC
        XdrEncoder::encode_opaque(data, &mut packet);
        (xid, packet)
    }

    /// Parse RPC Reply Header and return offset of NFS payload
    pub fn parse_rpc_reply(buf: &[u8], expected_xid: u32) -> Result<usize, &'static str> {
        if buf.len() < 24 {
            return Err("RPC packet smaller than 24 bytes");
        }
        let xid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if xid != expected_xid {
            return Err("RPC XID mismatch");
        }
        let msg_type = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if msg_type != RPC_REPLY {
            return Err("Expected RPC REPLY message");
        }
        let reply_stat = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if reply_stat != 0 {
            return Err("RPC MSG_DENIED by server");
        }
        // Skip verifier flavor & length
        let verf_len = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]) as usize;
        let pad = (4 - (verf_len % 4)) % 4;
        let offset = 20 + verf_len + pad;
        if buf.len() < offset + 4 {
            return Err("Truncated RPC accept status");
        }
        let accept_stat = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        if accept_stat != 0 {
            return Err("RPC Procedure execution failed on server");
        }
        Ok(offset + 4)
    }
}

impl fmt::Display for NfsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NfsClient(server={}.{}.{}.{}:{}, xid={})",
            self.server_ip[0], self.server_ip[1], self.server_ip[2], self.server_ip[3],
            self.server_port,
            self.xid_counter
        )
    }
}
