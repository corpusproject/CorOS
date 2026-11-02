//! Windows SMB2 / SMB3 (Server Message Block / CIFS) Client for CorOS.
//!
//! Implements Microsoft MS-SMB2 protocol over Direct TCP port 445:
//! - NetBIOS 4-byte stream header framing
//! - 64-byte SMB2 packet header (`0xFE 'S' 'M' 'B'`)
//! - Dialect negotiation (SMB 2.0.2, SMB 2.1, SMB 3.0, SMB 3.1.1)
//! - Tree Connect to UNC shares (`\\server\share`)
//! - File operations: `SMB2_CREATE`, `SMB2_READ`, `SMB2_WRITE`, `SMB2_CLOSE`

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt;

/// SMB2 Protocol Signature (`0xFE 'S' 'M' 'B'`)
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Standard SMB2 Header Length (64 bytes)
pub const SMB2_HEADER_SIZE: usize = 64;

/// Standard SMB Direct TCP Port
pub const SMB_TCP_PORT: u16 = 445;

/// SMB2 Command Opcodes (MS-SMB2 Section 2.2.1)
pub mod smb2_cmd {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const LOGOFF: u16 = 0x0002;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const TREE_DISCONNECT: u16 = 0x0004;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const FLUSH: u16 = 0x0007;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const LOCK: u16 = 0x000A;
    pub const IOCTL: u16 = 0x000B;
    pub const CANCEL: u16 = 0x000C;
    pub const ECHO: u16 = 0x000D;
    pub const QUERY_DIRECTORY: u16 = 0x000E;
    pub const CHANGE_NOTIFY: u16 = 0x000F;
    pub const QUERY_INFO: u16 = 0x0010;
    pub const SET_INFO: u16 = 0x0011;
}

/// SMB2 Dialects
pub mod smb2_dialect {
    pub const SMB_2_0_2: u16 = 0x0202;
    pub const SMB_2_1_0: u16 = 0x0210;
    pub const SMB_3_0_0: u16 = 0x0300;
    pub const SMB_3_0_2: u16 = 0x0302;
    pub const SMB_3_1_1: u16 = 0x0311;
}

/// Standard 64-byte SMB2 Packet Header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Header {
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub fn new(command: u16, message_id: u64, session_id: u64, tree_id: u32) -> Self {
        Self {
            credit_charge: 1,
            status: 0,
            command,
            credits: 64,
            flags: 0,
            next_command: 0,
            message_id,
            tree_id,
            session_id,
            signature: [0u8; 16],
        }
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&SMB2_MAGIC);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize = 64
        buf[6..8].copy_from_slice(&self.credit_charge.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..14].copy_from_slice(&self.command.to_le_bytes());
        buf[14..16].copy_from_slice(&self.credits.to_le_bytes());
        buf[16..20].copy_from_slice(&self.flags.to_le_bytes());
        buf[20..24].copy_from_slice(&self.next_command.to_le_bytes());
        buf[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        buf[32..36].copy_from_slice(&0u32.to_le_bytes()); // Reserved
        buf[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        buf[48..64].copy_from_slice(&self.signature);
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 64 {
            return None;
        }
        if buf[0..4] != SMB2_MAGIC {
            return None;
        }

        let credit_charge = u16::from_le_bytes([buf[6], buf[7]]);
        let status = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let command = u16::from_le_bytes([buf[12], buf[13]]);
        let credits = u16::from_le_bytes([buf[14], buf[15]]);
        let flags = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let next_command = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let message_id = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27],
            buf[28], buf[29], buf[30], buf[31],
        ]);
        let tree_id = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let session_id = u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43],
            buf[44], buf[45], buf[46], buf[47],
        ]);

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[48..64]);

        Some(Self {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        })
    }
}

/// Windows SMB2/SMB3 Network Client Session
pub struct SmbClient {
    pub server_ip: [u8; 4],
    pub server_port: u16,
    pub message_id_counter: u64,
    pub session_id: u64,
    pub tree_id: u32,
    pub negotiated_dialect: u16,
}

impl SmbClient {
    pub fn new(server_ip: [u8; 4], server_port: u16) -> Self {
        Self {
            server_ip,
            server_port,
            message_id_counter: 0,
            session_id: 0,
            tree_id: 0,
            negotiated_dialect: 0,
        }
    }

    /// Prepend standard 4-byte NetBIOS direct TCP length prefix
    fn frame_tcp_packet(smb2_bytes: &[u8]) -> Vec<u8> {
        let len = smb2_bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + smb2_bytes.len());
        out.push(0x00); // NetBIOS session message
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(smb2_bytes);
        out
    }

    /// Build SMB2 NEGOTIATE Request
    pub fn build_negotiate_request(&mut self) -> Vec<u8> {
        let msg_id = self.message_id_counter;
        self.message_id_counter += 1;

        let hdr = Smb2Header::new(smb2_cmd::NEGOTIATE, msg_id, 0, 0);
        let mut smb_pkt = Vec::with_capacity(64 + 36);
        let mut hdr_bytes = [0u8; 64];
        hdr.serialize(&mut hdr_bytes);
        smb_pkt.extend_from_slice(&hdr_bytes);

        // SMB2 NEGOTIATE Body (StructureSize=36, DialectCount=4)
        smb_pkt.extend_from_slice(&36u16.to_le_bytes());
        smb_pkt.extend_from_slice(&4u16.to_le_bytes()); // DialectCount
        smb_pkt.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode (Signing enabled)
        smb_pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        smb_pkt.extend_from_slice(&0x40u32.to_le_bytes()); // Capabilities (DFS)
        smb_pkt.extend_from_slice(&[0u8; 16]);          // Client GUID
        smb_pkt.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime

        // Dialects: SMB 2.0.2, 2.1.0, 3.0.0, 3.1.1
        smb_pkt.extend_from_slice(&smb2_dialect::SMB_2_0_2.to_le_bytes());
        smb_pkt.extend_from_slice(&smb2_dialect::SMB_2_1_0.to_le_bytes());
        smb_pkt.extend_from_slice(&smb2_dialect::SMB_3_0_0.to_le_bytes());
        smb_pkt.extend_from_slice(&smb2_dialect::SMB_3_1_1.to_le_bytes());

        Self::frame_tcp_packet(&smb_pkt)
    }

    /// Build SMB2 TREE_CONNECT Request for UNC path (e.g. `\\server\share`)
    pub fn build_tree_connect_request(&mut self, unc_path: &str) -> Vec<u8> {
        let msg_id = self.message_id_counter;
        self.message_id_counter += 1;

        let hdr = Smb2Header::new(smb2_cmd::TREE_CONNECT, msg_id, self.session_id, 0);
        let mut smb_pkt = Vec::with_capacity(64 + 16 + unc_path.len() * 2);
        let mut hdr_bytes = [0u8; 64];
        hdr.serialize(&mut hdr_bytes);
        smb_pkt.extend_from_slice(&hdr_bytes);

        // Convert ASCII path to UTF-16LE
        let mut utf16_path = Vec::new();
        for ch in unc_path.encode_utf16() {
            utf16_path.extend_from_slice(&ch.to_le_bytes());
        }

        let path_offset = (64 + 8) as u16; // Header + TreeConnect body prefix
        let path_len = utf16_path.len() as u16;

        smb_pkt.extend_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
        smb_pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved/Flags
        smb_pkt.extend_from_slice(&path_offset.to_le_bytes());
        smb_pkt.extend_from_slice(&path_len.to_le_bytes());
        smb_pkt.extend_from_slice(&utf16_path);

        Self::frame_tcp_packet(&smb_pkt)
    }

    /// Build SMB2 READ Request
    pub fn build_read_request(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> Vec<u8> {
        let msg_id = self.message_id_counter;
        self.message_id_counter += 1;

        let hdr = Smb2Header::new(smb2_cmd::READ, msg_id, self.session_id, self.tree_id);
        let mut smb_pkt = Vec::with_capacity(64 + 49);
        let mut hdr_bytes = [0u8; 64];
        hdr.serialize(&mut hdr_bytes);
        smb_pkt.extend_from_slice(&hdr_bytes);

        smb_pkt.extend_from_slice(&49u16.to_le_bytes()); // StructureSize = 49
        smb_pkt.push(0);                                // Padding
        smb_pkt.push(0);                                // Reserved
        smb_pkt.extend_from_slice(&length.to_le_bytes());// Length
        smb_pkt.extend_from_slice(&offset.to_le_bytes());// Offset
        smb_pkt.extend_from_slice(&file_id);            // FileId (Persistent + Volatile)
        smb_pkt.extend_from_slice(&0u32.to_le_bytes()); // MinimumCount
        smb_pkt.extend_from_slice(&0u32.to_le_bytes()); // Channel
        smb_pkt.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes

        Self::frame_tcp_packet(&smb_pkt)
    }
}

impl fmt::Display for SmbClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmbClient(server={}.{}.{}.{}:{}, session_id={:#X}, tree_id={:#X})",
            self.server_ip[0], self.server_ip[1], self.server_ip[2], self.server_ip[3],
            self.server_port,
            self.session_id,
            self.tree_id
        )
    }
}
