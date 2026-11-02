//! RFC 6455 Pure Bare-Metal WebSocket Protocol Engine for CorOS
//! 100% in-house implementation with zero external crates.
//!
//! Provides binary/text frame encoding and decoding, XOR masking, fragmented frame
//! streaming, ping/pong heartbeats, and client/server opening handshake verification
//! using pure Rust SHA-1 and Base64 implementations.

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Standard WebSocket GUID for Sec-WebSocket-Accept computation (RFC 6455 Section 1.3)
pub const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket Opcode enumeration
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

impl WsOpcode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => Self::Reserved(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
            Self::Reserved(b) => b,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// WebSocket Close Status Codes (RFC 6455 Section 7.4.1)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WsCloseCode {
    NormalClosure = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnsupportedData = 1003,
    NoStatusReceived = 1005,
    AbnormalClosure = 1006,
    InvalidPayload = 1007,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    MandatoryExtension = 1010,
    InternalServerError = 1011,
    TlsHandshakeFailure = 1015,
}

/// WebSocket Frame Header representation
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WsFrameHeader {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: WsOpcode,
    pub masked: bool,
    pub payload_len: usize,
    pub masking_key: Option<[u8; 4]>,
}

/// Decoded WebSocket Frame
#[derive(Clone, Debug)]
pub struct WsFrame {
    pub header: WsFrameHeader,
    pub payload: Vec<u8>,
}

impl WsFrame {
    /// Creates a new unmasked Text or Binary frame
    pub fn new(opcode: WsOpcode, payload: Vec<u8>, fin: bool) -> Self {
        let len = payload.len();
        Self {
            header: WsFrameHeader {
                fin,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode,
                masked: false,
                payload_len: len,
                masking_key: None,
            },
            payload,
        }
    }

    /// Creates a masked client frame with a 4-byte masking key
    pub fn new_masked(opcode: WsOpcode, mut payload: Vec<u8>, mask: [u8; 4], fin: bool) -> Self {
        let len = payload.len();
        // Mask payload in-place
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }

        Self {
            header: WsFrameHeader {
                fin,
                rsv1: false,
                rsv2: false,
                rsv3: false,
                opcode,
                masked: true,
                payload_len: len,
                masking_key: Some(mask),
            },
            payload,
        }
    }

    /// Serializes the frame into raw bytes ready for TCP transmission
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Byte 0: FIN, RSV1-3, Opcode
        let mut b0 = self.header.opcode.to_u8();
        if self.header.fin {
            b0 |= 0x80;
        }
        if self.header.rsv1 {
            b0 |= 0x40;
        }
        if self.header.rsv2 {
            b0 |= 0x20;
        }
        if self.header.rsv3 {
            b0 |= 0x10;
        }
        out.push(b0);

        // Byte 1: Mask bit + Payload Length
        let mask_bit = if self.header.masked { 0x80 } else { 0x00 };
        let len = self.header.payload_len;

        if len < 126 {
            out.push(mask_bit | (len as u8));
        } else if len <= 0xFFFF {
            out.push(mask_bit | 126);
            out.push(((len >> 8) & 0xFF) as u8);
            out.push((len & 0xFF) as u8);
        } else {
            out.push(mask_bit | 127);
            for i in (0..8).rev() {
                out.push(((len >> (i * 8)) & 0xFF) as u8);
            }
        }

        // Masking key (4 bytes if present)
        if let Some(mask) = self.header.masking_key {
            out.extend_from_slice(&mask);
        }

        // Payload
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses a WebSocket frame from incoming raw TCP stream
    pub fn parse(buffer: &[u8]) -> Option<(Self, usize)> {
        if buffer.len() < 2 {
            return None; // Header incomplete
        }

        let b0 = buffer[0];
        let fin = (b0 & 0x80) != 0;
        let rsv1 = (b0 & 0x40) != 0;
        let rsv2 = (b0 & 0x20) != 0;
        let rsv3 = (b0 & 0x10) != 0;
        let opcode = WsOpcode::from_u8(b0);

        let b1 = buffer[1];
        let masked = (b1 & 0x80) != 0;
        let basic_len = (b1 & 0x7F) as usize;

        let mut offset = 2;
        let payload_len = if basic_len < 126 {
            basic_len
        } else if basic_len == 126 {
            if buffer.len() < offset + 2 {
                return None;
            }
            let len = ((buffer[offset] as usize) << 8) | (buffer[offset + 1] as usize);
            offset += 2;
            len
        } else {
            if buffer.len() < offset + 8 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..8 {
                len = (len << 8) | (buffer[offset + i] as usize);
            }
            offset += 8;
            len
        };

        let masking_key = if masked {
            if buffer.len() < offset + 4 {
                return None;
            }
            let key = [
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        if buffer.len() < offset + payload_len {
            return None; // Incomplete payload, wait for more data
        }

        let raw_payload = &buffer[offset..offset + payload_len];
        let mut unmasked_payload = Vec::with_capacity(payload_len);

        if let Some(mask) = masking_key {
            for (i, &b) in raw_payload.iter().enumerate() {
                unmasked_payload.push(b ^ mask[i % 4]);
            }
        } else {
            unmasked_payload.extend_from_slice(raw_payload);
        }

        let total_frame_bytes = offset + payload_len;

        Some((
            Self {
                header: WsFrameHeader {
                    fin,
                    rsv1,
                    rsv2,
                    rsv3,
                    opcode,
                    masked,
                    payload_len,
                    masking_key,
                },
                payload: unmasked_payload,
            },
            total_frame_bytes,
        ))
    }
}

/// WebSocket Session State Machine
pub struct WsSession {
    pub is_connected: bool,
    pub rx_fragment_buffer: Vec<u8>,
    pub rx_fragment_opcode: Option<WsOpcode>,
    pub tx_masking_enabled: bool,
}

impl WsSession {
    pub fn new(is_client: bool) -> Self {
        Self {
            is_connected: false,
            rx_fragment_buffer: Vec::new(),
            rx_fragment_opcode: None,
            tx_masking_enabled: is_client,
        }
    }

    /// Process received frame and reassemble fragments if necessary
    pub fn process_incoming_frame(&mut self, frame: WsFrame) -> Option<(WsOpcode, Vec<u8>)> {
        match frame.header.opcode {
            WsOpcode::Ping => {
                // Should reply with Pong immediately
                Some((WsOpcode::Ping, frame.payload))
            }
            WsOpcode::Pong => {
                Some((WsOpcode::Pong, frame.payload))
            }
            WsOpcode::Close => {
                self.is_connected = false;
                Some((WsOpcode::Close, frame.payload))
            }
            WsOpcode::Text | WsOpcode::Binary => {
                if frame.header.fin {
                    Some((frame.header.opcode, frame.payload))
                } else {
                    // Start of fragmented message
                    self.rx_fragment_opcode = Some(frame.header.opcode);
                    self.rx_fragment_buffer = frame.payload;
                    None
                }
            }
            WsOpcode::Continuation => {
                if let Some(op) = self.rx_fragment_opcode {
                    self.rx_fragment_buffer.extend_from_slice(&frame.payload);
                    if frame.header.fin {
                        let full_payload = core::mem::take(&mut self.rx_fragment_buffer);
                        self.rx_fragment_opcode = None;
                        Some((op, full_payload))
                    } else {
                        None
                    }
                } else {
                    None // Unexpected continuation
                }
            }
            WsOpcode::Reserved(_) => None,
        }
    }

    /// Builds a Close frame response
    pub fn build_close_frame(&self, code: WsCloseCode) -> WsFrame {
        let c = code as u16;
        let payload = vec![(c >> 8) as u8, (c & 0xFF) as u8];
        WsFrame::new(WsOpcode::Close, payload, true)
    }

    /// Builds a Pong frame in response to a Ping
    pub fn build_pong_frame(&self, ping_payload: Vec<u8>) -> WsFrame {
        WsFrame::new(WsOpcode::Pong, ping_payload, true)
    }
}

/// Compute Sec-WebSocket-Accept response header given client's Sec-WebSocket-Key
pub fn compute_websocket_accept(sec_ws_key: &str) -> String {
    let mut combined = Vec::new();
    combined.extend_from_slice(sec_ws_key.trim().as_bytes());
    combined.extend_from_slice(WS_GUID);

    let sha1_digest = sha1_hash(&combined);
    base64_encode(&sha1_digest)
}

/// Pure Bare-Metal SHA-1 Implementation (RFC 3174) for WebSocket Handshake
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let msg_len_bits = (data.len() as u64) * 8;
    let mut padded = Vec::from(data);
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }

    for i in (0..8).rev() {
        padded.push(((msg_len_bits >> (i * 8)) & 0xFF) as u8);
    }

    let chunk_count = padded.len() / 64;
    for c in 0..chunk_count {
        let chunk = &padded[c * 64..(c + 1) * 64];
        let mut w = [0u32; 80];

        for i in 0..16 {
            w[i] = ((chunk[i * 4] as u32) << 24)
                | ((chunk[i * 4 + 1] as u32) << 16)
                | ((chunk[i * 4 + 2] as u32) << 8)
                | (chunk[i * 4 + 3] as u32);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c_val = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c_val) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c_val ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c_val) | (b & d) | (c_val & d), 0x8F1BBCDCu32),
                _ => (b ^ c_val ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);

            e = d;
            d = c_val;
            c_val = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c_val);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, val) in [h0, h1, h2, h3, h4].iter().enumerate() {
        out[i * 4] = ((val >> 24) & 0xFF) as u8;
        out[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        out[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        out[i * 4 + 3] = (val & 0xFF) as u8;
    }
    out
}

/// Pure Bare-Metal Base64 Encoder (RFC 4648)
pub fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;

    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() { input[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as usize } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARSET[(triple >> 18) & 0x3F] as char);
        out.push(CHARSET[(triple >> 12) & 0x3F] as char);

        if i + 1 < input.len() {
            out.push(CHARSET[(triple >> 6) & 0x3F] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(CHARSET[triple & 0x3F] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }

    out
}
