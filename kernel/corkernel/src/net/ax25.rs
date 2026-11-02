//! AX.25 Amateur Radio Packet Network Protocol & APRS for CorOS.
//!
//! Implements AX.25 Link Access Protocol v2.2 (Amateur Packet Radio),
//! High-Level Data Link Control (HDLC) framing with CCITT CRC-16 FCS,
//! digipeater routing paths, and APRS (Automatic Packet Reporting System) telemetry & position decoding.

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;

/// HDLC Frame Delimiter Flag (01111110)
pub const HDLC_FLAG: u8 = 0x7E;

/// AX.25 Protocol Identifiers (PID)
pub const AX25_PID_NO_L3: u8 = 0xF0;     // No Layer 3 protocol (Raw / APRS)
pub const AX25_PID_IPV4: u8 = 0xCC;      // RFC 1226 Internet Protocol v4
pub const AX25_PID_ARP: u8 = 0xCD;       // Address Resolution Protocol
pub const AX25_PID_FLEXNET: u8 = 0xCE;   // FlexNet
pub const AX25_PID_THELNET: u8 = 0xCF;   // TheNet

/// AX.25 Frame Control Field Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ax25FrameType {
    /// Information Frame (connection-oriented)
    I { ns: u8, nr: u8, pf: bool },
    /// Supervisory Frame: Receive Ready (RR)
    ReceiveReady { nr: u8, pf: bool },
    /// Supervisory Frame: Receive Not Ready (RNR)
    ReceiveNotReady { nr: u8, pf: bool },
    /// Supervisory Frame: Reject (REJ)
    Reject { nr: u8, pf: bool },
    /// Unnumbered Information (UI - used universally for APRS beacons)
    UnnumberedInfo { pf: bool },
    /// Set Asynchronous Balanced Mode (SABM)
    SetAsyncBalancedMode { pf: bool },
    /// Disconnect (DISC)
    Disconnect { pf: bool },
    /// Unnumbered Acknowledge (UA)
    UnnumberedAck { pf: bool },
    /// Disconnected Mode (DM)
    DisconnectedMode { pf: bool },
    /// Frame Reject (FRMR)
    FrameReject { pf: bool },
    Unknown(u8),
}

/// AX.25 Station Address (Callsign + SSID)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ax25Address {
    pub callsign: [u8; 6],
    pub callsign_len: usize,
    pub ssid: u8,        // 0 to 15
    pub c_bit: bool,     // Command/Response or Digipeater Has-been-repeated
    pub is_last: bool,   // HDLC address extension bit (1 = last address in header)
}

impl Ax25Address {
    pub fn new(call: &str, ssid: u8) -> Self {
        let mut callsign = [b' '; 6];
        let bytes = call.as_bytes();
        let len = bytes.len().min(6);
        for i in 0..len {
            callsign[i] = bytes[i].to_ascii_uppercase();
        }
        Self {
            callsign,
            callsign_len: len,
            ssid: ssid & 0x0F,
            c_bit: false,
            is_last: false,
        }
    }

    /// Parse 7-byte shifted AX.25 address
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 7 {
            return None;
        }

        let mut callsign = [b' '; 6];
        let mut len = 0;
        for i in 0..6 {
            let ch = buf[i] >> 1;
            callsign[i] = ch;
            if ch != b' ' {
                len = i + 1;
            }
        }

        let ssid_byte = buf[6];
        let ssid = (ssid_byte >> 1) & 0x0F;
        let c_bit = (ssid_byte & 0x80) != 0;
        let is_last = (ssid_byte & 0x01) != 0;

        Some(Self {
            callsign,
            callsign_len: len,
            ssid,
            c_bit,
            is_last,
        })
    }

    /// Serialize into 7-byte shifted AX.25 format
    pub fn serialize(&self, buf: &mut [u8]) {
        for i in 0..6 {
            buf[i] = self.callsign[i] << 1;
        }
        let mut ssid_byte = (self.ssid & 0x0F) << 1;
        ssid_byte |= 0x60; // Bits 5 and 6 are reserved (often set to 1)
        if self.c_bit {
            ssid_byte |= 0x80;
        }
        if self.is_last {
            ssid_byte |= 0x01;
        }
        buf[6] = ssid_byte;
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.callsign[..self.callsign_len]).unwrap_or("NOCALL")
    }
}

impl fmt::Debug for Ax25Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ssid == 0 {
            write!(f, "{}", self.as_str())
        } else {
            write!(f, "{}-{}", self.as_str(), self.ssid)
        }
    }
}

/// Complete AX.25 Packet Frame
#[derive(Debug, Clone)]
pub struct Ax25Frame {
    pub destination: Ax25Address,
    pub source: Ax25Address,
    pub repeaters: Vec<Ax25Address>,
    pub frame_type: Ax25FrameType,
    pub pid: Option<u8>,
    pub payload: Vec<u8>,
}

impl Ax25Frame {
    /// Create an APRS Unnumbered Information (UI) frame
    pub fn new_aprs_ui(source: &str, src_ssid: u8, dest: &str, digis: &[(&str, u8)], payload: &[u8]) -> Self {
        let destination = Ax25Address::new(dest, 0);
        let mut source = Ax25Address::new(source, src_ssid);

        let mut repeaters = Vec::new();
        for (digi_call, digi_ssid) in digis {
            repeaters.push(Ax25Address::new(digi_call, *digi_ssid));
        }

        if repeaters.is_empty() {
            source.is_last = true;
        } else if let Some(last) = repeaters.last_mut() {
            last.is_last = true;
        }

        Self {
            destination,
            source,
            repeaters,
            frame_type: Ax25FrameType::UnnumberedInfo { pf: false },
            pid: Some(AX25_PID_NO_L3),
            payload: payload.to_vec(),
        }
    }

    /// Parse an AX.25 frame from raw bytes (excluding HDLC framing flags)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 14 {
            return None;
        }

        let mut offset = 0;
        let destination = Ax25Address::parse(&buf[offset..])?;
        offset += 7;

        let source = Ax25Address::parse(&buf[offset..])?;
        offset += 7;

        let mut repeaters = Vec::new();
        let mut is_last = source.is_last;

        while !is_last && offset + 7 <= buf.len() {
            let digi = Ax25Address::parse(&buf[offset..])?;
            offset += 7;
            is_last = digi.is_last;
            repeaters.push(digi);
            if repeaters.len() > 8 {
                return None; // Exceeded max digipeaters
            }
        }

        if offset >= buf.len() {
            return None;
        }

        let control = buf[offset];
        offset += 1;

        let frame_type = match control {
            0x03 => Ax25FrameType::UnnumberedInfo { pf: false },
            0x13 => Ax25FrameType::UnnumberedInfo { pf: true },
            0x2F => Ax25FrameType::SetAsyncBalancedMode { pf: false },
            0x3F => Ax25FrameType::SetAsyncBalancedMode { pf: true },
            0x43 => Ax25FrameType::Disconnect { pf: false },
            0x53 => Ax25FrameType::Disconnect { pf: true },
            0x63 => Ax25FrameType::UnnumberedAck { pf: false },
            0x73 => Ax25FrameType::UnnumberedAck { pf: true },
            0x0F => Ax25FrameType::DisconnectedMode { pf: false },
            0x1F => Ax25FrameType::DisconnectedMode { pf: true },
            0x87 => Ax25FrameType::FrameReject { pf: false },
            0x97 => Ax25FrameType::FrameReject { pf: true },
            c if (c & 0x01) == 0 => {
                // I-Frame
                let ns = (c >> 1) & 0x07;
                let nr = (c >> 5) & 0x07;
                let pf = (c & 0x10) != 0;
                Ax25FrameType::I { ns, nr, pf }
            }
            c if (c & 0x0F) == 0x01 => {
                // RR
                let nr = (c >> 5) & 0x07;
                let pf = (c & 0x10) != 0;
                Ax25FrameType::ReceiveReady { nr, pf }
            }
            c if (c & 0x0F) == 0x05 => {
                // RNR
                let nr = (c >> 5) & 0x07;
                let pf = (c & 0x10) != 0;
                Ax25FrameType::ReceiveNotReady { nr, pf }
            }
            c if (c & 0x0F) == 0x09 => {
                // REJ
                let nr = (c >> 5) & 0x07;
                let pf = (c & 0x10) != 0;
                Ax25FrameType::Reject { nr, pf }
            }
            other => Ax25FrameType::Unknown(other),
        };

        // If I-frame or UI-frame, PID follows control byte
        let (pid, payload) = match frame_type {
            Ax25FrameType::I { .. } | Ax25FrameType::UnnumberedInfo { .. } => {
                if offset < buf.len() {
                    let p = buf[offset];
                    offset += 1;
                    (Some(p), buf[offset..].to_vec())
                } else {
                    (None, Vec::new())
                }
            }
            _ => (None, buf[offset..].to_vec()),
        };

        Some(Self {
            destination,
            source,
            repeaters,
            frame_type,
            pid,
            payload,
        })
    }

    /// Serialize complete AX.25 frame into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.payload.len());
        let mut addr_buf = [0u8; 7];

        self.destination.serialize(&mut addr_buf);
        out.extend_from_slice(&addr_buf);

        self.source.serialize(&mut addr_buf);
        out.extend_from_slice(&addr_buf);

        for digi in &self.repeaters {
            digi.serialize(&mut addr_buf);
            out.extend_from_slice(&addr_buf);
        }

        let ctrl_byte = match self.frame_type {
            Ax25FrameType::UnnumberedInfo { pf } => if pf { 0x13 } else { 0x03 },
            Ax25FrameType::SetAsyncBalancedMode { pf } => if pf { 0x3F } else { 0x2F },
            Ax25FrameType::Disconnect { pf } => if pf { 0x53 } else { 0x43 },
            Ax25FrameType::UnnumberedAck { pf } => if pf { 0x73 } else { 0x63 },
            Ax25FrameType::DisconnectedMode { pf } => if pf { 0x1F } else { 0x0F },
            Ax25FrameType::FrameReject { pf } => if pf { 0x97 } else { 0x87 },
            Ax25FrameType::I { ns, nr, pf } => {
                (nr << 5) | (if pf { 0x10 } else { 0x00 }) | (ns << 1)
            }
            Ax25FrameType::ReceiveReady { nr, pf } => {
                (nr << 5) | (if pf { 0x10 } else { 0x00 }) | 0x01
            }
            Ax25FrameType::ReceiveNotReady { nr, pf } => {
                (nr << 5) | (if pf { 0x10 } else { 0x00 }) | 0x05
            }
            Ax25FrameType::Reject { nr, pf } => {
                (nr << 5) | (if pf { 0x10 } else { 0x00 }) | 0x09
            }
            Ax25FrameType::Unknown(b) => b,
        };
        out.push(ctrl_byte);

        if let Some(p) = self.pid {
            out.push(p);
        }

        out.extend_from_slice(&self.payload);
        out
    }
}

/// Calculate HDLC / CCITT CRC-16 Frame Check Sequence (FCS)
pub fn calculate_fcs(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xFFFF;
    for &byte in data {
        let mut b = byte;
        for _ in 0..8 {
            let bit = (b & 0x01) ^ ((fcs & 0x0001) as u8);
            fcs >>= 1;
            if bit != 0 {
                fcs ^= 0x8408; // Reversed 0x1021 polynomial
            }
            b >>= 1;
        }
    }
    !fcs
}

/// Decoded APRS Position Report
#[derive(Debug, Clone, PartialEq)]
pub struct AprsPosition {
    pub latitude_deg: f64,
    pub longitude_deg: f64,
    pub symbol_table: char,
    pub symbol_code: char,
    pub comment: String,
}

/// Decoded APRS Packet Data Types
#[derive(Debug, Clone, PartialEq)]
pub enum AprsData {
    Position(AprsPosition),
    WeatherReport(String),
    TextMessage { addressee: String, message: String },
    RawTelemetry(String),
    Status(String),
}

/// APRS Protocol Decoder
pub struct AprsDecoder;

impl AprsDecoder {
    /// Parse an APRS Information Payload (typically begins with !, =, /, @, :, >, etc.)
    pub fn parse(payload: &[u8]) -> Option<AprsData> {
        if payload.is_empty() {
            return None;
        }

        let text = core::str::from_utf8(payload).ok()?;
        let data_type_char = text.chars().next()?;

        match data_type_char {
            // Position reports without timestamp: ! or =
            '!' | '=' => {
                // Format: !DDMM.mmN/DDDMM.mmW$comment
                if text.len() >= 19 {
                    Self::parse_uncompressed_position(&text[1..])
                } else {
                    None
                }
            }
            // Position reports with timestamp: / or @
            '/' | '@' => {
                // 7-character timestamp e.g. 092345z then position
                if text.len() >= 26 {
                    Self::parse_uncompressed_position(&text[8..])
                } else {
                    None
                }
            }
            // Message: :ADDRESSEE :Message text
            ':' => {
                if text.len() >= 11 {
                    let addressee = text[1..10].trim().into();
                    let colon_idx = text[10..].find(':')?;
                    let message = text[10 + colon_idx + 1..].trim().into();
                    Some(AprsData::TextMessage { addressee, message })
                } else {
                    None
                }
            }
            // Status report: >status text
            '>' => {
                Some(AprsData::Status(text[1..].trim().into()))
            }
            // Telemetry: T#MIC...
            'T' => {
                Some(AprsData::RawTelemetry(text.trim().into()))
            }
            // Weather report
            '_' => {
                Some(AprsData::WeatherReport(text[1..].trim().into()))
            }
            _ => None,
        }
    }

    fn parse_uncompressed_position(s: &str) -> Option<AprsData> {
        // Expecting: DDMM.hhN/DDDMM.hhW$comment
        // Length must be at least 18 chars (8 lat, 1 sym_tab, 9 lon, 1 sym_code)
        if s.len() < 19 {
            return None;
        }

        let lat_deg: f64 = s[0..2].parse().ok()?;
        let lat_min: f64 = s[2..7].parse().ok()?;
        let lat_dir = s.chars().nth(7)?;
        let mut lat = lat_deg + (lat_min / 60.0);
        if lat_dir == 'S' || lat_dir == 's' {
            lat = -lat;
        }

        let sym_table = s.chars().nth(8)?;

        let lon_deg: f64 = s[9..12].parse().ok()?;
        let lon_min: f64 = s[12..17].parse().ok()?;
        let lon_dir = s.chars().nth(17)?;
        let mut lon = lon_deg + (lon_min / 60.0);
        if lon_dir == 'W' || lon_dir == 'w' {
            lon = -lon;
        }

        let sym_code = s.chars().nth(18)?;
        let comment = if s.len() > 19 {
            s[19..].trim().into()
        } else {
            String::new()
        };

        Some(AprsData::Position(AprsPosition {
            latitude_deg: lat,
            longitude_deg: lon,
            symbol_table: sym_table,
            symbol_code: sym_code,
            comment,
        }))
    }
}
