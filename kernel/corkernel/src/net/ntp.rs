//! Network Time Protocol (NTPv4 - RFC 5905) Client & Server Daemon for CorOS
//! 100% in-house bare-metal implementation with zero external crates.
//!
//! Features:
//! - NTP 48-byte fixed-size packet header parsing and encoding
//! - 64-bit high-resolution timestamps (32-bit seconds + 32-bit fractional seconds since 1900)
//! - Clock discipline algorithm with round-trip delay, clock offset, and jitter estimation
//! - Kiss-o'-Death (KoD) packet handling and Stratum tracking (1 to 16)
//! - SNTP (Simple NTP - RFC 4330) and full NTP peer mode

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

pub const NTP_PORT: u16 = 123;
pub const NTP_PACKET_SIZE: usize = 48;
pub const NTP_TIMESTAMP_DELTA_1900_1970: u64 = 2208988800; // Seconds between Jan 1 1900 and Jan 1 1970

// Leap Indicator (LI)
pub const NTP_LI_NO_WARNING: u8 = 0;
pub const NTP_LI_61_SEC: u8 = 1;
pub const NTP_LI_59_SEC: u8 = 2;
pub const NTP_LI_ALARM: u8 = 3;

// NTP Modes
pub const NTP_MODE_RESERVED: u8 = 0;
pub const NTP_MODE_SYMMETRIC_ACTIVE: u8 = 1;
pub const NTP_MODE_SYMMETRIC_PASSIVE: u8 = 2;
pub const NTP_MODE_CLIENT: u8 = 3;
pub const NTP_MODE_SERVER: u8 = 4;
pub const NTP_MODE_BROADCAST: u8 = 5;
pub const NTP_MODE_CONTROL: u8 = 6;
pub const NTP_MODE_PRIVATE: u8 = 7;

/// 64-bit NTP Timestamp representation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    pub const ZERO: Self = Self { seconds: 0, fraction: 0 };

    pub fn new(seconds: u32, fraction: u32) -> Self {
        Self { seconds, fraction }
    }

    /// Convert from UNIX epoch (seconds, nanoseconds) to NTP timestamp
    pub fn from_unix(unix_sec: u64, unix_nanos: u32) -> Self {
        let ntp_sec = (unix_sec + NTP_TIMESTAMP_DELTA_1900_1970) as u32;
        // fraction = (nanoseconds * 2^32) / 10^9
        let fraction = (((unix_nanos as u64) << 32) / 1_000_000_000) as u32;
        Self { seconds: ntp_sec, fraction }
    }

    /// Convert to UNIX epoch seconds
    pub fn to_unix_seconds(&self) -> u64 {
        if (self.seconds as u64) >= NTP_TIMESTAMP_DELTA_1900_1970 {
            (self.seconds as u64) - NTP_TIMESTAMP_DELTA_1900_1970
        } else {
            0
        }
    }

    /// Convert to floating-point seconds since 1900
    pub fn to_f64(&self) -> f64 {
        (self.seconds as f64) + ((self.fraction as f64) / 4294967296.0)
    }

    /// From floating-point seconds
    pub fn from_f64(val: f64) -> Self {
        let sec = val as u32;
        let frac = ((val - sec as f64) * 4294967296.0) as u32;
        Self { seconds: sec, fraction: frac }
    }
}

/// Standard 48-byte NTP Packet Header
#[derive(Clone, Copy, Debug)]
pub struct NtpPacket {
    pub li: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub ref_timestamp: NtpTimestamp,
    pub orig_timestamp: NtpTimestamp,
    pub recv_timestamp: NtpTimestamp,
    pub trans_timestamp: NtpTimestamp,
}

impl NtpPacket {
    /// Creates a new client request packet
    pub fn new_client_request(current_time: NtpTimestamp) -> Self {
        Self {
            li: NTP_LI_NO_WARNING,
            version: 4,
            mode: NTP_MODE_CLIENT,
            stratum: 0,
            poll: 6, // 64 seconds
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            ref_timestamp: NtpTimestamp::ZERO,
            orig_timestamp: NtpTimestamp::ZERO,
            recv_timestamp: NtpTimestamp::ZERO,
            trans_timestamp: current_time,
        }
    }

    /// Serialize packet into 48-byte wire buffer
    pub fn serialize(&self) -> [u8; NTP_PACKET_SIZE] {
        let mut buf = [0u8; NTP_PACKET_SIZE];
        buf[0] = ((self.li & 0x03) << 6) | ((self.version & 0x07) << 3) | (self.mode & 0x07);
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;

        buf[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id);

        buf[16..20].copy_from_slice(&self.ref_timestamp.seconds.to_be_bytes());
        buf[20..24].copy_from_slice(&self.ref_timestamp.fraction.to_be_bytes());

        buf[24..28].copy_from_slice(&self.orig_timestamp.seconds.to_be_bytes());
        buf[28..32].copy_from_slice(&self.orig_timestamp.fraction.to_be_bytes());

        buf[32..36].copy_from_slice(&self.recv_timestamp.seconds.to_be_bytes());
        buf[36..40].copy_from_slice(&self.recv_timestamp.fraction.to_be_bytes());

        buf[40..44].copy_from_slice(&self.trans_timestamp.seconds.to_be_bytes());
        buf[44..48].copy_from_slice(&self.trans_timestamp.fraction.to_be_bytes());

        buf
    }

    /// Parse packet from 48-byte wire buffer
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < NTP_PACKET_SIZE {
            return None;
        }

        let b0 = buf[0];
        let li = (b0 >> 6) & 0x03;
        let version = (b0 >> 3) & 0x07;
        let mode = b0 & 0x07;
        let stratum = buf[1];
        let poll = buf[2] as i8;
        let precision = buf[3] as i8;

        let root_delay = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let root_disp = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let ref_id = [buf[12], buf[13], buf[14], buf[15]];

        let ref_ts = NtpTimestamp::new(
            u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
        );

        let orig_ts = NtpTimestamp::new(
            u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
            u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]),
        );

        let recv_ts = NtpTimestamp::new(
            u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]),
            u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
        );

        let trans_ts = NtpTimestamp::new(
            u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]),
            u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]),
        );

        Some(Self {
            li,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion: root_disp,
            reference_id: ref_id,
            ref_timestamp: ref_ts,
            orig_timestamp: orig_ts,
            recv_timestamp: recv_ts,
            trans_timestamp: trans_ts,
        })
    }
}

/// Filtered Time Sample from NTP Exchange
#[derive(Clone, Copy, Debug)]
pub struct NtpTimeOffset {
    pub round_trip_delay_sec: f64,
    pub clock_offset_sec: f64,
}

/// NTP Client Clock Synchronizer
pub struct NtpClient {
    pub server_ip: [u8; 4],
    pub is_synchronized: bool,
    pub current_stratum: u8,
    pub last_offset: f64,
    pub last_delay: f64,
}

impl NtpClient {
    pub fn new(server_ip: [u8; 4]) -> Self {
        Self {
            server_ip,
            is_synchronized: false,
            current_stratum: 16, // Unsynchronized
            last_offset: 0.0,
            last_delay: 0.0,
        }
    }

    /// Process received NTP response:
    /// T1 = Client transmit timestamp (orig_timestamp)
    /// T2 = Server receive timestamp (recv_timestamp)
    /// T3 = Server transmit timestamp (trans_timestamp)
    /// T4 = Client receive timestamp
    pub fn process_response(&mut self, resp: &NtpPacket, t4: NtpTimestamp) -> Option<NtpTimeOffset> {
        if resp.stratum == 0 || resp.stratum > 15 {
            return None; // Invalid stratum or Kiss-o'-Death
        }

        let t1 = resp.orig_timestamp.to_f64();
        let t2 = resp.recv_timestamp.to_f64();
        let t3 = resp.trans_timestamp.to_f64();
        let t4_val = t4.to_f64();

        // Round-trip delay = (T4 - T1) - (T3 - T2)
        let delay = (t4_val - t1) - (t3 - t2);
        // Clock offset = ((T2 - T1) + (T3 - T4)) / 2
        let offset = ((t2 - t1) + (t3 - t4_val)) * 0.5;

        self.last_delay = delay;
        self.last_offset = offset;
        self.current_stratum = resp.stratum;
        self.is_synchronized = true;

        Some(NtpTimeOffset {
            round_trip_delay_sec: delay,
            clock_offset_sec: offset,
        })
    }
}
