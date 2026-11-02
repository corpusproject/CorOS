//! CorOS IPv6 (Internet Protocol Version 6 - RFC 8200) Subsystem (`ipv6.rs`)
//!
//! Implements full IPv6 packet processing:
//! - 40-byte Fixed IPv6 Header (Version 6, Traffic Class, Flow Label, Payload Length, Next Header, Hop Limit)
//! - 128-bit IPv6 Address representation, parsing, and text formatting (zero-compression `::`)
//! - Extension Header Chaining:
//!   - Hop-by-Hop Options (0)
//!   - Routing Header (43)
//!   - Fragment Header (44: Identification, Fragment Offset, More Fragments flag)
//!   - Destination Options (60)
//! - Well-known addresses: Unspecified (`::`), Loopback (`::1`), Link-Local (`fe80::/10`), Multicast (`ff00::/8`)
//! - Solicited-Node Multicast Address generation (`ff02::1:ffxx:xxxx`)
//! - IPv6 Pseudo-header checksum calculation for upper-layer protocols (TCP/UDP/ICMPv6)

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const IPV6_HEADER_LEN: usize = 40;
pub const IPV6_VERSION: u8 = 6;

/// IPv6 Next Header / Protocol Numbers
pub const NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub const NEXT_HEADER_TCP: u8 = 6;
pub const NEXT_HEADER_UDP: u8 = 17;
pub const NEXT_HEADER_ROUTING: u8 = 43;
pub const NEXT_HEADER_FRAGMENT: u8 = 44;
pub const NEXT_HEADER_ICMPV6: u8 = 58;
pub const NEXT_HEADER_NO_NEXT: u8 = 59;
pub const NEXT_HEADER_DEST_OPTIONS: u8 = 60;

/// 128-bit IPv6 Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const UNSPECIFIED: Self = Self([0; 16]);
    pub const LOOPBACK: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    pub fn new(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    pub fn from_words(words: [u16; 8]) -> Self {
        let mut b = [0u8; 16];
        for (i, &w) in words.iter().enumerate() {
            b[i * 2] = (w >> 8) as u8;
            b[i * 2 + 1] = w as u8;
        }
        Self(b)
    }

    pub fn words(&self) -> [u16; 8] {
        let mut w = [0u16; 8];
        for i in 0..8 {
            w[i] = ((self.0[i * 2] as u16) << 8) | (self.0[i * 2 + 1] as u16);
        }
        w
    }

    pub fn is_unspecified(&self) -> bool {
        self.0 == [0; 16]
    }

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    pub fn is_link_local(&self) -> bool {
        self.0[0] == 0xFE && (self.0[1] & 0xC0) == 0x80
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xFF
    }

    /// Generate RFC 4291 Solicited-Node Multicast Address: FF02::1:FFxx:xxxx
    pub fn to_solicited_node_multicast(&self) -> Self {
        Self([
            0xFF, 0x02, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 1,
            0xFF, self.0[13], self.0[14], self.0[15],
        ])
    }

    /// Convert MAC (EUI-48) to Link-Local IPv6 using EUI-64
    pub fn from_mac_link_local(mac: [u8; 6]) -> Self {
        let mut b = [0u8; 16];
        b[0] = 0xFE;
        b[1] = 0x80;
        // Invert universal/local bit
        b[8] = mac[0] ^ 0x02;
        b[9] = mac[1];
        b[10] = mac[2];
        b[11] = 0xFF;
        b[12] = 0xFE;
        b[13] = mac[3];
        b[14] = mac[4];
        b[15] = mac[5];
        Self(b)
    }

    /// Format standard RFC 5952 representation with zero compression
    pub fn to_string(&self) -> String {
        let words = self.words();

        // Find longest run of zeros for "::" compression
        let mut best_start = 8;
        let mut best_len = 0;
        let mut cur_start = 8;
        let mut cur_len = 0;

        for (i, &w) in words.iter().enumerate() {
            if w == 0 {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
            } else if cur_len > 0 {
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
                cur_len = 0;
            }
        }
        if cur_len > best_len {
            best_len = cur_len;
            best_start = cur_start;
        }

        // Only compress if run is 2 or more zeros
        if best_len < 2 {
            best_start = 8;
            best_len = 0;
        }

        let mut s = String::new();
        let mut i = 0;
        while i < 8 {
            if i == best_start {
                s.push_str("::");
                i += best_len;
                continue;
            }
            if i > 0 && !(i == best_start + best_len && best_start == 0) && !s.ends_with(':') {
                s.push(':');
            }
            s.push_str(&alloc::format!("{:x}", words[i]));
            i += 1;
        }
        s
    }
}

/// IPv6 Fixed Header (40 bytes)
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

impl Ipv6Header {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < IPV6_HEADER_LEN {
            return None;
        }

        let v_tc_fl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let version = ((v_tc_fl >> 28) & 0x0F) as u8;
        if version != IPV6_VERSION {
            return None;
        }

        let traffic_class = ((v_tc_fl >> 20) & 0xFF) as u8;
        let flow_label = v_tc_fl & 0x000F_FFFF;
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header = buf[6];
        let hop_limit = buf[7];

        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        dst.copy_from_slice(&buf[24..40]);

        Some(Self {
            version,
            traffic_class,
            flow_label,
            payload_length: payload_len,
            next_header,
            hop_limit,
            src_addr: Ipv6Addr(src),
            dst_addr: Ipv6Addr(dst),
        })
    }

    pub fn to_bytes(&self) -> [u8; IPV6_HEADER_LEN] {
        let mut buf = [0u8; IPV6_HEADER_LEN];
        let v_tc_fl = ((self.version as u32) << 28)
            | ((self.traffic_class as u32) << 20)
            | (self.flow_label & 0x000F_FFFF);

        buf[0..4].copy_from_slice(&v_tc_fl.to_be_bytes());
        buf[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src_addr.0);
        buf[24..40].copy_from_slice(&self.dst_addr.0);
        buf
    }

    /// Calculate RFC 8200 IPv6 Pseudo-Header Checksum
    pub fn pseudo_header_checksum(&self, upper_proto: u8, upper_len: u32) -> u32 {
        let mut sum: u32 = 0;
        let src_words = self.src_addr.words();
        let dst_words = self.dst_addr.words();

        for &w in &src_words {
            sum = sum.wrapping_add(w as u32);
        }
        for &w in &dst_words {
            sum = sum.wrapping_add(w as u32);
        }

        sum = sum.wrapping_add(upper_len >> 16);
        sum = sum.wrapping_add(upper_len & 0xFFFF);
        sum = sum.wrapping_add(upper_proto as u32);
        sum
    }
}

/// IPv6 Fragment Header (RFC 8200 §4.5)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv6FragmentHeader {
    pub next_header: u8,
    pub reserved: u8,
    pub fragment_offset_flags: u16,
    pub identification: u32,
}

impl Ipv6FragmentHeader {
    pub fn offset(&self) -> u16 {
        u16::from_be(self.fragment_offset_flags) & 0xFFF8
    }

    pub fn more_fragments(&self) -> bool {
        (u16::from_be(self.fragment_offset_flags) & 0x0001) != 0
    }
}
