//! IPv6 40-Byte Fixed Header, EUI-64 SLAAC Address Generator & Extension Header Chain Walker.

use crate::ethernet_mac::MacAddress;
use alloc::vec::Vec;
use core::fmt;

/// A 128-bit IPv6 network address in network byte order (16 octets).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    /// Unspecified address (`::`).
    pub const UNSPECIFIED: Self = Self([0; 16]);
    /// Loopback address (`::1`).
    pub const LOCALHOST: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    /// Link-local all-nodes multicast (`ff02::1`).
    pub const ALL_NODES_LINK_LOCAL: Self =
        Self([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    /// Link-local all-routers multicast (`ff02::2`).
    pub const ALL_ROUTERS_LINK_LOCAL: Self =
        Self([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    /// Constructs an `Ipv6Addr` from eight 16-bit big-endian segments.
    pub const fn from_segments(s: [u16; 8]) -> Self {
        Self([
            (s[0] >> 8) as u8,
            s[0] as u8,
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
            (s[3] >> 8) as u8,
            s[3] as u8,
            (s[4] >> 8) as u8,
            s[4] as u8,
            (s[5] >> 8) as u8,
            s[5] as u8,
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ])
    }

    /// Returns the eight 16-bit segments of this IPv6 address.
    pub const fn segments(&self) -> [u16; 8] {
        let b = &self.0;
        [
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]]),
            u16::from_be_bytes([b[4], b[5]]),
            u16::from_be_bytes([b[6], b[7]]),
            u16::from_be_bytes([b[8], b[9]]),
            u16::from_be_bytes([b[10], b[11]]),
            u16::from_be_bytes([b[12], b[13]]),
            u16::from_be_bytes([b[14], b[15]]),
        ]
    }

    /// Returns the raw 16-byte array representation.
    #[inline]
    pub const fn octets(&self) -> [u8; 16] {
        self.0
    }

    /// Returns `true` if `::`.
    #[inline]
    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    /// Returns `true` if `::1`.
    #[inline]
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOCALHOST
    }

    /// Returns `true` if in `fe80::/10` link-local unicast space.
    #[inline]
    pub const fn is_unicast_link_local(&self) -> bool {
        self.0[0] == 0xFE && (self.0[1] & 0xC0) == 0x80
    }

    /// Returns `true` if in `ff00::/8` multicast space.
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.0[0] == 0xFF
    }

    /// Generates a Modified EUI-64 SLAAC link-local IPv6 address (`fe80::/64`)
    /// from a 48-bit IEEE 802 MAC address per RFC 4291 Appendix A.
    pub const fn from_mac_slaac_link_local(mac: MacAddress) -> Self {
        let m = mac.0;
        // Invert the Universal/Local (U/L) bit (bit 1 of the first octet) and insert FF:FE.
        Self([
            0xFE,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            m[0] ^ 0x02,
            m[1],
            m[2],
            0xFF,
            0xFE,
            m[3],
            m[4],
            m[5],
        ])
    }

    /// Generates a global or ULA SLAAC address by combining a 64-bit network prefix with Modified EUI-64.
    pub const fn from_prefix_eui64(prefix64: [u8; 8], mac: MacAddress) -> Self {
        let m = mac.0;
        Self([
            prefix64[0],
            prefix64[1],
            prefix64[2],
            prefix64[3],
            prefix64[4],
            prefix64[5],
            prefix64[6],
            prefix64[7],
            m[0] ^ 0x02,
            m[1],
            m[2],
            0xFF,
            0xFE,
            m[3],
            m[4],
            m[5],
        ])
    }

    /// Computes the Solicited-Node multicast address (`ff02::1:ffXX:XXXX`) for NDP resolution.
    #[inline]
    pub const fn solicited_node_multicast(&self) -> Self {
        Self([
            0xFF,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0xFF,
            self.0[13],
            self.0[14],
            self.0[15],
        ])
    }
}

impl fmt::Debug for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.segments();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
        )
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Errors encountered while parsing or serializing an IPv6 packet or extension header chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Error {
    /// Buffer is shorter than the fixed 40-byte IPv6 header.
    TruncatedHeader,
    /// Buffer is shorter than `40 + payload_len`.
    TruncatedPayload,
    /// IP version nibble is not `6`.
    InvalidVersion(u8),
    /// An extension header extends past the end of the packet payload.
    TruncatedExtensionHeader,
}

/// Fixed 40-byte RFC 8200 IPv6 Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    /// 8-bit Traffic Class (6-bit DSCP + 2-bit ECN).
    pub traffic_class: u8,
    /// 20-bit Flow Label.
    pub flow_label: u32,
    /// Payload length in bytes (including any extension headers).
    pub payload_len: u16,
    /// Next Header protocol number (`0` = Hop-by-Hop, `6` = TCP, `17` = UDP, `43` = Routing, `44` = Fragment, `58` = ICMPv6).
    pub next_header: u8,
    /// Hop Limit (decremented by 1 at each forwarding router).
    pub hop_limit: u8,
    /// 128-bit Source IPv6 address.
    pub src_ip: Ipv6Addr,
    /// 128-bit Destination IPv6 address.
    pub dst_ip: Ipv6Addr,
}

impl Ipv6Header {
    /// Fixed length of the base IPv6 header in bytes.
    pub const LEN: usize = 40;

    /// Constructs a new 40-byte IPv6 header with default `hop_limit = 64`.
    pub const fn new(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, next_header: u8, payload_len: u16) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_len,
            next_header,
            hop_limit: 64,
            src_ip,
            dst_ip,
        }
    }

    /// Parses an `Ipv6Header` from `buf`, returning `(header, payload_slice)`.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), Ipv6Error> {
        if buf.len() < Self::LEN {
            return Err(Ipv6Error::TruncatedHeader);
        }
        let version = buf[0] >> 4;
        if version != 6 {
            return Err(Ipv6Error::InvalidVersion(version));
        }
        let vtcfl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let traffic_class = ((vtcfl >> 20) & 0xFF) as u8;
        let flow_label = vtcfl & 0x000F_FFFF;
        let payload_len = u16::from_be_bytes([buf[4], buf[5]]);
        let next_header = buf[6];
        let hop_limit = buf[7];

        let total = Self::LEN + (payload_len as usize);
        if buf.len() < total {
            return Err(Ipv6Error::TruncatedPayload);
        }

        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&buf[8..24]);
        dst.copy_from_slice(&buf[24..40]);

        Ok((
            Self {
                traffic_class,
                flow_label,
                payload_len,
                next_header,
                hop_limit,
                src_ip: Ipv6Addr(src),
                dst_ip: Ipv6Addr(dst),
            },
            &buf[Self::LEN..total],
        ))
    }

    /// Serializes this 40-byte IPv6 header into `out`.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, Ipv6Error> {
        if out.len() < Self::LEN {
            return Err(Ipv6Error::TruncatedHeader);
        }
        let vtcfl: u32 = (6u32 << 28)
            | ((self.traffic_class as u32) << 20)
            | (self.flow_label & 0x000F_FFFF);
        out[0..4].copy_from_slice(&vtcfl.to_be_bytes());
        out[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        out[6] = self.next_header;
        out[7] = self.hop_limit;
        out[8..24].copy_from_slice(&self.src_ip.0);
        out[24..40].copy_from_slice(&self.dst_ip.0);
        Ok(Self::LEN)
    }
}

/// Decoded IPv6 Extension Header item encountered while walking the extension header chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6ExtensionHeader {
    /// Hop-by-Hop Options (`NextHeader = 0`), with total byte length of the header.
    HopByHop { len: usize },
    /// Routing Header (`NextHeader = 43`), with routing type and segments left.
    Routing {
        len: usize,
        routing_type: u8,
        segments_left: u8,
    },
    /// Fixed 8-byte Fragment Header (`NextHeader = 44`).
    Fragment {
        fragment_offset: u16,
        more_fragments: bool,
        identification: u32,
    },
    /// Destination Options (`NextHeader = 60`), with total byte length of the header.
    DestinationOptions { len: usize },
}

/// Walks an IPv6 extension header chain (`HopByHop = 0`, `Routing = 43`, `Fragment = 44`,
/// `DestinationOptions = 60`, `NoNextHeader = 59`) starting at `initial_next_header` and `payload`.
///
/// Returns `(upper_layer_protocol, upper_layer_payload_offset, parsed_extension_headers)`.
pub fn walk_extension_headers(
    initial_next_header: u8,
    payload: &[u8],
) -> Result<(u8, usize, Vec<Ipv6ExtensionHeader>), Ipv6Error> {
    let mut next_hdr = initial_next_header;
    let mut offset = 0usize;
    let mut chain = Vec::new();

    loop {
        match next_hdr {
            // Hop-by-Hop Options (0) or Destination Options (60)
            0 | 60 => {
                if offset + 2 > payload.len() {
                    return Err(Ipv6Error::TruncatedExtensionHeader);
                }
                let following = payload[offset];
                let hdr_ext_len = payload[offset + 1] as usize;
                let total_len = (hdr_ext_len + 1) * 8;
                if offset + total_len > payload.len() {
                    return Err(Ipv6Error::TruncatedExtensionHeader);
                }
                if next_hdr == 0 {
                    chain.push(Ipv6ExtensionHeader::HopByHop { len: total_len });
                } else {
                    chain.push(Ipv6ExtensionHeader::DestinationOptions { len: total_len });
                }
                next_hdr = following;
                offset += total_len;
            }
            // Routing Header (43)
            43 => {
                if offset + 4 > payload.len() {
                    return Err(Ipv6Error::TruncatedExtensionHeader);
                }
                let following = payload[offset];
                let hdr_ext_len = payload[offset + 1] as usize;
                let routing_type = payload[offset + 2];
                let segments_left = payload[offset + 3];
                let total_len = (hdr_ext_len + 1) * 8;
                if offset + total_len > payload.len() {
                    return Err(Ipv6Error::TruncatedExtensionHeader);
                }
                chain.push(Ipv6ExtensionHeader::Routing {
                    len: total_len,
                    routing_type,
                    segments_left,
                });
                next_hdr = following;
                offset += total_len;
            }
            // Fragment Header (44) - fixed 8 bytes
            44 => {
                if offset + 8 > payload.len() {
                    return Err(Ipv6Error::TruncatedExtensionHeader);
                }
                let following = payload[offset];
                let frag_off_flags = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
                let fragment_offset = frag_off_flags >> 3;
                let more_fragments = (frag_off_flags & 0x01) != 0;
                let identification = u32::from_be_bytes([
                    payload[offset + 4],
                    payload[offset + 5],
                    payload[offset + 6],
                    payload[offset + 7],
                ]);
                chain.push(Ipv6ExtensionHeader::Fragment {
                    fragment_offset,
                    more_fragments,
                    identification,
                });
                next_hdr = following;
                offset += 8;
            }
            // Upper-layer protocol (e.g., 6 = TCP, 17 = UDP, 58 = ICMPv6, 59 = No Next Header)
            upper => return Ok((upper, offset, chain)),
        }
    }
}

/// Runs self-tests for the `ipv6_core` module.
pub fn verify_net_ipv6_core() -> u32 {
    let mut passed = 0u32;

    // 1. Verify SLAAC Modified EUI-64 link-local generation.
    let mac = MacAddress::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E);
    let ll = Ipv6Addr::from_mac_slaac_link_local(mac);
    if ll.is_unicast_link_local()
        && ll.octets()[8..16] == [0x02, 0x1A, 0x2B, 0xFF, 0xFE, 0x3C, 0x4D, 0x5E]
    {
        passed += 1;
    }

    // 2. Verify Solicited-Node multicast computation.
    let sol = ll.solicited_node_multicast();
    if sol.is_multicast()
        && sol
            == Ipv6Addr([
                0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0x3C, 0x4D, 0x5E,
            ])
    {
        passed += 1;
    }

    // 3. Verify 40-byte IPv6 header serialization and parsing.
    let hdr = Ipv6Header {
        traffic_class: 0x28,
        flow_label: 0xABCDE,
        payload_len: 16,
        next_header: 0, // Hop-by-Hop
        hop_limit: 64,
        src_ip: ll,
        dst_ip: Ipv6Addr::ALL_NODES_LINK_LOCAL,
    };
    let mut wire = [0u8; 56];
    let _ = hdr.write_to(&mut wire[..40]);
    // 8-byte Hop-by-Hop header followed by 8-byte Fragment header followed by ICMPv6 (58)
    wire[40] = 44; // NextHeader = Fragment
    wire[41] = 0; // (0 + 1) * 8 = 8 bytes
    wire[48] = 58; // NextHeader = ICMPv6
    wire[49] = 0;
    wire[50..52].copy_from_slice(&((18u16 << 3) | 1).to_be_bytes());
    wire[52..56].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

    if let Ok((parsed, payload)) = Ipv6Header::parse(&wire) {
        if parsed == hdr {
            passed += 1;
        }
        if let Ok((upper, offset, chain)) = walk_extension_headers(parsed.next_header, payload) {
            let expected_hbh = Ipv6ExtensionHeader::HopByHop { len: 8 };
            let expected_frag = Ipv6ExtensionHeader::Fragment {
                fragment_offset: 18,
                more_fragments: true,
                identification: 0xDEAD_BEEF,
            };
            if upper == 58
                && offset == 16
                && chain.len() == 2
                && chain[0] == expected_hbh
                && chain[1] == expected_frag
            {
                passed += 1;
            }
        }
    }

    passed
}
