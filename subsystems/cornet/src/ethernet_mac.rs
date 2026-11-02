//! IEEE 802.3 Ethernet II MAC Framing, IEEE 802.1Q VLAN Tagging & FCS CRC-32.

use alloc::vec::Vec;
use core::fmt;

/// A 48-bit (6-octet) IEEE 802 MAC hardware address.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// All-zero unspecified hardware address (`00:00:00:00:00:00`).
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);
    /// Layer-2 broadcast address (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: Self = Self([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    /// Constructs a `MacAddress` from six octets.
    #[inline]
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }

    /// Returns the raw 6-byte array representation.
    #[inline]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Returns `true` if this is the all-ones broadcast address.
    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 0xFF
            && self.0[1] == 0xFF
            && self.0[2] == 0xFF
            && self.0[3] == 0xFF
            && self.0[4] == 0xFF
            && self.0[5] == 0xFF
    }

    /// Returns `true` if the I/G (Individual/Group) bit of the first octet is set.
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    /// Returns `true` if the address is unicast (I/G bit is 0 and not all zeros).
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        (self.0[0] & 0x01) == 0 && !self.is_zero()
    }

    /// Returns `true` if the U/L (Universal/Local) bit of the first octet is set.
    #[inline]
    pub const fn is_locally_administered(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }

    /// Returns `true` if all 6 octets are zero.
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.0[0] == 0
            && self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && self.0[4] == 0
            && self.0[5] == 0
    }

    /// Returns the 24-bit Organizationally Unique Identifier (OUI).
    #[inline]
    pub const fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Maps an IPv4 multicast group (`224.0.0.0/4`) into its IEEE 802.3 multicast MAC
    /// (`01:00:5e:xx:xx:xx`, masking the lower 23 bits of the IPv4 address).
    #[inline]
    pub const fn from_ipv4_multicast(ip: [u8; 4]) -> Self {
        Self([0x01, 0x00, 0x5E, ip[1] & 0x7F, ip[2], ip[3]])
    }

    /// Maps an IPv6 multicast address (`ff00::/8`) into its IEEE 802.3 multicast MAC
    /// (`33:33:xx:xx:xx:xx`, using the low 32 bits of the IPv6 address).
    #[inline]
    pub const fn from_ipv6_multicast(last_four: [u8; 4]) -> Self {
        Self([0x33, 0x33, last_four[0], last_four[1], last_four[2], last_four[3]])
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// IEEE 802.3 / Ethernet II 16-bit EtherType protocol identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EtherType {
    /// Internet Protocol version 4 (`0x0800`).
    IPv4,
    /// Address Resolution Protocol (`0x0806`).
    Arp,
    /// IEEE 802.1Q Customer VLAN Tag (`0x8100`).
    Vlan,
    /// Internet Protocol version 6 (`0x86DD`).
    IPv6,
    /// IEEE 802.1ad Provider Bridge S-Tag (`0x88A8`).
    QinQ,
    /// Link Layer Discovery Protocol (`0x88CC`).
    Lldp,
    /// Precision Time Protocol (`0x88F7`).
    Ptp,
    /// Unrecognized or proprietary EtherType value.
    Unknown(u16),
}

impl EtherType {
    /// Converts a raw big-endian `u16` protocol number into an `EtherType`.
    #[inline]
    pub const fn from_u16(code: u16) -> Self {
        match code {
            0x0800 => Self::IPv4,
            0x0806 => Self::Arp,
            0x8100 => Self::Vlan,
            0x86DD => Self::IPv6,
            0x88A8 => Self::QinQ,
            0x88CC => Self::Lldp,
            0x88F7 => Self::Ptp,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw 16-bit wire value for this `EtherType`.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::IPv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Vlan => 0x8100,
            Self::IPv6 => 0x86DD,
            Self::QinQ => 0x88A8,
            Self::Lldp => 0x88CC,
            Self::Ptp => 0x88F7,
            Self::Unknown(code) => code,
        }
    }
}

/// IEEE 802.1Q VLAN Tag Control Information (TCI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VlanTag {
    /// 3-bit Priority Code Point (PCP, 0..=7).
    pub pcp: u8,
    /// 1-bit Drop Eligible Indicator (DEI).
    pub dei: bool,
    /// 12-bit VLAN Identifier (VID, 0..=4095).
    pub vid: u16,
}

impl VlanTag {
    /// Creates a new 802.1Q VLAN tag, masking fields to their specification widths.
    #[inline]
    pub const fn new(pcp: u8, dei: bool, vid: u16) -> Self {
        Self {
            pcp: pcp & 0x07,
            dei,
            vid: vid & 0x0FFF,
        }
    }

    /// Encodes the TCI into a 16-bit integer `(PCP << 13) | (DEI << 12) | VID`.
    #[inline]
    pub const fn to_tci(self) -> u16 {
        ((self.pcp as u16 & 0x07) << 13) | ((self.dei as u16) << 12) | (self.vid & 0x0FFF)
    }

    /// Decodes a 16-bit TCI value into a `VlanTag`.
    #[inline]
    pub const fn from_tci(tci: u16) -> Self {
        Self {
            pcp: ((tci >> 13) & 0x07) as u8,
            dei: ((tci >> 12) & 0x01) != 0,
            vid: tci & 0x0FFF,
        }
    }
}

/// Errors encountered while parsing or building an Ethernet II frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthernetError {
    /// Frame buffer is shorter than the minimum header length (14 or 18 bytes).
    TruncatedHeader,
    /// Frame buffer is too short to contain the trailing 4-byte FCS.
    TruncatedFcs,
    /// Calculated IEEE 802.3 CRC-32 did not match the frame's trailing FCS.
    FcsMismatch { expected: u32, actual: u32 },
    /// Reserved VLAN identifier (`0xFFF`) encountered.
    InvalidVlanId,
}

/// Parsed Ethernet II frame header (14 bytes untagged, 18 bytes with 802.1Q tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetFrameHeader {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub vlan_tag: Option<VlanTag>,
    pub ether_type: EtherType,
}

impl EthernetFrameHeader {
    /// Size of an untagged Ethernet II header in bytes.
    pub const UNTAGGED_LEN: usize = 14;
    /// Size of a single-tagged 802.1Q Ethernet header in bytes.
    pub const VLAN_TAGGED_LEN: usize = 18;

    /// Returns the wire length of this header (`14` or `18` bytes).
    #[inline]
    pub const fn header_len(&self) -> usize {
        if self.vlan_tag.is_some() {
            Self::VLAN_TAGGED_LEN
        } else {
            Self::UNTAGGED_LEN
        }
    }

    /// Parses an `EthernetFrameHeader` from the start of `buf`, returning `(header, payload_offset)`.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), EthernetError> {
        if buf.len() < Self::UNTAGGED_LEN {
            return Err(EthernetError::TruncatedHeader);
        }

        let dst_mac = MacAddress([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]);
        let src_mac = MacAddress([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);
        let first_proto = u16::from_be_bytes([buf[12], buf[13]]);

        if first_proto == EtherType::Vlan.as_u16() {
            if buf.len() < Self::VLAN_TAGGED_LEN {
                return Err(EthernetError::TruncatedHeader);
            }
            let tci = u16::from_be_bytes([buf[14], buf[15]]);
            let vlan = VlanTag::from_tci(tci);
            if vlan.vid == 0x0FFF {
                return Err(EthernetError::InvalidVlanId);
            }
            let inner_proto = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((
                Self {
                    dst_mac,
                    src_mac,
                    vlan_tag: Some(vlan),
                    ether_type: EtherType::from_u16(inner_proto),
                },
                Self::VLAN_TAGGED_LEN,
            ))
        } else {
            Ok((
                Self {
                    dst_mac,
                    src_mac,
                    vlan_tag: None,
                    ether_type: EtherType::from_u16(first_proto),
                },
                Self::UNTAGGED_LEN,
            ))
        }
    }

    /// Serializes this header into `out`, returning the number of bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, EthernetError> {
        let needed = self.header_len();
        if out.len() < needed {
            return Err(EthernetError::TruncatedHeader);
        }
        out[0..6].copy_from_slice(&self.dst_mac.0);
        out[6..12].copy_from_slice(&self.src_mac.0);

        if let Some(vlan) = self.vlan_tag {
            out[12..14].copy_from_slice(&EtherType::Vlan.as_u16().to_be_bytes());
            out[14..16].copy_from_slice(&vlan.to_tci().to_be_bytes());
            out[16..18].copy_from_slice(&self.ether_type.as_u16().to_be_bytes());
        } else {
            out[12..14].copy_from_slice(&self.ether_type.as_u16().to_be_bytes());
        }
        Ok(needed)
    }

    /// Builds a complete Ethernet II frame (header + payload + optional 4-byte FCS).
    pub fn build_frame(&self, payload: &[u8], append_fcs: bool) -> Vec<u8> {
        let hdr_len = self.header_len();
        let total_len = hdr_len + payload.len() + if append_fcs { 4 } else { 0 };
        let mut frame = Vec::with_capacity(total_len);
        frame.resize(hdr_len, 0);
        let _ = self.write_to(&mut frame[..hdr_len]);
        frame.extend_from_slice(payload);
        if append_fcs {
            let crc = crc32_ieee8023(&frame);
            frame.extend_from_slice(&crc.to_le_bytes());
        }
        frame
    }
}

/// Computes the standard IEEE 802.3 Frame Check Sequence (CRC-32, reflected polynomial `0xEDB88320`).
pub fn crc32_ieee8023(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Verifies a frame buffer whose final 4 bytes contain a little-endian IEEE 802.3 FCS.
pub fn verify_frame_fcs(frame_with_fcs: &[u8]) -> Result<&[u8], EthernetError> {
    if frame_with_fcs.len() < EthernetFrameHeader::UNTAGGED_LEN + 4 {
        return Err(EthernetError::TruncatedFcs);
    }
    let split = frame_with_fcs.len() - 4;
    let body = &frame_with_fcs[..split];
    let expected = u32::from_le_bytes([
        frame_with_fcs[split],
        frame_with_fcs[split + 1],
        frame_with_fcs[split + 2],
        frame_with_fcs[split + 3],
    ]);
    let actual = crc32_ieee8023(body);
    if expected == actual {
        Ok(body)
    } else {
        Err(EthernetError::FcsMismatch { expected, actual })
    }
}

/// Runs self-tests for the `ethernet_mac` module.
pub fn verify_net_ethernet_mac() -> u32 {
    let mut passed = 0u32;

    let src = MacAddress::new(0x02, 0x42, 0xAC, 0x11, 0x00, 0x02);
    let dst = MacAddress::BROADCAST;
    if src.is_unicast() && src.is_locally_administered() && dst.is_broadcast() && dst.is_multicast() {
        passed += 1;
    }

    let mcast_v4 = MacAddress::from_ipv4_multicast([224, 0, 0, 251]);
    if mcast_v4 == MacAddress::new(0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB) && mcast_v4.is_multicast() {
        passed += 1;
    }

    // Standard IEEE 802.3 CRC-32 check value for ASCII "123456789" is 0xCBF43926.
    if crc32_ieee8023(b"123456789") == 0xCBF4_3926 {
        passed += 1;
    }

    let vlan = VlanTag::new(5, true, 100);
    let hdr = EthernetFrameHeader {
        dst_mac: dst,
        src_mac: src,
        vlan_tag: Some(vlan),
        ether_type: EtherType::IPv4,
    };
    let payload = [0x45, 0x00, 0x00, 0x14];
    let wire = hdr.build_frame(&payload, true);

    if let Ok(stripped) = verify_frame_fcs(&wire) {
        if let Ok((parsed, offset)) = EthernetFrameHeader::parse(stripped) {
            if parsed == hdr && offset == 18 && &stripped[offset..] == &payload {
                passed += 1;
            }
        }
    }

    passed
}
