//! IPv4 ARP (RFC 826) Codec, ARP Cache with Pending Queue & IPv6 NDP (RFC 4861) Solicitation/Advertisement.

use crate::ethernet_mac::MacAddress;
use crate::ipv4_routing::Ipv4Addr;
use crate::ipv6_core::Ipv6Addr;
use alloc::vec::Vec;

/// ARP hardware type for IEEE 802.3 Ethernet (`1`).
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type for IPv4 (`0x0800`).
pub const ARP_PTYPE_IPV4: u16 = 0x0800;

/// ARP Operation Code (RFC 826).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOp {
    /// ARP Request (`1`).
    Request,
    /// ARP Reply (`2`).
    Reply,
    /// Other/unknown ARP opcode.
    Other(u16),
}

impl ArpOp {
    #[inline]
    pub const fn from_u16(code: u16) -> Self {
        match code {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Other(other),
        }
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::Other(code) => code,
        }
    }
}

/// Errors encountered while parsing or encoding ARP / NDP messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpNdpError {
    /// Buffer is too short for the protocol message.
    TruncatedPacket,
    /// Unsupported hardware type or protocol type in ARP header.
    UnsupportedHardwareOrProtocol { htype: u16, ptype: u16 },
    /// Invalid hardware or protocol address length (expected `6` and `4`).
    InvalidAddressLength { hlen: u8, plen: u8 },
    /// Unexpected ICMPv6 message type or non-zero code for NDP.
    InvalidNdpMessage { icmp_type: u8, code: u8 },
    /// Malformed NDP link-layer address option (length in 8-octet units must be 1 for Ethernet).
    InvalidNdpOption,
}

/// 28-byte IPv4-over-Ethernet ARP Packet (RFC 826).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: ArpOp,
    pub sender_hw_addr: MacAddress,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddress,
    pub target_proto_addr: Ipv4Addr,
}

impl ArpPacket {
    /// Wire size of an Ethernet/IPv4 ARP packet in bytes.
    pub const LEN: usize = 28;

    /// Constructs a broadcast ARP Request ("Who has `target_ip`? Tell `sender_ip`").
    #[inline]
    pub const fn new_request(
        sender_mac: MacAddress,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            operation: ArpOp::Request,
            sender_hw_addr: sender_mac,
            sender_proto_addr: sender_ip,
            target_hw_addr: MacAddress::ZERO,
            target_proto_addr: target_ip,
        }
    }

    /// Constructs a unicast ARP Reply ("`sender_ip` is at `sender_mac`").
    #[inline]
    pub const fn new_reply(
        sender_mac: MacAddress,
        sender_ip: Ipv4Addr,
        target_mac: MacAddress,
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            operation: ArpOp::Reply,
            sender_hw_addr: sender_mac,
            sender_proto_addr: sender_ip,
            target_hw_addr: target_mac,
            target_proto_addr: target_ip,
        }
    }

    /// Parses a 28-byte `ArpPacket` from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, ArpNdpError> {
        if buf.len() < Self::LEN {
            return Err(ArpNdpError::TruncatedPacket);
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 {
            return Err(ArpNdpError::UnsupportedHardwareOrProtocol { htype, ptype });
        }
        let hlen = buf[4];
        let plen = buf[5];
        if hlen != 6 || plen != 4 {
            return Err(ArpNdpError::InvalidAddressLength { hlen, plen });
        }
        let op = ArpOp::from_u16(u16::from_be_bytes([buf[6], buf[7]]));
        let sha = MacAddress([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13]]);
        let spa = Ipv4Addr([buf[14], buf[15], buf[16], buf[17]]);
        let tha = MacAddress([buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        let tpa = Ipv4Addr([buf[24], buf[25], buf[26], buf[27]]);

        Ok(Self {
            operation: op,
            sender_hw_addr: sha,
            sender_proto_addr: spa,
            target_hw_addr: tha,
            target_proto_addr: tpa,
        })
    }

    /// Serializes this 28-byte ARP packet into `out`.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, ArpNdpError> {
        if out.len() < Self::LEN {
            return Err(ArpNdpError::TruncatedPacket);
        }
        out[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.operation.as_u16().to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_hw_addr.0);
        out[14..18].copy_from_slice(&self.sender_proto_addr.0);
        out[18..24].copy_from_slice(&self.target_hw_addr.0);
        out[24..28].copy_from_slice(&self.target_proto_addr.0);
        Ok(Self::LEN)
    }
}

/// Resolution state of an entry in the ARP Neighbor Cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArpEntryState {
    /// ARP Request has been transmitted; awaiting ARP Reply while buffering outbound packets.
    Incomplete {
        retries_sent: u8,
        pending_packets: Vec<Vec<u8>>,
    },
    /// Hardware address is resolved and valid until `expires_at_tick`.
    Reachable {
        mac: MacAddress,
        expires_at_tick: u64,
    },
    /// Permanent static ARP entry that never expires.
    Permanent { mac: MacAddress },
}

/// A single neighbor entry in the IPv4 ARP cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpCacheEntry {
    pub ip: Ipv4Addr,
    pub state: ArpEntryState,
}

/// Stateful IPv4 ARP Cache with TTL expiration and pending outbound packet queue.
#[derive(Clone, Debug)]
pub struct ArpCache {
    entries: Vec<ArpCacheEntry>,
    default_ttl_ticks: u64,
    max_pending_per_ip: usize,
}

impl ArpCache {
    /// Creates a new ARP cache with the specified entry TTL (in ticks).
    pub const fn new(default_ttl_ticks: u64) -> Self {
        Self {
            entries: Vec::new(),
            default_ttl_ticks,
            max_pending_per_ip: 8,
        }
    }

    /// Looks up a resolved `MacAddress` for `ip` at `now_tick`.
    pub fn lookup(&self, ip: Ipv4Addr, now_tick: u64) -> Option<MacAddress> {
        for entry in &self.entries {
            if entry.ip == ip {
                return match entry.state {
                    ArpEntryState::Reachable {
                        mac,
                        expires_at_tick,
                    } if now_tick < expires_at_tick => Some(mac),
                    ArpEntryState::Permanent { mac } => Some(mac),
                    _ => None,
                };
            }
        }
        None
    }

    /// Enqueues a packet waiting for ARP resolution of `target_ip`.
    /// Returns `true` if the caller should transmit an ARP Request on the link.
    pub fn enqueue_pending(&mut self, target_ip: Ipv4Addr, packet: Vec<u8>) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.ip == target_ip) {
            match &mut entry.state {
                ArpEntryState::Incomplete {
                    retries_sent,
                    pending_packets,
                } => {
                    if pending_packets.len() < self.max_pending_per_ip {
                        pending_packets.push(packet);
                    }
                    *retries_sent = retries_sent.saturating_add(1);
                    return true;
                }
                _ => {
                    let mut q = Vec::new();
                    q.push(packet);
                    entry.state = ArpEntryState::Incomplete {
                        retries_sent: 1,
                        pending_packets: q,
                    };
                    return true;
                }
            }
        }

        let mut q = Vec::new();
        q.push(packet);
        self.entries.push(ArpCacheEntry {
            ip: target_ip,
            state: ArpEntryState::Incomplete {
                retries_sent: 1,
                pending_packets: q,
            },
        });
        true
    }

    /// Inserts or refreshes a learned `(ip, mac)` mapping at `now_tick`, returning any
    /// queued outbound packets that were waiting for this address to resolve.
    pub fn insert_resolved(
        &mut self,
        ip: Ipv4Addr,
        mac: MacAddress,
        now_tick: u64,
    ) -> Vec<Vec<u8>> {
        let expires_at_tick = now_tick.saturating_add(self.default_ttl_ticks);
        if let Some(entry) = self.entries.iter_mut().find(|e| e.ip == ip) {
            let drained = match &mut entry.state {
                ArpEntryState::Incomplete {
                    pending_packets, ..
                } => core::mem::take(pending_packets),
                ArpEntryState::Permanent { .. } => return Vec::new(),
                ArpEntryState::Reachable { .. } => Vec::new(),
            };
            entry.state = ArpEntryState::Reachable {
                mac,
                expires_at_tick,
            };
            return drained;
        }

        self.entries.push(ArpCacheEntry {
            ip,
            state: ArpEntryState::Reachable {
                mac,
                expires_at_tick,
            },
        });
        Vec::new()
    }

    /// Purges expired dynamic entries at `now_tick`, returning the number of evicted entries.
    pub fn expire_stale(&mut self, now_tick: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| match e.state {
            ArpEntryState::Reachable {
                expires_at_tick, ..
            } => now_tick < expires_at_tick,
            _ => true,
        });
        before - self.entries.len()
    }
}

/// ICMPv6 Type for Neighbor Solicitation (`135`).
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 Type for Neighbor Advertisement (`136`).
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// NDP Option Type 1: Source Link-Layer Address.
pub const NDP_OPT_SOURCE_LINK_ADDR: u8 = 1;
/// NDP Option Type 2: Target Link-Layer Address.
pub const NDP_OPT_TARGET_LINK_ADDR: u8 = 2;

/// IPv6 Neighbor Solicitation (RFC 4861 Section 4.3, ICMPv6 Type 135).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdpNeighborSolicitation {
    pub checksum: u16,
    pub target_addr: Ipv6Addr,
    pub source_link_mac: Option<MacAddress>,
}

impl NdpNeighborSolicitation {
    /// Minimum wire size (24 bytes without options, 32 bytes with 8-byte Source Link-Layer Option).
    pub const MIN_LEN: usize = 24;

    /// Parses an `NdpNeighborSolicitation` from an ICMPv6 payload slice.
    pub fn parse(buf: &[u8]) -> Result<Self, ArpNdpError> {
        if buf.len() < Self::MIN_LEN {
            return Err(ArpNdpError::TruncatedPacket);
        }
        if buf[0] != ICMPV6_NEIGHBOR_SOLICITATION || buf[1] != 0 {
            return Err(ArpNdpError::InvalidNdpMessage {
                icmp_type: buf[0],
                code: buf[1],
            });
        }
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        let mut target = [0u8; 16];
        target.copy_from_slice(&buf[8..24]);

        let mut source_link_mac = None;
        if buf.len() >= 32 {
            let opt_type = buf[24];
            let opt_len_units = buf[25];
            if opt_type == NDP_OPT_SOURCE_LINK_ADDR {
                if opt_len_units != 1 {
                    return Err(ArpNdpError::InvalidNdpOption);
                }
                source_link_mac = Some(MacAddress([
                    buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
                ]));
            }
        }

        Ok(Self {
            checksum,
            target_addr: Ipv6Addr(target),
            source_link_mac,
        })
    }

    /// Serializes this Neighbor Solicitation into `out` (24 or 32 bytes).
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, ArpNdpError> {
        let needed = if self.source_link_mac.is_some() { 32 } else { 24 };
        if out.len() < needed {
            return Err(ArpNdpError::TruncatedPacket);
        }
        out[0] = ICMPV6_NEIGHBOR_SOLICITATION;
        out[1] = 0;
        out[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        out[4..8].fill(0); // Reserved
        out[8..24].copy_from_slice(&self.target_addr.0);
        if let Some(mac) = self.source_link_mac {
            out[24] = NDP_OPT_SOURCE_LINK_ADDR;
            out[25] = 1; // 1 * 8 bytes
            out[26..32].copy_from_slice(&mac.0);
        }
        Ok(needed)
    }
}

/// IPv6 Neighbor Advertisement (RFC 4861 Section 4.4, ICMPv6 Type 136).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdpNeighborAdvertisement {
    pub checksum: u16,
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target_addr: Ipv6Addr,
    pub target_link_mac: Option<MacAddress>,
}

impl NdpNeighborAdvertisement {
    pub const MIN_LEN: usize = 24;

    /// Parses an `NdpNeighborAdvertisement` from an ICMPv6 payload slice.
    pub fn parse(buf: &[u8]) -> Result<Self, ArpNdpError> {
        if buf.len() < Self::MIN_LEN {
            return Err(ArpNdpError::TruncatedPacket);
        }
        if buf[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT || buf[1] != 0 {
            return Err(ArpNdpError::InvalidNdpMessage {
                icmp_type: buf[0],
                code: buf[1],
            });
        }
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        let flags = buf[4];
        let router_flag = (flags & 0x80) != 0;
        let solicited_flag = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;
        let mut target = [0u8; 16];
        target.copy_from_slice(&buf[8..24]);

        let mut target_link_mac = None;
        if buf.len() >= 32 {
            let opt_type = buf[24];
            let opt_len_units = buf[25];
            if opt_type == NDP_OPT_TARGET_LINK_ADDR {
                if opt_len_units != 1 {
                    return Err(ArpNdpError::InvalidNdpOption);
                }
                target_link_mac = Some(MacAddress([
                    buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
                ]));
            }
        }

        Ok(Self {
            checksum,
            router_flag,
            solicited_flag,
            override_flag,
            target_addr: Ipv6Addr(target),
            target_link_mac,
        })
    }

    /// Serializes this Neighbor Advertisement into `out` (24 or 32 bytes).
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, ArpNdpError> {
        let needed = if self.target_link_mac.is_some() { 32 } else { 24 };
        if out.len() < needed {
            return Err(ArpNdpError::TruncatedPacket);
        }
        out[0] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
        out[1] = 0;
        out[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        out[4] = ((self.router_flag as u8) << 7)
            | ((self.solicited_flag as u8) << 6)
            | ((self.override_flag as u8) << 5);
        out[5..8].fill(0);
        out[8..24].copy_from_slice(&self.target_addr.0);
        if let Some(mac) = self.target_link_mac {
            out[24] = NDP_OPT_TARGET_LINK_ADDR;
            out[25] = 1;
            out[26..32].copy_from_slice(&mac.0);
        }
        Ok(needed)
    }
}

/// Runs self-tests for the `arp_ndp` module.
pub fn verify_net_arp_ndp() -> u32 {
    let mut passed = 0u32;

    // 1. Verify ARP Request / Reply wire serialization & parsing.
    let host_mac = MacAddress::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
    let host_ip = Ipv4Addr::new(10, 0, 2, 15);
    let gw_ip = Ipv4Addr::new(10, 0, 2, 2);
    let req = ArpPacket::new_request(host_mac, host_ip, gw_ip);
    let mut wire = [0u8; 28];
    if req.write_to(&mut wire).is_ok() {
        if let Ok(parsed) = ArpPacket::parse(&wire) {
            if parsed == req && parsed.operation == ArpOp::Request {
                passed += 1;
            }
        }
    }

    // 2. Verify ARP Cache pending packet queue and TTL expiration.
    let mut cache = ArpCache::new(100);
    let _ = cache.enqueue_pending(gw_ip, alloc::vec![0xAA, 0xBB]);
    let _ = cache.enqueue_pending(gw_ip, alloc::vec![0xCC, 0xDD]);
    let gw_mac = MacAddress::new(0x52, 0x55, 0x0A, 0x00, 0x02, 0x02);
    let flushed = cache.insert_resolved(gw_ip, gw_mac, 50);
    if flushed.len() == 2
        && cache.lookup(gw_ip, 149) == Some(gw_mac)
        && cache.lookup(gw_ip, 150).is_none()
        && cache.expire_stale(150) == 1
    {
        passed += 1;
    }

    // 3. Verify IPv6 NDP Neighbor Solicitation and Advertisement codecs.
    let target_v6 = Ipv6Addr::from_mac_slaac_link_local(gw_mac);
    let ns = NdpNeighborSolicitation {
        checksum: 0x1234,
        target_addr: target_v6,
        source_link_mac: Some(host_mac),
    };
    let mut ns_buf = [0u8; 32];
    if ns.write_to(&mut ns_buf).is_ok() && NdpNeighborSolicitation::parse(&ns_buf) == Ok(ns) {
        passed += 1;
    }

    let na = NdpNeighborAdvertisement {
        checksum: 0x5678,
        router_flag: true,
        solicited_flag: true,
        override_flag: true,
        target_addr: target_v6,
        target_link_mac: Some(gw_mac),
    };
    let mut na_buf = [0u8; 32];
    if na.write_to(&mut na_buf).is_ok() && NdpNeighborAdvertisement::parse(&na_buf) == Ok(na) {
        passed += 1;
    }

    passed
}
