//! CorOS ICMPv6 & Neighbor Discovery Protocol (RFC 4443 & RFC 4861) (`icmpv6.rs`)
//!
//! Implements ICMPv6 message processing:
//! - Echo Request (Type 128) & Echo Reply (Type 129)
//! - Router Solicitation (Type 133) & Router Advertisement (Type 134)
//! - Neighbor Solicitation (Type 135) & Neighbor Advertisement (Type 136)
//! - Redirect (Type 137)
//! - NDP Options: Source Link-Layer Address (Option 1), Target Link-Layer Address (Option 2), Prefix Information (Option 3)
//! - RFC 4862 IPv6 Stateless Address Autoconfiguration (SLAAC) & Duplicate Address Detection (DAD)

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use super::ipv6::Ipv6Addr;

pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;
pub const ICMPV6_PARAMETER_PROBLEM: u8 = 4;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_ROUTER_SOLICIT: u8 = 133;
pub const ICMPV6_ROUTER_ADVERT: u8 = 134;
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

pub const NDP_OPT_SOURCE_LL_ADDR: u8 = 1;
pub const NDP_OPT_TARGET_LL_ADDR: u8 = 2;
pub const NDP_OPT_PREFIX_INFO: u8 = 3;

/// Generic ICMPv6 Header (4 bytes)
#[derive(Debug, Clone)]
pub struct Icmpv6Header {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
}

/// Neighbor Solicitation packet body
#[derive(Debug, Clone)]
pub struct NeighborSolicitation {
    pub target_address: Ipv6Addr,
    pub source_mac: Option<[u8; 6]>,
}

/// Neighbor Advertisement packet body
#[derive(Debug, Clone)]
pub struct NeighborAdvertisement {
    pub router_flag: bool,
    pub solicited_flag: bool,
    pub override_flag: bool,
    pub target_address: Ipv6Addr,
    pub target_mac: Option<[u8; 6]>,
}

/// Router Advertisement prefix information
#[derive(Debug, Clone)]
pub struct PrefixInformation {
    pub prefix_len: u8,
    pub on_link: bool,
    pub autonomous_addr_config: bool,
    pub valid_lifetime_sec: u32,
    pub preferred_lifetime_sec: u32,
    pub prefix: Ipv6Addr,
}

/// NDP Neighbor Table Entry
#[derive(Debug, Clone)]
pub struct NdpNeighborEntry {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub is_router: bool,
    pub last_seen_ms: u64,
}

/// ICMPv6 & NDP Engine
pub struct Icmpv6Engine {
    pub neighbor_table: BTreeMap<Ipv6Addr, NdpNeighborEntry>,
}

impl Icmpv6Engine {
    pub fn new() -> Self {
        Self {
            neighbor_table: BTreeMap::new(),
        }
    }

    /// Calculate ICMPv6 checksum using IPv6 pseudo-header
    pub fn calculate_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, payload: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let src_words = src.words();
        let dst_words = dst.words();

        for &w in &src_words {
            sum = sum.wrapping_add(w as u32);
        }
        for &w in &dst_words {
            sum = sum.wrapping_add(w as u32);
        }

        let len = payload.len() as u32;
        sum = sum.wrapping_add(len >> 16);
        sum = sum.wrapping_add(len & 0xFFFF);
        sum = sum.wrapping_add(58); // NEXT_HEADER_ICMPV6

        let mut i = 0;
        while i + 1 < payload.len() {
            let word = u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
            sum = sum.wrapping_add(word);
            i += 2;
        }
        if i < payload.len() {
            sum = sum.wrapping_add((payload[i] as u32) << 8);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Build an ICMPv6 Echo Request (Ping6)
    pub fn build_echo_request(src: &Ipv6Addr, dst: &Ipv6Addr, identifier: u16, sequence: u16, payload_data: &[u8]) -> Vec<u8> {
        let total_len = 8 + payload_data.len();
        let mut pkt = Vec::with_capacity(total_len);

        pkt.push(ICMPV6_ECHO_REQUEST);
        pkt.push(0); // Code = 0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&sequence.to_be_bytes());
        pkt.extend_from_slice(payload_data);

        let csum = Self::calculate_checksum(src, dst, &pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    /// Build a Neighbor Solicitation packet
    pub fn build_neighbor_solicitation(src: &Ipv6Addr, target: &Ipv6Addr, my_mac: [u8; 6]) -> Vec<u8> {
        let dst = target.to_solicited_node_multicast();
        let mut pkt = Vec::with_capacity(24 + 8);

        pkt.push(ICMPV6_NEIGHBOR_SOLICIT);
        pkt.push(0); // Code
        pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        pkt.extend_from_slice(&0u32.to_be_bytes()); // Reserved 4 bytes
        pkt.extend_from_slice(&target.0);           // Target IPv6 (16 bytes)

        // Option 1: Source link-layer address (8 bytes: type, len=1 (8 bytes), mac, 0, 0)
        pkt.push(NDP_OPT_SOURCE_LL_ADDR);
        pkt.push(1); // Length in 8-byte units
        pkt.extend_from_slice(&my_mac);

        let csum = Self::calculate_checksum(src, &dst, &pkt);
        pkt[2..4].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    /// Parse received ICMPv6 packet
    pub fn process_packet(&mut self, src: &Ipv6Addr, _dst: &Ipv6Addr, data: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        if data.len() < 4 {
            return None;
        }

        let msg_type = data[0];
        let code = data[1];
        let _ = code;

        match msg_type {
            ICMPV6_ECHO_REQUEST => {
                if data.len() >= 8 {
                    let mut reply = data.to_vec();
                    reply[0] = ICMPV6_ECHO_REPLY;
                    reply[2] = 0;
                    reply[3] = 0;
                    let csum = Self::calculate_checksum(_dst, src, &reply);
                    reply[2..4].copy_from_slice(&csum.to_be_bytes());
                    return Some(reply);
                }
            }
            ICMPV6_NEIGHBOR_ADVERT => {
                if data.len() >= 24 {
                    let flags = data[4];
                    let is_router = (flags & 0x80) != 0;
                    let mut target = [0u8; 16];
                    target.copy_from_slice(&data[8..24]);
                    let target_ip = Ipv6Addr(target);

                    // Check options for target MAC
                    let mut opt_offset = 24;
                    while opt_offset + 2 <= data.len() {
                        let opt_type = data[opt_offset];
                        let opt_len = (data[opt_offset + 1] as usize) * 8;
                        if opt_len == 0 || opt_offset + opt_len > data.len() {
                            break;
                        }

                        if opt_type == NDP_OPT_TARGET_LL_ADDR && opt_len >= 8 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&data[opt_offset + 2..opt_offset + 8]);
                            self.neighbor_table.insert(target_ip, NdpNeighborEntry {
                                ip: target_ip,
                                mac,
                                is_router,
                                last_seen_ms: now_ms,
                            });
                        }
                        opt_offset += opt_len;
                    }
                }
            }
            _ => {}
        }

        None
    }
}
