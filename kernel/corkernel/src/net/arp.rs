//! Address Resolution Protocol (ARP - RFC 826) Subsystem for CorOS.
//! 100% in-house implementation supporting ARP request broadcasting,
//! reply processing, and dynamic ARP cache table with timeout tracking.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const ARP_HTYPE_ETHERNET: u16 = 0x0001;
pub const ARP_PTYPE_IPV4: u16     = 0x0800;

pub const ARP_OP_REQUEST: u16     = 0x0001;
pub const ARP_OP_REPLY: u16       = 0x0002;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ArpPacket {
    pub htype: u16,        // Hardware Type (Ethernet = 1)
    pub ptype: u16,        // Protocol Type (IPv4 = 0x0800)
    pub hlen: u8,          // Hardware Address Length (6)
    pub plen: u8,          // Protocol Address Length (4)
    pub oper: u16,         // Operation (Request = 1, Reply = 2)
    pub sha: [u8; 6],      // Sender Hardware Address (MAC)
    pub spa: [u8; 4],      // Sender Protocol Address (IPv4)
    pub tha: [u8; 6],      // Target Hardware Address (MAC)
    pub tpa: [u8; 4],      // Target Protocol Address (IPv4)
}

impl ArpPacket {
    pub fn new_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self {
            htype: ARP_HTYPE_ETHERNET.to_be(),
            ptype: ARP_PTYPE_IPV4.to_be(),
            hlen: 6,
            plen: 4,
            oper: ARP_OP_REQUEST.to_be(),
            sha: sender_mac,
            spa: sender_ip,
            tha: [0x00; 6],
            tpa: target_ip,
        }
    }

    pub fn new_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Self {
        Self {
            htype: ARP_HTYPE_ETHERNET.to_be(),
            ptype: ARP_PTYPE_IPV4.to_be(),
            hlen: 6,
            plen: 4,
            oper: ARP_OP_REPLY.to_be(),
            sha: sender_mac,
            spa: sender_ip,
            tha: target_mac,
            tpa: target_ip,
        }
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<ArpPacket>() {
            return None;
        }
        let pkt = unsafe { *(bytes.as_ptr() as *const ArpPacket) };
        if u16::from_be(pkt.htype) != ARP_HTYPE_ETHERNET || u16::from_be(pkt.ptype) != ARP_PTYPE_IPV4 {
            return None;
        }
        Some(pkt)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let size = core::mem::size_of::<ArpPacket>();
        let mut buf = Vec::with_capacity(size);
        let ptr = self as *const _ as *const u8;
        unsafe {
            for i in 0..size {
                buf.push(*ptr.add(i));
            }
        }
        buf
    }
}

// -----------------------------------------------------------------------------
// ARP Cache Table
// -----------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArpState {
    Incomplete,
    Reachable,
    Stale,
    Permanent,
}

#[derive(Clone, Debug)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub state: ArpState,
    pub timestamp: u64,
}

pub struct ArpTable {
    entries: BTreeMap<[u8; 4], ArpEntry>,
}

impl ArpTable {
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6], state: ArpState, timestamp: u64) {
        self.entries.insert(ip, ArpEntry {
            ip,
            mac,
            state,
            timestamp,
        });
    }

    pub fn lookup(&self, ip: &[u8; 4]) -> Option<[u8; 6]> {
        if let Some(entry) = self.entries.get(ip) {
            if entry.state == ArpState::Reachable || entry.state == ArpState::Permanent {
                return Some(entry.mac);
            }
        }
        None
    }

    pub fn process_incoming(&mut self, arp: &ArpPacket, now: u64) {
        let oper = u16::from_be(arp.oper);
        if oper == ARP_OP_REPLY || oper == ARP_OP_REQUEST {
            self.insert(arp.spa, arp.sha, ArpState::Reachable, now);
        }
    }

    pub fn garbage_collect(&mut self, now: u64, ttl_secs: u64) {
        self.entries.retain(|_, entry| {
            if entry.state == ArpState::Permanent {
                return true;
            }
            (now - entry.timestamp) < ttl_secs
        });
    }
}
