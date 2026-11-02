//! Internet Protocol Version 4 (IPv4 - RFC 791) Subsystem for CorOS.
//! 100% in-house implementation supporting header parsing, packet assembly,
//! RFC 1071 one's-complement checksum calculation, subnet matching, and routing table.

use alloc::vec::Vec;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8  = 6;
pub const IP_PROTO_UDP: u8  = 17;

pub const IP_FLAG_DONT_FRAGMENT: u16 = 0x4000;
pub const IP_FLAG_MORE_FRAGMENTS: u16= 0x2000;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Ipv4Header {
    pub ver_ihl: u8,          // Version (4 bits) | Internet Header Length (4 bits)
    pub dscp_ecn: u8,         // Differentiated Services / ECN
    pub total_len: u16,       // Total length in bytes (Header + Payload)
    pub identification: u16,  // Identification for fragmentation
    pub flags_fragment: u16,  // Flags (3 bits) | Fragment Offset (13 bits)
    pub ttl: u8,              // Time to Live
    pub protocol: u8,         // Protocol (TCP=6, UDP=17, ICMP=1)
    pub checksum: u16,        // Header Checksum
    pub src_ip: [u8; 4],      // Source IPv4 Address
    pub dst_ip: [u8; 4],      // Destination IPv4 Address
}

impl Ipv4Header {
    pub fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: u8,
        payload_len: usize,
        id: u16,
    ) -> Self {
        let total_len = (20 + payload_len) as u16;
        let mut hdr = Self {
            ver_ihl: (4 << 4) | 5, // IPv4, 5 x 32-bit words = 20 bytes
            dscp_ecn: 0,
            total_len: total_len.to_be(),
            identification: id.to_be(),
            flags_fragment: IP_FLAG_DONT_FRAGMENT.to_be(),
            ttl: 64,
            protocol,
            checksum: 0,
            src_ip,
            dst_ip,
        };

        hdr.checksum = hdr.calculate_checksum().to_be();
        hdr
    }

    pub fn version(&self) -> u8 {
        self.ver_ihl >> 4
    }

    pub fn ihl_bytes(&self) -> usize {
        ((self.ver_ihl & 0x0F) as usize) * 4
    }

    pub fn total_length(&self) -> usize {
        u16::from_be(self.total_len) as usize
    }

    pub fn calculate_checksum(&self) -> u16 {
        let ptr = self as *const _ as *const u16;
        let mut sum: u32 = 0;
        let words = 10; // 20 bytes = 10 16-bit words

        for i in 0..words {
            if i == 5 {
                // Skip checksum field itself
                continue;
            }
            let word = unsafe { u16::from_be(*ptr.add(i)) };
            sum += word as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    pub fn verify_checksum(&self) -> bool {
        let calculated = self.calculate_checksum();
        let current = u16::from_be(self.checksum);
        calculated == current
    }

    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 20 {
            return None;
        }
        let hdr = unsafe { *(bytes.as_ptr() as *const Ipv4Header) };
        if hdr.version() != 4 {
            return None;
        }
        let ihl = hdr.ihl_bytes();
        if bytes.len() < ihl {
            return None;
        }
        let total_len = hdr.total_length();
        if bytes.len() < total_len || total_len < ihl {
            return None;
        }

        if !hdr.verify_checksum() {
            return None;
        }

        let payload = &bytes[ihl..total_len];
        Some((hdr, payload))
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        let ptr = self as *const _ as *const u8;
        unsafe {
            for i in 0..20 {
                buf[i] = *ptr.add(i);
            }
        }
        buf
    }
}

// -----------------------------------------------------------------------------
// Routing Table
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct RouteEntry {
    pub destination: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: Option<[u8; 4]>,
    pub metric: u32,
    pub iface_name: &'static str,
}

pub struct RoutingTable {
    routes: Vec<RouteEntry>,
}

impl RoutingTable {
    pub const fn new() -> Self {
        Self {
            routes: Vec::new(),
        }
    }

    pub fn add_route(&mut self, dest: [u8; 4], mask: [u8; 4], gw: Option<[u8; 4]>, metric: u32, iface: &'static str) {
        self.routes.push(RouteEntry {
            destination: dest,
            netmask: mask,
            gateway: gw,
            metric,
            iface_name: iface,
        });
        // Sort by longest prefix match (most 1 bits in netmask) then lowest metric
        self.routes.sort_by(|a, b| {
            let a_ones = u32::from_be_bytes(a.netmask).count_ones();
            let b_ones = u32::from_be_bytes(b.netmask).count_ones();
            b_ones.cmp(&a_ones).then(a.metric.cmp(&b.metric))
        });
    }

    pub fn lookup(&self, target_ip: [u8; 4]) -> Option<&RouteEntry> {
        let target_u32 = u32::from_be_bytes(target_ip);
        for route in &self.routes {
            let mask_u32 = u32::from_be_bytes(route.netmask);
            let dest_u32 = u32::from_be_bytes(route.destination);
            if (target_u32 & mask_u32) == (dest_u32 & mask_u32) {
                return Some(route);
            }
        }
        None
    }
}
