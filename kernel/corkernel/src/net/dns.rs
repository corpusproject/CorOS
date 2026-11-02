//! RFC 1035 Domain Name System (DNS) Client & Cache Engine for CorOS.
//! 100% in-house implementation supporting DNS query formatting,
//! label compression traversal, Type A IPv4 record extraction, and TTL cache.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const DNS_TYPE_A: u16     = 1;
pub const DNS_CLASS_IN: u16   = 1;
pub const DNS_PORT: u16       = 53;

// DNS Header Flags
pub const DNS_FLAG_RD: u16    = 1 << 8;  // Recursion Desired
pub const DNS_FLAG_QR: u16    = 1 << 15; // Query (0) / Response (1)

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16, // Question count
    pub an_count: u16, // Answer record count
    pub ns_count: u16, // Authority record count
    pub ar_count: u16, // Additional record count
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        Self {
            id: id.to_be(),
            flags: DNS_FLAG_RD.to_be(),
            qd_count: (1u16).to_be(),
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
}

pub struct DnsClient;

impl DnsClient {
    /// Build a DNS query packet for an A record of given domain e.g. "www.example.com".
    pub fn build_query(domain: &str, tx_id: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // 1. Header (12 bytes)
        let hdr = DnsHeader::new_query(tx_id);
        let ptr = &hdr as *const _ as *const u8;
        unsafe {
            for i in 0..12 {
                pkt.push(*ptr.add(i));
            }
        }

        // 2. Question QNAME (e.g. 3www7example3com0)
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label null terminator

        // 3. QTYPE (Type A = 1)
        pkt.extend_from_slice(&DNS_TYPE_A.to_be_bytes());

        // 4. QCLASS (Class IN = 1)
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        pkt
    }

    /// Parse a DNS response and extract first IPv4 address.
    pub fn parse_response(bytes: &[u8]) -> Option<[u8; 4]> {
        if bytes.len() < 12 {
            return None;
        }

        let hdr = unsafe { *(bytes.as_ptr() as *const DnsHeader) };
        let flags = u16::from_be(hdr.flags);
        let an_count = u16::from_be(hdr.an_count);

        if (flags & DNS_FLAG_QR) == 0 || an_count == 0 {
            return None; // Not a response or 0 answers
        }

        let mut offset = 12;

        // Skip Question Section
        let qd_count = u16::from_be(hdr.qd_count);
        for _ in 0..qd_count {
            while offset < bytes.len() {
                let len = bytes[offset] as usize;
                offset += 1;
                if len == 0 {
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    offset += 1; // Compression offset
                    break;
                }
                offset += len;
            }
            offset += 4; // Skip QTYPE and QCLASS
        }

        // Parse Answer Section
        for _ in 0..an_count {
            if offset >= bytes.len() {
                break;
            }

            // Skip Name (can be compressed or label)
            if (bytes[offset] & 0xC0) == 0xC0 {
                offset += 2;
            } else {
                while offset < bytes.len() {
                    let len = bytes[offset] as usize;
                    offset += 1;
                    if len == 0 {
                        break;
                    }
                    offset += len;
                }
            }

            if offset + 10 > bytes.len() {
                return None;
            }

            let rtype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let _rclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let _ttl = u32::from_be_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]);
            let rdlen = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
            offset += 10;

            if rtype == DNS_TYPE_A && rdlen == 4 && offset + 4 <= bytes.len() {
                return Some([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]);
            }

            offset += rdlen;
        }

        None
    }
}

// -----------------------------------------------------------------------------
// DNS In-Memory Cache
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct DnsCacheEntry {
    pub ip: [u8; 4],
    pub expires_at: u64,
}

pub struct DnsCache {
    entries: BTreeMap<String, DnsCacheEntry>,
}

impl DnsCache {
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, ip: [u8; 4], ttl_secs: u64, now: u64) {
        self.entries.insert(String::from(domain), DnsCacheEntry {
            ip,
            expires_at: now + ttl_secs,
        });
    }

    pub fn lookup(&self, domain: &str, now: u64) -> Option<[u8; 4]> {
        if let Some(entry) = self.entries.get(domain) {
            if entry.expires_at > now {
                return Some(entry.ip);
            }
        }
        None
    }

    pub fn purge_expired(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }
}
