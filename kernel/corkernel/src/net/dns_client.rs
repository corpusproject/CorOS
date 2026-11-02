//! CorOS RFC 1035 Domain Name System (DNS) Client Resolver (`dns_client.rs`)
//!
//! Provides comprehensive DNS name resolution:
//! - DNS Header formatting (ID, QR, Opcode, AA, TC, RD, RA, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
//! - Query Types: A (IPv4 = 1), AAAA (IPv6 = 28), CNAME (Canonical Name = 5), PTR (Pointer = 12), MX (Mail = 15)
//! - Query Classes: IN (Internet = 1)
//! - Label-length string serialization (`www.google.com` -> `\x03www\x06google\x03com\x00`)
//! - RFC 1035 Pointer Decompression (`0xC000` bit-mask offset unpacking)
//! - In-memory DNS cache with TTL expiration tracking

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use super::ipv6::Ipv6Addr;

pub const DNS_PORT: u16 = 53;

/// DNS Record Types
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;

pub const DNS_CLASS_IN: u16 = 1;

/// DNS Header Flags
pub const DNS_FLAG_RD: u16 = 0x0100; // Recursion Desired
pub const DNS_FLAG_RA: u16 = 0x0080; // Recursion Available
pub const DNS_FLAG_QR: u16 = 0x8000; // 0 = Query, 1 = Response

/// Parsed DNS Resource Record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsRecord {
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        if self.rtype == DNS_TYPE_A && self.data.len() == 4 {
            Some([self.data[0], self.data[1], self.data[2], self.data[3]])
        } else {
            None
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rtype == DNS_TYPE_AAAA && self.data.len() == 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.data);
            Some(Ipv6Addr(b))
        } else {
            None
        }
    }
}

/// DNS Cache Entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<Ipv6Addr>,
    pub expires_at_ms: u64,
}

/// Complete DNS Client Engine
pub struct DnsClient {
    pub dns_server_ipv4: [u8; 4],
    cache: BTreeMap<String, DnsCacheEntry>,
    next_tx_id: u16,
}

impl DnsClient {
    pub fn new(server_ip: [u8; 4]) -> Self {
        Self {
            dns_server_ipv4: server_ip,
            cache: BTreeMap::new(),
            next_tx_id: 0x1234,
        }
    }

    /// Build raw DNS Query packet
    pub fn build_query(&mut self, hostname: &str, qtype: u16) -> (u16, Vec<u8>) {
        let tx_id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);

        let mut pkt = Vec::with_capacity(64);

        // 12-byte DNS Header
        pkt.extend_from_slice(&tx_id.to_be_bytes());
        pkt.extend_from_slice(&DNS_FLAG_RD.to_be_bytes()); // Recursion Desired
        pkt.extend_from_slice(&1u16.to_be_bytes());         // QDCOUNT = 1
        pkt.extend_from_slice(&0u16.to_be_bytes());         // ANCOUNT = 0
        pkt.extend_from_slice(&0u16.to_be_bytes());         // NSCOUNT = 0
        pkt.extend_from_slice(&0u16.to_be_bytes());         // ARCOUNT = 0

        // Question: QNAME
        for label in hostname.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Zero byte terminator

        // QTYPE and QCLASS
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        (tx_id, pkt)
    }

    /// Parse DNS Name with pointer compression support
    pub fn parse_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut jumped = false;
        let mut original_offset = 0;
        let mut jumps_taken = 0;

        loop {
            if offset >= buf.len() || jumps_taken > 10 {
                return None;
            }

            let len = buf[offset];
            if len == 0 {
                if !jumped {
                    offset += 1;
                }
                break;
            }

            // Check if 2 highest bits are set: 0xC0 indicates a compression pointer
            if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return None;
                }
                let ptr = (((len & 0x3F) as usize) << 8) | (buf[offset + 1] as usize);
                if !jumped {
                    original_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr;
                jumps_taken += 1;
                continue;
            }

            // Regular label
            offset += 1;
            let label_len = len as usize;
            if offset + label_len > buf.len() {
                return None;
            }

            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&buf[offset..offset + label_len]));
            offset += label_len;
        }

        let final_offset = if jumped { original_offset } else { offset };
        Some((name, final_offset))
    }

    /// Parse complete DNS Response packet
    pub fn parse_response(&mut self, buf: &[u8], now_ms: u64) -> Option<Vec<DnsRecord>> {
        if buf.len() < 12 {
            return None;
        }

        let _tx_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qd_count = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let an_count = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        // Verify this is a response (QR == 1) and no error (RCODE == 0)
        if (flags & DNS_FLAG_QR) == 0 || (flags & 0x000F) != 0 {
            return None;
        }

        let mut offset = 12;

        // Skip questions
        for _ in 0..qd_count {
            let (_, next_off) = Self::parse_name(buf, offset)?;
            offset = next_off + 4; // Skip QTYPE (2) + QCLASS (2)
        }

        let mut records = Vec::with_capacity(an_count);

        // Parse Answer records
        for _ in 0..an_count {
            let (rec_name, next_off) = Self::parse_name(buf, offset)?;
            offset = next_off;

            if offset + 10 > buf.len() {
                break;
            }

            let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
            let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > buf.len() {
                break;
            }

            let rdata = buf[offset..offset + rdlength].to_vec();
            offset += rdlength;

            let rec = DnsRecord {
                name: rec_name.clone(),
                rtype,
                rclass,
                ttl,
                data: rdata,
            };

            // Update cache
            if let Some(ipv4) = rec.as_ipv4() {
                let entry = self.cache.entry(rec_name.to_lowercase()).or_insert(DnsCacheEntry {
                    hostname: rec_name.clone(),
                    ipv4: None,
                    ipv6: None,
                    expires_at_ms: now_ms + (ttl as u64) * 1000,
                });
                entry.ipv4 = Some(ipv4);
            } else if let Some(ipv6) = rec.as_ipv6() {
                let entry = self.cache.entry(rec_name.to_lowercase()).or_insert(DnsCacheEntry {
                    hostname: rec_name.clone(),
                    ipv4: None,
                    ipv6: None,
                    expires_at_ms: now_ms + (ttl as u64) * 1000,
                });
                entry.ipv6 = Some(ipv6);
            }

            records.push(rec);
        }

        Some(records)
    }

    /// Lookup hostname from cache
    pub fn cache_lookup(&self, hostname: &str, now_ms: u64) -> Option<&DnsCacheEntry> {
        let entry = self.cache.get(&hostname.to_lowercase())?;
        if now_ms < entry.expires_at_ms {
            Some(entry)
        } else {
            None
        }
    }
}
