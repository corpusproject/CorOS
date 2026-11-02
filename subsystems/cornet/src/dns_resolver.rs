//! RFC 1035 DNS Wire Packet Codec, QNAME Label Compression/Decompression, Resource Record Parsers & TTL Cache.

use crate::ipv4_routing::Ipv4Addr;
use crate::ipv6_core::Ipv6Addr;
use alloc::string::String;
use alloc::vec::Vec;

/// DNS Query/Record Class `IN` (`1` = Internet).
pub const DNS_CLASS_IN: u16 = 1;

/// DNS Resource Record / Query Type (RFC 1035 & RFC 3596).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// IPv4 Host Address (`1`).
    A,
    /// Authoritative Name Server (`2`).
    Ns,
    /// Canonical Name for an alias (`5`).
    Cname,
    /// Domain Name Pointer (`12`).
    Ptr,
    /// Mail Exchange (`15`).
    Mx,
    /// Text Strings (`16`).
    Txt,
    /// IPv6 Host Address (`28`).
    Aaaa,
    /// Unrecognized QTYPE/TYPE code.
    Unknown(u16),
}

impl DnsRecordType {
    pub const fn from_u16(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Unknown(code) => code,
        }
    }
}

/// Errors encountered while encoding or decoding RFC 1035 DNS packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// Packet is shorter than the 12-byte DNS header or truncated mid-record.
    TruncatedPacket,
    /// Domain label exceeds 63 octets or total domain name exceeds 255 octets.
    InvalidDomainName,
    /// Compression pointer loop or forward pointer detected while decoding a QNAME.
    CompressionPointerLoop,
    /// Resource record RDATA length does not match the record format (e.g., `A` != 4 bytes).
    MalformedRdata,
}

/// 12-byte RFC 1035 Section 4.1.1 DNS Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DnsHeader {
    /// Fixed DNS header size in bytes.
    pub const LEN: usize = 12;

    /// Creates a standard recursive query header with `qd_count = 1`.
    pub const fn new_query(id: u16) -> Self {
        Self {
            id,
            is_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            rcode: 0,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    /// Parses a 12-byte `DnsHeader` from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < Self::LEN {
            return Err(DnsError::TruncatedPacket);
        }
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        Ok(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            is_response: (flags & 0x8000) != 0,
            opcode: ((flags >> 11) & 0x0F) as u8,
            authoritative_answer: (flags & 0x0400) != 0,
            truncated: (flags & 0x0200) != 0,
            recursion_desired: (flags & 0x0100) != 0,
            recursion_available: (flags & 0x0080) != 0,
            rcode: (flags & 0x000F) as u8,
            qd_count: u16::from_be_bytes([buf[4], buf[5]]),
            an_count: u16::from_be_bytes([buf[6], buf[7]]),
            ns_count: u16::from_be_bytes([buf[8], buf[9]]),
            ar_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    /// Serializes this 12-byte DNS header into `out`.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, DnsError> {
        if out.len() < Self::LEN {
            return Err(DnsError::TruncatedPacket);
        }
        let flags: u16 = ((self.is_response as u16) << 15)
            | (((self.opcode as u16) & 0x0F) << 11)
            | ((self.authoritative_answer as u16) << 10)
            | ((self.truncated as u16) << 9)
            | ((self.recursion_desired as u16) << 8)
            | ((self.recursion_available as u16) << 7)
            | ((self.rcode as u16) & 0x0F);
        out[0..2].copy_from_slice(&self.id.to_be_bytes());
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        out[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        out[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        out[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        out[10..12].copy_from_slice(&self.ar_count.to_be_bytes());
        Ok(Self::LEN)
    }
}

/// Encodes a dot-separated domain name (e.g., `"coros.kernel.org"`) into RFC 1035 length-prefixed wire labels.
pub fn encode_qname(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }
    let mut total_len = 0usize;
    for label in trimmed.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(DnsError::InvalidDomainName);
        }
        total_len += len + 1;
        if total_len > 255 {
            return Err(DnsError::InvalidDomainName);
        }
        out.push(len as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Decodes an RFC 1035 domain name starting at `offset` in `packet`, following `0xC0` compression pointers.
/// Returns `(decoded_domain_name,offset_immediately_after_name_in_stream)`.
pub fn decode_qname(packet: &[u8], start_offset: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut pos = start_offset;
    let mut jumped = false;
    let mut end_offset = start_offset;
    let mut jumps = 0usize;

    loop {
        if pos >= packet.len() {
            return Err(DnsError::TruncatedPacket);
        }
        let len_byte = packet[pos];
        if len_byte == 0 {
            if !jumped {
                end_offset = pos + 1;
            }
            break;
        }
        // Check for RFC 1035 Section 4.1.4 compression pointer (top 2 bits == 11).
        if (len_byte & 0xC0) == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(DnsError::TruncatedPacket);
            }
            if !jumped {
                end_offset = pos + 2;
                jumped = true;
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);
            if ptr >= pos {
                return Err(DnsError::CompressionPointerLoop);
            }
            pos = ptr;
            jumps += 1;
            if jumps > 16 {
                return Err(DnsError::CompressionPointerLoop);
            }
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return Err(DnsError::InvalidDomainName);
        }
        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > packet.len() {
            return Err(DnsError::TruncatedPacket);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &ch in &packet[pos..pos + label_len] {
            name.push(ch as char);
        }
        pos += label_len;
        if !jumped {
            end_offset = pos;
        }
    }

    Ok((name, end_offset))
}

/// RFC 1035 Section 4.1.2 DNS Question Entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
}

/// Decoded Resource Record Data (`RDATA`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRdata {
    /// IPv4 Address (`A`).
    A(Ipv4Addr),
    /// IPv6 Address (`AAAA`).
    Aaaa(Ipv6Addr),
    /// Canonical Name alias (`CNAME`).
    Cname(String),
    /// Reverse DNS Pointer (`PTR`).
    Ptr(String),
    /// Text record (`TXT`).
    Txt(String),
    /// Raw uninterpreted RDATA bytes.
    Raw(Vec<u8>),
}

/// RFC 1035 Section 4.1.3 DNS Resource Record (`RR`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

/// Complete DNS Message (Header + Questions + Answers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
}

impl DnsPacket {
    /// Serializes this DNS message into wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DnsError> {
        let mut out = alloc::vec![0u8; DnsHeader::LEN];
        let mut hdr = self.header;
        hdr.qd_count = self.questions.len() as u16;
        hdr.an_count = self.answers.len() as u16;
        let _ = hdr.write_to(&mut out[..DnsHeader::LEN]);

        for q in &self.questions {
            encode_qname(&q.qname, &mut out)?;
            out.extend_from_slice(&q.qtype.as_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }

        for rr in &self.answers {
            encode_qname(&rr.name, &mut out)?;
            out.extend_from_slice(&rr.rtype.as_u16().to_be_bytes());
            out.extend_from_slice(&rr.rclass.to_be_bytes());
            out.extend_from_slice(&rr.ttl.to_be_bytes());

            let mut rdata_bytes = Vec::new();
            match &rr.rdata {
                DnsRdata::A(ip) => rdata_bytes.extend_from_slice(&ip.0),
                DnsRdata::Aaaa(ip6) => rdata_bytes.extend_from_slice(&ip6.0),
                DnsRdata::Cname(target) | DnsRdata::Ptr(target) => {
                    encode_qname(target, &mut rdata_bytes)?;
                }
                DnsRdata::Txt(text) => {
                    let b = text.as_bytes();
                    let n = b.len().min(255);
                    rdata_bytes.push(n as u8);
                    rdata_bytes.extend_from_slice(&b[..n]);
                }
                DnsRdata::Raw(raw) => rdata_bytes.extend_from_slice(raw),
            }
            out.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata_bytes);
        }

        Ok(out)
    }

    /// Parses a complete `DnsPacket` (including compressed names in Questions and Answers) from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        let header = DnsHeader::parse(buf)?;
        let mut offset = DnsHeader::LEN;
        let mut questions = Vec::with_capacity(header.qd_count as usize);

        for _ in 0..header.qd_count {
            let (qname, next_off) = decode_qname(buf, offset)?;
            offset = next_off;
            if offset + 4 > buf.len() {
                return Err(DnsError::TruncatedPacket);
            }
            let qtype = DnsRecordType::from_u16(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;
            questions.push(DnsQuestion {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(header.an_count as usize);
        for _ in 0..header.an_count {
            let (name, next_off) = decode_qname(buf, offset)?;
            offset = next_off;
            if offset + 10 > buf.len() {
                return Err(DnsError::TruncatedPacket);
            }
            let rtype = DnsRecordType::from_u16(u16::from_be_bytes([buf[offset], buf[offset + 1]]));
            let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            let ttl = u32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
            offset += 10;
            if offset + rdlength > buf.len() {
                return Err(DnsError::TruncatedPacket);
            }
            let rdata_slice = &buf[offset..offset + rdlength];
            let rdata = match rtype {
                DnsRecordType::A => {
                    if rdlength != 4 {
                        return Err(DnsError::MalformedRdata);
                    }
                    DnsRdata::A(Ipv4Addr([
                        rdata_slice[0],
                        rdata_slice[1],
                        rdata_slice[2],
                        rdata_slice[3],
                    ]))
                }
                DnsRecordType::Aaaa => {
                    if rdlength != 16 {
                        return Err(DnsError::MalformedRdata);
                    }
                    let mut v6 = [0u8; 16];
                    v6.copy_from_slice(rdata_slice);
                    DnsRdata::Aaaa(Ipv6Addr(v6))
                }
                DnsRecordType::Cname => {
                    let (cname, _) = decode_qname(buf, offset)?;
                    DnsRdata::Cname(cname)
                }
                DnsRecordType::Ptr => {
                    let (ptr_name, _) = decode_qname(buf, offset)?;
                    DnsRdata::Ptr(ptr_name)
                }
                DnsRecordType::Txt => {
                    if rdlength < 1 {
                        return Err(DnsError::MalformedRdata);
                    }
                    let txt_len = (rdata_slice[0] as usize).min(rdlength - 1);
                    let mut s = String::new();
                    for &b in &rdata_slice[1..1 + txt_len] {
                        s.push(b as char);
                    }
                    DnsRdata::Txt(s)
                }
                _ => DnsRdata::Raw(rdata_slice.to_vec()),
            };
            offset += rdlength;
            answers.push(DnsResourceRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(Self {
            header,
            questions,
            answers,
        })
    }
}

/// Cached DNS Answer Entry with absolute expiration timestamp (`expires_at_sec`).
#[derive(Clone, Debug)]
struct DnsCacheEntry {
    domain: String,
    rdata: DnsRdata,
    expires_at_sec: u64,
}

/// In-memory Stub Resolver DNS Cache honoring Resource Record TTLs.
#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    entries: Vec<DnsCacheEntry>,
}

impl DnsCache {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts all `A` and `AAAA` answers from `pkt` into the cache at `now_sec`.
    pub fn ingest_response(&mut self, pkt: &DnsPacket, now_sec: u64) {
        for rr in &pkt.answers {
            if rr.ttl == 0 {
                continue;
            }
            self.entries.push(DnsCacheEntry {
                domain: rr.name.clone(),
                rdata: rr.rdata.clone(),
                expires_at_sec: now_sec.saturating_add(rr.ttl as u64),
            });
        }
    }

    /// Looks up a non-expired IPv4 `A` record for `domain` at `now_sec`.
    pub fn lookup_ipv4(&self, domain: &str, now_sec: u64) -> Option<Ipv4Addr> {
        for entry in &self.entries {
            if entry.domain.eq_ignore_ascii_case(domain) && now_sec < entry.expires_at_sec {
                if let DnsRdata::A(ip) = entry.rdata {
                    return Some(ip);
                }
            }
        }
        None
    }
}

/// Runs self-tests for the `dns_resolver` module.
pub fn verify_net_dns_resolver() -> u32 {
    let mut passed = 0u32;

    // 1. Build and round-trip a DNS response containing A, AAAA, CNAME, and TXT records.
    let mut hdr = DnsHeader::new_query(0x4242);
    hdr.is_response = true;
    hdr.recursion_available = true;

    let pkt = DnsPacket {
        header: hdr,
        questions: alloc::vec![DnsQuestion {
            qname: String::from("coros.org"),
            qtype: DnsRecordType::A,
            qclass: DNS_CLASS_IN,
        }],
        answers: alloc::vec![
            DnsResourceRecord {
                name: String::from("coros.org"),
                rtype: DnsRecordType::A,
                rclass: DNS_CLASS_IN,
                ttl: 300,
                rdata: DnsRdata::A(Ipv4Addr::new(93, 184, 216, 34)),
            },
            DnsResourceRecord {
                name: String::from("coros.org"),
                rtype: DnsRecordType::Txt,
                rclass: DNS_CLASS_IN,
                ttl: 300,
                rdata: DnsRdata::Txt(String::from("v=spf1 -all")),
            },
        ],
    };

    if let Ok(wire) = pkt.to_bytes() {
        if let Ok(parsed) = DnsPacket::parse(&wire) {
            if parsed == pkt {
                passed += 1;
            }
            let mut cache = DnsCache::new();
            cache.ingest_response(&parsed, 1_000);
            if cache.lookup_ipv4("coros.org", 1_299) == Some(Ipv4Addr::new(93, 184, 216, 34))
                && cache.lookup_ipv4("coros.org", 1_301).is_none()
            {
                passed += 1;
            }
        }
    }

    // 2. Verify RFC 1035 Section 4.1.4 pointer compression (`0xC0 0x0C` pointing to offset 12).
    let mut compressed = alloc::vec![
        0x11, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Offset 12: "\x03dns\x06google\x00"
        3, b'd', b'n', b's', 6, b'g', b'o', b'o', b'g', b'l', b'e', 0,
        // Offset 24: compressed pointer "\x03ns1\xC0\x0C" -> "ns1.dns.google"
        3, b'n', b's', b'1', 0xC0, 0x0C,
    ];
    if let Ok((name, end_off)) = decode_qname(&compressed, 24) {
        if name == "ns1.dns.google" && end_off == 30 {
            passed += 1;
        }
    }

    // 3. Verify forward/looping compression pointer rejection.
    compressed.extend_from_slice(&[0xC0, 30]); // Self-referential pointer at offset 30
    if decode_qname(&compressed, 30) == Err(DnsError::CompressionPointerLoop) {
        passed += 1;
    }

    passed
}
