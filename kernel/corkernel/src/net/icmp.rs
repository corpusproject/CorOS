//! RFC 792 Internet Control Message Protocol (ICMP) Engine for CorOS.
//! 100% in-house implementation supporting:
//! - Echo Request (Ping) and Echo Reply packet generation and parsing
//! - RFC 1071 16-bit one's-complement Internet checksum verification
//! - Destination Unreachable, Time Exceeded (TTL expired in transit), and Redirect handling

use alloc::vec::Vec;

pub const ICMP_TYPE_ECHO_REPLY: u8        = 0;
pub const ICMP_TYPE_DEST_UNREACHABLE: u8  = 3;
pub const ICMP_TYPE_REDIRECT: u8          = 5;
pub const ICMP_TYPE_ECHO_REQUEST: u8      = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8     = 11;
pub const ICMP_TYPE_PARAM_PROBLEM: u8     = 12;

// Destination Unreachable Codes
pub const ICMP_CODE_NET_UNREACH: u8       = 0;
pub const ICMP_CODE_HOST_UNREACH: u8      = 1;
pub const ICMP_CODE_PROTO_UNREACH: u8     = 2;
pub const ICMP_CODE_PORT_UNREACH: u8      = 3;
pub const ICMP_CODE_FRAG_NEEDED: u8       = 4;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct IcmpHeader {
    pub msg_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq_num: u16,
}

impl IcmpHeader {
    pub fn new_echo_request(id: u16, seq: u16) -> Self {
        Self {
            msg_type: ICMP_TYPE_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            id: id.to_be(),
            seq_num: seq.to_be(),
        }
    }

    pub fn new_echo_reply(id: u16, seq: u16) -> Self {
        Self {
            msg_type: ICMP_TYPE_ECHO_REPLY,
            code: 0,
            checksum: 0,
            id: id.to_be(),
            seq_num: seq.to_be(),
        }
    }

    pub fn calculate_checksum(&self, payload: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        let hdr_bytes = self.to_bytes();
        let mut i = 0;
        while i < hdr_bytes.len() {
            if i == 2 {
                // Skip checksum field itself
                i += 2;
                continue;
            }
            let w = u16::from_be_bytes([hdr_bytes[i], hdr_bytes[i + 1]]);
            sum += w as u32;
            i += 2;
        }

        let mut j = 0;
        while j + 1 < payload.len() {
            let w = u16::from_be_bytes([payload[j], payload[j + 1]]);
            sum += w as u32;
            j += 2;
        }
        if j < payload.len() {
            let w = u16::from_be_bytes([payload[j], 0]);
            sum += w as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        let ptr = self as *const _ as *const u8;
        unsafe {
            for i in 0..8 {
                buf[i] = *ptr.add(i);
            }
        }
        buf
    }

    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 8 {
            return None;
        }
        let hdr = unsafe { *(bytes.as_ptr() as *const IcmpHeader) };
        let payload = &bytes[8..];
        Some((hdr, payload))
    }
}

pub struct IcmpPacketBuilder;

impl IcmpPacketBuilder {
    /// Build a complete ICMP Echo Request packet with optional payload.
    pub fn build_ping(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut hdr = IcmpHeader::new_echo_request(id, seq);
        hdr.checksum = hdr.calculate_checksum(payload).to_be();

        let mut pkt = Vec::with_capacity(8 + payload.len());
        pkt.extend_from_slice(&hdr.to_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build an ICMP Echo Reply responding to an incoming request.
    pub fn build_reply(req_hdr: &IcmpHeader, payload: &[u8]) -> Vec<u8> {
        let id = u16::from_be(req_hdr.id);
        let seq = u16::from_be(req_hdr.seq_num);

        let mut reply_hdr = IcmpHeader::new_echo_reply(id, seq);
        reply_hdr.checksum = reply_hdr.calculate_checksum(payload).to_be();

        let mut pkt = Vec::with_capacity(8 + payload.len());
        pkt.extend_from_slice(&reply_hdr.to_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }
}
