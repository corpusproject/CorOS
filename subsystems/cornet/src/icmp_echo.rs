//! ICMPv4 (RFC 792) Packet Codec, Checksum Verification & Ping Round-Trip Time (RTT) Tracker.

use crate::ipv4_routing::rfc1071_checksum;
use alloc::vec::Vec;

/// Decoded ICMPv4 Message Type and Code (RFC 792).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmpv4Type {
    /// Echo Reply (`type = 0, code = 0`).
    EchoReply { identifier: u16, sequence: u16 },
    /// Destination Unreachable (`type = 3`), with code and RFC 1191 Path MTU `next_hop_mtu`.
    DestinationUnreachable { code: u8, next_hop_mtu: u16 },
    /// Echo Request (`type = 8, code = 0`).
    EchoRequest { identifier: u16, sequence: u16 },
    /// Time Exceeded (`type = 11`, `code = 0` TTL expired in transit, `code = 1` fragment reassembly time exceeded).
    TimeExceeded { code: u8 },
    /// Any other ICMPv4 message type/code with its 4-byte rest-of-header field.
    Other {
        icmp_type: u8,
        code: u8,
        rest_of_header: [u8; 4],
    },
}

/// Errors encountered while parsing or validating an ICMPv4 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpError {
    /// Packet is shorter than the 8-byte ICMPv4 header.
    TruncatedHeader,
    /// RFC 1071 ones'-complement checksum verification failed.
    ChecksumMismatch { expected: u16, actual: u16 },
}

/// Parsed or constructible ICMPv4 Packet (8-byte header + variable payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4Packet {
    pub message: Icmpv4Type,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl Icmpv4Packet {
    /// Minimum ICMPv4 header size in bytes.
    pub const HEADER_LEN: usize = 8;

    /// Constructs a new ICMPv4 Echo Request packet and computes its wire checksum.
    pub fn new_echo_request(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        let mut pkt = Self {
            message: Icmpv4Type::EchoRequest {
                identifier,
                sequence,
            },
            checksum: 0,
            payload,
        };
        pkt.checksum = pkt.compute_checksum();
        pkt
    }

    /// Constructs a new ICMPv4 Echo Reply matching an Echo Request.
    pub fn new_echo_reply(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        let mut pkt = Self {
            message: Icmpv4Type::EchoReply {
                identifier,
                sequence,
            },
            checksum: 0,
            payload,
        };
        pkt.checksum = pkt.compute_checksum();
        pkt
    }

    /// Encodes the 8-byte header fields with a caller-supplied checksum value.
    fn encode_header(&self, checksum_field: u16) -> [u8; 8] {
        let mut h = [0u8; 8];
        match self.message {
            Icmpv4Type::EchoReply {
                identifier,
                sequence,
            } => {
                h[0] = 0;
                h[1] = 0;
                h[4..6].copy_from_slice(&identifier.to_be_bytes());
                h[6..8].copy_from_slice(&sequence.to_be_bytes());
            }
            Icmpv4Type::DestinationUnreachable { code, next_hop_mtu } => {
                h[0] = 3;
                h[1] = code;
                h[4..6].copy_from_slice(&0u16.to_be_bytes());
                h[6..8].copy_from_slice(&next_hop_mtu.to_be_bytes());
            }
            Icmpv4Type::EchoRequest {
                identifier,
                sequence,
            } => {
                h[0] = 8;
                h[1] = 0;
                h[4..6].copy_from_slice(&identifier.to_be_bytes());
                h[6..8].copy_from_slice(&sequence.to_be_bytes());
            }
            Icmpv4Type::TimeExceeded { code } => {
                h[0] = 11;
                h[1] = code;
            }
            Icmpv4Type::Other {
                icmp_type,
                code,
                rest_of_header,
            } => {
                h[0] = icmp_type;
                h[1] = code;
                h[4..8].copy_from_slice(&rest_of_header);
            }
        }
        h[2..4].copy_from_slice(&checksum_field.to_be_bytes());
        h
    }

    /// Computes the RFC 1071 checksum over the ICMPv4 header and payload.
    pub fn compute_checksum(&self) -> u16 {
        let mut buf = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&self.encode_header(0));
        buf.extend_from_slice(&self.payload);
        rfc1071_checksum(&buf)
    }

    /// Serializes this ICMPv4 packet into a newly allocated byte vector with a valid checksum.
    pub fn to_bytes(&mut self) -> Vec<u8> {
        self.checksum = self.compute_checksum();
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.encode_header(self.checksum));
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses and verifies an `Icmpv4Packet` from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, IcmpError> {
        if buf.len() < Self::HEADER_LEN {
            return Err(IcmpError::TruncatedHeader);
        }
        let wire_csum = u16::from_be_bytes([buf[2], buf[3]]);
        if rfc1071_checksum(buf) != 0 {
            let mut copy = buf.to_vec();
            copy[2] = 0;
            copy[3] = 0;
            let expected = rfc1071_checksum(&copy);
            return Err(IcmpError::ChecksumMismatch {
                expected,
                actual: wire_csum,
            });
        }

        let icmp_type = buf[0];
        let code = buf[1];
        let message = match (icmp_type, code) {
            (0, 0) => Icmpv4Type::EchoReply {
                identifier: u16::from_be_bytes([buf[4], buf[5]]),
                sequence: u16::from_be_bytes([buf[6], buf[7]]),
            },
            (3, c) => Icmpv4Type::DestinationUnreachable {
                code: c,
                next_hop_mtu: u16::from_be_bytes([buf[6], buf[7]]),
            },
            (8, 0) => Icmpv4Type::EchoRequest {
                identifier: u16::from_be_bytes([buf[4], buf[5]]),
                sequence: u16::from_be_bytes([buf[6], buf[7]]),
            },
            (11, c) => Icmpv4Type::TimeExceeded { code: c },
            (t, c) => Icmpv4Type::Other {
                icmp_type: t,
                code: c,
                rest_of_header: [buf[4], buf[5], buf[6], buf[7]],
            },
        };

        Ok(Self {
            message,
            checksum: wire_csum,
            payload: buf[Self::HEADER_LEN..].to_vec(),
        })
    }
}

/// Tracks in-flight ICMP Echo Requests and computes min/avg/max Round-Trip Time (RTT) in microseconds.
#[derive(Clone, Debug)]
pub struct PingSession {
    pub identifier: u16,
    pub next_sequence: u16,
    inflight: Vec<(u16, u64)>,
    pub transmitted: u32,
    pub received: u32,
    pub min_rtt_us: u64,
    pub max_rtt_us: u64,
    pub total_rtt_us: u64,
}

impl PingSession {
    /// Creates a new `PingSession` with the given 16-bit ICMP Echo identifier.
    pub const fn new(identifier: u16) -> Self {
        Self {
            identifier,
            next_sequence: 1,
            inflight: Vec::new(),
            transmitted: 0,
            received: 0,
            min_rtt_us: u64::MAX,
            max_rtt_us: 0,
            total_rtt_us: 0,
        }
    }

    /// Generates the next ICMP Echo Request packet and records its transmit timestamp (`now_us`).
    pub fn build_next_request(&mut self, now_us: u64, payload: &[u8]) -> Icmpv4Packet {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.transmitted += 1;
        self.inflight.push((seq, now_us));
        Icmpv4Packet::new_echo_request(self.identifier, seq, payload.to_vec())
    }

    /// Processes an incoming ICMP Echo Reply at `now_us`, returning `Some(rtt_us)` if matched.
    pub fn record_reply(&mut self, packet: &Icmpv4Packet, now_us: u64) -> Option<u64> {
        if let Icmpv4Type::EchoReply {
            identifier,
            sequence,
        } = packet.message
        {
            if identifier != self.identifier {
                return None;
            }
            if let Some(pos) = self.inflight.iter().position(|&(s, _)| s == sequence) {
                let (_, sent_us) = self.inflight.remove(pos);
                let rtt = now_us.saturating_sub(sent_us);
                self.received += 1;
                if rtt < self.min_rtt_us {
                    self.min_rtt_us = rtt;
                }
                if rtt > self.max_rtt_us {
                    self.max_rtt_us = rtt;
                }
                self.total_rtt_us = self.total_rtt_us.saturating_add(rtt);
                return Some(rtt);
            }
        }
        None
    }

    /// Returns the mean RTT in microseconds across all received Echo Replies.
    #[inline]
    pub const fn mean_rtt_us(&self) -> u64 {
        if self.received == 0 {
            0
        } else {
            self.total_rtt_us / (self.received as u64)
        }
    }

    /// Returns packet loss in basis points (`0..=10000`, where `10000` = 100.00%).
    #[inline]
    pub const fn loss_bps(&self) -> u32 {
        if self.transmitted == 0 {
            0
        } else {
            let lost = self.transmitted.saturating_sub(self.received);
            (lost * 10_000) / self.transmitted
        }
    }
}

/// Runs self-tests for the `icmp_echo` module.
pub fn verify_net_icmp_echo() -> u32 {
    let mut passed = 0u32;

    let mut session = PingSession::new(0xC0DE);
    let mut req1 = session.build_next_request(1_000, b"CorOS-Ping-Payload-1");
    let wire1 = req1.to_bytes();

    if let Ok(parsed_req) = Icmpv4Packet::parse(&wire1) {
        if parsed_req == req1 {
            passed += 1;
        }
        if let Icmpv4Type::EchoRequest {
            identifier,
            sequence,
        } = parsed_req.message
        {
            let mut reply1 = Icmpv4Packet::new_echo_reply(identifier, sequence, parsed_req.payload);
            let reply_wire = reply1.to_bytes();
            if let Ok(parsed_rep) = Icmpv4Packet::parse(&reply_wire) {
                if session.record_reply(&parsed_rep, 1_420) == Some(420) {
                    passed += 1;
                }
            }
        }
    }

    let mut req2 = session.build_next_request(2_000, b"CorOS-Ping-Payload-2");
    let _ = req2.to_bytes();
    let reply2 = Icmpv4Packet::new_echo_reply(0xC0DE, 2, b"CorOS-Ping-Payload-2".to_vec());
    if session.record_reply(&reply2, 2_780) == Some(780)
        && session.min_rtt_us == 420
        && session.max_rtt_us == 780
        && session.mean_rtt_us() == 600
        && session.loss_bps() == 0
    {
        passed += 1;
    }

    // Verify Destination Unreachable (Fragmentation Needed, Code 4) with Next-Hop MTU 1400.
    let mut unreach = Icmpv4Packet {
        message: Icmpv4Type::DestinationUnreachable {
            code: 4,
            next_hop_mtu: 1400,
        },
        checksum: 0,
        payload: alloc::vec![0x45, 0x00, 0x05, 0xDC],
    };
    let unreach_wire = unreach.to_bytes();
    if Icmpv4Packet::parse(&unreach_wire) == Ok(unreach) {
        passed += 1;
    }

    passed
}
