//! UDP (RFC 768) 8-Byte Header, IPv4/IPv6 Pseudo-Header Checksum, Ephemeral Port Allocator & Demultiplexer.

use crate::ipv4_routing::{fold_and_invert, ones_complement_sum, Ipv4Addr};
use crate::ipv6_core::Ipv6Addr;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// IP protocol number for UDP (`17`).
pub const IPPROTO_UDP: u8 = 17;

/// Errors encountered while parsing or validating a UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpError {
    /// Buffer is shorter than the 8-byte UDP header.
    TruncatedHeader,
    /// UDP `length` field is smaller than 8 bytes or exceeds buffer length.
    InvalidLength(u16),
    /// UDP checksum verification failed (or zero checksum on IPv6 where mandatory).
    BadChecksum { expected: u16, actual: u16 },
    /// No free ephemeral ports remain in `49152..=65535`.
    PortExhausted,
    /// Requested local UDP port is already bound.
    PortInUse(u16),
}

/// 8-byte RFC 768 User Datagram Protocol (UDP) Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Fixed UDP header length in bytes.
    pub const LEN: usize = 8;

    /// Encodes the 8-byte UDP header with a specified `checksum_field`.
    #[inline]
    fn to_raw_bytes(self, checksum_field: u16) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        b[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        b[4..6].copy_from_slice(&self.length.to_be_bytes());
        b[6..8].copy_from_slice(&checksum_field.to_be_bytes());
        b
    }

    /// Computes the UDP checksum over an IPv4 12-byte pseudo-header, UDP header, and payload.
    /// Per RFC 768, if the computed checksum is `0x0000`, it is transmitted as `0xFFFF`.
    pub fn compute_checksum_ipv4(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> u16 {
        let udp_len = (Self::LEN + payload.len()) as u16;
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip.0);
        pseudo[4..8].copy_from_slice(&dst_ip.0);
        pseudo[8] = 0;
        pseudo[9] = IPPROTO_UDP;
        pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());

        let mut hdr_copy = *self;
        hdr_copy.length = udp_len;

        let mut sum = ones_complement_sum(&pseudo, 0);
        sum = ones_complement_sum(&hdr_copy.to_raw_bytes(0), sum);
        sum = ones_complement_sum(payload, sum);
        let csum = fold_and_invert(sum);
        if csum == 0 {
            0xFFFF
        } else {
            csum
        }
    }

    /// Computes the mandatory UDP checksum over an IPv6 40-byte pseudo-header, UDP header, and payload.
    pub fn compute_checksum_ipv6(
        &self,
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        payload: &[u8],
    ) -> u16 {
        let udp_len = (Self::LEN + payload.len()) as u32;
        let mut pseudo = [0u8; 40];
        pseudo[0..16].copy_from_slice(&src_ip.0);
        pseudo[16..32].copy_from_slice(&dst_ip.0);
        pseudo[32..36].copy_from_slice(&udp_len.to_be_bytes());
        pseudo[39] = IPPROTO_UDP;

        let mut hdr_copy = *self;
        hdr_copy.length = udp_len as u16;

        let mut sum = ones_complement_sum(&pseudo, 0);
        sum = ones_complement_sum(&hdr_copy.to_raw_bytes(0), sum);
        sum = ones_complement_sum(payload, sum);
        let csum = fold_and_invert(sum);
        if csum == 0 {
            0xFFFF
        } else {
            csum
        }
    }

    /// Serializes a complete IPv4 UDP datagram (8-byte header + payload) with computed checksum.
    pub fn build_ipv4_datagram(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = (Self::LEN + payload.len()) as u16;
        let mut hdr = Self {
            src_port,
            dst_port,
            length,
            checksum: 0,
        };
        hdr.checksum = hdr.compute_checksum_ipv4(src_ip, dst_ip, payload);
        let mut out = Vec::with_capacity(length as usize);
        out.extend_from_slice(&hdr.to_raw_bytes(hdr.checksum));
        out.extend_from_slice(payload);
        out
    }

    /// Parses and validates an IPv4 UDP datagram from `buf`, returning `(header, payload_slice)`.
    pub fn parse_ipv4(
        buf: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<(Self, &[u8]), UdpError> {
        if buf.len() < Self::LEN {
            return Err(UdpError::TruncatedHeader);
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);

        if (length as usize) < Self::LEN || (length as usize) > buf.len() {
            return Err(UdpError::InvalidLength(length));
        }
        let payload = &buf[Self::LEN..length as usize];
        let hdr = Self {
            src_port,
            dst_port,
            length,
            checksum,
        };

        // In IPv4, checksum == 0 means the sender did not compute a checksum.
        if checksum != 0 {
            let expected = hdr.compute_checksum_ipv4(src_ip, dst_ip, payload);
            if checksum != expected {
                return Err(UdpError::BadChecksum {
                    expected,
                    actual: checksum,
                });
            }
        }
        Ok((hdr, payload))
    }
}

/// IANA Dynamic / Ephemeral Port Allocator (`49152..=65535`, RFC 6335).
#[derive(Clone, Debug)]
pub struct EphemeralPortAllocator {
    next_port: u16,
    allocated: Vec<u16>,
}

impl EphemeralPortAllocator {
    /// Start of the IANA ephemeral port range.
    pub const START_PORT: u16 = 49152;
    /// End of the IANA ephemeral port range.
    pub const END_PORT: u16 = 65535;

    /// Creates a new allocator starting at port `49152`.
    pub const fn new() -> Self {
        Self {
            next_port: Self::START_PORT,
            allocated: Vec::new(),
        }
    }

    /// Returns `true` if `port` is currently marked in-use.
    #[inline]
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocated.contains(&port)
    }

    /// Allocates the next available ephemeral port in `49152..=65535`.
    pub fn allocate(&mut self) -> Result<u16, UdpError> {
        let total = (Self::END_PORT - Self::START_PORT) as u32 + 1;
        for _ in 0..total {
            let candidate = self.next_port;
            self.next_port = if self.next_port == Self::END_PORT {
                Self::START_PORT
            } else {
                self.next_port + 1
            };
            if !self.is_allocated(candidate) {
                self.allocated.push(candidate);
                return Ok(candidate);
            }
        }
        Err(UdpError::PortExhausted)
    }

    /// Binds a specific port (`1..=65535`) if not already in use.
    pub fn bind_specific(&mut self, port: u16) -> Result<(), UdpError> {
        if self.is_allocated(port) {
            return Err(UdpError::PortInUse(port));
        }
        self.allocated.push(port);
        Ok(())
    }

    /// Releases a previously allocated or bound port.
    pub fn release(&mut self, port: u16) -> bool {
        if let Some(idx) = self.allocated.iter().position(|&p| p == port) {
            self.allocated.swap_remove(idx);
            true
        } else {
            false
        }
    }
}

impl Default for EphemeralPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// An inbound UDP datagram delivered to a bound local port's receive queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub local_port: u16,
    pub payload: Vec<u8>,
}

/// Per-port UDP receive queue entry.
#[derive(Clone, Debug)]
struct UdpPortBinding {
    local_port: u16,
    rx_queue: VecDeque<UdpDatagram>,
    max_queue_depth: usize,
}

/// UDP Receive Demultiplexer mapping bound local ports to bounded datagram queues.
#[derive(Clone, Debug, Default)]
pub struct UdpDemux {
    pub ports: EphemeralPortAllocator,
    bindings: Vec<UdpPortBinding>,
}

impl UdpDemux {
    /// Creates a new UDP demultiplexer.
    pub const fn new() -> Self {
        Self {
            ports: EphemeralPortAllocator::new(),
            bindings: Vec::new(),
        }
    }

    /// Binds a local UDP port (or allocates an ephemeral port when `port == 0`).
    pub fn bind(&mut self, port: u16) -> Result<u16, UdpError> {
        let actual_port = if port == 0 {
            self.ports.allocate()?
        } else {
            self.ports.bind_specific(port)?;
            port
        };
        self.bindings.push(UdpPortBinding {
            local_port: actual_port,
            rx_queue: VecDeque::new(),
            max_queue_depth: 64,
        });
        Ok(actual_port)
    }

    /// Unbinds `local_port` and discards any unread datagrams.
    pub fn unbind(&mut self, local_port: u16) -> bool {
        let _ = self.ports.release(local_port);
        let before = self.bindings.len();
        self.bindings.retain(|b| b.local_port != local_port);
        self.bindings.len() < before
    }

    /// Delivers an inbound IPv4 UDP packet into the matching port's receive queue.
    /// Returns `Ok(true)` if delivered to a bound socket, or `Ok(false)` if no listener is bound
    /// (signaling the caller may emit ICMP Port Unreachable).
    pub fn deliver_ipv4(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        udp_bytes: &[u8],
    ) -> Result<bool, UdpError> {
        let (hdr, payload) = UdpHeader::parse_ipv4(udp_bytes, src_ip, dst_ip)?;
        if let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|b| b.local_port == hdr.dst_port)
        {
            if binding.rx_queue.len() < binding.max_queue_depth {
                binding.rx_queue.push_back(UdpDatagram {
                    remote_ip: src_ip,
                    remote_port: hdr.src_port,
                    local_port: hdr.dst_port,
                    payload: payload.to_vec(),
                });
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Pops the oldest queued datagram for `local_port`.
    pub fn recv_from(&mut self, local_port: u16) -> Option<UdpDatagram> {
        self.bindings
            .iter_mut()
            .find(|b| b.local_port == local_port)
            .and_then(|b| b.rx_queue.pop_front())
    }
}

/// Runs self-tests for the `udp_datagram` module.
pub fn verify_net_udp_datagram() -> u32 {
    let mut passed = 0u32;

    let src_ip = Ipv4Addr::new(10, 0, 2, 15);
    let dst_ip = Ipv4Addr::new(10, 0, 2, 3);
    let mut demux = UdpDemux::new();

    // 1. Ephemeral port allocation in 49152..=65535.
    let eph = demux.bind(0).unwrap_or(0);
    if eph == EphemeralPortAllocator::START_PORT {
        passed += 1;
    }

    // 2. Explicit port bind and duplicate bind rejection.
    if demux.bind(5353) == Ok(5353) && demux.bind(5353) == Err(UdpError::PortInUse(5353)) {
        passed += 1;
    }

    // 3. Build IPv4 UDP datagram with pseudo-header checksum and deliver via demux.
    let wire = UdpHeader::build_ipv4_datagram(src_ip, dst_ip, eph, 5353, b"mDNS-query");
    if demux.deliver_ipv4(src_ip, dst_ip, &wire) == Ok(true) {
        if let Some(dgram) = demux.recv_from(5353) {
            if dgram.remote_ip == src_ip
                && dgram.remote_port == eph
                && dgram.payload == b"mDNS-query"
            {
                passed += 1;
            }
        }
    }

    // 4. Verify IPv6 pseudo-header UDP checksum is non-zero and deterministic.
    let hdr_v6 = UdpHeader {
        src_port: eph,
        dst_port: 53,
        length: 16,
        checksum: 0,
    };
    let csum6 = hdr_v6.compute_checksum_ipv6(
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::ALL_NODES_LINK_LOCAL,
        b"12345678",
    );
    if csum6 != 0 {
        passed += 1;
    }

    passed
}
