//! Virtual Loopback Network Interface (`lo`: `127.0.0.1/8`, `::1/128`, MTU 65536, TX-to-RX Ring Queue & Telemetry Counters).

use crate::ethernet_mac::MacAddress;
use crate::ipv4_routing::Ipv4Addr;
use crate::ipv6_core::Ipv6Addr;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Default Maximum Transmission Unit for the virtual loopback interface (65,536 bytes).
pub const LOOPBACK_MTU: usize = 65_536;

/// Errors returned by `LoopbackInterface` transmit operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackError {
    /// Interface administrative state is `DOWN`.
    InterfaceDown,
    /// Packet length exceeds `mtu` (65,536 bytes).
    PacketTooLarge { len: usize, mtu: usize },
    /// Ring buffer queue depth reached `max_queue_depth`.
    QueueFull,
}

/// Cumulative RFC 2863 IF-MIB Packet and Octet Counters for a Network Interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
}

/// Kernel Virtual Loopback Interface (`lo`, index `1`).
#[derive(Clone, Debug)]
pub struct LoopbackInterface {
    pub if_index: u16,
    pub name: &'static str,
    pub mac: MacAddress,
    pub ipv4_addr: Ipv4Addr,
    pub ipv4_prefix_len: u8,
    pub ipv6_addr: Ipv6Addr,
    pub ipv6_prefix_len: u8,
    pub mtu: usize,
    pub admin_up: bool,
    pub max_queue_depth: usize,
    ring_queue: VecDeque<Vec<u8>>,
    pub stats: InterfaceStats,
}

impl LoopbackInterface {
    /// Creates the standard `lo` loopback interface configured with `127.0.0.1/8` and `::1/128`.
    pub const fn new() -> Self {
        Self {
            if_index: 1,
            name: "lo",
            mac: MacAddress::ZERO,
            ipv4_addr: Ipv4Addr::LOCALHOST,
            ipv4_prefix_len: 8,
            ipv6_addr: Ipv6Addr::LOCALHOST,
            ipv6_prefix_len: 128,
            mtu: LOOPBACK_MTU,
            admin_up: true,
            max_queue_depth: 256,
            ring_queue: VecDeque::new(),
            stats: InterfaceStats {
                rx_packets: 0,
                rx_bytes: 0,
                tx_packets: 0,
                tx_bytes: 0,
                tx_dropped: 0,
            },
        }
    }

    /// Returns `true` if `addr` falls within `127.0.0.0/8`.
    #[inline]
    pub const fn owns_ipv4(&self, addr: Ipv4Addr) -> bool {
        addr.is_loopback()
    }

    /// Returns `true` if `addr` equals `::1/128`.
    #[inline]
    pub fn owns_ipv6(&self, addr: Ipv6Addr) -> bool {
        addr.is_loopback()
    }

    /// Transmits a packet into the loopback TX-to-RX ring queue and updates TX counters.
    pub fn transmit(&mut self, packet: Vec<u8>) -> Result<(), LoopbackError> {
        if !self.admin_up {
            self.stats.tx_dropped += 1;
            return Err(LoopbackError::InterfaceDown);
        }
        if packet.len() > self.mtu {
            self.stats.tx_dropped += 1;
            return Err(LoopbackError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        if self.ring_queue.len() >= self.max_queue_depth {
            self.stats.tx_dropped += 1;
            return Err(LoopbackError::QueueFull);
        }

        let len = packet.len() as u64;
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += len;
        self.ring_queue.push_back(packet);
        Ok(())
    }

    /// Dequeues the next packet from the loopback RX ring and updates RX counters.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        let pkt = self.ring_queue.pop_front()?;
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += pkt.len() as u64;
        Some(pkt)
    }

    /// Returns the number of packets currently pending in the loopback ring queue.
    #[inline]
    pub fn pending_packets(&self) -> usize {
        self.ring_queue.len()
    }
}

impl Default for LoopbackInterface {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs self-tests for the `loopback_if` module.
pub fn verify_net_loopback_if() -> u32 {
    let mut passed = 0u32;

    let mut lo = LoopbackInterface::new();

    // 1. Verify default IPv4 127.0.0.1/8, IPv6 ::1/128, and MTU 65536 properties.
    if lo.owns_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        && lo.owns_ipv4(Ipv4Addr::new(127, 255, 255, 254))
        && lo.owns_ipv6(Ipv6Addr::LOCALHOST)
        && lo.mtu == 65_536
    {
        passed += 1;
    }

    // 2. Transmit and receive back-to-back frames, checking TX/RX packet and byte counters.
    let p1 = b"loopback-frame-alpha".to_vec();
    let p2 = b"loopback-frame-bravo-1234".to_vec();
    if lo.transmit(p1.clone()).is_ok() && lo.transmit(p2.clone()).is_ok() {
        let r1 = lo.receive();
        let r2 = lo.receive();
        if r1.as_ref() == Some(&p1)
            && r2.as_ref() == Some(&p2)
            && lo.stats.tx_packets == 2
            && lo.stats.rx_packets == 2
            && lo.stats.tx_bytes == (p1.len() + p2.len()) as u64
            && lo.stats.rx_bytes == lo.stats.tx_bytes
        {
            passed += 1;
        }
    }

    // 3. Verify MTU enforcement rejects oversized frames and increments tx_dropped.
    lo.mtu = 16;
    if lo.transmit(alloc::vec![0u8; 32]) == Err(LoopbackError::PacketTooLarge { len: 32, mtu: 16 })
        && lo.stats.tx_dropped == 1
    {
        passed += 1;
    }

    // 4. Verify administrative down state blocks transmission.
    lo.admin_up = false;
    if lo.transmit(alloc::vec![1, 2, 3]) == Err(LoopbackError::InterfaceDown)
        && lo.stats.tx_dropped == 2
    {
        passed += 1;
    }

    passed
}
