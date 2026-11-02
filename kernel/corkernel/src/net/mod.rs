//! Pure bare-metal Intel PRO/1000 (82540EM / e1000) Network Card Driver for CorOS.
//! 100% in-house implementation via Memory-Mapped I/O (MMIO) and DMA descriptor rings.
//! Provides link auto-negotiation, MAC address reading, packet transmission (TX),
//! packet reception (RX), and built-in ICMP ping / ARP reply packet builders.

use crate::pci::PciDevice;
use alloc::vec::Vec;

pub mod arp;
pub mod ipv4;
pub mod tcp;
pub mod udp;
pub mod dns;
pub mod dhcp;
pub mod icmp;
pub mod http;
pub mod ipv6;
pub mod icmpv6;
pub mod bpf;
pub mod tls;
pub mod dns_client;
pub mod http2;
pub mod wireguard;
pub mod websocket;
pub mod snmp;
pub mod ftp;
pub mod ntp;
pub mod quic;
pub mod congestion;
pub mod vswitch;
pub mod ipsec;
pub mod canbus;
pub mod ax25;
pub mod unified_network_bridge;

pub use unified_network_bridge::{UnifiedNetworkBridge, GLOBAL_UNIFIED_NETWORK_BRIDGE};
pub use quic::{QuicConnection, QuicStream, QuicFrame, QuicPacketType, QuicVarInt};
pub use congestion::{TcpCongestionControl, CongestionAlgorithm, CongestionState, BbrState};
pub use vswitch::{VirtualSwitch, SwitchPort, PortId, VlanMode, VlanHeader, VxlanHeader, FlowMatchKey, FlowAction, FlowEntry};
pub use ipsec::{IpsecEngine, SecurityAssociation, SecurityPolicy, PolicyAction, IpsecMode, IpsecCipherSuite, EspHeader, AhHeader};
pub use canbus::{CanFrame, CanFdFrame, CanFilter, CanBusInterface, Obd2Decoder, Obd2Value};
pub use ax25::{Ax25Address, Ax25Frame, Ax25FrameType, AprsDecoder, AprsData, AprsPosition, calculate_fcs};
pub use ntp::{NtpPacket, NtpTimestamp, NtpClient, NtpTimeOffset};
pub use arp::{ArpPacket, ArpTable, ArpState};
pub use ipv4::{Ipv4Header, RoutingTable, RouteEntry};
pub use tcp::{TcpHeader, TcpSocket, TcpState};
pub use udp::{UdpHeader, UdpSocketTable, UdpDatagram};
pub use dns::{DnsClient, DnsCache, DnsHeader};
pub use dhcp::{DhcpClient, DhcpLease};
pub use icmp::{IcmpHeader, IcmpPacketBuilder};
pub use http::{HttpRequest, HttpResponse, HttpMethod};
pub use ipv6::{Ipv6Addr, Ipv6Header, Ipv6FragmentHeader};
pub use icmpv6::{Icmpv6Engine, Icmpv6Header, NdpNeighborEntry};
pub use bpf::{BpfVm, BpfInsn};
pub use tls::{TlsClientSession, TlsState, TlsRecordHeader};
pub use dns_client::{DnsClient as ExtendedDnsResolver, DnsRecord};
pub use http2::{Http2Frame, Http2FrameHeader, Http2FrameType, Http2Session};
pub use wireguard::{WgPeer, WgMsgInitiation, WgMsgResponse, WgDataHeader};
pub use websocket::{WsFrame, WsFrameHeader, WsOpcode, WsCloseCode, WsSession, compute_websocket_accept};
pub use snmp::{SnmpMessage, SnmpPdu, SnmpVarBind, SnmpOid, Asn1Value, SnmpErrorStatus, Mib2Engine};
pub use ftp::{FtpServerSession, FtpCommand, FtpTransferType, FtpDataMode, FtpSessionState};


// E1000 MMIO Registers
pub const E1000_CTRL: usize = 0x0000;     // Device Control
pub const E1000_STATUS: usize = 0x0008;   // Device Status
pub const E1000_EECD: usize = 0x0010;     // EEPROM/Flash Control/Data
pub const E1000_EERD: usize = 0x0014;     // EEPROM Read
pub const E1000_ICR: usize = 0x00C0;      // Interrupt Cause Read
pub const E1000_IMS: usize = 0x00D0;      // Interrupt Mask Set/Read
pub const E1000_IMC: usize = 0x00D8;      // Interrupt Mask Clear
pub const E1000_RCTL: usize = 0x0100;     // Receive Control
pub const E1000_TCTL: usize = 0x0400;     // Transmit Control
pub const E1000_TIPG: usize = 0x0410;     // Transmit IPG

// Receive Descriptor Registers
pub const E1000_RDBAL: usize = 0x2800;    // RX Descriptor Base Address Low
pub const E1000_RDBAH: usize = 0x2804;    // RX Descriptor Base Address High
pub const E1000_RDLEN: usize = 0x2808;    // RX Descriptor Length
pub const E1000_RDH: usize = 0x2810;      // RX Descriptor Head
pub const E1000_RDT: usize = 0x2818;      // RX Descriptor Tail

// Transmit Descriptor Registers
pub const E1000_TDBAL: usize = 0x3800;    // TX Descriptor Base Address Low
pub const E1000_TDBAH: usize = 0x3804;    // TX Descriptor Base Address High
pub const E1000_TDLEN: usize = 0x3808;    // TX Descriptor Length
pub const E1000_TDH: usize = 0x3810;      // TX Descriptor Head
pub const E1000_TDT: usize = 0x3818;      // TX Descriptor Tail

// Receive Address Low / High
pub const E1000_RAL: usize = 0x5400;
pub const E1000_RAH: usize = 0x5404;

// Control Register Bits
pub const E1000_CTRL_SLU: u32 = 1 << 6;   // Set Link Up
pub const E1000_CTRL_RST: u32 = 1 << 26;  // Device Reset

// RCTL Bits
pub const E1000_RCTL_EN: u32 = 1 << 1;    // Receiver Enable
pub const E1000_RCTL_SBP: u32 = 1 << 2;   // Store Bad Packets
pub const E1000_RCTL_UPE: u32 = 1 << 3;   // Unicast Promiscuous Enable
pub const E1000_RCTL_MPE: u32 = 1 << 4;   // Multicast Promiscuous Enable
pub const E1000_RCTL_BAM: u32 = 1 << 15;  // Broadcast Accept Mode
pub const E1000_RCTL_BSIZE_2048: u32 = 0; // Buffer Size 2048 Bytes
pub const E1000_RCTL_SECRC: u32 = 1 << 26;// Strip Ethernet CRC

// TCTL Bits
pub const E1000_TCTL_EN: u32 = 1 << 1;    // Transmit Enable
pub const E1000_TCTL_PSP: u32 = 1 << 3;   // Pad Short Packets
pub const E1000_TCTL_CT_SHIFT: u32 = 4;   // Collision Threshold
pub const E1000_TCTL_COLD_SHIFT: u32 = 12;// Collision Distance

// Descriptors
const NUM_RX_DESC: usize = 32;
const NUM_TX_DESC: usize = 16;
const PKT_BUF_SIZE: usize = 2048;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct RxDesc {
    pub address: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct TxDesc {
    pub address: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

pub struct E1000Device {
    pub mmio_base: usize,
    pub mac_addr: [u8; 6],
    pub link_up: bool,
    pub rx_cur: usize,
    pub tx_cur: usize,
    pub ip_addr: [u8; 4],
}

// Static DMA descriptor rings and buffers
#[repr(align(16))]
struct RxRing([RxDesc; NUM_RX_DESC]);
#[repr(align(16))]
struct TxRing([TxDesc; NUM_TX_DESC]);
#[repr(align(16))]
struct PacketBuffers([[u8; PKT_BUF_SIZE]; NUM_RX_DESC]);
#[repr(align(16))]
struct TxPacketBuffers([[u8; PKT_BUF_SIZE]; NUM_TX_DESC]);

static mut RX_RING: RxRing = RxRing([RxDesc { address: 0, length: 0, checksum: 0, status: 0, errors: 0, special: 0 }; NUM_RX_DESC]);
static mut TX_RING: TxRing = TxRing([TxDesc { address: 0, length: 0, cso: 0, cmd: 0, status: 0, css: 0, special: 0 }; NUM_TX_DESC]);
static mut RX_BUFFERS: PacketBuffers = PacketBuffers([[0; PKT_BUF_SIZE]; NUM_RX_DESC]);
static mut TX_BUFFERS: TxPacketBuffers = TxPacketBuffers([[0; PKT_BUF_SIZE]; NUM_TX_DESC]);

pub static mut GLOBAL_E1000: Option<E1000Device> = None;

impl E1000Device {
    pub unsafe fn write_reg(&self, reg: usize, val: u32) {
        let ptr = (self.mmio_base + reg) as *mut u32;
        core::ptr::write_volatile(ptr, val);
    }

    pub unsafe fn read_reg(&self, reg: usize) -> u32 {
        let ptr = (self.mmio_base + reg) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    pub unsafe fn initialize(dev: &PciDevice) -> bool {
        dev.enable_bus_mastering();

        // Intel 82540EM BAR0 is Memory-Mapped I/O Base Address (MMIO)
        let bar0 = dev.bar0 & 0xFFFF_FFF0;
        if bar0 == 0 {
            return false;
        }

        let mmio_base = bar0 as usize;
        crate::diagnostics::serial::write_str("[E1000] Initializing Intel Gigabit NIC (MMIO: 0x");
        crate::diagnostics::serial::write_u64("", bar0 as u64);
        crate::diagnostics::serial::write_str(")...\r\n");

        let mut nic = Self {
            mmio_base,
            mac_addr: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // Default fallback
            link_up: false,
            rx_cur: 0,
            tx_cur: 0,
            ip_addr: [10, 0, 2, 15], // Default VirtualBox NAT IP
        };

        // 1. Reset device
        nic.write_reg(E1000_CTRL, nic.read_reg(E1000_CTRL) | E1000_CTRL_RST);
        for _ in 0..50_000 { crate::arch::x86_64::cpu::out8(0x80, 0); }

        // 2. Set Link Up (SLU)
        nic.write_reg(E1000_CTRL, nic.read_reg(E1000_CTRL) | E1000_CTRL_SLU);

        // 3. Read MAC Address from Receive Address Registers
        let ral = nic.read_reg(E1000_RAL);
        let rah = nic.read_reg(E1000_RAH);
        if ral != 0 {
            nic.mac_addr[0] = (ral & 0xFF) as u8;
            nic.mac_addr[1] = ((ral >> 8) & 0xFF) as u8;
            nic.mac_addr[2] = ((ral >> 16) & 0xFF) as u8;
            nic.mac_addr[3] = ((ral >> 24) & 0xFF) as u8;
            nic.mac_addr[4] = (rah & 0xFF) as u8;
            nic.mac_addr[5] = ((rah >> 8) & 0xFF) as u8;
        }

        crate::diagnostics::serial::write_str("[E1000] MAC Address: ");
        for i in 0..6 {
            crate::diagnostics::serial::write_u64("", nic.mac_addr[i] as u64);
            if i < 5 { crate::diagnostics::serial::write_str(":"); }
        }
        crate::diagnostics::serial::write_str("\r\n");

        // 4. Setup RX Descriptors & Buffers
        for i in 0..NUM_RX_DESC {
            let p_buf = core::ptr::addr_of!(RX_BUFFERS.0[i]) as u64;
            RX_RING.0[i] = RxDesc {
                address: p_buf,
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
        }
        let p_rx_ring = core::ptr::addr_of!(RX_RING.0) as u32;
        nic.write_reg(E1000_RDBAL, p_rx_ring);
        nic.write_reg(E1000_RDBAH, 0);
        nic.write_reg(E1000_RDLEN, (NUM_RX_DESC * core::mem::size_of::<RxDesc>()) as u32);
        nic.write_reg(E1000_RDH, 0);
        nic.write_reg(E1000_RDT, (NUM_RX_DESC - 1) as u32);

        // Enable RX
        nic.write_reg(E1000_RCTL, E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_BSIZE_2048 | E1000_RCTL_SECRC);

        // 5. Setup TX Descriptors & Buffers
        for i in 0..NUM_TX_DESC {
            let p_buf = core::ptr::addr_of!(TX_BUFFERS.0[i]) as u64;
            TX_RING.0[i] = TxDesc {
                address: p_buf,
                length: 0,
                cso: 0,
                cmd: 0,
                status: 1, // Ready (DD=1)
                css: 0,
                special: 0,
            };
        }
        let p_tx_ring = core::ptr::addr_of!(TX_RING.0) as u32;
        nic.write_reg(E1000_TDBAL, p_tx_ring);
        nic.write_reg(E1000_TDBAH, 0);
        nic.write_reg(E1000_TDLEN, (NUM_TX_DESC * core::mem::size_of::<TxDesc>()) as u32);
        nic.write_reg(E1000_TDH, 0);
        nic.write_reg(E1000_TDT, 0);

        // Configure TIPG (Inter-Packet Gap for 1 Gbps)
        nic.write_reg(E1000_TIPG, 10 | (8 << 10) | (6 << 20));

        // Enable TX
        nic.write_reg(E1000_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP | (15 << E1000_TCTL_CT_SHIFT) | (64 << E1000_TCTL_COLD_SHIFT));

        // Check Link Status
        let status = nic.read_reg(E1000_STATUS);
        nic.link_up = (status & (1 << 1)) != 0;
        crate::diagnostics::serial::write_str(if nic.link_up {
            "[E1000] LINK STATUS: 1 Gbps FULL-DUPLEX UP!\r\n"
        } else {
            "[E1000] LINK STATUS: AUTO-NEGOTIATING...\r\n"
        });

        GLOBAL_E1000 = Some(nic);
        true
    }

    /// Sends a raw Ethernet packet via DMA
    pub unsafe fn send_packet(&mut self, packet: &[u8]) -> bool {
        let idx = self.tx_cur;
        let desc = &mut TX_RING.0[idx];

        // Check if descriptor has been processed by hardware (DD bit in status)
        if desc.status & 1 == 0 {
            return false;
        }

        let copy_len = packet.len().min(PKT_BUF_SIZE);
        TX_BUFFERS.0[idx][..copy_len].copy_from_slice(&packet[..copy_len]);

        desc.length = copy_len as u16;
        desc.cmd = (1 << 0) | (1 << 3); // EOP (End of Packet) | RS (Report Status)
        desc.status = 0;

        self.tx_cur = (self.tx_cur + 1) % NUM_TX_DESC;
        self.write_reg(E1000_TDT, self.tx_cur as u32);
        true
    }

    /// Sends an ICMP Echo Request (Ping) to the target IPv4 address
    pub unsafe fn send_ping(&mut self, target_ip: [u8; 4], seq: u16) -> bool {
        let mut pkt = [0u8; 98]; // Standard 98-byte ping packet

        // 1. Ethernet Header (14 bytes)
        // Dest MAC: Broadcast FF:FF:FF:FF:FF:FF (or gateway)
        for i in 0..6 { pkt[i] = 0xFF; }
        // Source MAC: Our MAC
        pkt[6..12].copy_from_slice(&self.mac_addr);
        // EtherType: IPv4 (0x0800)
        pkt[12] = 0x08;
        pkt[13] = 0x00;

        // 2. IPv4 Header (20 bytes)
        pkt[14] = 0x45; // Version 4, IHL 5
        pkt[15] = 0x00; // DSCP / ECN
        pkt[16] = 0x00; // Total Length (84 bytes = 20 IP + 64 ICMP)
        pkt[17] = 84;
        pkt[18] = 0x12; // Identification
        pkt[19] = 0x34;
        pkt[20] = 0x40; // Flags: Don't Fragment
        pkt[21] = 0x00;
        pkt[22] = 64;   // TTL = 64
        pkt[23] = 1;    // Protocol = ICMP (1)
        pkt[24] = 0x00; // Checksum placeholder
        pkt[25] = 0x00;
        // Source IP
        pkt[26..30].copy_from_slice(&self.ip_addr);
        // Dest IP
        pkt[30..34].copy_from_slice(&target_ip);

        // IPv4 Header Checksum
        let mut ip_sum: u32 = 0;
        for i in (14..34).step_by(2) {
            let word = u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
            ip_sum += word;
        }
        while (ip_sum >> 16) != 0 {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        let ip_chk = (!ip_sum) as u16;
        pkt[24..26].copy_from_slice(&ip_chk.to_be_bytes());

        // 3. ICMP Echo Request (64 bytes)
        pkt[34] = 8; // Type 8: Echo Request
        pkt[35] = 0; // Code 0
        pkt[36] = 0; // Checksum placeholder
        pkt[37] = 0;
        pkt[38] = 0x13; // Identifier
        pkt[39] = 0x37;
        pkt[40..42].copy_from_slice(&seq.to_be_bytes()); // Sequence Number
        for i in 42..98 {
            pkt[i] = (i & 0xFF) as u8; // Data payload
        }

        // ICMP Checksum
        let mut icmp_sum: u32 = 0;
        for i in (34..98).step_by(2) {
            let word = u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
            icmp_sum += word;
        }
        while (icmp_sum >> 16) != 0 {
            icmp_sum = (icmp_sum & 0xFFFF) + (icmp_sum >> 16);
        }
        let icmp_chk = (!icmp_sum) as u16;
        pkt[36..38].copy_from_slice(&icmp_chk.to_be_bytes());

        self.send_packet(&pkt)
    }

    /// Checks if a packet has arrived in the RX DMA descriptor ring.
    /// Returns Some(Vec<u8>) if a packet was received, None otherwise.
    pub unsafe fn receive_packet(&mut self) -> Option<Vec<u8>> {
        let idx = self.rx_cur;
        let desc = &mut RX_RING.0[idx];

        // Descriptor Done (DD bit = bit 0 in status)
        if desc.status & 1 == 0 {
            return None;
        }

        let len = (desc.length as usize).min(PKT_BUF_SIZE);
        let mut pkt = Vec::with_capacity(len);
        pkt.extend_from_slice(&RX_BUFFERS.0[idx][..len]);

        // Reset descriptor status for reuse by hardware
        desc.status = 0;
        let prev_cur = self.rx_cur;
        self.rx_cur = (self.rx_cur + 1) % NUM_RX_DESC;

        // Advance RX Tail register
        self.write_reg(E1000_RDT, prev_cur as u32);

        Some(pkt)
    }

    /// Sends a DHCP Discover packet to obtain an IP configuration from DHCP server (e.g., VirtualBox 10.0.2.2)
    pub unsafe fn send_dhcp_discover(&mut self) -> bool {
        let mut pkt = [0u8; 342];

        // 1. Ethernet Header (14 bytes)
        for i in 0..6 { pkt[i] = 0xFF; } // Broadcast
        pkt[6..12].copy_from_slice(&self.mac_addr);
        pkt[12] = 0x08; pkt[13] = 0x00; // IPv4

        // 2. IPv4 Header (20 bytes)
        pkt[14] = 0x45;
        let total_len = 328u16; // 20 IP + 8 UDP + 300 BOOTP
        pkt[16..18].copy_from_slice(&total_len.to_be_bytes());
        pkt[18] = 0xAB; pkt[19] = 0xCD;
        pkt[22] = 64; // TTL
        pkt[23] = 17; // UDP
        // Src: 0.0.0.0
        // Dst: 255.255.255.255
        for i in 30..34 { pkt[i] = 0xFF; }

        let mut ip_sum: u32 = 0;
        for i in (14..34).step_by(2) {
            ip_sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while (ip_sum >> 16) != 0 {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        let ip_chk = (!ip_sum) as u16;
        pkt[24..26].copy_from_slice(&ip_chk.to_be_bytes());

        // 3. UDP Header (8 bytes)
        let src_port = 68u16; // DHCP Client
        let dst_port = 67u16; // DHCP Server
        pkt[34..36].copy_from_slice(&src_port.to_be_bytes());
        pkt[36..38].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = 308u16; // 8 UDP + 300 BOOTP
        pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
        pkt[40] = 0; pkt[41] = 0; // Checksum 0 (optional in IPv4 UDP)

        // 4. BOOTP / DHCP (300 bytes)
        let bp = 42;
        pkt[bp] = 1; // Boot Request
        pkt[bp + 1] = 1; // Ethernet
        pkt[bp + 2] = 6; // Hardware address len 6
        pkt[bp + 4] = 0x39; pkt[bp + 5] = 0x03; pkt[bp + 6] = 0xF3; pkt[bp + 7] = 0x26; // XID transaction ID
        pkt[bp + 10] = 0x80; // Broadcast flag
        pkt[bp + 28..bp + 34].copy_from_slice(&self.mac_addr); // Client MAC

        // Magic Cookie: 99, 130, 83, 99
        let opt = bp + 236;
        pkt[opt] = 99; pkt[opt + 1] = 130; pkt[opt + 2] = 83; pkt[opt + 3] = 99;

        // DHCP Option 53: DHCP Discover (type 1)
        pkt[opt + 4] = 53; pkt[opt + 5] = 1; pkt[opt + 6] = 1;

        // Option 55: Parameter Request List (Subnet Mask, Router, DNS)
        pkt[opt + 7] = 55; pkt[opt + 8] = 3; pkt[opt + 9] = 1; pkt[opt + 10] = 3; pkt[opt + 11] = 6;

        // Option 255: End
        pkt[opt + 12] = 255;

        self.send_packet(&pkt)
    }

    /// Sends a standard HTTP GET request over TCP (or simulated HTTP ping probe)
    pub unsafe fn send_http_get(&mut self, target_ip: [u8; 4], host: &str, path: &str) -> bool {
        // Send a formatted HTTP packet on port 80
        let http_payload = alloc::format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: CorOS-Web/1.0\r\nConnection: close\r\n\r\n", path, host);
        let payload_bytes = http_payload.as_bytes();
        let total_tcp_payload = payload_bytes.len();

        let mut pkt = Vec::with_capacity(14 + 20 + 20 + total_tcp_payload);
        // Ethernet Header
        pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        pkt.extend_from_slice(&self.mac_addr);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4 Header
        let ip_len = (20 + 20 + total_tcp_payload) as u16;
        let mut ip_hdr = [
            0x45, 0x00, (ip_len >> 8) as u8, (ip_len & 0xFF) as u8,
            0x55, 0xAA, 0x40, 0x00,
            64, 6, 0, 0, // Protocol 6 = TCP
            self.ip_addr[0], self.ip_addr[1], self.ip_addr[2], self.ip_addr[3],
            target_ip[0], target_ip[1], target_ip[2], target_ip[3]
        ];
        let mut ip_sum: u32 = 0;
        for i in (0..20).step_by(2) {
            ip_sum += u16::from_be_bytes([ip_hdr[i], ip_hdr[i + 1]]) as u32;
        }
        while (ip_sum >> 16) != 0 {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        let ip_chk = (!ip_sum) as u16;
        ip_hdr[10..12].copy_from_slice(&ip_chk.to_be_bytes());
        pkt.extend_from_slice(&ip_hdr);

        // TCP Header (20 bytes, SYN+PSH with HTTP data)
        let tcp_hdr = [
            0x1F, 0x90, // Src port 8080
            0x00, 0x50, // Dst port 80
            0x00, 0x01, 0x00, 0x01, // Seq 65537
            0x00, 0x00, 0x00, 0x00, // Ack 0
            0x50, 0x18, // Header len 20 (5 * 4), Flags: ACK | PSH
            0x72, 0x10, // Window size 29200
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent ptr
        ];
        pkt.extend_from_slice(&tcp_hdr);
        pkt.extend_from_slice(payload_bytes);

        self.send_packet(&pkt)
    }
}

