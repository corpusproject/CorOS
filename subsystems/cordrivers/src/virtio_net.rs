//! CorOS Hardware Driver Module: `virtio_net`
//!
//! VirtIO 1.2 Network Device (`virtio-net`) 12-byte Packet Header (`VirtioNetHdr`),
//! checksum offload and Generic Segmentation Offload (`GSO`) metadata, MAC address
//! unicast/multicast filter classifier, and RX/TX virtqueue ring buffer accounting.

/// VirtIO Network Device feature bits.
pub mod virtio_net_features {
    pub const CSUM: u64 = 1 << 0;
    pub const GUEST_CSUM: u64 = 1 << 1;
    pub const MAC: u64 = 1 << 5;
    pub const GUEST_TSO4: u64 = 1 << 7;
    pub const GUEST_TSO6: u64 = 1 << 8;
    pub const HOST_TSO4: u64 = 1 << 11;
    pub const HOST_TSO6: u64 = 1 << 12;
    pub const MRG_RXBUF: u64 = 1 << 15;
    pub const STATUS: u64 = 1 << 16;
    pub const CTRL_VQ: u64 = 1 << 17;
    pub const CTRL_RX: u64 = 1 << 18;
    pub const CTRL_VLAN: u64 = 1 << 19;
    pub const MQ: u64 = 1 << 22;
}

/// `VirtioNetHdr::flags` bit definitions.
pub mod virtio_net_hdr_flags {
    pub const NEEDS_CSUM: u8 = 1 << 0;
    pub const DATA_VALID: u8 = 1 << 1;
    pub const RSC_INFO: u8 = 1 << 2;
}

/// `VirtioNetHdr::gso_type` segmentation offload modes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioNetGsoType {
    None = 0,
    Tcpv4 = 1,
    Udp = 3,
    Tcpv6 = 4,
    EcnFlag = 0x80,
}

/// 12-byte VirtIO 1.2 Network Packet Header (`virtio_net_hdr_v1`) prepended to every Ethernet frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Standard zeroed header for an unsegmented frame with no checksum offload.
    #[inline]
    pub const fn standard_tx() -> Self {
        Self {
            flags: 0,
            gso_type: VirtioNetGsoType::None as u8,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        }
    }

    /// Builds a TX header requesting hardware L4 checksum offload starting at `csum_start`
    /// (e.g., `14 + 20 = 34` for Ethernet + IPv4) and writing the 16-bit checksum at `csum_offset`
    /// (`16` for TCP, `6` for UDP).
    #[inline]
    pub const fn tx_with_csum_offload(csum_start: u16, csum_offset: u16) -> Self {
        Self {
            flags: virtio_net_hdr_flags::NEEDS_CSUM,
            gso_type: VirtioNetGsoType::None as u8,
            hdr_len: csum_start,
            gso_size: 0,
            csum_start,
            csum_offset,
            num_buffers: 0,
        }
    }

    /// Builds a TCPv4 Segmentation Offload (TSO) header for a large TCP segment.
    #[inline]
    pub const fn tx_tcpv4_tso(hdr_len: u16, mss: u16, csum_start: u16) -> Self {
        Self {
            flags: virtio_net_hdr_flags::NEEDS_CSUM,
            gso_type: VirtioNetGsoType::Tcpv4 as u8,
            hdr_len,
            gso_size: mss,
            csum_start,
            csum_offset: 16, // TCP checksum offset within TCP header
            num_buffers: 0,
        }
    }
}

/// Ethernet Frame classification result from the `VirtioNetMacFilter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFilterVerdict {
    AcceptLocalUnicast,
    AcceptBroadcast,
    AcceptMulticast,
    AcceptPromiscuous,
    DropForeignUnicast,
    DropMulticast,
}

/// VirtIO Network MAC Filter & RX/TX Queue State Machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetController {
    pub mac_address: [u8; 6],
    pub mtu: u16,
    pub promiscuous: bool,
    pub all_multicast: bool,
    pub link_up: bool,
    pub rx_posted_buffers: u16,
    pub tx_inflight_packets: u16,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl VirtioNetController {
    #[inline]
    pub const fn new(mac_address: [u8; 6], mtu: u16) -> Self {
        Self {
            mac_address,
            mtu,
            promiscuous: false,
            all_multicast: false,
            link_up: true,
            rx_posted_buffers: 0,
            tx_inflight_packets: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// Evaluates whether an incoming Ethernet frame with `dst_mac` should be accepted by the NIC.
    pub fn classify_destination_mac(&self, dst_mac: &[u8; 6]) -> FrameFilterVerdict {
        if *dst_mac == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return FrameFilterVerdict::AcceptBroadcast;
        }
        if *dst_mac == self.mac_address {
            return FrameFilterVerdict::AcceptLocalUnicast;
        }
        if (dst_mac[0] & 0x01) != 0 {
            if self.all_multicast || self.promiscuous {
                return FrameFilterVerdict::AcceptMulticast;
            } else {
                return FrameFilterVerdict::DropMulticast;
            }
        }
        if self.promiscuous {
            FrameFilterVerdict::AcceptPromiscuous
        } else {
            FrameFilterVerdict::DropForeignUnicast
        }
    }

    /// Prepends a 12-byte `VirtioNetHdr` and validates frame length against `MTU + 14` before TX enqueue.
    pub fn prepare_tx_frame(
        &mut self,
        hdr: VirtioNetHdr,
        eth_frame: &[u8],
        out_dma_buf: &mut [u8],
    ) -> Option<usize> {
        let max_eth_len = (self.mtu as usize) + 14;
        if !self.link_up || eth_frame.len() < 14 || (hdr.gso_type == 0 && eth_frame.len() > max_eth_len) {
            return None;
        }
        let total_len = 12 + eth_frame.len();
        if out_dma_buf.len() < total_len {
            return None;
        }

        out_dma_buf[0] = hdr.flags;
        out_dma_buf[1] = hdr.gso_type;
        out_dma_buf[2..4].copy_from_slice(&hdr.hdr_len.to_le_bytes());
        out_dma_buf[4..6].copy_from_slice(&hdr.gso_size.to_le_bytes());
        out_dma_buf[6..8].copy_from_slice(&hdr.csum_start.to_le_bytes());
        out_dma_buf[8..10].copy_from_slice(&hdr.csum_offset.to_le_bytes());
        out_dma_buf[10..12].copy_from_slice(&hdr.num_buffers.to_le_bytes());
        out_dma_buf[12..total_len].copy_from_slice(eth_frame);

        self.tx_inflight_packets = self.tx_inflight_packets.saturating_add(1);
        self.tx_packets += 1;
        self.tx_bytes += eth_frame.len() as u64;
        Some(total_len)
    }
}

/// Self-test for `virtio_net` 12-byte header serialization, TSO/checksum metadata, and MAC filtering.
pub fn verify_driver_module_virtio_net() -> u32 {
    let mut passed = 0u32;

    // 1. Verify VirtioNetHdr size is 12 bytes
    if core::mem::size_of::<VirtioNetHdr>() == 12 {
        passed += 1;
    }

    // 2. Verify MAC filter unicast, broadcast, and multicast verdicts
    let mut nic = VirtioNetController::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], 1500);
    if nic.classify_destination_mac(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        == FrameFilterVerdict::AcceptLocalUnicast
        && nic.classify_destination_mac(&[0xFF; 6]) == FrameFilterVerdict::AcceptBroadcast
        && nic.classify_destination_mac(&[0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB])
            == FrameFilterVerdict::DropMulticast
    {
        passed += 1;
    }

    // 3. Verify enabling all_multicast allows IPv4/IPv6 multicast frames
    nic.all_multicast = true;
    if nic.classify_destination_mac(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01])
        == FrameFilterVerdict::AcceptMulticast
    {
        passed += 1;
    }

    // 4. Verify TX frame assembly with TCP checksum offload header
    let hdr = VirtioNetHdr::tx_with_csum_offload(34, 16);
    let eth_pkt = [0xAAu8; 64];
    let mut dma_buf = [0u8; 128];
    if let Some(written) = nic.prepare_tx_frame(hdr, &eth_pkt, &mut dma_buf) {
        if written == 76 && dma_buf[0] == virtio_net_hdr_flags::NEEDS_CSUM && nic.tx_bytes == 64 {
            passed += 1;
        }
    }

    passed
}
