//! CorOS Hardware Driver Module: `realtek_nic`
//!
//! Realtek RTL8168 / RTL8111 PCIe Gigabit Ethernet Controller register layout
//! (`IDR0..5`, `MAR0..7`, `TNPDS`, `RDSAR`, `CR`, `TCR`, `RCR`, `IMR`, `ISR`, `PHYAR`),
//! 16-byte C+ Command Descriptor Ring (`Rtl8168Desc`) with `OWN`, `EOR`, `FS`, `LS`
//! flags, VLAN tag insertion/extraction, and MDIO/MII `PHYAR` transceiver access.

/// Realtek RTL8168/RTL8111 MMIO Register Offsets.
pub mod rtl8168_regs {
    /// MAC ID Register 0..5 (6 bytes).
    pub const IDR0: usize = 0x00;
    /// Multicast Filter Register 0..7 (8 bytes).
    pub const MAR0: usize = 0x08;
    /// Transmit Normal Priority Descriptors Start Address (64-bit).
    pub const TNPDS: usize = 0x20;
    /// Command Register (8-bit: `TE = bit 2`, `RE = bit 3`, `RST = bit 4`).
    pub const CR: usize = 0x37;
    /// Transmit Priority Polling Register (8-bit: `NPQ = bit 6`).
    pub const TPPOLL: usize = 0x38;
    /// Interrupt Mask Register (16-bit).
    pub const IMR: usize = 0x3C;
    /// Interrupt Status Register (16-bit).
    pub const ISR: usize = 0x3E;
    /// Transmit Configuration Register (32-bit).
    pub const TCR: usize = 0x40;
    /// Receive Configuration Register (32-bit).
    pub const RCR: usize = 0x44;
    /// 93C46 EEPROM Command Register (8-bit: lock/unlock config registers).
    pub const CR9346: usize = 0x50;
    /// PHY Access Register (32-bit MDIO read/write).
    pub const PHYAR: usize = 0x60;
    /// PHY Status Register (8-bit: `LinkStatus = bit 1`, `1000MF = bit 4`).
    pub const PHYSTATUS: usize = 0x6C;
    /// Receive Packet Maximum Size (16-bit).
    pub const RMS: usize = 0xDA;
    /// C+ Command Register (16-bit).
    pub const CPCR: usize = 0xE0;
    /// Receive Descriptor Start Address Register (64-bit).
    pub const RDSAR: usize = 0xE4;
    /// Max Transmit Packet Size (8-bit in 128-byte units).
    pub const MTPS: usize = 0xEC;
}

/// RTL8168 Command Register (`CR`) bitflags.
pub mod rtl_cr {
    pub const TE: u8 = 1 << 2;
    pub const RE: u8 = 1 << 3;
    pub const RST: u8 = 1 << 4;
}

/// RTL8168 RX/TX Descriptor `opts1` bitflags.
pub mod rtl_desc_opts1 {
    /// Owned by NIC DMA engine when set (`1`), owned by Host CPU when clear (`0`).
    pub const OWN: u32 = 1 << 31;
    /// End of Descriptor Ring (`EOR`) — instructs DMA engine to wrap back to index `0`.
    pub const EOR: u32 = 1 << 30;
    /// First Segment of frame (`FS`).
    pub const FS: u32 = 1 << 29;
    /// Last Segment of frame (`LS`).
    pub const LS: u32 = 1 << 28;
    /// Large Send Offload (TSO) enable on TX.
    pub const LGSEN: u32 = 1 << 27;
    /// IPv4 Checksum Offload enable on TX.
    pub const IPCS: u32 = 1 << 18;
    /// UDP Checksum Offload enable on TX.
    pub const UDPCS: u32 = 1 << 17;
    /// TCP Checksum Offload enable on TX.
    pub const TCPCS: u32 = 1 << 16;
}

/// 16-byte Realtek RTL8168 / RTL8111 C+ RX/TX Ring Descriptor (`Rtl8168Desc`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtl8168Desc {
    /// `OWN` (bit 31), `EOR` (bit 30), `FS` (bit 29), `LS` (bit 28), flags, and frame length (`bits 15:0`).
    pub opts1: u32,
    /// VLAN Tag Action & TCI (`bits 15:0` in byte-swapped 802.1Q order).
    pub opts2: u32,
    /// 64-bit Physical DMA Buffer Address.
    pub addr: u64,
}

impl Rtl8168Desc {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            opts1: 0,
            opts2: 0,
            addr: 0,
        }
    }

    /// Initializes an RX descriptor posted to the NIC DMA engine.
    #[inline]
    pub const fn new_rx_posted(buffer_phys: u64, buffer_size: u16, is_end_of_ring: bool) -> Self {
        let eor_bit = if is_end_of_ring {
            rtl_desc_opts1::EOR
        } else {
            0
        };
        Self {
            opts1: rtl_desc_opts1::OWN | eor_bit | ((buffer_size as u32) & 0x3FFF),
            opts2: 0,
            addr: buffer_phys,
        }
    }

    /// Initializes a single-buffer TX descriptor (`FS | LS | OWN`) with optional VLAN tag insertion.
    #[inline]
    pub const fn new_tx_single(
        buffer_phys: u64,
        frame_len: u16,
        is_end_of_ring: bool,
        vlan_tci: Option<u16>,
    ) -> Self {
        let eor_bit = if is_end_of_ring {
            rtl_desc_opts1::EOR
        } else {
            0
        };
        let opts1 = rtl_desc_opts1::OWN
            | eor_bit
            | rtl_desc_opts1::FS
            | rtl_desc_opts1::LS
            | ((frame_len as u32) & 0xFFFF);
        let opts2 = match vlan_tci {
            Some(tci) => (1u32 << 17) | ((tci.swap_bytes()) as u32),
            None => 0,
        };
        Self {
            opts1,
            opts2,
            addr: buffer_phys,
        }
    }

    #[inline]
    pub const fn is_owned_by_nic(&self) -> bool {
        (self.opts1 & rtl_desc_opts1::OWN) != 0
    }

    #[inline]
    pub const fn is_end_of_ring(&self) -> bool {
        (self.opts1 & rtl_desc_opts1::EOR) != 0
    }

    #[inline]
    pub const fn frame_length(&self) -> u16 {
        (self.opts1 & 0x3FFF) as u16
    }
}

/// Encodes a 32-bit `PHYAR` register value to read or write a 5-bit MII PHY register (`0..=31`).
///
/// In RTL8168 `PHYAR`:
/// - Bit 31: `Flag` (`1` = Write to PHY, `0` = Read from PHY; hardware flips this bit when complete)
/// - Bits `20:16`: 5-bit MII register address
/// - Bits `15:0`: 16-bit data payload
#[inline]
pub const fn encode_phyar_access(reg_addr: u8, write_data: Option<u16>) -> u32 {
    let reg_bits = ((reg_addr & 0x1F) as u32) << 16;
    match write_data {
        Some(data) => (1u32 << 31) | reg_bits | (data as u32),
        None => reg_bits,
    }
}

/// Decodes a completed MII PHY read from `PHYAR` (returns `Some(data)` once hardware sets bit 31 = `1`).
#[inline]
pub const fn decode_phyar_read_result(phyar_val: u32) -> Option<u16> {
    if (phyar_val & (1u32 << 31)) != 0 {
        Some((phyar_val & 0xFFFF) as u16)
    } else {
        None
    }
}

/// Realtek RTL8168 Descriptor Ring manager preserving the `EOR` marker on the final slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtl8168RingManager {
    pub num_descriptors: usize,
    pub tx_prod: usize,
    pub rx_cons: usize,
}

impl Rtl8168RingManager {
    pub fn init_rings(
        rx_ring: &mut [Rtl8168Desc],
        tx_ring: &mut [Rtl8168Desc],
        rx_dma_base: u64,
        rx_buf_size: u16,
    ) -> Self {
        let n = rx_ring.len().min(tx_ring.len());
        let mut i = 0;
        while i < n {
            let is_last = i + 1 == n;
            rx_ring[i] = Rtl8168Desc::new_rx_posted(
                rx_dma_base + (i as u64) * (rx_buf_size as u64),
                rx_buf_size,
                is_last,
            );
            tx_ring[i] = Rtl8168Desc {
                opts1: if is_last { rtl_desc_opts1::EOR } else { 0 },
                opts2: 0,
                addr: 0,
            };
            i += 1;
        }
        Self {
            num_descriptors: n,
            tx_prod: 0,
            rx_cons: 0,
        }
    }

    /// Submits a packet to `tx_ring`, preserving the `EOR` bit on the last descriptor in the ring.
    pub fn submit_tx(
        &mut self,
        tx_ring: &mut [Rtl8168Desc],
        pkt_phys: u64,
        pkt_len: u16,
        vlan_tci: Option<u16>,
    ) -> Option<usize> {
        let slot = self.tx_prod;
        if slot >= tx_ring.len() || tx_ring[slot].is_owned_by_nic() {
            return None;
        }
        let is_last = slot + 1 == self.num_descriptors;
        tx_ring[slot] = Rtl8168Desc::new_tx_single(pkt_phys, pkt_len, is_last, vlan_tci);
        self.tx_prod = (self.tx_prod + 1) % self.num_descriptors;
        Some(slot)
    }
}

/// Self-test for `realtek_nic` C+ descriptor ring `OWN`/`EOR`/`FS`/`LS` handling and PHY MII register access.
pub fn verify_driver_module_realtek_nic() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Rtl8168Desc size is 16 bytes
    if core::mem::size_of::<Rtl8168Desc>() == 16 {
        passed += 1;
    }

    // 2. Verify RX/TX ring initialization sets EOR only on the final descriptor
    let mut rx_ring = [Rtl8168Desc::zeroed(); 4];
    let mut tx_ring = [Rtl8168Desc::zeroed(); 4];
    let mut mgr = Rtl8168RingManager::init_rings(&mut rx_ring, &mut tx_ring, 0x5000_0000, 2048);

    if rx_ring[0].is_owned_by_nic()
        && !rx_ring[0].is_end_of_ring()
        && rx_ring[3].is_end_of_ring()
        && tx_ring[3].is_end_of_ring()
    {
        passed += 1;
    }

    // 3. Verify submitting 4 TX packets preserves EOR on slot 3 and wraps tx_prod to 0
    for i in 0..4 {
        let _ = mgr.submit_tx(&mut tx_ring, 0x6000_0000 + (i as u64) * 2048, 512, Some(100));
    }
    if mgr.tx_prod == 0
        && tx_ring[3].is_owned_by_nic()
        && tx_ring[3].is_end_of_ring()
        && tx_ring[3].frame_length() == 512
    {
        passed += 1;
    }

    // 4. Verify PHYAR MII register read/write encoding (BMCR = reg 0x00, BMSR = reg 0x01)
    let write_bmcr = encode_phyar_access(0x00, Some(0x1200)); // Auto-negotiation enable + restart
    let read_bmsr = encode_phyar_access(0x01, None);
    if write_bmcr == 0x8000_1200
        && read_bmsr == 0x0001_0000
        && decode_phyar_read_result(0x8001_796D) == Some(0x796D)
    {
        passed += 1;
    }

    passed
}
