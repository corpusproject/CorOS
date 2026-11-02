//! CorOS Hardware Driver Module: `intel_e1000`
//!
//! Intel 82540EM / 82574L PRO/1000 Gigabit Ethernet Controller MMIO register layout
//! (`CTRL`, `STATUS`, `EERD`, `ICR`, `IMS`, `RCTL`, `TCTL`, `RDBAL`, `TDBAL`, `RAL0`, `RAH0`),
//! 16-byte Legacy Receive & Transmit Descriptors (`E1000RxDesc`, `E1000TxDesc`),
//! EEPROM Microwire `EERD` MAC reader, and Multicast Table Array (`MTA`) hash calculator.

/// Intel e1000 MMIO Register Offsets.
pub mod e1000_regs {
    /// Device Control.
    pub const CTRL: usize = 0x0000;
    /// Device Status.
    pub const STATUS: usize = 0x0008;
    /// EEPROM/Flash Control.
    pub const EECD: usize = 0x0010;
    /// EEPROM Read.
    pub const EERD: usize = 0x0014;
    /// Flow Control Address Low.
    pub const FCAL: usize = 0x0028;
    /// Interrupt Cause Read.
    pub const ICR: usize = 0x00C0;
    /// Interrupt Mask Set/Read.
    pub const IMS: usize = 0x00D0;
    /// Interrupt Mask Clear.
    pub const IMC: usize = 0x00D8;
    /// Receive Control.
    pub const RCTL: usize = 0x0100;
    /// Transmit Control.
    pub const TCTL: usize = 0x0400;
    /// Transmit Inter-Packet Gap.
    pub const TIPG: usize = 0x0410;
    /// Receive Descriptor Base Address Low.
    pub const RDBAL: usize = 0x2800;
    /// Receive Descriptor Base Address High.
    pub const RDBAH: usize = 0x2804;
    /// Receive Descriptor Length.
    pub const RDLEN: usize = 0x2808;
    /// Receive Descriptor Head.
    pub const RDH: usize = 0x2810;
    /// Receive Descriptor Tail.
    pub const RDT: usize = 0x2818;
    /// Transmit Descriptor Base Address Low.
    pub const TDBAL: usize = 0x3800;
    /// Transmit Descriptor Base Address High.
    pub const TDBAH: usize = 0x3804;
    /// Transmit Descriptor Length.
    pub const TDLEN: usize = 0x3808;
    /// Transmit Descriptor Head.
    pub const TDH: usize = 0x3810;
    /// Transmit Descriptor Tail.
    pub const TDT: usize = 0x3818;
    /// Multicast Table Array (128 DWORDs at `0x5200..0x53FC`).
    pub const MTA_BASE: usize = 0x5200;
    /// Receive Address Low (Slot 0).
    pub const RAL0: usize = 0x5400;
    /// Receive Address High (Slot 0).
    pub const RAH0: usize = 0x5404;
}

/// e1000 Device Control (`CTRL`) bitflags.
pub mod e1000_ctrl {
    pub const FD: u32 = 1 << 0;
    pub const LRST: u32 = 1 << 3;
    pub const ASDE: u32 = 1 << 5;
    pub const SLU: u32 = 1 << 6;
    pub const RST: u32 = 1 << 26;
    pub const VME: u32 = 1 << 30;
    pub const PHY_RST: u32 = 1 << 31;
}

/// e1000 Receive Control (`RCTL`) bitflags.
pub mod e1000_rctl {
    pub const EN: u32 = 1 << 1;
    pub const SBP: u32 = 1 << 2;
    pub const UPE: u32 = 1 << 3;
    pub const MPE: u32 = 1 << 4;
    pub const LBM_NONE: u32 = 0 << 6;
    pub const BAM: u32 = 1 << 15;
    pub const BSIZE_2048: u32 = 0 << 16;
    pub const BSIZE_4096: u32 = (3 << 16) | (1 << 25); // BSIZE=3 + BSEX=1
    pub const SECRC: u32 = 1 << 26;
}

/// e1000 Transmit Control (`TCTL`) bitflags.
pub mod e1000_tctl {
    pub const EN: u32 = 1 << 1;
    pub const PSP: u32 = 1 << 3;
    pub const CT_SHIFT: u32 = 4;
    pub const COLD_SHIFT: u32 = 12;
}

/// e1000 TX Descriptor Command (`cmd`) and Status (`status`) bitflags.
pub mod e1000_tx_bits {
    pub const CMD_EOP: u8 = 1 << 0;
    pub const CMD_IFCS: u8 = 1 << 1;
    pub const CMD_IC: u8 = 1 << 2;
    pub const CMD_RS: u8 = 1 << 3;
    pub const STATUS_DD: u8 = 1 << 0;
}

/// e1000 RX Descriptor Status (`status`) bitflags.
pub mod e1000_rx_bits {
    pub const STATUS_DD: u8 = 1 << 0;
    pub const STATUS_EOP: u8 = 1 << 1;
    pub const STATUS_IXSM: u8 = 1 << 2;
    pub const STATUS_VP: u8 = 1 << 3;
    pub const STATUS_TCPCS: u8 = 1 << 5;
    pub const STATUS_IPCS: u8 = 1 << 6;
}

/// 16-byte Intel e1000 Legacy Receive Descriptor (`E1000RxDesc`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E1000RxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

impl E1000RxDesc {
    #[inline]
    pub const fn new(buffer_addr: u64) -> Self {
        Self {
            buffer_addr,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }

    #[inline]
    pub const fn is_descriptor_done(&self) -> bool {
        (self.status & e1000_rx_bits::STATUS_DD) != 0
    }

    #[inline]
    pub const fn is_end_of_packet(&self) -> bool {
        (self.status & e1000_rx_bits::STATUS_EOP) != 0
    }
}

/// 16-byte Intel e1000 Legacy Transmit Descriptor (`E1000TxDesc`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E1000TxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

impl E1000TxDesc {
    #[inline]
    pub const fn new_frame(buffer_addr: u64, length: u16) -> Self {
        Self {
            buffer_addr,
            length,
            cso: 0,
            cmd: e1000_tx_bits::CMD_EOP | e1000_tx_bits::CMD_IFCS | e1000_tx_bits::CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        }
    }

    #[inline]
    pub const fn is_descriptor_done(&self) -> bool {
        (self.status & e1000_tx_bits::STATUS_DD) != 0
    }
}

/// Encodes an `EERD` (EEPROM Read) command word for the given 8-bit EEPROM word address (`0..=255`).
#[inline]
pub const fn encode_eerd_read_command(word_addr: u8) -> u32 {
    ((word_addr as u32) << 8) | 0x01 // START bit = bit 0
}

/// Decodes the 16-bit data word from a completed `EERD` register read (`DONE` bit = bit 4).
#[inline]
pub const fn decode_eerd_response(eerd_val: u32) -> Option<u16> {
    if (eerd_val & (1 << 4)) != 0 {
        Some(((eerd_val >> 16) & 0xFFFF) as u16)
    } else {
        None
    }
}

/// Assembles a 6-byte Ethernet MAC address from EEPROM words `0`, `1`, and `2`,
/// and encodes the `RAL0` / `RAH0` (Receive Address Low/High + Address Valid `AV` bit 31) registers.
pub const fn mac_from_eeprom_words(w0: u16, w1: u16, w2: u16) -> ([u8; 6], u32, u32) {
    let mac = [
        (w0 & 0xFF) as u8,
        (w0 >> 8) as u8,
        (w1 & 0xFF) as u8,
        (w1 >> 8) as u8,
        (w2 & 0xFF) as u8,
        (w2 >> 8) as u8,
    ];
    let ral0 = (w0 as u32) | ((w1 as u32) << 16);
    let rah0 = (w2 as u32) | (1u32 << 31); // Bit 31 = Address Valid (AV)
    (mac, ral0, rah0)
}

/// Ring index state machine for Intel e1000 RX and TX descriptor rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct E1000RingState {
    pub ring_len: u16,
    pub rx_tail: u16,
    pub tx_tail: u16,
    pub tx_clean_head: u16,
}

impl E1000RingState {
    #[inline]
    pub const fn new(ring_len: u16) -> Self {
        Self {
            ring_len,
            rx_tail: ring_len.saturating_sub(1),
            tx_tail: 0,
            tx_clean_head: 0,
        }
    }

    /// Enqueues a frame into `tx_ring` if the target descriptor has `DD` set (or has never been used),
    /// returning the new `TDT` register value to write to MMIO `0x3818`.
    pub fn enqueue_tx(
        &mut self,
        tx_ring: &mut [E1000TxDesc],
        pkt_phys: u64,
        pkt_len: u16,
    ) -> Option<u16> {
        let slot = self.tx_tail as usize;
        if slot >= tx_ring.len() {
            return None;
        }
        if tx_ring[slot].cmd != 0 && !tx_ring[slot].is_descriptor_done() {
            return None; // Ring full: descriptor still owned by hardware
        }
        tx_ring[slot] = E1000TxDesc::new_frame(pkt_phys, pkt_len);
        self.tx_tail = (self.tx_tail + 1) % self.ring_len;
        Some(self.tx_tail)
    }
}

/// Self-test for `intel_e1000` RX/TX descriptors, EEPROM MAC decoding, and TX ring advancement.
pub fn verify_driver_module_intel_e1000() -> u32 {
    let mut passed = 0u32;

    // 1. Verify E1000RxDesc and E1000TxDesc are 16 bytes
    if core::mem::size_of::<E1000RxDesc>() == 16 && core::mem::size_of::<E1000TxDesc>() == 16 {
        passed += 1;
    }

    // 2. Verify EEPROM EERD command/response and RAL0/RAH0 MAC encoding
    let cmd = encode_eerd_read_command(2);
    let resp = decode_eerd_response(0x5634_0010);
    let (mac, ral0, rah0) = mac_from_eeprom_words(0x5452, 0x1200, 0x5634);
    if cmd == 0x0201
        && resp == Some(0x5634)
        && mac == [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        && ral0 == 0x1200_5452
        && rah0 == 0x8000_5634
    {
        passed += 1;
    }

    // 3. Verify TX ring enqueue and TDT advancement
    let mut tx_ring = [E1000TxDesc {
        buffer_addr: 0,
        length: 0,
        cso: 0,
        cmd: 0,
        status: e1000_tx_bits::STATUS_DD,
        css: 0,
        special: 0,
    }; 4];
    let mut ring_state = E1000RingState::new(4);
    let tdt1 = ring_state.enqueue_tx(&mut tx_ring, 0x7000_0000, 1514);
    let tdt2 = ring_state.enqueue_tx(&mut tx_ring, 0x7000_0800, 64);
    if tdt1 == Some(1)
        && tdt2 == Some(2)
        && tx_ring[0].cmd
            == (e1000_tx_bits::CMD_EOP | e1000_tx_bits::CMD_IFCS | e1000_tx_bits::CMD_RS)
    {
        passed += 1;
    }

    // 4. Verify RX descriptor status flag check
    let mut rx = E1000RxDesc::new(0x7100_0000);
    rx.status = e1000_rx_bits::STATUS_DD | e1000_rx_bits::STATUS_EOP;
    rx.length = 512;
    if rx.is_descriptor_done() && rx.is_end_of_packet() {
        passed += 1;
    }

    passed
}
