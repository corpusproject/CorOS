//! Realtek RTL8139 Fast Ethernet 10/100 Mbps PCI Network Driver for CorOS.
//! 100% in-house bare-metal implementation supporting I/O port registers,
//! circular RX ring buffer, 4-descriptor round-robin TX, and MAC reading.

use crate::arch::x86_64::cpu;
use alloc::vec::Vec;

// RTL8139 I/O Port Register Offsets
pub const RTL_REG_MAC0: u16      = 0x00; // MAC Address bytes 0-3
pub const RTL_REG_MAC4: u16      = 0x04; // MAC Address bytes 4-5
pub const RTL_REG_MAR0: u16      = 0x08; // Multicast filter bytes 0-7
pub const RTL_REG_TX_STAT0: u16  = 0x10; // Transmit Status of Descriptor 0
pub const RTL_REG_TX_ADDR0: u16  = 0x20; // Transmit Start Address of Descriptor 0
pub const RTL_REG_RX_BUF: u16    = 0x30; // Receive Buffer Start Address
pub const RTL_REG_CMD: u16       = 0x37; // Command Register
pub const RTL_REG_CAPR: u16      = 0x38; // Current Address of Packet Read
pub const RTL_REG_CBR: u16       = 0x3A; // Current Buffer Address
pub const RTL_REG_IMR: u16       = 0x3C; // Interrupt Mask Register
pub const RTL_REG_ISR: u16       = 0x3E; // Interrupt Status Register
pub const RTL_REG_TCR: u16       = 0x40; // Transmit Configuration Register
pub const RTL_REG_RCR: u16       = 0x44; // Receive Configuration Register
pub const RTL_REG_CONFIG1: u16   = 0x52; // Configuration Register 1

// Command Register Bits
pub const RTL_CMD_BUFE: u8       = 0x01; // Buffer Empty
pub const RTL_CMD_TE: u8         = 0x04; // Transmitter Enable
pub const RTL_CMD_RE: u8         = 0x08; // Receiver Enable
pub const RTL_CMD_RST: u8        = 0x10; // Software Reset

// Interrupt Bits
pub const RTL_INT_ROK: u16       = 0x0001; // Receive OK
pub const RTL_INT_RER: u16       = 0x0002; // Receive Error
pub const RTL_INT_TOK: u16       = 0x0004; // Transmit OK
pub const RTL_INT_TER: u16       = 0x0008; // Transmit Error

// RCR (Receive Configuration) Bits
pub const RTL_RCR_AAP: u32       = 1 << 0; // Accept All Packets (Promiscuous)
pub const RTL_RCR_APM: u32       = 1 << 1; // Accept Physical Match (Unicast)
pub const RTL_RCR_AM: u32        = 1 << 2; // Accept Multicast
pub const RTL_RCR_AB: u32        = 1 << 3; // Accept Broadcast
pub const RTL_RCR_WRAP: u32      = 1 << 7; // Wrap around buffer end

pub const RX_BUF_SIZE: usize     = 8192 + 16 + 1500; // 8K + 16-byte header + max packet wrap
pub const TX_BUF_SIZE: usize     = 2048;

pub struct Rtl8139Device {
    pub io_base: u16,
    pub mac_addr: [u8; 6],
    pub rx_buffer: Vec<u8>,
    pub rx_offset: usize,
    pub tx_buffers: [Vec<u8>; 4],
    pub tx_cur: usize,
}

impl Rtl8139Device {
    pub unsafe fn init(io_base: u16) -> Result<Self, &'static str> {
        // 1. Power on the device: write 0x00 to CONFIG1
        cpu::out8(io_base + RTL_REG_CONFIG1, 0x00);

        // 2. Software reset
        cpu::out8(io_base + RTL_REG_CMD, RTL_CMD_RST);
        let mut timeout = 100_000;
        while (cpu::in8(io_base + RTL_REG_CMD) & RTL_CMD_RST) != 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("RTL8139 software reset timeout");
            }
        }

        // 3. Read MAC Address
        let mut mac = [0u8; 6];
        let mac0_3 = cpu::in32(io_base + RTL_REG_MAC0);
        let mac4_5 = cpu::in16(io_base + RTL_REG_MAC4);
        mac[0] = (mac0_3 & 0xFF) as u8;
        mac[1] = ((mac0_3 >> 8) & 0xFF) as u8;
        mac[2] = ((mac0_3 >> 16) & 0xFF) as u8;
        mac[3] = ((mac0_3 >> 24) & 0xFF) as u8;
        mac[4] = (mac4_5 & 0xFF) as u8;
        mac[5] = ((mac4_5 >> 8) & 0xFF) as u8;

        // 4. Allocate RX circular buffer
        let mut rx_buffer = Vec::with_capacity(RX_BUF_SIZE);
        rx_buffer.resize(RX_BUF_SIZE, 0);

        // Set RX buffer physical address
        let rx_phys = rx_buffer.as_ptr() as u32;
        cpu::out32(io_base + RTL_REG_RX_BUF, rx_phys);

        // 5. Configure IMR (Interrupt Mask Register)
        cpu::out16(io_base + RTL_REG_IMR, RTL_INT_ROK | RTL_INT_TOK | RTL_INT_RER | RTL_INT_TER);

        // 6. Configure RCR (Receive Configuration Register)
        // Accept Broadcast, Multicast, Physical Match, with Wrap bit
        cpu::out32(io_base + RTL_REG_RCR, RTL_RCR_AB | RTL_RCR_AM | RTL_RCR_APM | RTL_RCR_WRAP);

        // 7. Enable Transmitter and Receiver
        cpu::out8(io_base + RTL_REG_CMD, RTL_CMD_TE | RTL_CMD_RE);

        // 8. Allocate 4 TX Buffers
        let mut tx_bufs: [Vec<u8>; 4] = Default::default();
        for b in &mut tx_bufs {
            b.resize(TX_BUF_SIZE, 0);
        }

        Ok(Self {
            io_base,
            mac_addr: mac,
            rx_buffer,
            rx_offset: 0,
            tx_buffers: tx_bufs,
            tx_cur: 0,
        })
    }

    /// Transmit raw Ethernet frame using 4-slot ring buffer.
    pub unsafe fn send_packet(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() > 1792 {
            return Err("Packet length exceeds RTL8139 maximum transfer size");
        }

        let desc = self.tx_cur;
        self.tx_cur = (self.tx_cur + 1) % 4;

        let tx_buf = &mut self.tx_buffers[desc];
        tx_buf[..packet.len()].copy_from_slice(packet);

        let phys_addr = tx_buf.as_ptr() as u32;
        let addr_reg = self.io_base + RTL_REG_TX_ADDR0 + (desc as u16 * 4);
        let stat_reg = self.io_base + RTL_REG_TX_STAT0 + (desc as u16 * 4);

        // Write buffer physical address
        cpu::out32(addr_reg, phys_addr);

        // Write length to status register to trigger transmit
        // Length in bits 12:0, clear OWN bit
        cpu::out32(stat_reg, packet.len() as u32);

        // Busy-wait for completion (TOK bit in status register)
        let mut timeout = 200_000;
        loop {
            let stat = cpu::in32(stat_reg);
            if (stat & (1 << 15)) != 0 {
                // Transmit OK bit
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                return Err("RTL8139 transmit timeout");
            }
        }

        Ok(())
    }

    /// Poll and receive packets from the RX circular buffer.
    pub unsafe fn receive_packet(&mut self) -> Option<Vec<u8>> {
        let cmd = cpu::in8(self.io_base + RTL_REG_CMD);
        if (cmd & RTL_CMD_BUFE) != 0 {
            return None; // Buffer is empty
        }

        let offset = self.rx_offset;
        let header_ptr = (self.rx_buffer.as_ptr() as usize + offset) as *const u16;
        let status = *header_ptr;
        let length = *header_ptr.add(1) as usize;

        if (status & 0x01) == 0 || length < 4 || length > 1518 {
            return None; // Invalid packet
        }

        let packet_len = length - 4; // Exclude 4-byte CRC
        let packet_start = offset + 4;
        let mut packet = Vec::with_capacity(packet_len);

        for i in 0..packet_len {
            packet.push(self.rx_buffer[(packet_start + i) % RX_BUF_SIZE]);
        }

        // Advance RX read pointer (aligned to 4 bytes, skipping 4-byte header)
        self.rx_offset = (offset + length + 4 + 3) & !3;
        self.rx_offset %= 8192; // 8K ring wrap

        // Inform chip of new read address (CAPR - 16 bytes according to datasheet)
        let capr_val = (self.rx_offset.wrapping_sub(16)) as u16;
        cpu::out16(self.io_base + RTL_REG_CAPR, capr_val);

        Some(packet)
    }
}
