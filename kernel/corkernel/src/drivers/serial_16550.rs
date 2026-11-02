//! National Semiconductor 16550A High-Speed UART Serial Driver for CorOS.
//! 100% in-house implementation supporting:
//! - Multi-port COM1..COM4 discovery and loopback test verification
//! - Programmable Baud Rate Divisor Latch (DLAB) for rates up to 115,200 bps
//! - 16-byte FIFO hardware buffer configuration
//! - 8 data bits, no parity, 1 stop bit (8N1) framing

use crate::arch::x86_64::cpu;

pub const COM1_BASE: u16 = 0x3F8;
pub const COM2_BASE: u16 = 0x2F8;
pub const COM3_BASE: u16 = 0x3E8;
pub const COM4_BASE: u16 = 0x2E8;

// Register Offsets
pub const UART_REG_DATA: u16        = 0; // Data / Divisor Latch Low (when DLAB=1)
pub const UART_REG_IER: u16         = 1; // Interrupt Enable / Divisor Latch High (when DLAB=1)
pub const UART_REG_IIR_FCR: u16     = 2; // Interrupt Ident (R) / FIFO Control (W)
pub const UART_REG_LCR: u16         = 3; // Line Control
pub const UART_REG_MCR: u16         = 4; // Modem Control
pub const UART_REG_LSR: u16         = 5; // Line Status
pub const UART_REG_MSR: u16         = 6; // Modem Status
pub const UART_REG_SCRATCH: u16     = 7; // Scratch Register

// Line Status Register Bits
pub const LSR_DATA_READY: u8        = 1 << 0;
pub const LSR_OVERRUN_ERR: u8       = 1 << 1;
pub const LSR_PARITY_ERR: u8        = 1 << 2;
pub const LSR_FRAMING_ERR: u8       = 1 << 3;
pub const LSR_BREAK_INT: u8         = 1 << 4;
pub const LSR_TX_EMPTY: u8          = 1 << 5; // Transmitter Holding Register Empty
pub const LSR_TX_IDLE: u8           = 1 << 6; // Transmitter Empty

pub struct SerialPort {
    pub base_port: u16,
}

impl SerialPort {
    pub const fn new(base_port: u16) -> Self {
        Self { base_port }
    }

    /// Initialize the 16550A UART port with 115,200 baud, 8N1, and 14-byte FIFO.
    pub unsafe fn init(&self) -> Result<(), &'static str> {
        // 1. Disable all interrupts
        cpu::out8(self.base_port + UART_REG_IER, 0x00);

        // 2. Enable DLAB (set Divisor Latch Access Bit in LCR)
        cpu::out8(self.base_port + UART_REG_LCR, 0x80);

        // 3. Set divisor to 1 (115200 baud: 115200 / 1 = 115200)
        cpu::out8(self.base_port + UART_REG_DATA, 0x01); // Divisor Low = 1
        cpu::out8(self.base_port + UART_REG_IER, 0x00);  // Divisor High = 0

        // 4. Configure Line Control: 8 bits, no parity, 1 stop bit (8N1), clear DLAB
        cpu::out8(self.base_port + UART_REG_LCR, 0x03);

        // 5. Enable FIFO, clear TX/RX FIFOs, 14-byte threshold (0xC7)
        cpu::out8(self.base_port + UART_REG_IIR_FCR, 0xC7);

        // 6. Set Modem Control: DTR, RTS, OUT2 (required for IRQ routing)
        cpu::out8(self.base_port + UART_REG_MCR, 0x0B);

        // 7. Test loopback mode to verify healthy chip
        cpu::out8(self.base_port + UART_REG_MCR, 0x1E); // Loopback mode
        cpu::out8(self.base_port + UART_REG_DATA, 0xAE);
        if cpu::in8(self.base_port + UART_REG_DATA) != 0xAE {
            return Err("Serial 16550 UART hardware loopback test failed");
        }

        // Return to normal operational mode
        cpu::out8(self.base_port + UART_REG_MCR, 0x0F);

        Ok(())
    }

    /// Check if transmitter holding register is empty and ready to accept a byte.
    pub unsafe fn is_transmit_empty(&self) -> bool {
        (cpu::in8(self.base_port + UART_REG_LSR) & LSR_TX_EMPTY) != 0
    }

    /// Send a single byte.
    pub unsafe fn write_byte(&self, byte: u8) {
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        cpu::out8(self.base_port + UART_REG_DATA, byte);
    }

    /// Send a string slice.
    pub unsafe fn write_str(&self, s: &str) {
        for &b in s.as_bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    /// Check if an incoming byte is available.
    pub unsafe fn is_data_ready(&self) -> bool {
        (cpu::in8(self.base_port + UART_REG_LSR) & LSR_DATA_READY) != 0
    }

    /// Read an incoming byte (non-blocking).
    pub unsafe fn read_byte(&self) -> Option<u8> {
        if self.is_data_ready() {
            Some(cpu::in8(self.base_port + UART_REG_DATA))
        } else {
            None
        }
    }
}
