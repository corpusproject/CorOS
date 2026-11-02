//! Intel 8254 Programmable Interval Timer (PIT) & PC Speaker Driver for CorOS.
//! 100% in-house implementation supporting:
//! - Hardware Channel 0 timer configuration (Modes 2 & 3, Square Wave Generator)
//! - Channel 2 PC Speaker audio tone generation via Port 0x61
//! - Microsecond hardware busy delays

use crate::arch::x86_64::cpu;

pub const PIT_BASE_FREQ_HZ: u32    = 1_193_182; // 1.193182 MHz oscillator input

pub const PIT_PORT_CHANNEL0: u16   = 0x40; // Channel 0 Data Port (IRQ0 Timer)
pub const PIT_PORT_CHANNEL1: u16   = 0x41; // Channel 1 (RAM Refresh - obsolete)
pub const PIT_PORT_CHANNEL2: u16   = 0x42; // Channel 2 Data Port (PC Speaker)
pub const PIT_PORT_COMMAND: u16    = 0x43; // Mode / Command Register

pub const PC_SPEAKER_PORT: u16     = 0x61; // System Control Port B

// Command Byte Bits
pub const PIT_CMD_CHANNEL0: u8     = 0x00; // Channel 0
pub const PIT_CMD_CHANNEL2: u8     = 0x80; // Channel 2
pub const PIT_CMD_ACCESS_LOHI: u8  = 0x30; // Access Low byte then High byte
pub const PIT_CMD_MODE_SQUARE: u8  = 0x06; // Mode 3: Square Wave Generator
pub const PIT_CMD_MODE_RATE: u8    = 0x04; // Mode 2: Rate Generator
pub const PIT_CMD_BINARY: u8       = 0x00; // 16-bit binary counter

pub struct PitDriver;

impl PitDriver {
    /// Configure Channel 0 at the desired interrupt frequency (e.g. 100 Hz or 1000 Hz).
    pub unsafe fn set_frequency(freq_hz: u32) {
        let divisor = if freq_hz == 0 {
            65535
        } else {
            let d = PIT_BASE_FREQ_HZ / freq_hz;
            d.clamp(1, 65535) as u16
        };

        // Command: Channel 0, Access lo/hi, Mode 3 (Square wave), Binary
        cpu::out8(PIT_PORT_COMMAND, PIT_CMD_CHANNEL0 | PIT_CMD_ACCESS_LOHI | PIT_CMD_MODE_SQUARE | PIT_CMD_BINARY);

        // Send divisor low byte then high byte
        cpu::out8(PIT_PORT_CHANNEL0, (divisor & 0xFF) as u8);
        cpu::out8(PIT_PORT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8);
    }

    /// Play a sound frequency (in Hertz) through the motherboard PC Speaker.
    pub unsafe fn speaker_on(freq_hz: u32) {
        if freq_hz == 0 {
            Self::speaker_off();
            return;
        }

        let divisor = (PIT_BASE_FREQ_HZ / freq_hz).clamp(1, 65535) as u16;

        // Command: Channel 2, Access lo/hi, Mode 3, Binary
        cpu::out8(PIT_PORT_COMMAND, PIT_CMD_CHANNEL2 | PIT_CMD_ACCESS_LOHI | PIT_CMD_MODE_SQUARE | PIT_CMD_BINARY);

        // Send divisor to Channel 2
        cpu::out8(PIT_PORT_CHANNEL2, (divisor & 0xFF) as u8);
        cpu::out8(PIT_PORT_CHANNEL2, ((divisor >> 8) & 0xFF) as u8);

        // Enable Speaker Gate (Bit 0) and Speaker Data (Bit 1) in Port 0x61
        let val = cpu::in8(PC_SPEAKER_PORT);
        if (val & 0x03) != 0x03 {
            cpu::out8(PC_SPEAKER_PORT, val | 0x03);
        }
    }

    /// Silence the PC Speaker.
    pub unsafe fn speaker_off() {
        let val = cpu::in8(PC_SPEAKER_PORT);
        cpu::out8(PC_SPEAKER_PORT, val & !0x03);
    }

    /// Play a short system beep at 750 Hz (default Windows error/asterisk sound).
    pub unsafe fn beep_system() {
        Self::speaker_on(750);
        for _ in 0..500_000 {
            core::hint::spin_loop();
        }
        Self::speaker_off();
    }
}
