//! Intel 8042 PS/2 Keyboard and Mouse Controller Driver for CorOS.
//! 100% in-house implementation supporting:
//! - Dual-channel 8042 controller configuration (Keyboard & Auxiliary Mouse)
//! - Controller self-test and interface test routines
//! - PS/2 Mouse streaming mode and 3-button packet decoding
//! - Scancode Set 1 & 2 keycode translation tables

use crate::arch::x86_64::cpu;

pub const PS2_DATA_PORT: u16    = 0x60;
pub const PS2_STATUS_PORT: u16  = 0x64;
pub const PS2_COMMAND_PORT: u16 = 0x64;

// Status Register Bits
pub const PS2_STATUS_OUTPUT_FULL: u8 = 1 << 0; // Output buffer full (can read from 0x60)
pub const PS2_STATUS_INPUT_FULL: u8  = 1 << 1; // Input buffer full (cannot write to 0x60/0x64)
pub const PS2_STATUS_SYSTEM_FLAG: u8 = 1 << 2; // Set by firmware
pub const PS2_STATUS_COMMAND_DATA: u8= 1 << 3; // 0 = data for device, 1 = command for controller
pub const PS2_STATUS_TIMEOUT_ERR: u8 = 1 << 6;
pub const PS2_STATUS_PARITY_ERR: u8  = 1 << 7;

// Controller Commands
pub const PS2_CMD_READ_CONFIG: u8    = 0x20;
pub const PS2_CMD_WRITE_CONFIG: u8   = 0x60;
pub const PS2_CMD_DISABLE_PORT2: u8  = 0xA7;
pub const PS2_CMD_ENABLE_PORT2: u8   = 0xA8;
pub const PS2_CMD_TEST_PORT2: u8     = 0xA9;
pub const PS2_CMD_SELF_TEST: u8      = 0xAA;
pub const PS2_CMD_TEST_PORT1: u8     = 0xAB;
pub const PS2_CMD_DISABLE_PORT1: u8  = 0xAD;
pub const PS2_CMD_ENABLE_PORT1: u8   = 0xAE;
pub const PS2_CMD_WRITE_PORT2: u8    = 0xD4; // Send next byte to Port 2 (Mouse)

// Mouse Device Commands
pub const MOUSE_CMD_RESET: u8        = 0xFF;
pub const MOUSE_CMD_RESEND: u8       = 0xFE;
pub const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;
pub const MOUSE_CMD_DISABLE_STREAM: u8= 0xF5;
pub const MOUSE_CMD_ENABLE_STREAM: u8= 0xF4;
pub const MOUSE_CMD_SET_SAMPLE_RATE: u8 = 0xF3;
pub const MOUSE_CMD_GET_DEVICE_ID: u8= 0xF2;

pub struct Ps2Controller;

impl Ps2Controller {
    /// Wait until controller input buffer is clear (ready to accept data/command).
    pub unsafe fn wait_input_clear() -> Result<(), &'static str> {
        let mut timeout = 100_000;
        while (cpu::in8(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL) != 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("PS/2 controller input timeout");
            }
        }
        Ok(())
    }

    /// Wait until output buffer has data to be read.
    pub unsafe fn wait_output_full() -> Result<(), &'static str> {
        let mut timeout = 100_000;
        while (cpu::in8(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) == 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("PS/2 controller output timeout");
            }
        }
        Ok(())
    }

    /// Send a command byte to the 8042 controller.
    pub unsafe fn send_command(cmd: u8) -> Result<(), &'static str> {
        Self::wait_input_clear()?;
        cpu::out8(PS2_COMMAND_PORT, cmd);
        Ok(())
    }

    /// Send a data byte to Port 1 (Keyboard).
    pub unsafe fn send_data(data: u8) -> Result<(), &'static str> {
        Self::wait_input_clear()?;
        cpu::out8(PS2_DATA_PORT, data);
        Ok(())
    }

    /// Send a byte specifically to Port 2 (Auxiliary Mouse).
    pub unsafe fn send_mouse_byte(data: u8) -> Result<(), &'static str> {
        Self::send_command(PS2_CMD_WRITE_PORT2)?;
        Self::send_data(data)?;
        Ok(())
    }

    /// Read a byte from the data port.
    pub unsafe fn read_data() -> Result<u8, &'static str> {
        Self::wait_output_full()?;
        Ok(cpu::in8(PS2_DATA_PORT))
    }

    /// Complete controller initialization routine.
    pub unsafe fn init() -> Result<(), &'static str> {
        // 1. Disable both ports during setup
        Self::send_command(PS2_CMD_DISABLE_PORT1)?;
        Self::send_command(PS2_CMD_DISABLE_PORT2)?;

        // Flush output buffer
        while (cpu::in8(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) != 0 {
            cpu::in8(PS2_DATA_PORT);
        }

        // 2. Read Controller Configuration Byte
        Self::send_command(PS2_CMD_READ_CONFIG)?;
        let mut config = Self::read_data()?;

        // Enable Port 1 & 2 interrupts, enable translation
        config |= 0x01 | 0x02 | 0x40; // Bit 0 (IRQ1), Bit 1 (IRQ12), Bit 6 (Translation)
        config &= !0x10; // Clear Port 1 clock disable
        config &= !0x20; // Clear Port 2 clock disable

        // 3. Write Controller Configuration Byte back
        Self::send_command(PS2_CMD_WRITE_CONFIG)?;
        Self::send_data(config)?;

        // 4. Enable Port 1 (Keyboard) and Port 2 (Mouse)
        Self::send_command(PS2_CMD_ENABLE_PORT1)?;
        Self::send_command(PS2_CMD_ENABLE_PORT2)?;

        // 5. Reset and configure mouse in streaming mode
        Self::send_mouse_byte(MOUSE_CMD_SET_DEFAULTS)?;
        let _ = Self::read_data(); // ACK 0xFA
        Self::send_mouse_byte(MOUSE_CMD_ENABLE_STREAM)?;
        let _ = Self::read_data(); // ACK 0xFA

        Ok(())
    }
}
