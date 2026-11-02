//! Serial I/O (serio) input transport bus multiplexing PS/2, keyboard & mouse ports.

use alloc::vec::Vec;

/// Serio Port Type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerioPortType {
    I8042Kbd,
    I8042Aux,
    SerialMouse,
    VirtualGuest,
}

/// Standard PS/2 command constants.
pub mod ps2_commands {
    pub const CMD_RESET: u8 = 0xFF;
    pub const CMD_RESEND: u8 = 0xFE;
    pub const CMD_SET_DEFAULTS: u8 = 0xF6;
    pub const CMD_DISABLE_SCANNING: u8 = 0xF5;
    pub const CMD_ENABLE_SCANNING: u8 = 0xF4;
    pub const CMD_SET_SAMPLE_RATE: u8 = 0xF3;
    pub const CMD_IDENTIFY: u8 = 0xF2;
    pub const CMD_SET_LEDS: u8 = 0xED;
    pub const CMD_ECHO: u8 = 0xEE;

    pub const RESP_ACK: u8 = 0xFA;
    pub const RESP_BAT_OK: u8 = 0xAA;
    pub const RESP_ECHO: u8 = 0xEE;
    pub const RESP_RESEND: u8 = 0xFE;
    pub const RESP_ERROR: u8 = 0xFC;
}

/// Decoded standard PS/2 mouse packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2MousePacket {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub dx: i16,
    pub dy: i16,
}

/// Decoded PS/2 keyboard scancode event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2KeyEvent {
    pub scancode: u8,
    pub is_break: bool,
    pub is_extended: bool,
}

/// Serio packet transport callback and PS/2 protocol state machine.
pub struct SerioPort {
    pub port_type: SerioPortType,
    pub rx_buffer: Vec<u8>,
    pub is_open: bool,
    pub extended_prefix: bool,
}

impl SerioPort {
    pub fn new(port_type: SerioPortType) -> Self {
        Self {
            port_type,
            rx_buffer: Vec::new(),
            is_open: true,
            extended_prefix: false,
        }
    }

    pub fn receive_byte(&mut self, byte: u8) {
        if self.is_open {
            self.rx_buffer.push(byte);
        }
    }

    pub fn flush(&mut self) -> Vec<u8> {
        let data = self.rx_buffer.clone();
        self.rx_buffer.clear();
        data
    }

    /// Evaluates PS/2 command and produces standard response bytes.
    pub fn process_command(&mut self, cmd: u8) -> Vec<u8> {
        use ps2_commands::*;
        match (self.port_type, cmd) {
            (_, CMD_RESET) => alloc::vec![RESP_ACK, RESP_BAT_OK],
            (SerioPortType::I8042Kbd, CMD_IDENTIFY) => alloc::vec![RESP_ACK, 0xAB, 0x83],
            (SerioPortType::I8042Aux | SerioPortType::SerialMouse, CMD_IDENTIFY) => {
                alloc::vec![RESP_ACK, 0x00]
            }
            (_, CMD_ENABLE_SCANNING) => alloc::vec![RESP_ACK],
            (_, CMD_DISABLE_SCANNING) => alloc::vec![RESP_ACK],
            (_, CMD_SET_DEFAULTS) => alloc::vec![RESP_ACK],
            (_, CMD_ECHO) => alloc::vec![RESP_ECHO],
            (SerioPortType::I8042Kbd, CMD_SET_LEDS) => alloc::vec![RESP_ACK],
            _ => alloc::vec![RESP_ACK],
        }
    }

    /// Decodes a 3-byte standard PS/2 mouse packet.
    pub fn decode_mouse_packet(packet: &[u8; 3]) -> Result<Ps2MousePacket, &'static str> {
        let flags = packet[0];
        // Bit 3 of packet[0] must always be set (sync bit)
        if (flags & 0x08) == 0 {
            return Err("Invalid PS/2 mouse synchronization bit");
        }
        let left_button = (flags & 0x01) != 0;
        let right_button = (flags & 0x02) != 0;
        let middle_button = (flags & 0x04) != 0;
        let x_sign = (flags & 0x10) != 0;
        let y_sign = (flags & 0x20) != 0;

        let raw_x = packet[1] as i16;
        let raw_y = packet[2] as i16;

        let dx = if x_sign { raw_x - 256 } else { raw_x };
        let dy = if y_sign { raw_y - 256 } else { raw_y };

        Ok(Ps2MousePacket {
            left_button,
            right_button,
            middle_button,
            dx,
            dy,
        })
    }

    /// Decodes a streaming PS/2 keyboard byte into a make/break key event.
    pub fn decode_keyboard_byte(&mut self, byte: u8) -> Option<Ps2KeyEvent> {
        if byte == 0xE0 {
            self.extended_prefix = true;
            return None;
        }
        let is_extended = self.extended_prefix;
        self.extended_prefix = false;

        let is_break = (byte & 0x80) != 0;
        let scancode = byte & 0x7F;

        Some(Ps2KeyEvent {
            scancode,
            is_break,
            is_extended,
        })
    }
}
