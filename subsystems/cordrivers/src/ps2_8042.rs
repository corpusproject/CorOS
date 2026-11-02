//! CorOS Hardware Driver Module: `ps2_8042`
//!
//! Intel 8042 PS/2 Keyboard & Auxiliary Mouse Controller (`I/O Port 0x60` Data,
//! `I/O Port 0x64` Status/Command), Controller Configuration Byte (`CCB`) encoder,
//! AT Scancode Set 1 and Set 2 multi-byte state machine (`0xE0` extended prefix,
//! `0xF0` break prefix), and 3-byte Standard / 4-byte Microsoft Intellimouse
//! scroll-wheel packet assembler.

/// i8042 I/O Port addresses and Status Register (`0x64`) bitflags.
pub mod i8042_regs {
    pub const DATA_PORT: u16 = 0x60;
    pub const STATUS_CMD_PORT: u16 = 0x64;

    /// Output Buffer Full (`OBF`): data is ready to be read from `0x60`.
    pub const STATUS_OBF: u8 = 1 << 0;
    /// Input Buffer Full (`IBF`): controller is busy; wait before writing to `0x60`/`0x64`.
    pub const STATUS_IBF: u8 = 1 << 1;
    /// System Flag (`SYS`).
    pub const STATUS_SYS: u8 = 1 << 2;
    /// Command/Data (`A2`): `1 = byte written to 0x64`, `0 = byte written to 0x60`.
    pub const STATUS_CMD_DATA: u8 = 1 << 3;
    /// Auxiliary Output Buffer Full (`AUXB`): `1 = byte from PS/2 Mouse`, `0 = byte from PS/2 Keyboard`.
    pub const STATUS_AUX_OBF: u8 = 1 << 5;
    /// Timeout Error (`TO`).
    pub const STATUS_TIMEOUT: u8 = 1 << 6;
    /// Parity Error (`PERR`).
    pub const STATUS_PARITY: u8 = 1 << 7;
}

/// i8042 Controller Commands written to Port `0x64`.
pub mod i8042_commands {
    pub const READ_CONFIG_BYTE: u8 = 0x20;
    pub const WRITE_CONFIG_BYTE: u8 = 0x60;
    pub const DISABLE_AUX_PORT: u8 = 0xA7;
    pub const ENABLE_AUX_PORT: u8 = 0xA8;
    pub const TEST_AUX_PORT: u8 = 0xA9;
    pub const SELF_TEST_CONTROLLER: u8 = 0xAA;
    pub const TEST_FIRST_PORT: u8 = 0xAB;
    pub const DISABLE_FIRST_PORT: u8 = 0xAD;
    pub const ENABLE_FIRST_PORT: u8 = 0xAE;
    pub const WRITE_NEXT_TO_AUX_PORT: u8 = 0xD4;
    pub const PULSE_CPU_RESET_LINE: u8 = 0xFE;
}

/// i8042 Controller Configuration Byte (`CCB`) bitflags.
pub mod i8042_ccb {
    pub const PORT1_IRQ1_ENABLE: u8 = 1 << 0;
    pub const PORT2_IRQ12_ENABLE: u8 = 1 << 1;
    pub const SYSTEM_FLAG: u8 = 1 << 2;
    pub const PORT1_CLOCK_DISABLE: u8 = 1 << 4;
    pub const PORT2_CLOCK_DISABLE: u8 = 1 << 5;
    pub const PORT1_SCANCODE_TRANSLATION: u8 = 1 << 6;
}

/// Logical Key Identifiers decoded from PS/2 Scancode Set 1 and Set 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ps2Keycode {
    Ascii(u8),
    Escape,
    Backspace,
    Tab,
    Enter,
    LeftCtrl,
    RightCtrl,
    LeftShift,
    RightShift,
    LeftAlt,
    RightAlt,
    CapsLock,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    Unknown(u8),
}

/// Decoded Keyboard Transition Event (`pressed = true` on Make, `pressed = false` on Break).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2KeyEvent {
    pub keycode: Ps2Keycode,
    pub pressed: bool,
    pub extended_e0: bool,
}

/// Stateful PS/2 Scancode Set 1 & Set 2 decoder handling `0xE0` extended and `0xF0` release prefixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2ScancodeDecoder {
    pub use_set_2: bool,
    pub seen_e0: bool,
    pub seen_f0: bool,
    pub shift_held: bool,
}

impl Ps2ScancodeDecoder {
    #[inline]
    pub const fn new(use_set_2: bool) -> Self {
        Self {
            use_set_2,
            seen_e0: false,
            seen_f0: false,
            shift_held: false,
        }
    }

    /// Feeds one raw scancode byte from I/O Port `0x60` and returns `Some(Ps2KeyEvent)` once a complete sequence finishes.
    pub fn feed_byte(&mut self, byte: u8) -> Option<Ps2KeyEvent> {
        if byte == 0xE0 {
            self.seen_e0 = true;
            return None;
        }
        if self.use_set_2 && byte == 0xF0 {
            self.seen_f0 = true;
            return None;
        }

        let ext = self.seen_e0;
        let (pressed, code) = if self.use_set_2 {
            let p = !self.seen_f0;
            (p, byte)
        } else {
            // Scancode Set 1: bit 7 is Break (`1 = released`, `0 = pressed`)
            ((byte & 0x80) == 0, byte & 0x7F)
        };

        self.seen_e0 = false;
        self.seen_f0 = false;

        let keycode = if self.use_set_2 {
            decode_set2_code(code, ext, self.shift_held)
        } else {
            decode_set1_code(code, ext, self.shift_held)
        };

        if matches!(keycode, Ps2Keycode::LeftShift | Ps2Keycode::RightShift) {
            self.shift_held = pressed;
        }

        Some(Ps2KeyEvent {
            keycode,
            pressed,
            extended_e0: ext,
        })
    }
}

const fn decode_set1_code(code: u8, ext: bool, shift: bool) -> Ps2Keycode {
    if ext {
        return match code {
            0x1D => Ps2Keycode::RightCtrl,
            0x38 => Ps2Keycode::RightAlt,
            0x47 => Ps2Keycode::Home,
            0x48 => Ps2Keycode::ArrowUp,
            0x49 => Ps2Keycode::PageUp,
            0x4B => Ps2Keycode::ArrowLeft,
            0x4D => Ps2Keycode::ArrowRight,
            0x4F => Ps2Keycode::End,
            0x50 => Ps2Keycode::ArrowDown,
            0x51 => Ps2Keycode::PageDown,
            0x52 => Ps2Keycode::Insert,
            0x53 => Ps2Keycode::Delete,
            other => Ps2Keycode::Unknown(other),
        };
    }

    match code {
        0x01 => Ps2Keycode::Escape,
        0x0E => Ps2Keycode::Backspace,
        0x0F => Ps2Keycode::Tab,
        0x1C => Ps2Keycode::Enter,
        0x1D => Ps2Keycode::LeftCtrl,
        0x2A => Ps2Keycode::LeftShift,
        0x36 => Ps2Keycode::RightShift,
        0x38 => Ps2Keycode::LeftAlt,
        0x39 => Ps2Keycode::Ascii(b' '),
        0x3A => Ps2Keycode::CapsLock,
        0x10..=0x19 => {
            const ROW_Q: [u8; 10] = *b"qwertyuiop";
            const ROW_Q_SHIFT: [u8; 10] = *b"QWERTYUIOP";
            let idx = (code - 0x10) as usize;
            Ps2Keycode::Ascii(if shift { ROW_Q_SHIFT[idx] } else { ROW_Q[idx] })
        }
        0x1E..=0x26 => {
            const ROW_A: [u8; 9] = *b"asdfghjkl";
            const ROW_A_SHIFT: [u8; 9] = *b"ASDFGHJKL";
            let idx = (code - 0x1E) as usize;
            Ps2Keycode::Ascii(if shift { ROW_A_SHIFT[idx] } else { ROW_A[idx] })
        }
        0x2C..=0x32 => {
            const ROW_Z: [u8; 7] = *b"zxcvbnm";
            const ROW_Z_SHIFT: [u8; 7] = *b"ZXCVBNM";
            let idx = (code - 0x2C) as usize;
            Ps2Keycode::Ascii(if shift { ROW_Z_SHIFT[idx] } else { ROW_Z[idx] })
        }
        other => Ps2Keycode::Unknown(other),
    }
}

const fn decode_set2_code(code: u8, ext: bool, shift: bool) -> Ps2Keycode {
    if ext {
        return match code {
            0x14 => Ps2Keycode::RightCtrl,
            0x11 => Ps2Keycode::RightAlt,
            0x75 => Ps2Keycode::ArrowUp,
            0x72 => Ps2Keycode::ArrowDown,
            0x6B => Ps2Keycode::ArrowLeft,
            0x74 => Ps2Keycode::ArrowRight,
            0x70 => Ps2Keycode::Insert,
            0x71 => Ps2Keycode::Delete,
            other => Ps2Keycode::Unknown(other),
        };
    }
    match code {
        0x76 => Ps2Keycode::Escape,
        0x66 => Ps2Keycode::Backspace,
        0x0D => Ps2Keycode::Tab,
        0x5A => Ps2Keycode::Enter,
        0x12 => Ps2Keycode::LeftShift,
        0x59 => Ps2Keycode::RightShift,
        0x14 => Ps2Keycode::LeftCtrl,
        0x11 => Ps2Keycode::LeftAlt,
        0x29 => Ps2Keycode::Ascii(b' '),
        0x1C => Ps2Keycode::Ascii(if shift { b'A' } else { b'a' }),
        0x21 => Ps2Keycode::Ascii(if shift { b'C' } else { b'c' }),
        other => Ps2Keycode::Unknown(other),
    }
}

/// Decoded PS/2 Mouse / Intellimouse 3-byte or 4-byte packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2MousePacket {
    pub left_btn: bool,
    pub right_btn: bool,
    pub middle_btn: bool,
    pub dx: i16,
    pub dy: i16,
    pub dz_scroll: i8,
}

/// Stateful PS/2 Mouse / Intellimouse (Device ID `0x03`) packet assembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ps2MousePacketAssembler {
    pub intellimouse_4byte: bool,
    pub buf: [u8; 4],
    pub index: usize,
}

impl Ps2MousePacketAssembler {
    #[inline]
    pub const fn new(intellimouse_4byte: bool) -> Self {
        Self {
            intellimouse_4byte,
            buf: [0; 4],
            index: 0,
        }
    }

    /// Feeds one auxiliary port byte (`AUXB`) and returns a decoded `Ps2MousePacket` once 3 (or 4) bytes arrive.
    pub fn feed_byte(&mut self, b: u8) -> Option<Ps2MousePacket> {
        // Byte 0 of a valid PS/2 mouse packet MUST have Bit 3 (`Always 1`) set; otherwise resynchronize.
        if self.index == 0 && (b & 0x08) == 0 {
            return None;
        }
        self.buf[self.index] = b;
        self.index += 1;

        let target_len = if self.intellimouse_4byte { 4 } else { 3 };
        if self.index < target_len {
            return None;
        }
        self.index = 0;

        let flags = self.buf[0];
        // Discard packet if X or Y hardware overflow bits (bits 6 or 7) are set
        if (flags & 0xC0) != 0 {
            return None;
        }
        let raw_x = self.buf[1] as i16;
        let raw_y = self.buf[2] as i16;
        let dx = if (flags & 0x10) != 0 {
            raw_x - 256
        } else {
            raw_x
        };
        let dy = if (flags & 0x20) != 0 {
            raw_y - 256
        } else {
            raw_y
        };
        let dz = if self.intellimouse_4byte {
            // Sign-extend 4-bit scroll wheel delta
            let low4 = self.buf[3] & 0x0F;
            if (low4 & 0x08) != 0 {
                (low4 | 0xF0) as i8
            } else {
                low4 as i8
            }
        } else {
            0
        };

        Some(Ps2MousePacket {
            left_btn: (flags & 0x01) != 0,
            right_btn: (flags & 0x02) != 0,
            middle_btn: (flags & 0x04) != 0,
            dx,
            dy,
            dz_scroll: dz,
        })
    }
}

/// Self-test for `ps2_8042` Scancode Set 1/Set 2 `0xE0` state machine and 4-byte Intellimouse scroll decoding.
pub fn verify_driver_module_ps2_8042() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Scancode Set 1 Shift + 'q' -> 'Q' and key release
    let mut dec1 = Ps2ScancodeDecoder::new(false);
    let _ = dec1.feed_byte(0x2A); // Left Shift Make
    let ev_q = dec1.feed_byte(0x10); // 'q' Make while Shift held -> 'Q'
    let _ = dec1.feed_byte(0xAA); // Left Shift Break
    if ev_q
        == Some(Ps2KeyEvent {
            keycode: Ps2Keycode::Ascii(b'Q'),
            pressed: true,
            extended_e0: false,
        })
        && !dec1.shift_held
    {
        passed += 1;
    }

    // 2. Verify Extended 0xE0 ArrowUp make/break in Scancode Set 1
    let _ = dec1.feed_byte(0xE0);
    let ev_up = dec1.feed_byte(0x48);
    if ev_up
        == Some(Ps2KeyEvent {
            keycode: Ps2Keycode::ArrowUp,
            pressed: true,
            extended_e0: true,
        })
    {
        passed += 1;
    }

    // 3. Verify Scancode Set 2 `0xE0 0xF0 0x74` (Extended ArrowRight Break)
    let mut dec2 = Ps2ScancodeDecoder::new(true);
    let _ = dec2.feed_byte(0xE0);
    let _ = dec2.feed_byte(0xF0);
    let ev_right_rel = dec2.feed_byte(0x74);
    if ev_right_rel
        == Some(Ps2KeyEvent {
            keycode: Ps2Keycode::ArrowRight,
            pressed: false,
            extended_e0: true,
        })
    {
        passed += 1;
    }

    // 4. Verify 4-byte Intellimouse packet with 9-bit signed negative X delta and scroll wheel -1
    let mut mouse = Ps2MousePacketAssembler::new(true);
    let _ = mouse.feed_byte(0x19); // Bit 3=1, X sign=1 (-), Left button=1
    let _ = mouse.feed_byte(246); // 246 - 256 = -10
    let _ = mouse.feed_byte(15); // +15
    let pkt = mouse.feed_byte(0xFF); // 4-bit signed -1 scroll
    if pkt
        == Some(Ps2MousePacket {
            left_btn: true,
            right_btn: false,
            middle_btn: false,
            dx: -10,
            dy: 15,
            dz_scroll: -1,
        })
    {
        passed += 1;
    }

    passed
}
