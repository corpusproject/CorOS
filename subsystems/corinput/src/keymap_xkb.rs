//! XKB-style modifier state machine, dead-key compose sequences & US/Turkish-Q layout maps.

/// Active keyboard modifier bitflags.
pub mod modifiers {
    pub const SHIFT: u16 = 1 << 0;
    pub const LOCK_CAPS: u16 = 1 << 1;
    pub const CONTROL: u16 = 1 << 2;
    pub const ALT: u16 = 1 << 3;
    pub const ALT_GR: u16 = 1 << 4;
    pub const SUPER: u16 = 1 << 5;
    pub const NUM_LOCK: u16 = 1 << 6;
}

/// Keyboard layout variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeymapLayout {
    UsQwerty,
    TurkishQ,
}

/// Translates a standard PS/2 Set 1 scancode (with optional extended 0xE0 prefix) to Linux keycode.
pub fn ps2_scancode_to_keycode(scancode: u8, extended: bool) -> Option<u16> {
    if extended {
        return match scancode {
            0x1C => Some(96),  // KEY_KPENTER
            0x1D => Some(97),  // KEY_RIGHTCTRL
            0x35 => Some(98),  // KEY_KPSLASH
            0x38 => Some(100), // KEY_RIGHTALT (AltGr)
            0x47 => Some(102), // KEY_HOME
            0x48 => Some(103), // KEY_UP
            0x49 => Some(104), // KEY_PAGEUP
            0x4B => Some(105), // KEY_LEFT
            0x4D => Some(106), // KEY_RIGHT
            0x4F => Some(107), // KEY_END
            0x50 => Some(108), // KEY_DOWN
            0x51 => Some(109), // KEY_PAGEDOWN
            0x52 => Some(110), // KEY_INSERT
            0x53 => Some(111), // KEY_DELETE
            0x5B => Some(125), // KEY_LEFTMETA (Super)
            0x5C => Some(126), // KEY_RIGHTMETA
            _ => None,
        };
    }

    match scancode {
        0x01 => Some(1),  // KEY_ESC
        0x02 => Some(2),  // KEY_1
        0x03 => Some(3),  // KEY_2
        0x04 => Some(4),  // KEY_3
        0x05 => Some(5),  // KEY_4
        0x06 => Some(6),  // KEY_5
        0x07 => Some(7),  // KEY_6
        0x08 => Some(8),  // KEY_7
        0x09 => Some(9),  // KEY_8
        0x0A => Some(10), // KEY_9
        0x0B => Some(11), // KEY_0
        0x0C => Some(12), // KEY_MINUS
        0x0D => Some(13), // KEY_EQUAL
        0x0E => Some(14), // KEY_BACKSPACE
        0x0F => Some(15), // KEY_TAB
        0x10 => Some(16), // KEY_Q
        0x11 => Some(17), // KEY_W
        0x12 => Some(18), // KEY_E
        0x13 => Some(19), // KEY_R
        0x14 => Some(20), // KEY_T
        0x15 => Some(21), // KEY_Y
        0x16 => Some(22), // KEY_U
        0x17 => Some(23), // KEY_I
        0x18 => Some(24), // KEY_O
        0x19 => Some(25), // KEY_P
        0x1A => Some(26), // KEY_LEFTBRACE
        0x1B => Some(27), // KEY_RIGHTBRACE
        0x1C => Some(28), // KEY_ENTER
        0x1D => Some(29), // KEY_LEFTCTRL
        0x1E => Some(30), // KEY_A
        0x1F => Some(31), // KEY_S
        0x20 => Some(32), // KEY_D
        0x21 => Some(33), // KEY_F
        0x22 => Some(34), // KEY_G
        0x23 => Some(35), // KEY_H
        0x24 => Some(36), // KEY_J
        0x25 => Some(37), // KEY_K
        0x26 => Some(38), // KEY_L
        0x27 => Some(39), // KEY_SEMICOLON
        0x28 => Some(40), // KEY_APOSTROPHE
        0x29 => Some(41), // KEY_GRAVE
        0x2A => Some(42), // KEY_LEFTSHIFT
        0x2B => Some(43), // KEY_BACKSLASH
        0x2C => Some(44), // KEY_Z
        0x2D => Some(45), // KEY_X
        0x2E => Some(46), // KEY_C
        0x2F => Some(47), // KEY_V
        0x30 => Some(48), // KEY_B
        0x31 => Some(49), // KEY_N
        0x32 => Some(50), // KEY_M
        0x33 => Some(51), // KEY_COMMA
        0x34 => Some(52), // KEY_DOT
        0x35 => Some(53), // KEY_SLASH
        0x36 => Some(54), // KEY_RIGHTSHIFT
        0x37 => Some(55), // KEY_KPASTERISK
        0x38 => Some(56), // KEY_LEFTALT
        0x39 => Some(57), // KEY_SPACE
        0x3A => Some(58), // KEY_CAPSLOCK
        0x45 => Some(69), // KEY_NUMLOCK
        0x46 => Some(70), // KEY_SCROLLLOCK
        _ => None,
    }
}

/// Dead-key compose state for European & Turkish accents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadKeyState {
    None,
    Acute,      // ´
    Grave,      // `
    Circumflex, // ^
    Diaeresis,  // ¨
}

/// Stateful keyboard translator converting Linux keycodes to UTF-8 Unicode characters.
pub struct XkbKeyboardTranslator {
    pub layout: KeymapLayout,
    pub active_modifiers: u16,
    pub dead_key: DeadKeyState,
}

impl XkbKeyboardTranslator {
    pub fn new(layout: KeymapLayout) -> Self {
        Self {
            layout,
            active_modifiers: 0,
            dead_key: DeadKeyState::None,
        }
    }

    pub fn is_shift_active(&self) -> bool {
        (self.active_modifiers & modifiers::SHIFT) != 0
    }

    pub fn is_caps_lock_active(&self) -> bool {
        (self.active_modifiers & modifiers::LOCK_CAPS) != 0
    }

    pub fn is_ctrl_active(&self) -> bool {
        (self.active_modifiers & modifiers::CONTROL) != 0
    }

    pub fn is_alt_active(&self) -> bool {
        (self.active_modifiers & modifiers::ALT) != 0
    }

    pub fn is_num_lock_active(&self) -> bool {
        (self.active_modifiers & modifiers::NUM_LOCK) != 0
    }

    pub fn set_dead_key(&mut self, dead_key: DeadKeyState) {
        self.dead_key = dead_key;
    }

    pub fn update_modifier(&mut self, keycode: u16, is_pressed: bool) {
        let mask = match keycode {
            42 | 54 => modifiers::SHIFT,
            58 => modifiers::LOCK_CAPS,
            29 | 97 => modifiers::CONTROL,
            56 => modifiers::ALT,
            100 => modifiers::ALT_GR,
            125 => modifiers::SUPER,
            69 => modifiers::NUM_LOCK,
            _ => 0,
        };
        if mask != 0 {
            if is_pressed {
                if mask == modifiers::LOCK_CAPS || mask == modifiers::NUM_LOCK {
                    self.active_modifiers ^= mask; // Toggle lock
                } else {
                    self.active_modifiers |= mask;
                }
            } else if mask != modifiers::LOCK_CAPS && mask != modifiers::NUM_LOCK {
                self.active_modifiers &= !mask;
            }
        }
    }

    /// Translates keycode into an ASCII/UTF-8 character based on current shift/caps/compose state.
    pub fn translate_keycode(&mut self, keycode: u16) -> Option<char> {
        let shift = (self.active_modifiers & modifiers::SHIFT) != 0;
        let caps = (self.active_modifiers & modifiers::LOCK_CAPS) != 0;
        let uppercase = shift ^ caps;

        let base_char = match (self.layout, keycode) {
            // Turkish-Q specific overrides
            (KeymapLayout::TurkishQ, 23) => Some(if uppercase { 'I' } else { 'ı' }),
            (KeymapLayout::TurkishQ, 26) => Some(if uppercase { 'Ğ' } else { 'ğ' }),
            (KeymapLayout::TurkishQ, 27) => Some(if uppercase { 'Ü' } else { 'ü' }),
            (KeymapLayout::TurkishQ, 39) => Some(if uppercase { 'Ş' } else { 'ş' }),
            (KeymapLayout::TurkishQ, 40) => Some(if uppercase { 'İ' } else { 'i' }),
            (KeymapLayout::TurkishQ, 51) => Some(if uppercase { 'Ö' } else { 'ö' }),
            (KeymapLayout::TurkishQ, 52) => Some(if uppercase { 'Ç' } else { 'ç' }),

            // Common alphabet keys
            (_, 16) => Some(if uppercase { 'Q' } else { 'q' }),
            (_, 17) => Some(if uppercase { 'W' } else { 'w' }),
            (_, 18) => Some(if uppercase { 'E' } else { 'e' }),
            (_, 19) => Some(if uppercase { 'R' } else { 'r' }),
            (_, 20) => Some(if uppercase { 'T' } else { 't' }),
            (_, 21) => Some(if uppercase { 'Y' } else { 'y' }),
            (_, 22) => Some(if uppercase { 'U' } else { 'u' }),
            (KeymapLayout::UsQwerty, 23) => Some(if uppercase { 'I' } else { 'i' }),
            (_, 24) => Some(if uppercase { 'O' } else { 'o' }),
            (_, 25) => Some(if uppercase { 'P' } else { 'p' }),
            (_, 30) => Some(if uppercase { 'A' } else { 'a' }),
            (_, 31) => Some(if uppercase { 'S' } else { 's' }),
            (_, 32) => Some(if uppercase { 'D' } else { 'd' }),
            (_, 33) => Some(if uppercase { 'F' } else { 'f' }),
            (_, 34) => Some(if uppercase { 'G' } else { 'g' }),
            (_, 35) => Some(if uppercase { 'H' } else { 'h' }),
            (_, 36) => Some(if uppercase { 'J' } else { 'j' }),
            (_, 37) => Some(if uppercase { 'K' } else { 'k' }),
            (_, 38) => Some(if uppercase { 'L' } else { 'l' }),
            (_, 44) => Some(if uppercase { 'Z' } else { 'z' }),
            (_, 45) => Some(if uppercase { 'X' } else { 'x' }),
            (_, 46) => Some(if uppercase { 'C' } else { 'c' }),
            (_, 47) => Some(if uppercase { 'V' } else { 'v' }),
            (_, 48) => Some(if uppercase { 'B' } else { 'b' }),
            (_, 49) => Some(if uppercase { 'N' } else { 'n' }),
            (_, 50) => Some(if uppercase { 'M' } else { 'm' }),
            (_, 57) => Some(' '),
            (_, 28) => Some('\n'),
            _ => None,
        };

        let ch = base_char?;
        if self.dead_key == DeadKeyState::None {
            Some(ch)
        } else {
            let composed = match (self.dead_key, ch) {
                (DeadKeyState::Acute, 'e') => 'é',
                (DeadKeyState::Acute, 'E') => 'É',
                (DeadKeyState::Acute, 'a') => 'á',
                (DeadKeyState::Acute, 'A') => 'Á',
                (DeadKeyState::Acute, 'o') => 'ó',
                (DeadKeyState::Acute, 'O') => 'Ó',
                (DeadKeyState::Grave, 'a') => 'à',
                (DeadKeyState::Grave, 'e') => 'è',
                (DeadKeyState::Circumflex, 'a') => 'â',
                (DeadKeyState::Circumflex, 'e') => 'ê',
                (DeadKeyState::Circumflex, 'i') => 'î',
                (DeadKeyState::Circumflex, 'o') => 'ô',
                (DeadKeyState::Circumflex, 'u') => 'û',
                (DeadKeyState::Diaeresis, 'a') => 'ä',
                (DeadKeyState::Diaeresis, 'o') => 'ö',
                (DeadKeyState::Diaeresis, 'u') => 'ü',
                _ => ch,
            };
            self.dead_key = DeadKeyState::None;
            Some(composed)
        }
    }
}
