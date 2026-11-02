//! Linux evdev Input Subsystem: 24-byte InputEvent, client rings & capability bitmaps.

use alloc::collections::VecDeque;

/// Standard Linux input event type constants.
pub mod ev_types {
    pub const EV_SYN: u16 = 0x00;
    pub const EV_KEY: u16 = 0x01;
    pub const EV_REL: u16 = 0x02;
    pub const EV_ABS: u16 = 0x03;
    pub const EV_MSC: u16 = 0x04;
    pub const EV_SW: u16 = 0x05;
    pub const EV_LED: u16 = 0x11;
    pub const EV_REP: u16 = 0x14;
}

pub mod syn_codes {
    pub const SYN_REPORT: u16 = 0;
    pub const SYN_CONFIG: u16 = 1;
    pub const SYN_MT_REPORT: u16 = 2;
    pub const SYN_DROPPED: u16 = 3;
}

pub mod key_codes {
    pub const KEY_RESERVED: u16 = 0;
    pub const KEY_ESC: u16 = 1;
    pub const KEY_1: u16 = 2;
    pub const KEY_2: u16 = 3;
    pub const KEY_3: u16 = 4;
    pub const KEY_TAB: u16 = 15;
    pub const KEY_Q: u16 = 16;
    pub const KEY_W: u16 = 17;
    pub const KEY_E: u16 = 18;
    pub const KEY_R: u16 = 19;
    pub const KEY_ENTER: u16 = 28;
    pub const KEY_LEFTCTRL: u16 = 29;
    pub const KEY_A: u16 = 30;
    pub const KEY_S: u16 = 31;
    pub const KEY_D: u16 = 32;
    pub const KEY_C: u16 = 46;
    pub const KEY_B: u16 = 48;
    pub const KEY_LEFTSHIFT: u16 = 42;
    pub const KEY_RIGHTSHIFT: u16 = 54;
    pub const KEY_LEFTALT: u16 = 56;
    pub const KEY_SPACE: u16 = 57;
    pub const KEY_CAPSLOCK: u16 = 58;
    pub const KEY_NUMLOCK: u16 = 69;
    pub const KEY_SCROLLLOCK: u16 = 70;
    pub const KEY_RIGHTCTRL: u16 = 97;
    pub const KEY_RIGHTALT: u16 = 100;
    pub const BTN_LEFT: u16 = 0x110;
    pub const BTN_RIGHT: u16 = 0x111;
    pub const BTN_MIDDLE: u16 = 0x112;
}

pub mod rel_codes {
    pub const REL_X: u16 = 0x00;
    pub const REL_Y: u16 = 0x01;
    pub const REL_Z: u16 = 0x02;
    pub const REL_WHEEL: u16 = 0x08;
    pub const REL_HWHEEL: u16 = 0x06;
}

pub mod abs_codes {
    pub const ABS_X: u16 = 0x00;
    pub const ABS_Y: u16 = 0x01;
    pub const ABS_Z: u16 = 0x02;
    pub const ABS_PRESSURE: u16 = 0x18;
    pub const ABS_MT_SLOT: u16 = 0x2F;
    pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
    pub const ABS_MT_POSITION_X: u16 = 0x35;
    pub const ABS_MT_POSITION_Y: u16 = 0x36;
    pub const ABS_MT_TRACKING_ID: u16 = 0x39;
}

/// Linux-compatible 24-byte input_event structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub time_sec: u64,
    pub time_usec: u64,
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

impl InputEvent {
    pub const SIZE: usize = 24;

    pub fn new(sec: u64, usec: u64, event_type: u16, code: u16, value: i32) -> Self {
        Self {
            time_sec: sec,
            time_usec: usec,
            event_type,
            code,
            value,
        }
    }

    pub fn syn_report(sec: u64, usec: u64) -> Self {
        Self::new(sec, usec, ev_types::EV_SYN, syn_codes::SYN_REPORT, 0)
    }

    pub fn syn_dropped(sec: u64, usec: u64) -> Self {
        Self::new(sec, usec, ev_types::EV_SYN, syn_codes::SYN_DROPPED, 0)
    }

    /// Serializes (packs) 24-byte Linux input_event into little-endian wire bytes.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&self.time_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&self.time_usec.to_le_bytes());
        buf[16..18].copy_from_slice(&self.event_type.to_le_bytes());
        buf[18..20].copy_from_slice(&self.code.to_le_bytes());
        buf[20..24].copy_from_slice(&self.value.to_le_bytes());
        buf
    }

    /// Deserializes (unpacks) 24-byte Linux input_event from little-endian wire bytes.
    pub fn from_bytes(bytes: &[u8; 24]) -> Self {
        let mut sec_buf = [0u8; 8];
        let mut usec_buf = [0u8; 8];
        let mut type_buf = [0u8; 2];
        let mut code_buf = [0u8; 2];
        let mut val_buf = [0u8; 4];

        sec_buf.copy_from_slice(&bytes[0..8]);
        usec_buf.copy_from_slice(&bytes[8..16]);
        type_buf.copy_from_slice(&bytes[16..18]);
        code_buf.copy_from_slice(&bytes[18..20]);
        val_buf.copy_from_slice(&bytes[20..24]);

        Self {
            time_sec: u64::from_le_bytes(sec_buf),
            time_usec: u64::from_le_bytes(usec_buf),
            event_type: u16::from_le_bytes(type_buf),
            code: u16::from_le_bytes(code_buf),
            value: i32::from_le_bytes(val_buf),
        }
    }
}

/// Per-client circular event queue with SYN_DROPPED overflow protection.
pub struct EvdevClientQueue {
    pub ring: VecDeque<InputEvent>,
    pub max_capacity: usize,
    pub dropped_overflow: bool,
}

impl EvdevClientQueue {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            ring: VecDeque::with_capacity(max_capacity),
            max_capacity,
            dropped_overflow: false,
        }
    }

    pub fn push_event(&mut self, event: InputEvent) {
        if self.max_capacity == 0 {
            return;
        }

        if self.dropped_overflow {
            if self.max_capacity >= 2 {
                while self.ring.len() + 2 > self.max_capacity && !self.ring.is_empty() {
                    self.ring.pop_front();
                }
                self.ring.push_back(InputEvent::syn_dropped(event.time_sec, event.time_usec));
                self.ring.push_back(event);
                self.dropped_overflow = false;
            } else {
                self.ring.clear();
                self.ring.push_back(event);
                self.dropped_overflow = false;
            }
            return;
        }

        if self.ring.len() >= self.max_capacity {
            self.dropped_overflow = true;
            return;
        }

        self.ring.push_back(event);
    }

    pub fn pop_event(&mut self) -> Option<InputEvent> {
        self.ring.pop_front()
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn clear(&mut self) {
        self.ring.clear();
        self.dropped_overflow = false;
    }
}
