use alloc::string::String;
use crate::evdev_core::{ev_types, syn_codes, InputEvent};

/// Linux uinput ioctl command codes.
pub mod uinput_ioctls {
    pub const UI_SET_EVBIT: u32 = 0x40045564;
    pub const UI_SET_KEYBIT: u32 = 0x40045565;
    pub const UI_SET_RELBIT: u32 = 0x40045566;
    pub const UI_SET_ABSBIT: u32 = 0x40045567;
    pub const UI_DEV_CREATE: u32 = 0x5501;
    pub const UI_DEV_DESTROY: u32 = 0x5502;
}

/// Absolute axis calibration info.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbsAxisInfo {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub resolution: i32,
}

impl AbsAxisInfo {
    pub fn clamp_and_filter(&self, raw_val: i32) -> i32 {
        let clamped = raw_val.clamp(self.minimum, self.maximum);
        if (clamped - self.value).abs() <= self.fuzz {
            self.value
        } else {
            clamped
        }
    }
}

/// Virtual input device specification.
pub struct VirtualInputDevice {
    pub name: String,
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    pub ev_bits: u32,
    pub key_bits: [u64; 8],
    pub rel_bits: u32,
    pub abs_bits: u32,
    pub is_created: bool,
}

impl VirtualInputDevice {
    pub fn new(name: &str, vendor: u16, product: u16) -> Self {
        Self {
            name: String::from(name),
            bustype: 0x03, // BUS_USB
            vendor,
            product,
            version: 1,
            ev_bits: 0,
            key_bits: [0u64; 8],
            rel_bits: 0,
            abs_bits: 0,
            is_created: false,
        }
    }

    pub fn set_evbit(&mut self, ev_type: u16) -> bool {
        if ev_type < 32 {
            self.ev_bits |= 1 << ev_type;
            true
        } else {
            false
        }
    }

    pub fn has_evbit(&self, ev_type: u16) -> bool {
        ev_type < 32 && (self.ev_bits & (1 << ev_type)) != 0
    }

    pub fn set_keybit(&mut self, keycode: u16) -> bool {
        let idx = (keycode as usize) / 64;
        let bit = (keycode as usize) % 64;
        if idx < self.key_bits.len() {
            self.key_bits[idx] |= 1 << bit;
            true
        } else {
            false
        }
    }

    pub fn has_keybit(&self, keycode: u16) -> bool {
        let idx = (keycode as usize) / 64;
        let bit = (keycode as usize) % 64;
        idx < self.key_bits.len() && (self.key_bits[idx] & (1 << bit)) != 0
    }

    pub fn set_relbit(&mut self, rel_code: u16) -> bool {
        if rel_code < 32 {
            self.rel_bits |= 1 << rel_code;
            true
        } else {
            false
        }
    }

    pub fn has_relbit(&self, rel_code: u16) -> bool {
        rel_code < 32 && (self.rel_bits & (1 << rel_code)) != 0
    }

    pub fn set_absbit(&mut self, abs_code: u16) -> bool {
        if abs_code < 32 {
            self.abs_bits |= 1 << abs_code;
            true
        } else {
            false
        }
    }

    pub fn has_absbit(&self, abs_code: u16) -> bool {
        abs_code < 32 && (self.abs_bits & (1 << abs_code)) != 0
    }

    pub fn create_device(&mut self) -> bool {
        self.is_created = true;
        true
    }

    pub fn destroy_device(&mut self) {
        self.is_created = false;
    }

    /// Synthesizes an individual input_event on this virtual device.
    pub fn synthesize_event(
        &self,
        event_type: u16,
        code: u16,
        value: i32,
        sec: u64,
        usec: u64,
    ) -> Result<InputEvent, &'static str> {
        if !self.is_created {
            return Err("Virtual input device not created");
        }
        if !self.has_evbit(event_type) {
            return Err("Event type EV_* not supported by this device");
        }
        if event_type == ev_types::EV_KEY && !self.has_keybit(code) {
            return Err("Key code not configured on this virtual device");
        }
        Ok(InputEvent::new(sec, usec, event_type, code, value))
    }

    /// Synthesizes a key stroke event pair (EV_KEY followed by EV_SYN SYN_REPORT).
    pub fn synthesize_key_event(
        &self,
        keycode: u16,
        pressed: bool,
        sec: u64,
        usec: u64,
    ) -> Result<[InputEvent; 2], &'static str> {
        let val = if pressed { 1 } else { 0 };
        let ev = self.synthesize_event(ev_types::EV_KEY, keycode, val, sec, usec)?;
        let syn = InputEvent::new(sec, usec, ev_types::EV_SYN, syn_codes::SYN_REPORT, 0);
        Ok([ev, syn])
    }
}
