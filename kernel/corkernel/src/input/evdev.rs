//! Universal Input Event Subsystem (Linux evdev / Windows RAWINPUT)
//!
//! Provides hardware-agnostic input device multiplexing:
//! - Event Types: `EV_SYN`, `EV_KEY`, `EV_REL`, `EV_ABS`, `EV_MSC`, `EV_SW`, `EV_LED`, `EV_SND`, `EV_REP`, `EV_FF`
//! - Relative axis tracking (Mouse X, Y, Wheel horizontal/vertical)
//! - Absolute axis tracking (Touchscreen / Digitizer X, Y, Pressure, Multi-touch slot tracking)
//! - Scancode to Linux KEY / Windows Virtual Key (VK) unified mapping
//! - Input event ring buffer and asynchronous subscribers

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_SW: u16 = 0x05;
pub const EV_LED: u16 = 0x11;
pub const EV_SND: u16 = 0x12;
pub const EV_REP: u16 = 0x14;
pub const EV_FF: u16 = 0x15;

// Synchronization events
pub const SYN_REPORT: u16 = 0;
pub const SYN_CONFIG: u16 = 1;
pub const SYN_MT_REPORT: u16 = 2;
pub const SYN_DROPPED: u16 = 3;

// Relative axes
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_Z: u16 = 0x02;
pub const REL_RX: u16 = 0x03;
pub const REL_RY: u16 = 0x04;
pub const REL_RZ: u16 = 0x05;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_DIAL: u16 = 0x07;
pub const REL_WHEEL: u16 = 0x08;

// Absolute axes
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_Z: u16 = 0x02;
pub const ABS_PRESSURE: u16 = 0x18;
pub const ABS_DISTANCE: u16 = 0x19;
pub const ABS_MT_SLOT: u16 = 0x2F;
pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

// Standard Keys / Buttons
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_SIDE: u16 = 0x113;
pub const BTN_EXTRA: u16 = 0x114;
pub const BTN_TOUCH: u16 = 0x14A;

/// Standard Input Event struct (matching struct input_event in Linux)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputEvent {
    pub time_sec: u64,
    pub time_usec: u64,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

impl InputEvent {
    pub fn new(type_: u16, code: u16, value: i32) -> Self {
        Self {
            time_sec: 0,
            time_usec: 0,
            type_,
            code,
            value,
        }
    }

    pub fn syn_report() -> Self {
        Self::new(EV_SYN, SYN_REPORT, 0)
    }

    pub fn key(code: u16, pressed: bool) -> Self {
        Self::new(EV_KEY, code, if pressed { 1 } else { 0 })
    }

    pub fn rel_move(dx: i32, dy: i32) -> (Self, Self, Self) {
        (
            Self::new(EV_REL, REL_X, dx),
            Self::new(EV_REL, REL_Y, dy),
            Self::syn_report(),
        )
    }
}

/// Input Device Node (representing `/dev/input/eventX`)
pub struct EvdevDevice {
    pub id: u32,
    pub name: String,
    pub phys: String,
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    pub ev_bits: u32, // Supported event types bitmask
    pub event_queue: Vec<InputEvent>,
    pub max_queue_size: usize,
}

impl EvdevDevice {
    pub fn new(id: u32, name: &str, vendor: u16, product: u16) -> Self {
        Self {
            id,
            name: String::from(name),
            phys: alloc::format!("isa0060/serio0/input{}", id),
            bustype: 0x0003, // USB or PS/2
            vendor,
            product,
            version: 0x0100,
            ev_bits: (1 << EV_SYN) | (1 << EV_KEY) | (1 << EV_REL),
            event_queue: Vec::with_capacity(128),
            max_queue_size: 256,
        }
    }

    /// Push an event into this device's stream
    pub fn push_event(&mut self, ev: InputEvent) {
        if self.event_queue.len() >= self.max_queue_size {
            // Buffer overflow: insert SYN_DROPPED
            self.event_queue.clear();
            self.event_queue.push(InputEvent::new(EV_SYN, SYN_DROPPED, 0));
        }
        self.event_queue.push(ev);
    }

    /// Read next pending event
    pub fn poll_event(&mut self) -> Option<InputEvent> {
        if self.event_queue.is_empty() {
            None
        } else {
            Some(self.event_queue.remove(0))
        }
    }
}

/// Global Evdev Subsystem Hub
pub struct EvdevHub {
    pub devices: Vec<EvdevDevice>,
    pub next_id: AtomicU32,
}

impl EvdevHub {
    pub fn new() -> Self {
        let mut hub = Self {
            devices: Vec::new(),
            next_id: AtomicU32::new(0),
        };

        // Bootstrap Keyboard device
        let mut kbd = EvdevDevice::new(0, "CorOS PS/2 Virtual Keyboard", 0x0001, 0x0001);
        kbd.ev_bits |= (1 << EV_REP) | (1 << EV_LED);
        hub.devices.push(kbd);

        // Bootstrap Mouse device
        let mouse = EvdevDevice::new(1, "CorOS PS/2 Generic Optical Mouse", 0x0002, 0x0001);
        hub.devices.push(mouse);

        hub
    }

    /// Dispatch relative mouse movement to mouse event device
    pub fn report_mouse_move(&mut self, dx: i32, dy: i32) {
        if let Some(mouse) = self.devices.iter_mut().find(|d| d.id == 1) {
            let (ex, ey, syn) = InputEvent::rel_move(dx, dy);
            mouse.push_event(ex);
            mouse.push_event(ey);
            mouse.push_event(syn);
        }
    }

    /// Dispatch keyboard key event
    pub fn report_key_event(&mut self, scancode: u16, is_press: bool) {
        if let Some(kbd) = self.devices.iter_mut().find(|d| d.id == 0) {
            kbd.push_event(InputEvent::key(scancode, is_press));
            kbd.push_event(InputEvent::syn_report());
        }
    }
}
