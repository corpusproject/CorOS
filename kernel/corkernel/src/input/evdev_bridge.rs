//! CorOS Evdev Input Subsystem Bridge (`evdev_bridge.rs`)
//!
//! Integrates:
//! - `corinput::evdev_core::{EvdevClientQueue, InputEvent, ev_types, key_codes, rel_codes, syn_codes}`
//! - `corinput::keymap_xkb::{XkbKeyboardTranslator, KeymapLayout, ps2_scancode_to_keycode}`
//! - Routes PS/2 8042, USB HID, and VirtIO-Input events into a unified event queue.

extern crate alloc;

use crate::sync::SpinLock;
use corinput::evdev_core::{abs_codes, ev_types, key_codes, rel_codes, syn_codes, EvdevClientQueue, InputEvent};
use corinput::keymap_xkb::{ps2_scancode_to_keycode, KeymapLayout, XkbKeyboardTranslator};

pub struct EvdevBridge {
    event_queue: SpinLock<Option<EvdevClientQueue>>,
    translator: SpinLock<Option<XkbKeyboardTranslator>>,
}

unsafe impl Send for EvdevBridge {}
unsafe impl Sync for EvdevBridge {}

impl EvdevBridge {
    pub const fn uninit() -> Self {
        Self {
            event_queue: SpinLock::new(None),
            translator: SpinLock::new(None),
        }
    }

    /// Initializes the evdev client ring queue and XKB keymap translator.
    pub fn initialize(&self) {
        let mut eq = self.event_queue.lock_irqsave();
        if eq.is_none() {
            *eq = Some(EvdevClientQueue::new(256));
        }
        drop(eq);

        let mut tr = self.translator.lock_irqsave();
        if tr.is_none() {
            *tr = Some(XkbKeyboardTranslator::new(KeymapLayout::UsQwerty));
        }
    }

    /// Converts a raw PS/2 Set 1 scancode into an evdev `EV_KEY` input event.
    pub fn route_ps2_scancode(&self, scancode: u8, now_ms: u64) -> Option<char> {
        self.initialize();
        let is_release = (scancode & 0x80) != 0;
        let make_code = scancode & 0x7F;

        let keycode = ps2_scancode_to_keycode(make_code, false)?;
        let value = if is_release { 0 } else { 1 };
        let sec = now_ms / 1000;
        let usec = (now_ms % 1000) * 1000;

        let mut tr_guard = self.translator.lock_irqsave();
        let ch = if let Some(ref mut tr) = *tr_guard {
            tr.update_modifier(keycode, !is_release);
            tr.translate_keycode(keycode)
        } else {
            None
        };
        drop(tr_guard);

        let mut eq_guard = self.event_queue.lock_irqsave();
        if let Some(ref mut queue) = *eq_guard {
            // Push EV_KEY event
            queue.push_event(InputEvent::new(sec, usec, ev_types::EV_KEY, keycode, value));
            // Push SYN_REPORT
            queue.push_event(InputEvent::syn_report(sec, usec));
        }

        ch
    }

    /// Translates relative mouse movement and button clicks into evdev events.
    pub fn route_mouse_rel(&self, dx: i32, dy: i32, left: bool, right: bool, now_ms: u64) {
        self.initialize();
        let sec = now_ms / 1000;
        let usec = (now_ms % 1000) * 1000;

        let mut eq_guard = self.event_queue.lock_irqsave();
        if let Some(ref mut queue) = *eq_guard {
            if dx != 0 {
                queue.push_event(InputEvent::new(sec, usec, ev_types::EV_REL, rel_codes::REL_X, dx));
            }
            if dy != 0 {
                queue.push_event(InputEvent::new(sec, usec, ev_types::EV_REL, rel_codes::REL_Y, dy));
            }
            queue.push_event(InputEvent::new(
                sec,
                usec,
                ev_types::EV_KEY,
                key_codes::BTN_LEFT,
                if left { 1 } else { 0 },
            ));
            queue.push_event(InputEvent::new(
                sec,
                usec,
                ev_types::EV_KEY,
                key_codes::BTN_RIGHT,
                if right { 1 } else { 0 },
            ));
            queue.push_event(InputEvent::syn_report(sec, usec));
        }
    }

    /// Polls the next pending `InputEvent` from the evdev queue.
    pub fn poll_event(&self) -> Option<InputEvent> {
        self.initialize();
        let mut eq_guard = self.event_queue.lock_irqsave();
        eq_guard.as_mut().and_then(|q| q.ring.pop_front())
    }

    /// Returns the number of events currently queued.
    pub fn pending_count(&self) -> usize {
        self.initialize();
        self.event_queue
            .lock_irqsave()
            .as_ref()
            .map(|q| q.ring.len())
            .unwrap_or(0)
    }
}

pub static GLOBAL_EVDEV_BRIDGE: EvdevBridge = EvdevBridge::uninit();
