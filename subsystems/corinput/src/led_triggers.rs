//! Kernel LED class & trigger state machine (capslock, numlock, heartbeat).

/// Standard LED Triggers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedTrigger {
    None,
    KbdCapsLock,
    KbdNumLock,
    KbdScrollLock,
    DiskActivity,
    Heartbeat,
}

/// Managed LED Indicator.
pub struct LedIndicator {
    pub name: &'static str,
    pub brightness: u8,
    pub max_brightness: u8,
    pub trigger: LedTrigger,
    pub heartbeat_phase: u8,
}

impl LedIndicator {
    pub fn new(name: &'static str, trigger: LedTrigger) -> Self {
        Self {
            name,
            brightness: 0,
            max_brightness: 255,
            trigger,
            heartbeat_phase: 0,
        }
    }

    /// Advances heartbeat double-pulse animation tick.
    pub fn tick_heartbeat(&mut self) {
        if self.trigger == LedTrigger::Heartbeat {
            self.heartbeat_phase = (self.heartbeat_phase + 1) % 10;
            self.brightness = match self.heartbeat_phase {
                0 | 2 => 255,
                _ => 0,
            };
        }
    }

    pub fn set_trigger(&mut self, trigger: LedTrigger) {
        self.trigger = trigger;
    }
}

/// Controller managing standard keyboard LED indicators (NumLock, CapsLock, ScrollLock).
pub struct KeyboardLedController {
    pub num_lock: LedIndicator,
    pub caps_lock: LedIndicator,
    pub scroll_lock: LedIndicator,
}

impl KeyboardLedController {
    pub fn new() -> Self {
        Self {
            num_lock: LedIndicator::new("input::numlock", LedTrigger::KbdNumLock),
            caps_lock: LedIndicator::new("input::capslock", LedTrigger::KbdCapsLock),
            scroll_lock: LedIndicator::new("input::scrolllock", LedTrigger::KbdScrollLock),
        }
    }

    pub fn set_num_lock(&mut self, active: bool) {
        self.num_lock.brightness = if active { 255 } else { 0 };
    }

    pub fn set_caps_lock(&mut self, active: bool) {
        self.caps_lock.brightness = if active { 255 } else { 0 };
    }

    pub fn set_scroll_lock(&mut self, active: bool) {
        self.scroll_lock.brightness = if active { 255 } else { 0 };
    }

    pub fn is_num_lock_lit(&self) -> bool {
        self.num_lock.brightness > 0
    }

    pub fn is_caps_lock_lit(&self) -> bool {
        self.caps_lock.brightness > 0
    }

    pub fn is_scroll_lock_lit(&self) -> bool {
        self.scroll_lock.brightness > 0
    }

    /// Updates LED brightness levels based on XKB modifier bitflags.
    pub fn update_from_modifiers(&mut self, modifiers_mask: u16) {
        use crate::keymap_xkb::modifiers;
        self.set_caps_lock((modifiers_mask & modifiers::LOCK_CAPS) != 0);
        self.set_num_lock((modifiers_mask & modifiers::NUM_LOCK) != 0);
    }

    /// Generates standard PS/2 Set LEDs (command 0xED) byte payload:
    /// Bit 0: Scroll Lock
    /// Bit 1: Num Lock
    /// Bit 2: Caps Lock
    pub fn to_ps2_led_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.is_scroll_lock_lit() {
            byte |= 1 << 0;
        }
        if self.is_num_lock_lit() {
            byte |= 1 << 1;
        }
        if self.is_caps_lock_lit() {
            byte |= 1 << 2;
        }
        byte
    }
}
