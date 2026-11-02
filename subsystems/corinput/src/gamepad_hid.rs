//! Standard Gamepad Controller, radial deadzone normalizer & dual-motor rumble envelope.

/// Standard Gamepad Buttons bitmask.
pub mod gamepad_buttons {
    pub const A_SOUTH: u16 = 1 << 0;
    pub const B_EAST: u16 = 1 << 1;
    pub const X_WEST: u16 = 1 << 2;
    pub const Y_NORTH: u16 = 1 << 3;
    pub const DPAD_UP: u16 = 1 << 4;
    pub const DPAD_DOWN: u16 = 1 << 5;
    pub const DPAD_LEFT: u16 = 1 << 6;
    pub const DPAD_RIGHT: u16 = 1 << 7;
    pub const L1_BUMPER: u16 = 1 << 8;
    pub const R1_BUMPER: u16 = 1 << 9;
    pub const START: u16 = 1 << 10;
    pub const SELECT: u16 = 1 << 11;
}

/// Standardized Gamepad State.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GamepadState {
    pub buttons: u16,
    pub left_stick_x: i16,
    pub left_stick_y: i16,
    pub right_stick_x: i16,
    pub right_stick_y: i16,
    pub left_trigger: u8,
    pub right_trigger: u8,
}

/// Dual-motor force feedback rumble envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RumbleEffect {
    pub strong_magnitude: u16, // Low-frequency heavy rumble
    pub weak_magnitude: u16,   // High-frequency subtle rumble
    pub duration_ms: u32,
}

impl RumbleEffect {
    pub fn new(strong_magnitude: u16, weak_magnitude: u16, duration_ms: u32) -> Self {
        Self {
            strong_magnitude,
            weak_magnitude,
            duration_ms,
        }
    }

    /// Serializes rumble envelope into standard 8-byte HID force-feedback output report.
    pub fn create_rumble_packet(&self) -> [u8; 8] {
        let mut packet = [0u8; 8];
        packet[0] = 0x05; // Output Report ID for force feedback
        let mut enable_flags = 0u8;
        if self.weak_magnitude > 0 {
            enable_flags |= 0x01;
        }
        if self.strong_magnitude > 0 {
            enable_flags |= 0x02;
        }
        packet[1] = enable_flags;
        packet[2] = 0xFF; // Continuous duration pulse
        packet[3] = (self.weak_magnitude >> 8) as u8; // High byte (0..255)
        packet[4] = 0xFF; // Continuous duration pulse
        packet[5] = (self.strong_magnitude >> 8) as u8; // High byte (0..255)
        let dur_u16 = (self.duration_ms.min(u16::MAX as u32)) as u16;
        let dur_bytes = dur_u16.to_le_bytes();
        packet[6] = dur_bytes[0];
        packet[7] = dur_bytes[1];
        packet
    }
}

/// Gamepad deadzone filter and stick normalizer.
pub struct GamepadFilter {
    pub radial_deadzone: i32,
}

impl GamepadFilter {
    pub fn new(radial_deadzone: i32) -> Self {
        Self { radial_deadzone }
    }

    /// Computes Euclidean radial distance for stick coordinates.
    pub fn radial_distance(&self, raw_x: i16, raw_y: i16) -> i32 {
        let x = raw_x as i64;
        let y = raw_y as i64;
        let sq = x * x + y * y;
        if sq <= 0 {
            return 0;
        }
        let mut val = sq;
        let mut next = (val + 1) / 2;
        while next < val {
            val = next;
            next = (val + sq / val) / 2;
        }
        val as i32
    }

    /// Filters analog stick axes with binary radial deadzone cut-off.
    pub fn filter_stick(&self, raw_x: i16, raw_y: i16) -> (i16, i16) {
        let mag = self.radial_distance(raw_x, raw_y);
        if mag < self.radial_deadzone {
            (0, 0)
        } else {
            (raw_x, raw_y)
        }
    }

    /// Normalizes analog stick axes into smoothly scaled [-1.0, 1.0] unit vectors.
    pub fn normalize_stick(&self, raw_x: i16, raw_y: i16) -> (f32, f32) {
        let mag = self.radial_distance(raw_x, raw_y);
        if mag <= self.radial_deadzone {
            return (0.0, 0.0);
        }
        let max_val = 32767;
        let active_range = (max_val - self.radial_deadzone).max(1) as f32;
        let normalized_mag = ((mag - self.radial_deadzone) as f32 / active_range).clamp(0.0, 1.0);
        let nx = (raw_x as f32 / mag as f32) * normalized_mag;
        let ny = (raw_y as f32 / mag as f32) * normalized_mag;
        (nx, ny)
    }

    /// Normalizes trigger raw byte [0..255] into linear unit pressure [0.0..1.0].
    pub fn normalize_trigger(raw_trigger: u8, deadzone: u8) -> f32 {
        if raw_trigger <= deadzone {
            return 0.0;
        }
        let active_span = (255 - deadzone).max(1) as f32;
        ((raw_trigger - deadzone) as f32 / active_span).clamp(0.0, 1.0)
    }

    /// Converts trigger pressure to a percentage [0..100].
    pub fn trigger_pressure_percent(raw_trigger: u8, deadzone: u8) -> u8 {
        let norm = Self::normalize_trigger(raw_trigger, deadzone);
        (norm * 100.0) as u8
    }
}
