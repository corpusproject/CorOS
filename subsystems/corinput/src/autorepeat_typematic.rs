//! Typematic key repeat state machine (delay_ms = 250, period_ms = 33).

/// Typematic key repeat parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypematicConfig {
    pub delay_ms: u32,
    pub period_ms: u32,
}

impl Default for TypematicConfig {
    fn default() -> Self {
        Self {
            delay_ms: 250,
            period_ms: 33,
        }
    }
}

/// Software Typematic Repeat controller.
pub struct TypematicRepeatState {
    pub config: TypematicConfig,
    pub active_keycode: Option<u16>,
    pub key_press_timestamp_ms: u64,
    pub next_repeat_timestamp_ms: u64,
}

impl TypematicRepeatState {
    pub fn new(config: TypematicConfig) -> Self {
        Self {
            config,
            active_keycode: None,
            key_press_timestamp_ms: 0,
            next_repeat_timestamp_ms: 0,
        }
    }

    pub fn key_down(&mut self, keycode: u16, timestamp_ms: u64) {
        self.active_keycode = Some(keycode);
        self.key_press_timestamp_ms = timestamp_ms;
        self.next_repeat_timestamp_ms = timestamp_ms + self.config.delay_ms as u64;
    }

    pub fn key_up(&mut self, keycode: u16) {
        if self.active_keycode == Some(keycode) {
            self.active_keycode = None;
        }
    }

    /// Polls repeat timer. Emits repeating keycode if period has elapsed.
    pub fn poll_repeat(&mut self, current_time_ms: u64) -> Option<u16> {
        let key = self.active_keycode?;
        if current_time_ms >= self.next_repeat_timestamp_ms {
            self.next_repeat_timestamp_ms += self.config.period_ms as u64;
            Some(key)
        } else {
            None
        }
    }

    pub fn is_active(&self) -> bool {
        self.active_keycode.is_some()
    }

    pub fn active_key(&self) -> Option<u16> {
        self.active_keycode
    }

    pub fn set_config(&mut self, config: TypematicConfig) {
        self.config = config;
    }

    pub fn reset(&mut self) {
        self.active_keycode = None;
        self.key_press_timestamp_ms = 0;
        self.next_repeat_timestamp_ms = 0;
    }
}
