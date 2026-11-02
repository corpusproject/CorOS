//! System Wakeup Sources & Race-Free Suspend/Resume synchronizer.

use alloc::vec::Vec;

/// Tracked system wakeup source (e.g. RTC alarm, keyboard, power button, PCIe PME).
#[derive(Clone, Debug)]
pub struct WakeupSource {
    pub name: &'static str,
    pub event_count: u64,
    pub active_count: u32,
    pub prevent_sleep_time_ms: u64,
}

impl WakeupSource {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            event_count: 0,
            active_count: 0,
            prevent_sleep_time_ms: 0,
        }
    }

    pub fn activate(&mut self) {
        self.active_count += 1;
        self.event_count += 1;
    }

    pub fn deactivate(&mut self) {
        self.active_count = self.active_count.saturating_sub(1);
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active_count > 0
    }
}

/// Global Wakeup Source manager preventing race conditions during sleep entry.
pub struct WakeupManager {
    pub sources: Vec<WakeupSource>,
    pub saved_event_count: u64,
}

impl WakeupManager {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            saved_event_count: 0,
        }
    }

    pub fn register_source(&mut self, name: &'static str) {
        self.sources.push(WakeupSource::new(name));
    }

    pub fn total_event_count(&self) -> u64 {
        self.sources.iter().map(|s| s.event_count).sum()
    }

    /// Prepares for suspend by snapshotting the total wakeup event counter.
    pub fn prepare_for_suspend(&mut self) -> bool {
        if self.sources.iter().any(|s| s.is_active()) {
            return false; // Active wakeup source aborts suspend
        }
        self.saved_event_count = self.total_event_count();
        true
    }

    /// Verifies no new wakeup events fired between prepare and final CPU sleep.
    pub fn verify_sleep_validity(&self) -> bool {
        self.total_event_count() == self.saved_event_count
    }
}
