//! Device Runtime Power Management (RPM), active reference counting & autosuspend delay timers.

/// Runtime PM State of an individual device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimePmStatus {
    Active,
    Suspending,
    Suspended,
    Resuming,
}

/// Runtime Power Management controller for peripheral devices.
pub struct RuntimePmDevice {
    pub name: &'static str,
    pub status: RuntimePmStatus,
    pub usage_count: u32,
    pub autosuspend_delay_ms: u32,
    pub last_busy_timestamp_ms: u64,
}

impl RuntimePmDevice {
    pub fn new(name: &'static str, autosuspend_delay_ms: u32) -> Self {
        Self {
            name,
            status: RuntimePmStatus::Active,
            usage_count: 0,
            autosuspend_delay_ms,
            last_busy_timestamp_ms: 0,
        }
    }

    /// Increments usage count and wakes the device if suspended.
    pub fn pm_runtime_get(&mut self) {
        self.usage_count = self.usage_count.saturating_add(1);
        if self.status == RuntimePmStatus::Suspended {
            self.status = RuntimePmStatus::Active;
        }
    }

    /// Decrements usage count and marks device active with timestamp.
    pub fn pm_runtime_put(&mut self, current_time_ms: u64) {
        self.usage_count = self.usage_count.saturating_sub(1);
        self.last_busy_timestamp_ms = current_time_ms;
    }

    /// Checks if autosuspend threshold has elapsed with 0 active users.
    pub fn check_autosuspend(&mut self, current_time_ms: u64) -> bool {
        if self.status == RuntimePmStatus::Active && self.usage_count == 0 {
            if current_time_ms.saturating_sub(self.last_busy_timestamp_ms) >= self.autosuspend_delay_ms as u64 {
                self.status = RuntimePmStatus::Suspended;
                return true;
            }
        }
        false
    }
}
