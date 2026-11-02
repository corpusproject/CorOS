//! Menu idle governor: C-state latency evaluation, expected residency & PM QoS limits.

use alloc::vec::Vec;

/// Processor C-State power saving level descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CStateDescriptor {
    pub name: &'static str,
    pub exit_latency_us: u32,
    pub target_residency_us: u32,
    pub power_consumption_mw: u32,
}

/// Menu CPUIdle Governor.
pub struct MenuGovernor {
    pub cstates: Vec<CStateDescriptor>,
    pub pm_qos_max_latency_us: u32,
    pub moving_average_idle_us: u32,
}

impl MenuGovernor {
    pub fn new(cstates: Vec<CStateDescriptor>) -> Self {
        Self {
            cstates,
            pm_qos_max_latency_us: 1000,
            moving_average_idle_us: 500,
        }
    }

    /// Selects the deepest C-state that satisfies latency limits and expected residency.
    pub fn select_cstate(&self, predicted_idle_us: u32) -> usize {
        let max_acceptable_latency = self.pm_qos_max_latency_us;
        let effective_residency = predicted_idle_us.min(self.moving_average_idle_us);

        let mut selected_idx = 0;
        for (idx, state) in self.cstates.iter().enumerate() {
            if state.exit_latency_us <= max_acceptable_latency
                && state.target_residency_us <= effective_residency
            {
                selected_idx = idx;
            }
        }
        selected_idx
    }

    /// Updates moving average after CPU wakes up.
    pub fn update_wakeup(&mut self, actual_idle_us: u32) {
        // Exponential moving average: new_avg = (old_avg * 7 + actual) / 8
        self.moving_average_idle_us =
            (self.moving_average_idle_us.saturating_mul(7) + actual_idle_us) / 8;
    }
}
