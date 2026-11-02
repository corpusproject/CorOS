//! ACPI Control Method Battery (_BIX/_BST) & SBS Smart Battery monitor and runtime estimators.

/// Battery charging and health state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatteryStatus {
    Charging,
    Discharging,
    Full,
    Critical,
}

/// Battery Information Structure (_BIX format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatteryInfo {
    pub design_capacity_mwh: u32,
    pub last_full_capacity_mwh: u32,
    pub design_voltage_mv: u32,
    pub cycle_count: u32,
}

/// Dynamic Battery Status (_BST format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatteryDynamicStatus {
    pub state: BatteryStatus,
    pub present_rate_mw: u32,
    pub remaining_capacity_mwh: u32,
    pub present_voltage_mv: u32,
}

/// Smart Battery Monitor.
pub struct SmartBatteryMonitor {
    pub info: BatteryInfo,
    pub status: BatteryDynamicStatus,
}

impl SmartBatteryMonitor {
    pub fn new(info: BatteryInfo, status: BatteryDynamicStatus) -> Self {
        Self { info, status }
    }

    /// Computes battery health degradation percentage (0..100%).
    pub fn health_percent(&self) -> u32 {
        if self.info.design_capacity_mwh == 0 {
            return 100;
        }
        ((self.info.last_full_capacity_mwh as u64 * 100) / self.info.design_capacity_mwh as u64) as u32
    }

    /// Computes remaining battery charge percentage (0..100%).
    pub fn charge_percent(&self) -> u32 {
        if self.info.last_full_capacity_mwh == 0 {
            return 0;
        }
        ((self.status.remaining_capacity_mwh as u64 * 100) / self.info.last_full_capacity_mwh as u64) as u32
    }

    /// Estimates remaining runtime in minutes when discharging.
    pub fn estimated_runtime_minutes(&self) -> Option<u32> {
        if self.status.state != BatteryStatus::Discharging || self.status.present_rate_mw == 0 {
            None
        } else {
            let minutes = (self.status.remaining_capacity_mwh as u64 * 60)
                / self.status.present_rate_mw as u64;
            Some(minutes as u32)
        }
    }
}
