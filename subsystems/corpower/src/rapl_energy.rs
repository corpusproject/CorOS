//! Running Average Power Limit (RAPL) energy telemetry, MSR decoding & PL1/PL2 power caps.

/// RAPL Power and Energy unit scalers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaplUnits {
    pub power_units_watts: u32,
    pub energy_status_units_microjoules: u32,
    pub time_units_seconds: u32,
}

impl RaplUnits {
    /// Decodes MSR_RAPL_POWER_UNIT (0x606).
    pub fn from_msr_value(val: u64) -> Self {
        let power_exponent = (val & 0x0F) as u32;
        let energy_exponent = ((val >> 8) & 0x1F) as u32;
        let time_exponent = ((val >> 16) & 0x0F) as u32;

        Self {
            power_units_watts: 1 << power_exponent,
            energy_status_units_microjoules: 1_000_000 / (1 << energy_exponent),
            time_units_seconds: 1 << time_exponent,
        }
    }
}

/// RAPL Power Domain Monitor with 32-bit counter wrap-around handling.
#[derive(Clone, Debug)]
pub struct RaplDomainMonitor {
    pub name: &'static str,
    pub last_energy_counter: u32,
    pub total_microjoules: u64,
    pub units: RaplUnits,
}

impl RaplDomainMonitor {
    pub fn new(name: &'static str, units: RaplUnits) -> Self {
        Self {
            name,
            last_energy_counter: 0,
            total_microjoules: 0,
            units,
        }
    }

    /// Accumulates energy counter tick, handling 32-bit hardware overflow.
    pub fn sample_energy_counter(&mut self, current_raw_counter: u32) -> u64 {
        let delta_ticks = current_raw_counter.wrapping_sub(self.last_energy_counter);
        self.last_energy_counter = current_raw_counter;

        let delta_uj = (delta_ticks as u64)
            .saturating_mul(self.units.energy_status_units_microjoules as u64);
        self.total_microjoules = self.total_microjoules.saturating_add(delta_uj);
        delta_uj
    }
}
