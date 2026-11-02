//! CPU Frequency scaling governors (Performance, Powersave, Ondemand, Schedutil) and P-State tables.

use alloc::vec::Vec;

/// Standard CPU Frequency Scaling Governors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpufreqGovernor {
    Performance,
    Powersave,
    Ondemand,
    Conservative,
    Schedutil,
}

/// Hardware P-State frequency entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PStateEntry {
    pub frequency_mhz: u32,
    pub core_voltage_mv: u16,
    pub bus_ratio: u8,
}

/// CPU Frequency Governor controller.
pub struct CpufreqController {
    pub pstate_table: Vec<PStateEntry>,
    pub min_freq_mhz: u32,
    pub max_freq_mhz: u32,
    pub current_freq_mhz: u32,
    pub governor: CpufreqGovernor,
    pub hwp_energy_performance_preference: u8, // Intel HWP EPP: 0=Performance, 128=Balance, 255=Energy
}

impl CpufreqController {
    pub fn new(pstate_table: Vec<PStateEntry>, governor: CpufreqGovernor) -> Self {
        let min_freq = pstate_table.iter().map(|p| p.frequency_mhz).min().unwrap_or(800);
        let max_freq = pstate_table.iter().map(|p| p.frequency_mhz).max().unwrap_or(3600);
        Self {
            pstate_table,
            min_freq_mhz: min_freq,
            max_freq_mhz: max_freq,
            current_freq_mhz: min_freq,
            governor,
            hwp_energy_performance_preference: 128,
        }
    }

    /// Evaluates governor policy and returns target frequency in MHz.
    pub fn calculate_target_frequency(&self, cpu_utilization_permille: u32) -> u32 {
        match self.governor {
            CpufreqGovernor::Performance => self.max_freq_mhz,
            CpufreqGovernor::Powersave => self.min_freq_mhz,
            CpufreqGovernor::Ondemand => {
                if cpu_utilization_permille >= 800 {
                    self.max_freq_mhz
                } else {
                    let span = self.max_freq_mhz - self.min_freq_mhz;
                    self.min_freq_mhz + (span * cpu_utilization_permille) / 1000
                }
            }
            CpufreqGovernor::Conservative => {
                if cpu_utilization_permille >= 800 {
                    (self.current_freq_mhz + 200).min(self.max_freq_mhz)
                } else if cpu_utilization_permille <= 200 {
                    self.current_freq_mhz.saturating_sub(200).max(self.min_freq_mhz)
                } else {
                    self.current_freq_mhz
                }
            }
            CpufreqGovernor::Schedutil => {
                // Schedutil formula: f_next = 1.25 * f_max * util / cap
                let raw_next = (self.max_freq_mhz as u64 * cpu_utilization_permille as u64 * 5) / (1000 * 4);
                (raw_next as u32).clamp(self.min_freq_mhz, self.max_freq_mhz)
            }
        }
    }

    /// Snaps calculated target frequency to the nearest hardware P-state.
    pub fn snap_to_nearest_pstate(&self, target_mhz: u32) -> u32 {
        let mut best_mhz = self.min_freq_mhz;
        let mut min_diff = u32::MAX;
        for p in &self.pstate_table {
            let diff = if p.frequency_mhz >= target_mhz {
                p.frequency_mhz - target_mhz
            } else {
                target_mhz - p.frequency_mhz
            };
            if diff < min_diff {
                min_diff = diff;
                best_mhz = p.frequency_mhz;
            }
        }
        best_mhz
    }
}
