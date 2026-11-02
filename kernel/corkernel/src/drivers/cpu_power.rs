//! CPU Hardware Power, Frequency & Thermal Management Subsystem
//!
//! Bare-metal no_std pure Rust driver for x86_64 CPU frequency governors and sensors:
//! - Intel Speed Shift (HWP - Hardware P-States) via MSR 0x770 (IA32_PM_ENABLE) and 0x774 (IA32_HWP_REQUEST)
//! - Digital Thermal Sensors (DTS) reading via MSR 0x19C (IA32_THERM_STATUS) & TjMax from MSR 0x1A2
//! - AMD Core Performance Boost (CPB) and P-State MSRs (0xC0010064..0xC001006B)
//! - Dynamic CPU Frequency Governors: Performance, Powersave, Balanced

#![allow(dead_code)]

use crate::arch::x86_64::msr::Msr;

// Intel Power & Thermal MSRs
pub const MSR_IA32_THERM_STATUS: u32        = 0x19C;
pub const MSR_IA32_TEMPERATURE_TARGET: u32  = 0x1A2;
pub const MSR_IA32_PACKAGE_THERM_STATUS: u32= 0x1B1;
pub const MSR_IA32_PM_ENABLE: u32           = 0x770;
pub const MSR_IA32_HWP_CAPABILITIES: u32    = 0x771;
pub const MSR_IA32_HWP_REQUEST: u32         = 0x774;

// AMD Power MSRs
pub const MSR_AMD_HWCR: u32                 = 0xC0010015;
pub const MSR_AMD_PSTATE_STATUS: u32        = 0xC0010063;

/// Energy Performance Preference (EPP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorPolicy {
    Performance, // Max clocks, EPP = 0
    Balanced,    // Dynamic, EPP = 128
    PowerSave,   // Min clocks, EPP = 255
}

/// CPU Core Thermal Reading
#[derive(Debug, Clone, Copy)]
pub struct CpuThermalStatus {
    pub current_temp_celsius: i32,
    pub tj_max_celsius: i32,
    pub is_throttling: bool,
    pub is_critical: bool,
}

/// Hardware CPU Power Controller
pub struct CpuPowerManager {
    pub is_hwp_supported: bool,
    pub is_hwp_enabled: bool,
    pub tj_max: i32,
    pub current_policy: GovernorPolicy,
    pub highest_perf_ratio: u8,
    pub lowest_perf_ratio: u8,
}

impl CpuPowerManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            is_hwp_supported: false,
            is_hwp_enabled: false,
            tj_max: 100, // Default 100°C for modern Intel/AMD
            current_policy: GovernorPolicy::Performance,
            highest_perf_ratio: 40, // 4.0 GHz baseline
            lowest_perf_ratio: 8,   // 800 MHz baseline
        };

        mgr.probe_hardware();
        mgr
    }

    fn probe_hardware(&mut self) {
        // 1. Detect Intel HWP support via CPUID leaf 6: EAX bit 7
        let cpuid_leaf6 = unsafe { core::arch::x86_64::__cpuid(6) };
        if (cpuid_leaf6.eax & (1 << 7)) != 0 {
            self.is_hwp_supported = true;

            // Read TjMax from IA32_TEMPERATURE_TARGET
            let target_msr = unsafe { Msr::read(MSR_IA32_TEMPERATURE_TARGET) };
            let tj = ((target_msr >> 16) & 0xFF) as i32;
            if tj > 50 && tj < 130 {
                self.tj_max = tj;
            }

            // Read HWP Capabilities (Lowest, Efficient, Guaranteed, Highest)
            let cap_msr = unsafe { Msr::read(MSR_IA32_HWP_CAPABILITIES) };
            self.highest_perf_ratio = (cap_msr & 0xFF) as u8;
            self.lowest_perf_ratio = ((cap_msr >> 24) & 0xFF) as u8;

            // Enable HWP autonomous governor
            unsafe {
                Msr::write(MSR_IA32_PM_ENABLE, 1);
            }
            self.is_hwp_enabled = true;

            // Apply default performance profile
            self.set_governor(GovernorPolicy::Performance);
        }
    }

    /// Read Digital Thermal Sensor (DTS)
    pub fn read_temperature(&self) -> CpuThermalStatus {
        let therm_msr = unsafe { Msr::read(MSR_IA32_THERM_STATUS) };
        let digital_readout = ((therm_msr >> 16) & 0x7F) as i32;
        let is_throttling = (therm_msr & (1 << 0)) != 0;
        let is_critical = (therm_msr & (1 << 4)) != 0;

        let current_temp = self.tj_max - digital_readout;

        CpuThermalStatus {
            current_temp_celsius: current_temp.clamp(0, 125),
            tj_max_celsius: self.tj_max,
            is_throttling,
            is_critical,
        }
    }

    /// Change active CPU power governor
    pub fn set_governor(&mut self, policy: GovernorPolicy) {
        self.current_policy = policy;
        if !self.is_hwp_enabled {
            return;
        }

        let epp: u64 = match policy {
            GovernorPolicy::Performance => 0,    // 0 = Full Performance
            GovernorPolicy::Balanced => 128,    // 128 = Balance performance/power
            GovernorPolicy::PowerSave => 255,   // 255 = Maximum power savings
        };

        let min_ratio = self.lowest_perf_ratio as u64;
        let max_ratio = self.highest_perf_ratio as u64;

        // IA32_HWP_REQUEST layout:
        // bits 0-7: Min Perf, 8-15: Max Perf, 16-23: Desired Perf (0 = hardware auto), 24-31: EPP
        let hwp_request = min_ratio | (max_ratio << 8) | (0 << 16) | (epp << 24);
        unsafe {
            Msr::write(MSR_IA32_HWP_REQUEST, hwp_request);
        }
    }
}
