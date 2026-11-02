//! CorOS Power Management & Thermal Subsystem Bridge (`power_thermal_bridge.rs`)
//!
//! Integrates:
//! - `corpower::cpufreq_gov::{CpufreqController, CpufreqGovernor, PStateEntry}`
//! - `corpower::rapl_energy::{RaplDomainMonitor, RaplUnits}`
//! - `corpower::thermal_zone::{ThermalZone as CorpowerThermalZone, TripPoint, TripPointType}`
//! - `corpower::suspend_s3_s0ix::{SleepState, SleepTransitionSequencer, PowerPhase}`

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use corpower::cpufreq_gov::{CpufreqController, CpufreqGovernor, PStateEntry};
use corpower::rapl_energy::{RaplDomainMonitor, RaplUnits};
use corpower::suspend_s3_s0ix::{PowerPhase, SleepState, SleepTransitionSequencer};
use corpower::thermal_zone::{ThermalZone as CorpowerThermalZone, TripPoint, TripPointType};

#[derive(Debug, Clone, Copy, Default)]
pub struct PowerThermalStats {
    pub is_initialized: bool,
    pub current_freq_mhz: u32,
    pub min_freq_mhz: u32,
    pub max_freq_mhz: u32,
    pub governor: Option<CpufreqGovernor>,
    pub rapl_total_uj: u64,
    pub thermal_temp_mc: i32,
    pub fan_duty_percent: u8,
    pub suspended_devices_count: usize,
}

pub struct PowerThermalBridge {
    cpufreq: SpinLock<Option<CpufreqController>>,
    rapl_monitor: SpinLock<Option<RaplDomainMonitor>>,
    thermal_zone: SpinLock<Option<CorpowerThermalZone>>,
    sleep_sequencer: SpinLock<Option<SleepTransitionSequencer>>,
    is_active: SpinLock<bool>,
}

unsafe impl Send for PowerThermalBridge {}
unsafe impl Sync for PowerThermalBridge {}

impl PowerThermalBridge {
    pub const fn uninit() -> Self {
        Self {
            cpufreq: SpinLock::new(None),
            rapl_monitor: SpinLock::new(None),
            thermal_zone: SpinLock::new(None),
            sleep_sequencer: SpinLock::new(None),
            is_active: SpinLock::new(false),
        }
    }

    /// Initializes CPU frequency governor, RAPL energy monitor, thermal zone PID, and sleep sequencer.
    pub fn initialize(&self) {
        let mut cf = self.cpufreq.lock_irqsave();
        if cf.is_none() {
            let pstates = vec![
                PStateEntry { frequency_mhz: 800, core_voltage_mv: 850, bus_ratio: 8 },
                PStateEntry { frequency_mhz: 1600, core_voltage_mv: 950, bus_ratio: 16 },
                PStateEntry { frequency_mhz: 2400, core_voltage_mv: 1100, bus_ratio: 24 },
                PStateEntry { frequency_mhz: 3200, core_voltage_mv: 1200, bus_ratio: 32 },
                PStateEntry { frequency_mhz: 4000, core_voltage_mv: 1300, bus_ratio: 40 },
            ];
            *cf = Some(CpufreqController::new(pstates, CpufreqGovernor::Schedutil));
        }
        drop(cf);

        let mut rapl = self.rapl_monitor.lock_irqsave();
        if rapl.is_none() {
            let units = RaplUnits {
                power_units_watts: 1,
                energy_status_units_microjoules: 61,
                time_units_seconds: 1,
            };
            *rapl = Some(RaplDomainMonitor::new("Package", units));
        }
        drop(rapl);

        let mut tz = self.thermal_zone.lock_irqsave();
        if tz.is_none() {
            let mut zone = CorpowerThermalZone::new(0, 65_000); // Target 65 °C
            zone.trip_points.push(TripPoint {
                trip_type: TripPointType::Passive,
                temp_millicelsius: 80_000,
                cooling_device_id: 0,
            });
            zone.trip_points.push(TripPoint {
                trip_type: TripPointType::Critical,
                temp_millicelsius: 105_000,
                cooling_device_id: 0,
            });
            *tz = Some(zone);
        }
        drop(tz);

        let mut seq = self.sleep_sequencer.lock_irqsave();
        if seq.is_none() {
            let mut s = SleepTransitionSequencer::new(SleepState::S3SuspendToRam);
            s.register_device("NVMe", 10);
            s.register_device("AHCI", 20);
            s.register_device("VirtIO-Net", 30);
            s.register_device("VirtIO-Blk", 40);
            s.register_device("AC97", 50);
            s.register_device("DRM-GPU", 60);
            *seq = Some(s);
        }
        drop(seq);

        let mut act = self.is_active.lock_irqsave();
        *act = true;
    }

    /// Evaluates CPU utilization (0..1000 permille) and updates target frequency according to active governor.
    pub fn update_cpufreq(&self, utilization_permille: u32) -> u32 {
        self.initialize();
        let mut cf = self.cpufreq.lock_irqsave();
        if let Some(ref mut ctrl) = *cf {
            let target = ctrl.calculate_target_frequency(utilization_permille);
            let snapped = ctrl.snap_to_nearest_pstate(target);
            ctrl.current_freq_mhz = snapped;
            snapped
        } else {
            2400
        }
    }

    /// Changes CPUFreq governor (Performance, Powersave, Ondemand, Schedutil).
    pub fn set_governor(&self, gov: CpufreqGovernor) {
        self.initialize();
        let mut cf = self.cpufreq.lock_irqsave();
        if let Some(ref mut ctrl) = *cf {
            ctrl.governor = gov;
        }
    }

    /// Samples MSR energy counter and returns delta microjoules.
    pub fn sample_rapl_energy(&self, raw_counter: u32) -> u64 {
        self.initialize();
        let mut rapl = self.rapl_monitor.lock_irqsave();
        if let Some(ref mut mon) = *rapl {
            mon.sample_energy_counter(raw_counter)
        } else {
            0
        }
    }

    /// Updates thermal zone temperature in milliCelsius, running fan PID and checking trip points.
    pub fn update_temperature(&self, temp_mc: i32) -> Option<TripPointType> {
        self.initialize();
        let mut tz = self.thermal_zone.lock_irqsave();
        if let Some(ref mut zone) = *tz {
            zone.set_temperature(temp_mc)
        } else {
            None
        }
    }

    /// Executes system sleep transition sequence across registered hardware devices.
    pub fn execute_sleep_transition(&self, target_state: SleepState) -> bool {
        self.initialize();
        let mut seq = self.sleep_sequencer.lock_irqsave();
        if let Some(ref mut s) = *seq {
            s.target_state = target_state;
            s.execute_suspend_sequence()
        } else {
            false
        }
    }

    /// Executes system resume transition sequence across registered hardware devices.
    pub fn execute_resume_transition(&self) -> bool {
        let mut seq = self.sleep_sequencer.lock_irqsave();
        if let Some(ref mut s) = *seq {
            s.execute_resume_sequence()
        } else {
            false
        }
    }

    /// ACPI S5 Soft-off shutdown trigger. Quiesces devices and triggers hardware sleep state.
    pub fn trigger_s5_shutdown(&self) {
        self.execute_sleep_transition(SleepState::S5SoftOff);

        let mut pm = crate::acpi::AcpiPowerManager::new();
        let _ = pm.enter_sleep_state(crate::acpi::ACPI_SLEEP_S5);
    }

    /// Collects full diagnostic telemetry for power, frequency, RAPL, and thermal domains.
    pub fn stats(&self) -> PowerThermalStats {
        let active = *self.is_active.lock_irqsave();
        let cf = self.cpufreq.lock_irqsave();
        let rapl = self.rapl_monitor.lock_irqsave();
        let tz = self.thermal_zone.lock_irqsave();
        let seq = self.sleep_sequencer.lock_irqsave();

        let (cur_f, min_f, max_f, gov) = if let Some(ref c) = *cf {
            (c.current_freq_mhz, c.min_freq_mhz, c.max_freq_mhz, Some(c.governor))
        } else {
            (0, 0, 0, None)
        };

        let rapl_total = if let Some(ref r) = *rapl {
            r.total_microjoules
        } else {
            0
        };

        let (temp_mc, fan_duty) = if let Some(ref z) = *tz {
            (z.current_temp_mc, z.pid.current_duty_percent)
        } else {
            (0, 0)
        };

        let suspended_devs = if let Some(ref s) = *seq {
            s.devices.iter().filter(|d| d.is_suspended).count()
        } else {
            0
        };

        PowerThermalStats {
            is_initialized: active,
            current_freq_mhz: cur_f,
            min_freq_mhz: min_f,
            max_freq_mhz: max_f,
            governor: gov,
            rapl_total_uj: rapl_total,
            thermal_temp_mc: temp_mc,
            fan_duty_percent: fan_duty,
            suspended_devices_count: suspended_devs,
        }
    }
}

pub static GLOBAL_POWER_THERMAL_BRIDGE: PowerThermalBridge = PowerThermalBridge::uninit();
