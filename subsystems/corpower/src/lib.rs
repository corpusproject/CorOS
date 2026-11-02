#![no_std]
//! `corpower` — CorOS ACPI Thermal, CPUFreq/CPUIDLE, Suspend/Hibernate & Battery Power Management Subsystem.

extern crate alloc;

pub mod cpufreq_gov;
pub mod cpuidle_menu;
pub mod rapl_energy;
pub mod thermal_zone;
pub mod suspend_s3_s0ix;
pub mod swsusp_hiber;
pub mod smart_battery;
pub mod usb_runtime_pm;
pub mod pcie_aspm;
pub mod wakeup_sources;

pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. cpufreq_gov test
    let pstates = alloc::vec![
        cpufreq_gov::PStateEntry { frequency_mhz: 800, core_voltage_mv: 850, bus_ratio: 8 },
        cpufreq_gov::PStateEntry { frequency_mhz: 2400, core_voltage_mv: 1100, bus_ratio: 24 },
        cpufreq_gov::PStateEntry { frequency_mhz: 3600, core_voltage_mv: 1250, bus_ratio: 36 },
    ];
    let ctrl = cpufreq_gov::CpufreqController::new(pstates, cpufreq_gov::CpufreqGovernor::Schedutil);
    let target = ctrl.calculate_target_frequency(500);
    let snapped = ctrl.snap_to_nearest_pstate(target);
    if snapped >= 800 && snapped <= 3600 {
        passed += 1;
    }

    // 2. cpuidle_menu test
    let cstates = alloc::vec![
        cpuidle_menu::CStateDescriptor { name: "C1", exit_latency_us: 2, target_residency_us: 4, power_consumption_mw: 1000 },
        cpuidle_menu::CStateDescriptor { name: "C6", exit_latency_us: 100, target_residency_us: 300, power_consumption_mw: 50 },
    ];
    let menu = cpuidle_menu::MenuGovernor::new(cstates);
    let sel = menu.select_cstate(500);
    if sel == 1 {
        passed += 1;
    }

    // 3. rapl_energy test
    let units = rapl_energy::RaplUnits {
        power_units_watts: 1,
        energy_status_units_microjoules: 61,
        time_units_seconds: 1,
    };
    let mut rapl = rapl_energy::RaplDomainMonitor::new("Package", units);
    let delta = rapl.sample_energy_counter(1000);
    if delta > 0 && rapl.total_microjoules == delta {
        passed += 1;
    }

    // 4. thermal_zone test
    let mut tz = thermal_zone::ThermalZone::new(0, 65_000);
    tz.trip_points.push(thermal_zone::TripPoint {
        trip_type: thermal_zone::TripPointType::Critical,
        temp_millicelsius: 100_000,
        cooling_device_id: 0,
    });
    let alert = tz.set_temperature(105_000);
    if alert == Some(thermal_zone::TripPointType::Critical) {
        passed += 1;
    }

    // 5. suspend_s3_s0ix test
    let mut seq = suspend_s3_s0ix::SleepTransitionSequencer::new(suspend_s3_s0ix::SleepState::S3SuspendToRam);
    seq.register_device("NVMe", 1);
    seq.register_device("PCIe", 2);
    if seq.execute_suspend_sequence() && seq.execute_resume_sequence() {
        passed += 1;
    }

    // 6. swsusp_hiber test
    let header = swsusp_hiber::SwsuspHeader::new(65536, 0x12345678, 2048);
    let mut bitmap = swsusp_hiber::SaveablePageBitmap::new(100);
    bitmap.set_saveable(10);
    bitmap.set_saveable(20);
    if header.is_valid() && bitmap.count_saveable_pages() == 2 {
        passed += 1;
    }

    // 7. smart_battery test
    let info = smart_battery::BatteryInfo {
        design_capacity_mwh: 50_000,
        last_full_capacity_mwh: 48_000,
        design_voltage_mv: 11_100,
        cycle_count: 50,
    };
    let status = smart_battery::BatteryDynamicStatus {
        state: smart_battery::BatteryStatus::Discharging,
        present_rate_mw: 10_000,
        remaining_capacity_mwh: 24_000,
        present_voltage_mv: 11_000,
    };
    let bat = smart_battery::SmartBatteryMonitor::new(info, status);
    if bat.charge_percent() == 50 && bat.estimated_runtime_minutes() == Some(144) {
        passed += 1;
    }

    // 8. usb_runtime_pm test
    let mut rpm = usb_runtime_pm::RuntimePmDevice::new("xhci_port", 200);
    rpm.pm_runtime_get();
    rpm.pm_runtime_put(1000);
    if rpm.check_autosuspend(1250) && rpm.status == usb_runtime_pm::RuntimePmStatus::Suspended {
        passed += 1;
    }

    // 9. pcie_aspm test
    let mut aspm = pcie_aspm::PcieAspmController::new(0, 2, 0, pcie_aspm::AspmSupport::L0sAndL1);
    if aspm.configure_aspm(true) && aspm.enabled {
        passed += 1;
    }

    // 10. wakeup_sources test
    let mut wm = wakeup_sources::WakeupManager::new();
    wm.register_source("RTC");
    if wm.prepare_for_suspend() && wm.verify_sleep_validity() {
        passed += 1;
    }

    passed
}
