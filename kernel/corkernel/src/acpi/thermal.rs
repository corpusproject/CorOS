//! CorOS ACPI Thermal Zone & Hardware Cooling Subsystem (`thermal.rs`)
//!
//! Monitors system CPU temperature and manages active/passive cooling:
//! - Temperature in tenths of Kelvin (dK: 3000 dK = 26.85 °C, 3732 dK = 100.0 °C)
//! - Thermal Trip Points:
//!   - `_CRT` (Critical): Threshold for emergency system shutdown to prevent CPU destruction
//!   - `_HOT`: Threshold for emergency hibernation (S4)
//!   - `_PSV` (Passive): Threshold for CPU clock throttling
//!   - `_AC0` - `_AC9` (Active): Thresholds for fan speed steps (100%, 80%, etc.)
//! - Sampling Period (`_TSP`) and Thermal Constant (`_TC1`, `_TC2`) calculation

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Convert tenths of Kelvin to Celsius
pub fn kelvin_tenths_to_celsius(dk: u32) -> f32 {
    ((dk as f32) - 2732.0) / 10.0
}

/// Convert Celsius to tenths of Kelvin
pub fn celsius_to_kelvin_tenths(c: f32) -> u32 {
    ((c * 10.0) + 2732.0) as u32
}

/// ACPI Active Cooling Level (Fan speed)
#[derive(Debug, Clone, Copy)]
pub struct ActiveCoolingTrip {
    pub level: u8,
    pub trip_temp_dk: u32,
    pub fan_speed_percent: u8,
}

/// ACPI Thermal Zone Descriptor
pub struct ThermalZone {
    pub name: String,
    pub current_temp_dk: u32,
    pub critical_temp_dk: u32, // _CRT
    pub hot_temp_dk: u32,      // _HOT
    pub passive_temp_dk: u32,  // _PSV
    pub active_trips: Vec<ActiveCoolingTrip>,
    pub passive_cooling_active: bool,
    pub current_fan_percent: u8,
}

impl ThermalZone {
    pub fn new(name: &str) -> Self {
        let mut tz = Self {
            name: String::from(name),
            current_temp_dk: celsius_to_kelvin_tenths(42.0),
            critical_temp_dk: celsius_to_kelvin_tenths(105.0), // 105 °C emergency shutdown
            hot_temp_dk: celsius_to_kelvin_tenths(95.0),
            passive_temp_dk: celsius_to_kelvin_tenths(80.0),
            active_trips: Vec::new(),
            passive_cooling_active: false,
            current_fan_percent: 30,
        };

        // Standard active fan trip points
        tz.active_trips.push(ActiveCoolingTrip { level: 0, trip_temp_dk: celsius_to_kelvin_tenths(75.0), fan_speed_percent: 100 });
        tz.active_trips.push(ActiveCoolingTrip { level: 1, trip_temp_dk: celsius_to_kelvin_tenths(65.0), fan_speed_percent: 75 });
        tz.active_trips.push(ActiveCoolingTrip { level: 2, trip_temp_dk: celsius_to_kelvin_tenths(55.0), fan_speed_percent: 50 });
        tz.active_trips.push(ActiveCoolingTrip { level: 3, trip_temp_dk: celsius_to_kelvin_tenths(45.0), fan_speed_percent: 30 });

        tz
    }

    /// Update zone temperature and adjust fan / throttling states
    pub fn update_temperature(&mut self, temp_celsius: f32) -> Result<(), &'static str> {
        let dk = celsius_to_kelvin_tenths(temp_celsius);
        self.current_temp_dk = dk;

        // 1. Critical Trip Check
        if dk >= self.critical_temp_dk {
            return Err("CRITICAL THERMAL TRIP: CPU Temperature exceeded maximum safety limit!");
        }

        // 2. Passive Cooling Check
        if dk >= self.passive_temp_dk {
            self.passive_cooling_active = true;
        } else {
            self.passive_cooling_active = false;
        }

        // 3. Active Cooling Fan Speeds
        let mut target_fan = 20u8;
        for trip in &self.active_trips {
            if dk >= trip.trip_temp_dk {
                target_fan = trip.fan_speed_percent;
                break;
            }
        }
        self.current_fan_percent = target_fan;

        Ok(())
    }

    pub fn current_temp_celsius(&self) -> f32 {
        kelvin_tenths_to_celsius(self.current_temp_dk)
    }
}
