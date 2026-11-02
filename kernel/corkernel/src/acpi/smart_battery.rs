//! ACPI Smart Battery System (SBS 1.1) & Control Method Battery Subsystem for CorOS
//! 100% in-house bare-metal implementation conforming to ACPI 6.4 Specification Section 10.2
//! and Smart Battery Data Specification Revision 1.1.
//!
//! Provides SMBus-based battery communication, ACPI _BIF (Battery Information) and
//! _BST (Battery Status) method modeling, health degradation tracking, and power profiling.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use crate::drivers::i2c_smbus::SmbusController;

/// Smart Battery SMBus Standard Slave Address (SBS 1.1 Section 5.1)
pub const SBS_SMBUS_BATTERY_ADDR: u8 = 0x0B;
/// Smart Battery Charger Standard Slave Address
pub const SBS_SMBUS_CHARGER_ADDR: u8 = 0x09;
/// Smart Battery System Host Address
pub const SBS_SMBUS_HOST_ADDR: u8 = 0x10;

// Standard SBS 1.1 SMBus Command Codes
pub const SBS_CMD_MANUFACTURER_ACCESS: u8 = 0x00;
pub const SBS_CMD_REMAINING_CAPACITY_ALARM: u8 = 0x01;
pub const SBS_CMD_REMAINING_TIME_ALARM: u8 = 0x02;
pub const SBS_CMD_BATTERY_MODE: u8 = 0x03;
pub const SBS_CMD_AT_RATE: u8 = 0x04;
pub const SBS_CMD_AT_RATE_TIME_TO_FULL: u8 = 0x05;
pub const SBS_CMD_AT_RATE_TIME_TO_EMPTY: u8 = 0x06;
pub const SBS_CMD_AT_RATE_OK: u8 = 0x07;
pub const SBS_CMD_TEMPERATURE: u8 = 0x08;
pub const SBS_CMD_VOLTAGE: u8 = 0x09;
pub const SBS_CMD_CURRENT: u8 = 0x0A;
pub const SBS_CMD_AVERAGE_CURRENT: u8 = 0x0B;
pub const SBS_CMD_MAX_ERROR: u8 = 0x0C;
pub const SBS_CMD_RELATIVE_STATE_OF_CHARGE: u8 = 0x0D;
pub const SBS_CMD_ABSOLUTE_STATE_OF_CHARGE: u8 = 0x0E;
pub const SBS_CMD_REMAINING_CAPACITY: u8 = 0x0F;
pub const SBS_CMD_FULL_CHARGE_CAPACITY: u8 = 0x10;
pub const SBS_CMD_RUN_TIME_TO_EMPTY: u8 = 0x11;
pub const SBS_CMD_AVERAGE_TIME_TO_EMPTY: u8 = 0x12;
pub const SBS_CMD_AVERAGE_TIME_TO_FULL: u8 = 0x13;
pub const SBS_CMD_CHARGING_CURRENT: u8 = 0x14;
pub const SBS_CMD_CHARGING_VOLTAGE: u8 = 0x15;
pub const SBS_CMD_BATTERY_STATUS: u8 = 0x16;
pub const SBS_CMD_CYCLE_COUNT: u8 = 0x17;
pub const SBS_CMD_DESIGN_CAPACITY: u8 = 0x18;
pub const SBS_CMD_DESIGN_VOLTAGE: u8 = 0x19;
pub const SBS_CMD_SPECIFICATION_INFO: u8 = 0x1A;
pub const SBS_CMD_MANUFACTURE_DATE: u8 = 0x1B;
pub const SBS_CMD_SERIAL_NUMBER: u8 = 0x1C;
pub const SBS_CMD_MANUFACTURER_NAME: u8 = 0x20;
pub const SBS_CMD_DEVICE_NAME: u8 = 0x21;
pub const SBS_CMD_DEVICE_CHEMISTRY: u8 = 0x22;
pub const SBS_CMD_MANUFACTURER_DATA: u8 = 0x23;

// SBS Battery Status Bitmasks (Word register 0x16)
pub const SBS_STATUS_OVER_CHARGED_ALARM: u16 = 1 << 15;
pub const SBS_STATUS_TERMINATE_CHARGE_ALARM: u16 = 1 << 14;
pub const SBS_STATUS_OVER_TEMP_ALARM: u16 = 1 << 12;
pub const SBS_STATUS_TERMINATE_DISCHARGE_ALARM: u16 = 1 << 11;
pub const SBS_STATUS_REMAINING_CAPACITY_ALARM: u16 = 1 << 9;
pub const SBS_STATUS_REMAINING_TIME_ALARM: u16 = 1 << 8;
pub const SBS_STATUS_INITIALIZED: u16 = 1 << 7;
pub const SBS_STATUS_DISCHARGING: u16 = 1 << 6;
pub const SBS_STATUS_FULLY_CHARGED: u16 = 1 << 5;
pub const SBS_STATUS_FULLY_DISCHARGED: u16 = 1 << 4;

// ACPI _BST State Bitmasks (ACPI 6.4 Table 10-6)
pub const ACPI_BST_DISCHARGING: u32 = 1 << 0;
pub const ACPI_BST_CHARGING: u32 = 1 << 1;
pub const ACPI_BST_CRITICAL: u32 = 1 << 2;

/// Power Units used in ACPI _BIF
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PowerUnits {
    CapacityInMWh = 0,
    CapacityInMAh = 1,
}

/// Battery Technology
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BatteryTechnology {
    Primary = 0,
    SecondaryRechargeable = 1,
}

/// ACPI _BIF (Battery Information) Package representation
#[derive(Clone, Debug)]
pub struct AcpiBif {
    /// 0: mWh, 1: mAh
    pub power_unit: PowerUnits,
    /// Nominal capacity of a new battery in mWh or mAh
    pub design_capacity: u32,
    /// Predicted battery capacity when fully charged in mWh or mAh
    pub last_full_charge_capacity: u32,
    /// 0: Primary (non-rechargeable), 1: Secondary (rechargeable)
    pub battery_technology: BatteryTechnology,
    /// Nominal design voltage in mV
    pub design_voltage: u32,
    /// OEM-designed capacity warning threshold in mWh/mAh
    pub design_capacity_warning: u32,
    /// OEM-designed capacity low threshold in mWh/mAh
    pub design_capacity_low: u32,
    /// Granularity between low and warning in mWh/mAh
    pub capacity_granularity_1: u32,
    /// Granularity between warning and full in mWh/mAh
    pub capacity_granularity_2: u32,
    /// Model number / device name
    pub model_number: String,
    /// Serial number string
    pub serial_number: String,
    /// Battery Chemistry (e.g., "LION", "NiMH", "LiP")
    pub battery_type: String,
    /// OEM Manufacturer name
    pub oem_info: String,
}

/// ACPI _BST (Battery Status) Package representation
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AcpiBst {
    /// Bit 0: Discharging, Bit 1: Charging, Bit 2: Critical
    pub battery_state: u32,
    /// Present rate of power flow in mW or mA (0 = offline/not charging)
    pub present_rate: u32,
    /// Remaining capacity in mWh or mAh
    pub remaining_capacity: u32,
    /// Present battery voltage in mV
    pub present_voltage: u32,
}

/// Battery degradation and health assessment
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BatteryHealth {
    /// Wear level percentage (0% to 100%, where 0% is pristine)
    pub wear_percentage: f32,
    /// Current capacity ratio relative to original design capacity
    pub health_percentage: f32,
    /// Estimated time to full charge or discharge in minutes
    pub estimated_minutes_remaining: u32,
    /// Discharge or Charge rate in Watts (calculated)
    pub power_rate_watts: f32,
    /// Battery temperature in Celsius
    pub temperature_celsius: f32,
    /// Number of completed full discharge/charge cycles
    pub cycle_count: u16,
}

/// Smart Battery System Controller
pub struct SmartBatteryManager {
    pub is_present: bool,
    pub bif: AcpiBif,
    pub bst: AcpiBst,
    pub cycle_count: u16,
    pub temperature_kelvin_tenths: u16,
    pub ac_connected: bool,
}

impl SmartBatteryManager {
    /// Creates a default initialized Smart Battery Manager
    pub fn new() -> Self {
        Self {
            is_present: true,
            bif: AcpiBif {
                power_unit: PowerUnits::CapacityInMWh,
                design_capacity: 56000,          // 56.0 Wh
                last_full_charge_capacity: 52000,// 52.0 Wh
                battery_technology: BatteryTechnology::SecondaryRechargeable,
                design_voltage: 11400,           // 11.4 V
                design_capacity_warning: 5200,   // 10%
                design_capacity_low: 2600,       // 5%
                capacity_granularity_1: 100,
                capacity_granularity_2: 100,
                model_number: String::from("CorOS-BAT-01"),
                serial_number: String::from("COR-9874102"),
                battery_type: String::from("LION"),
                oem_info: String::from("CorOS Hardware Labs"),
            },
            bst: AcpiBst {
                battery_state: 0,                // AC connected / Idle
                present_rate: 0,
                remaining_capacity: 48000,
                present_voltage: 12200,          // 12.2 V
            },
            cycle_count: 42,
            temperature_kelvin_tenths: 2981,     // 25.0 C (273.15 + 25.0) * 10
            ac_connected: true,
        }
    }

    /// Read raw SMBus registers from a real hardware SMBus controller if detected
    pub fn probe_smbus(&mut self, smbus: &mut SmbusController) -> bool {
        // Probe battery device presence
        if smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_BATTERY_STATUS).is_err() {
            self.is_present = false;
            return false;
        }

        self.is_present = true;

        // Read Voltage
        if let Ok(voltage_mv) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_VOLTAGE) {
            self.bst.present_voltage = voltage_mv as u32;
        }

        // Read Temperature (0.1K)
        if let Ok(temp_tenths) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_TEMPERATURE) {
            self.temperature_kelvin_tenths = temp_tenths;
        }

        // Read Remaining Capacity
        if let Ok(rem_cap) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_REMAINING_CAPACITY) {
            self.bst.remaining_capacity = rem_cap as u32;
        }

        // Read Full Charge Capacity
        if let Ok(full_cap) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_FULL_CHARGE_CAPACITY) {
            self.bif.last_full_charge_capacity = full_cap as u32;
        }

        // Read Cycle Count
        if let Ok(cycles) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_CYCLE_COUNT) {
            self.cycle_count = cycles;
        }

        // Read Current (signed i16: positive = charging, negative = discharging)
        if let Ok(cur_raw) = smbus.read_word_data(SBS_SMBUS_BATTERY_ADDR, SBS_CMD_CURRENT) {
            let cur_signed = cur_raw as i16;
            if cur_signed < 0 {
                self.bst.battery_state = ACPI_BST_DISCHARGING;
                self.bst.present_rate = cur_signed.unsigned_abs() as u32;
                self.ac_connected = false;
            } else if cur_signed > 0 {
                self.bst.battery_state = ACPI_BST_CHARGING;
                self.bst.present_rate = cur_signed as u32;
                self.ac_connected = true;
            } else {
                self.bst.battery_state = 0;
                self.bst.present_rate = 0;
            }
        }

        true
    }

    /// Calculate detailed health, wear, remaining runtime, and power metrics
    pub fn compute_health(&self) -> BatteryHealth {
        let health_pct = if self.bif.design_capacity > 0 {
            (self.bif.last_full_charge_capacity as f32 / self.bif.design_capacity as f32) * 100.0
        } else {
            100.0
        };

        let wear_pct = (100.0 - health_pct).max(0.0);

        // Power in Watts = (Rate mA/mW * Voltage mV) / 1,000,000
        let power_w = (self.bst.present_rate as f32 * self.bst.present_voltage as f32) / 1_000_000.0;

        // Estimated minutes remaining
        let minutes_rem = if self.bst.present_rate > 0 {
            if (self.bst.battery_state & ACPI_BST_DISCHARGING) != 0 {
                (self.bst.remaining_capacity * 60) / self.bst.present_rate
            } else if (self.bst.battery_state & ACPI_BST_CHARGING) != 0 {
                let missing = self.bif.last_full_charge_capacity.saturating_sub(self.bst.remaining_capacity);
                (missing * 60) / self.bst.present_rate
            } else {
                0
            }
        } else {
            0
        };

        let temp_c = (self.temperature_kelvin_tenths as f32 - 2731.5) / 10.0;

        BatteryHealth {
            wear_percentage: wear_pct,
            health_percentage: health_pct,
            estimated_minutes_remaining: minutes_rem,
            power_rate_watts: power_w,
            temperature_celsius: temp_c,
            cycle_count: self.cycle_count,
        }
    }

    /// Percentage of charge currently remaining (0% to 100%)
    pub fn percentage(&self) -> u32 {
        if self.bif.last_full_charge_capacity > 0 {
            let pct = (self.bst.remaining_capacity * 100) / self.bif.last_full_charge_capacity;
            pct.min(100)
        } else {
            100
        }
    }

    /// Returns true if battery is discharging and below critical threshold
    pub fn is_critical(&self) -> bool {
        (self.bst.battery_state & ACPI_BST_CRITICAL) != 0 || self.bst.remaining_capacity <= self.bif.design_capacity_low
    }

    /// Returns true if system is plugged into AC power
    pub fn is_on_ac_power(&self) -> bool {
        self.ac_connected || (self.bst.battery_state & ACPI_BST_CHARGING) != 0
    }
}
