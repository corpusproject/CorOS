//! CorOS Advanced Configuration and Power Interface (ACPI) Subsystem
//!
//! Provides bare-metal ACPI table parsing, AML bytecode interpretation,
//! hardware sleep state transitions, FADT power registers, and thermal zone cooling:
//! - AML Bytecode Interpreter (`AmlInterpreter`, `AmlValue`, `AmlNamespaceNode`)
//! - ACPI Power States (`AcpiPowerManager`, `AcpiFadt`, S0-S5 sleep states)
//! - Thermal Zones (`ThermalZone`, `ActiveCoolingTrip`)

pub mod aml_parser;
pub mod power_states;
pub mod thermal;
pub mod smart_battery;
pub mod ec;
pub mod power_thermal_bridge;

pub use aml_parser::{AmlInterpreter, AmlValue, AmlNamespaceNode};
pub use power_states::{AcpiPowerManager, AcpiFadt, ACPI_SLEEP_S0, ACPI_SLEEP_S3, ACPI_SLEEP_S5};
pub use thermal::{ThermalZone, ActiveCoolingTrip, celsius_to_kelvin_tenths, kelvin_tenths_to_celsius};
pub use smart_battery::{SmartBatteryManager, AcpiBif, AcpiBst, BatteryHealth, PowerUnits, BatteryTechnology};
pub use ec::{EmbeddedController, EcEvent};
pub use power_thermal_bridge::{PowerThermalBridge, PowerThermalStats, GLOBAL_POWER_THERMAL_BRIDGE};
