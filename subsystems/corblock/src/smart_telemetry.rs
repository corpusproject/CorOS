//! `smart_telemetry.rs` — S.M.A.R.T. Health Telemetry & Predictive Failure Analysis for CorOS.
//! Covers ATA S.M.A.R.T. attributes, NVMe 1.4 health log parsing, wear tracking,
//! temperature surveillance, and heuristic failure warning engines.

use alloc::string::String;
use alloc::vec::Vec;

/// Overall drive health assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveHealthStatus {
    Healthy,
    Warning,
    Critical,
    PredictiveFailure,
}

/// Known critical ATA S.M.A.R.T. attribute IDs.
pub mod ata_attr_id {
    pub const REALLOCATED_SECTOR_COUNT: u8 = 0x05;
    pub const POWER_ON_HOURS: u8 = 0x09;
    pub const SPIN_RETRY_COUNT: u8 = 0x0A;
    pub const POWER_CYCLE_COUNT: u8 = 0x0C;
    pub const REPORTED_UNCORRECTABLE_ERRORS: u8 = 0xBB;
    pub const COMMAND_TIMEOUT: u8 = 0xBC;
    pub const AIRFLOW_TEMPERATURE: u8 = 0xBE;
    pub const TEMPERATURE_CELSIUS: u8 = 0xC2;
    pub const CURRENT_PENDING_SECTOR_COUNT: u8 = 0xC5;
    pub const OFFLINE_UNCORRECTABLE_SECTOR_COUNT: u8 = 0xC6;
    pub const SSD_LIFE_REMAINING: u8 = 0xE7;
}

/// An individual normalized ATA S.M.A.R.T. attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartAttribute {
    pub id: u8,
    pub name: &'static str,
    pub current_value: u8,
    pub worst_value: u8,
    pub threshold: u8,
    pub raw_value: u64,
    pub is_critical: bool,
}

impl SmartAttribute {
    pub fn new(
        id: u8,
        name: &'static str,
        current_value: u8,
        worst_value: u8,
        threshold: u8,
        raw_value: u64,
        is_critical: bool,
    ) -> Self {
        Self {
            id,
            name,
            current_value,
            worst_value,
            threshold,
            raw_value,
            is_critical,
        }
    }

    /// Evaluates if normalized current value has breached the manufacturer failure threshold.
    pub fn has_threshold_exceeded(&self) -> bool {
        self.threshold > 0 && self.current_value <= self.threshold
    }
}

/// NVMe 1.4 Health / SMART Information Log (512-byte standard payload).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvmeSmartLog {
    pub critical_warning: u8,
    pub composite_temperature_kelvin: u16,
    pub available_spare_percent: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_time_minutes: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_and_data_integrity_errors: u128,
    pub number_of_error_log_entries: u128,
    pub warning_composite_temp_time_minutes: u32,
    pub critical_composite_temp_time_minutes: u32,
}

impl NvmeSmartLog {
    pub const CRITICAL_WARN_SPARE_BELOW_THRESHOLD: u8 = 1 << 0;
    pub const CRITICAL_WARN_TEMPERATURE_EXCEEDED: u8 = 1 << 1;
    pub const CRITICAL_WARN_RELIABILITY_DEGRADED: u8 = 1 << 2;
    pub const CRITICAL_WARN_MEDIA_READ_ONLY: u8 = 1 << 3;
    pub const CRITICAL_WARN_VOLATILE_BACKUP_FAILED: u8 = 1 << 4;

    /// Parses an NVMe 512-byte raw log buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 512 {
            return None;
        }

        let critical_warning = buf[0];
        let composite_temperature_kelvin = u16::from_le_bytes([buf[1], buf[2]]);
        let available_spare_percent = buf[3];
        let available_spare_threshold = buf[4];
        let percentage_used = buf[5];

        let parse_u128 = |start: usize| -> u128 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&buf[start..start + 16]);
            u128::from_le_bytes(arr)
        };

        let data_units_read = parse_u128(32);
        let data_units_written = parse_u128(48);
        let host_read_commands = parse_u128(64);
        let host_write_commands = parse_u128(80);
        let controller_busy_time_minutes = parse_u128(96);
        let power_cycles = parse_u128(112);
        let power_on_hours = parse_u128(128);
        let unsafe_shutdowns = parse_u128(144);
        let media_and_data_integrity_errors = parse_u128(160);
        let number_of_error_log_entries = parse_u128(176);

        let warning_composite_temp_time_minutes = u32::from_le_bytes(buf[192..196].try_into().unwrap());
        let critical_composite_temp_time_minutes = u32::from_le_bytes(buf[196..200].try_into().unwrap());

        Some(Self {
            critical_warning,
            composite_temperature_kelvin,
            available_spare_percent,
            available_spare_threshold,
            percentage_used,
            data_units_read,
            data_units_written,
            host_read_commands,
            host_write_commands,
            controller_busy_time_minutes,
            power_cycles,
            power_on_hours,
            unsafe_shutdowns,
            media_and_data_integrity_errors,
            number_of_error_log_entries,
            warning_composite_temp_time_minutes,
            critical_composite_temp_time_minutes,
        })
    }

    /// Converts Kelvin temperature to Celsius.
    pub fn temperature_celsius(&self) -> i32 {
        (self.composite_temperature_kelvin as i32) - 273
    }
}

/// Actionable diagnostic report generated by the predictive failure analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReport {
    pub status: DriveHealthStatus,
    pub temperature_celsius: i32,
    pub wear_remaining_percent: u8,
    pub failing_reasons: Vec<String>,
    pub recommendation: &'static str,
}

/// Predictive Failure Heuristics Analyzer for storage media.
#[derive(Debug, Clone, Default)]
pub struct PredictiveFailureAnalyzer;

impl PredictiveFailureAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates ATA SMART attributes and returns a diagnostic health report.
    pub fn evaluate_ata_attributes(&self, attributes: &[SmartAttribute]) -> DiagnosticReport {
        let mut status = DriveHealthStatus::Healthy;
        let mut reasons = Vec::new();
        let mut temp_c = 35i32;
        let mut life_remaining = 100u8;

        for attr in attributes {
            if attr.id == ata_attr_id::TEMPERATURE_CELSIUS || attr.id == ata_attr_id::AIRFLOW_TEMPERATURE {
                temp_c = attr.raw_value as i32;
            }
            if attr.id == ata_attr_id::SSD_LIFE_REMAINING {
                life_remaining = attr.current_value;
            }

            // Check manufacturer threshold breaches
            if attr.has_threshold_exceeded() {
                reasons.push(String::from(attr.name));
                status = DriveHealthStatus::PredictiveFailure;
            }

            // Raw critical checks
            if attr.id == ata_attr_id::REALLOCATED_SECTOR_COUNT && attr.raw_value > 50 {
                reasons.push(String::from("Reallocated sector count high"));
                if status != DriveHealthStatus::PredictiveFailure {
                    status = DriveHealthStatus::Critical;
                }
            }
            if attr.id == ata_attr_id::CURRENT_PENDING_SECTOR_COUNT && attr.raw_value > 10 {
                reasons.push(String::from("Unstable pending sectors detected"));
                if status != DriveHealthStatus::PredictiveFailure {
                    status = DriveHealthStatus::Critical;
                }
            }
            if attr.id == ata_attr_id::REPORTED_UNCORRECTABLE_ERRORS && attr.raw_value > 0 {
                reasons.push(String::from("Uncorrectable read errors logged"));
                if status == DriveHealthStatus::Healthy {
                    status = DriveHealthStatus::Warning;
                }
            }
        }

        // Temperature warnings (>70C is dangerous)
        if temp_c > 70 {
            reasons.push(String::from("Thermal overheating limit reached"));
            if status == DriveHealthStatus::Healthy {
                status = DriveHealthStatus::Warning;
            }
        }

        let recommendation = match status {
            DriveHealthStatus::Healthy => "Drive operating normally within nominal endurance parameters.",
            DriveHealthStatus::Warning => "Monitor drive telemetry; plan preventative maintenance.",
            DriveHealthStatus::Critical => "Urgent: Back up data immediately; reallocated sector surge detected.",
            DriveHealthStatus::PredictiveFailure => "Fatal failure imminent: Replace drive and rebuild RAID array immediately.",
        };

        DiagnosticReport {
            status,
            temperature_celsius: temp_c,
            wear_remaining_percent: life_remaining,
            failing_reasons: reasons,
            recommendation,
        }
    }

    /// Evaluates NVMe health log telemetry and produces a diagnostic report.
    pub fn evaluate_nvme_health(&self, log: &NvmeSmartLog) -> DiagnosticReport {
        let mut status = DriveHealthStatus::Healthy;
        let mut reasons = Vec::new();
        let temp_c = log.temperature_celsius();
        let life_remaining = 100u8.saturating_sub(log.percentage_used);

        if (log.critical_warning & NvmeSmartLog::CRITICAL_WARN_SPARE_BELOW_THRESHOLD) != 0 {
            reasons.push(String::from("Available spare endurance below threshold"));
            status = DriveHealthStatus::PredictiveFailure;
        }
        if (log.critical_warning & NvmeSmartLog::CRITICAL_WARN_MEDIA_READ_ONLY) != 0 {
            reasons.push(String::from("Media placed in read-only write protection"));
            status = DriveHealthStatus::PredictiveFailure;
        }
        if (log.critical_warning & NvmeSmartLog::CRITICAL_WARN_RELIABILITY_DEGRADED) != 0 {
            reasons.push(String::from("NAND flash reliability degraded"));
            if status != DriveHealthStatus::PredictiveFailure {
                status = DriveHealthStatus::Critical;
            }
        }
        if (log.critical_warning & NvmeSmartLog::CRITICAL_WARN_TEMPERATURE_EXCEEDED) != 0 || temp_c > 75 {
            reasons.push(String::from("Controller composite temperature critical"));
            if status == DriveHealthStatus::Healthy {
                status = DriveHealthStatus::Warning;
            }
        }
        if log.media_and_data_integrity_errors > 0 {
            reasons.push(String::from("Media and data integrity errors logged"));
            if status == DriveHealthStatus::Healthy {
                status = DriveHealthStatus::Warning;
            }
        }

        let recommendation = match status {
            DriveHealthStatus::Healthy => "NVMe subsystem operating within normal endurance limits.",
            DriveHealthStatus::Warning => "Thermal or ECC warning: inspect airflow and thermal throttling.",
            DriveHealthStatus::Critical => "Severe NAND degradation: initiate data backup immediately.",
            DriveHealthStatus::PredictiveFailure => "Spare capacity depleted or device read-only: replace NVMe drive immediately.",
        };

        DiagnosticReport {
            status,
            temperature_celsius: temp_c,
            wear_remaining_percent: life_remaining,
            failing_reasons: reasons,
            recommendation,
        }
    }
}
