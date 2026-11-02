//! CorOS Userland Coreutil: `dmesg`
//! Kernel ring buffer log filter & formatter supporting:
//! - `-l <levels>` comma-separated syslog severity filter (`emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug`)
//! - `-T` human-readable `[HH:MM:SS.mmm]` timestamps vs monotonic `[    0.012345]` seconds
//! - `-C` clear ring buffer action
//! - `-x` decode facility & level prefix (`kern  :info  : `)

use alloc::format;
use alloc::string::String;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KlogSeverity {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Err = 3,
    Warn = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl KlogSeverity {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim() {
            "emerg" | "panic" => Some(Self::Emerg),
            "alert" => Some(Self::Alert),
            "crit" => Some(Self::Crit),
            "err" | "error" => Some(Self::Err),
            "warn" | "warning" => Some(Self::Warn),
            "notice" => Some(Self::Notice),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Emerg => "emerg ",
            Self::Alert => "alert ",
            Self::Crit => "crit  ",
            Self::Err => "err   ",
            Self::Warn => "warn  ",
            Self::Notice => "notice",
            Self::Info => "info  ",
            Self::Debug => "debug ",
        }
    }

    pub const fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmesgFlags {
    pub level_mask: u8,
    pub human_time: bool,
    pub clear_ring: bool,
    pub decode_prefix: bool,
}

impl DmesgFlags {
    pub const fn default_flags() -> Self {
        Self {
            level_mask: 0xFF, // all 8 levels enabled
            human_time: false,
            clear_ring: false,
            decode_prefix: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        let mut idx = 0;
        while idx < args.len() {
            let arg = args[idx];
            if (arg == "-l" || arg == "--level") && idx + 1 < args.len() {
                let mut mask = 0u8;
                for tok in args[idx + 1].split(',') {
                    if let Some(sev) = KlogSeverity::from_name(tok) {
                        mask |= sev.bit();
                    }
                }
                if mask != 0 {
                    flags.level_mask = mask;
                }
                idx += 2;
            } else if let Some(rest) = arg.strip_prefix("-l") {
                let mut mask = 0u8;
                for tok in rest.split(',') {
                    if let Some(sev) = KlogSeverity::from_name(tok) {
                        mask |= sev.bit();
                    }
                }
                if mask != 0 {
                    flags.level_mask = mask;
                }
                idx += 1;
            } else if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'T' => flags.human_time = true,
                        'C' => flags.clear_ring = true,
                        'x' => flags.decode_prefix = true,
                        _ => {}
                    }
                }
                idx += 1;
            } else {
                idx += 1;
            }
        }
        flags
    }
}

#[derive(Clone, Debug)]
pub struct KernelLogRecord {
    pub timestamp_us: u64,
    pub severity: KlogSeverity,
    pub subsystem: &'static str,
    pub message: &'static str,
}

/// Filters and formats kernel ring buffer records according to `DmesgFlags`.
pub fn format_dmesg_buffer(records: &mut &[KernelLogRecord], flags: DmesgFlags) -> String {
    if flags.clear_ring {
        *records = &[];
        return String::new();
    }

    let mut out = String::new();
    for rec in *records {
        if (flags.level_mask & rec.severity.bit()) == 0 {
            continue;
        }

        if flags.decode_prefix {
            out.push_str(&format!("kern  :{} : ", rec.severity.short_label()));
        }

        if flags.human_time {
            let total_secs = rec.timestamp_us / 1_000_000;
            let millis = (rec.timestamp_us % 1_000_000) / 1_000;
            let hrs = (total_secs / 3600) % 24;
            let mins = (total_secs / 60) % 60;
            let secs = total_secs % 60;
            out.push_str(&format!(
                "[{:02}:{:02}:{:02}.{:03}] {}: {}\n",
                hrs, mins, secs, millis, rec.subsystem, rec.message
            ));
        } else {
            let secs = rec.timestamp_us / 1_000_000;
            let micros = rec.timestamp_us % 1_000_000;
            out.push_str(&format!(
                "[{:>5}.{:06}] {}: {}\n",
                secs, micros, rec.subsystem, rec.message
            ));
        }
    }

    out
}

pub fn verify_util_dmesg() -> u32 {
    let mut passed = 0u32;

    let sample = [
        KernelLogRecord {
            timestamp_us: 12_450,
            severity: KlogSeverity::Info,
            subsystem: "smp",
            message: "Brought up 4 CPUs via ACPI MADT",
        },
        KernelLogRecord {
            timestamp_us: 85_000,
            severity: KlogSeverity::Warn,
            subsystem: "fat32",
            message: "Volume dirty bit set; running quick journal check",
        },
        KernelLogRecord {
            timestamp_us: 140_200,
            severity: KlogSeverity::Err,
            subsystem: "pcie",
            message: "AER corrected error received on root port 00:1c.0",
        },
    ];

    let mut view: &[KernelLogRecord] = &sample;
    let err_warn = format_dmesg_buffer(&mut view, DmesgFlags::parse_args(&["-l", "err,warn", "-x"]));
    if !err_warn.contains("Brought up 4 CPUs")
        && err_warn.contains("kern  :warn   : [    0.085000] fat32:")
        && err_warn.contains("kern  :err    : [    0.140200] pcie:")
    {
        passed += 1;
    }

    let human = format_dmesg_buffer(&mut view, DmesgFlags::parse_args(&["-T"]));
    if human.contains("[00:00:00.012] smp: Brought up 4 CPUs") {
        passed += 1;
    }

    let cleared = format_dmesg_buffer(&mut view, DmesgFlags::parse_args(&["-C"]));
    if cleared.is_empty() && view.is_empty() {
        passed += 1;
    }

    passed
}
