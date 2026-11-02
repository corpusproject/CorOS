//! CorOS Userland Coreutil: `uname`
//! POSIX `utsname` system identification utility supporting `-a` (all), `-s` (sysname),
//! `-n` (nodename), `-r` (release), `-v` (version), `-m` (machine), `-p` (processor), and `-o` (operating system).

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnameFlags {
    pub sysname: bool,
    pub nodename: bool,
    pub release: bool,
    pub version: bool,
    pub machine: bool,
    pub processor: bool,
    pub operating_system: bool,
}

impl UnameFlags {
    pub const fn default_sysname_only() -> Self {
        Self {
            sysname: true,
            nodename: false,
            release: false,
            version: false,
            machine: false,
            processor: false,
            operating_system: false,
        }
    }

    pub const fn all_fields() -> Self {
        Self {
            sysname: true,
            nodename: true,
            release: true,
            version: true,
            machine: true,
            processor: false, // GNU/Linux uname -a omits duplicate unknown/x86_64 processor token when matching CorOS format
            operating_system: true,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self {
            sysname: false,
            nodename: false,
            release: false,
            version: false,
            machine: false,
            processor: false,
            operating_system: false,
        };
        let mut any_set = false;

        for arg in args {
            if *arg == "--all" {
                return Self::all_fields();
            }
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'a' => return Self::all_fields(),
                        's' => {
                            flags.sysname = true;
                            any_set = true;
                        }
                        'n' => {
                            flags.nodename = true;
                            any_set = true;
                        }
                        'r' => {
                            flags.release = true;
                            any_set = true;
                        }
                        'v' => {
                            flags.version = true;
                            any_set = true;
                        }
                        'm' => {
                            flags.machine = true;
                            any_set = true;
                        }
                        'p' => {
                            flags.processor = true;
                            any_set = true;
                        }
                        'o' => {
                            flags.operating_system = true;
                            any_set = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        if !any_set {
            Self::default_sysname_only()
        } else {
            flags
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UtsnameRecord {
    pub sysname: &'static str,
    pub nodename: &'static str,
    pub release: &'static str,
    pub version: &'static str,
    pub machine: &'static str,
    pub processor: &'static str,
    pub operating_system: &'static str,
}

pub const COROS_UTSNAME: UtsnameRecord = UtsnameRecord {
    sysname: "CorOS",
    nodename: "coros-workstation",
    release: "7.5.0-uefi",
    version: "#1 SMP PREEMPT_DYNAMIC",
    machine: "x86_64",
    processor: "x86_64",
    operating_system: "CorOS",
};

/// Formats the selected `UtsnameRecord` fields according to `UnameFlags`.
pub fn format_uname(uts: &UtsnameRecord, flags: UnameFlags) -> String {
    let mut fields: Vec<&str> = Vec::new();
    if flags.sysname {
        fields.push(uts.sysname);
    }
    if flags.nodename {
        fields.push(uts.nodename);
    }
    if flags.release {
        fields.push(uts.release);
    }
    if flags.version {
        fields.push(uts.version);
    }
    if flags.machine {
        fields.push(uts.machine);
    }
    if flags.processor {
        fields.push(uts.processor);
    }
    if flags.operating_system {
        fields.push(uts.operating_system);
    }
    fields.join(" ")
}

/// Convenience entry point executing `uname` against `COROS_UTSNAME`.
pub fn execute_uname(args: &[&str]) -> String {
    let flags = UnameFlags::parse_args(args);
    format_uname(&COROS_UTSNAME, flags)
}

pub fn verify_util_uname() -> u32 {
    let mut passed = 0u32;

    if execute_uname(&[]) == "CorOS" {
        passed += 1;
    }

    if execute_uname(&["-a"]) == "CorOS coros-workstation 7.5.0-uefi #1 SMP PREEMPT_DYNAMIC x86_64 CorOS" {
        passed += 1;
    }

    if execute_uname(&["-sr"]) == "CorOS 7.5.0-uefi" && execute_uname(&["-m"]) == "x86_64" {
        passed += 1;
    }

    passed
}
