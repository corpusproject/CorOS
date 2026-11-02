//! CorOS Userland Coreutil: `sysctl`
//! Hierarchical `/proc/sys` kernel parameter store supporting:
//! - Standard keys (`kernel.hostname`, `kernel.osrelease`, `vm.swappiness`, `net.ipv4.ip_forward`, `net.core.somaxconn`)
//! - `-a` dump all parameters
//! - `-n` print values only without key names
//! - `-w key=value` runtime parameter mutation (with read-only enforcement)

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SysctlEntry {
    pub key: &'static str,
    pub value: String,
    pub writable: bool,
}

#[derive(Clone, Debug)]
pub struct SysctlStore {
    entries: Vec<SysctlEntry>,
}

impl SysctlStore {
    pub fn with_coros_defaults() -> Self {
        let mut entries = Vec::with_capacity(8);
        entries.push(SysctlEntry {
            key: "kernel.hostname",
            value: String::from("coros-workstation"),
            writable: true,
        });
        entries.push(SysctlEntry {
            key: "kernel.osrelease",
            value: String::from("7.5.0-uefi"),
            writable: false,
        });
        entries.push(SysctlEntry {
            key: "kernel.ostype",
            value: String::from("CorOS"),
            writable: false,
        });
        entries.push(SysctlEntry {
            key: "kernel.pid_max",
            value: String::from("65536"),
            writable: true,
        });
        entries.push(SysctlEntry {
            key: "vm.swappiness",
            value: String::from("10"),
            writable: true,
        });
        entries.push(SysctlEntry {
            key: "vm.overcommit_memory",
            value: String::from("0"),
            writable: true,
        });
        entries.push(SysctlEntry {
            key: "net.ipv4.ip_forward",
            value: String::from("0"),
            writable: true,
        });
        entries.push(SysctlEntry {
            key: "net.core.somaxconn",
            value: String::from("4096"),
            writable: true,
        });
        Self { entries }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_str())
    }

    pub fn set(&mut self, key: &str, new_val: &str) -> Result<String, &'static str> {
        for e in self.entries.iter_mut() {
            if e.key == key {
                if !e.writable {
                    return Err("sysctl: permission denied on read-only kernel parameter");
                }
                e.value = String::from(new_val.trim());
                return Ok(format!("{} = {}\n", e.key, e.value));
            }
        }
        Err("sysctl: cannot stat /proc/sys parameter: No such file or directory")
    }

    pub fn dump_all(&self, values_only: bool) -> String {
        let mut out = String::new();
        for e in &self.entries {
            if values_only {
                out.push_str(&e.value);
                out.push('\n');
            } else {
                out.push_str(&format!("{} = {}\n", e.key, e.value));
            }
        }
        out
    }
}

/// Executes `sysctl` CLI arguments (`-a`, `-n`, `-w key=val`, or specific key lookups) against `store`.
pub fn execute_sysctl_command(store: &mut SysctlStore, args: &[&str]) -> Result<String, &'static str> {
    let mut dump_all = false;
    let mut values_only = false;
    let mut write_mode = false;
    let mut targets: Vec<&str> = Vec::new();

    for arg in args {
        if let Some(rest) = arg.strip_prefix('-') {
            for ch in rest.chars() {
                match ch {
                    'a' => dump_all = true,
                    'n' => values_only = true,
                    'w' => write_mode = true,
                    _ => {}
                }
            }
        } else {
            targets.push(*arg);
        }
    }

    if dump_all {
        return Ok(store.dump_all(values_only));
    }

    let mut out = String::new();
    for t in targets {
        if write_mode || t.contains('=') {
            let (k, v) = t.split_once('=').ok_or("sysctl: invalid key=value assignment")?;
            let line = store.set(k.trim(), v.trim())?;
            if values_only {
                out.push_str(v.trim());
                out.push('\n');
            } else {
                out.push_str(&line);
            }
        } else {
            let val = store
                .get(t.trim())
                .ok_or("sysctl: unknown kernel parameter key")?;
            if values_only {
                out.push_str(val);
                out.push('\n');
            } else {
                out.push_str(&format!("{} = {}\n", t.trim(), val));
            }
        }
    }

    Ok(out)
}

pub fn verify_util_sysctl() -> u32 {
    let mut passed = 0u32;

    let mut store = SysctlStore::with_coros_defaults();

    // Read single parameter
    if execute_sysctl_command(&mut store, &["kernel.hostname"]).as_deref()
        == Ok("kernel.hostname = coros-workstation\n")
    {
        passed += 1;
    }

    // Write mutable parameter (`-w net.ipv4.ip_forward=1`)
    if execute_sysctl_command(&mut store, &["-w", "net.ipv4.ip_forward=1"]).is_ok()
        && store.get("net.ipv4.ip_forward") == Some("1")
    {
        passed += 1;
    }

    // Reject writing to read-only `kernel.osrelease`
    if execute_sysctl_command(&mut store, &["-w", "kernel.osrelease=8.0"]).is_err() {
        passed += 1;
    }

    // Dump all (`-a`)
    if let Ok(all) = execute_sysctl_command(&mut store, &["-a"]) {
        if all.contains("vm.swappiness = 10") && all.contains("net.core.somaxconn = 4096") {
            passed += 1;
        }
    }

    passed
}
