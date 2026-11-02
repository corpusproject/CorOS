//! CorOS POSIX Environment Subsystem
//!
//! Provides global and process-level environment variables (getenv, setenv, unsetenv),
//! standard UNIX PATH resolution, and export functionality.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::SpinLock;

pub struct EnvironmentManager {
    vars: BTreeMap<String, String>,
}

impl EnvironmentManager {
    pub const fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
        }
    }

    /// Initialize default Linux system environment
    pub fn init_defaults(&mut self) {
        self.vars.insert(String::from("USER"), String::from("coros"));
        self.vars.insert(String::from("HOME"), String::from("/home/coros"));
        self.vars.insert(String::from("SHELL"), String::from("/bin/coros-sh"));
        self.vars.insert(String::from("PATH"), String::from("/bin:/usr/bin:/sbin:/coros/system"));
        self.vars.insert(String::from("TERM"), String::from("xterm-256color"));
        self.vars.insert(String::from("LANG"), String::from("en_US.UTF-8"));
        self.vars.insert(String::from("HOSTNAME"), String::from("silicon-coros"));
        self.vars.insert(String::from("KERNEL"), String::from("x86_64-coros-6.10-compat"));
        self.vars.insert(String::from("DISPLAY"), String::from(":0.0"));
        self.vars.insert(String::from("VFS_ROOT"), String::from("C:\\EFI\\COROS"));
    }

    /// Get value of environment variable
    pub fn get(&self, key: &str) -> Option<&String> {
        self.vars.get(key)
    }

    /// Set environment variable (setenv / export)
    pub fn set(&mut self, key: &str, value: &str) {
        self.vars.insert(String::from(key), String::from(value));
    }

    /// Remove environment variable (unset)
    pub fn unset(&mut self, key: &str) -> bool {
        self.vars.remove(key).is_some()
    }

    /// Format all environment variables as KEY=VALUE lines
    pub fn print_all(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.vars {
            out.push_str(&format!("{}={}\n", k, v));
        }
        out
    }
}

pub static ENV_MANAGER: SpinLock<EnvironmentManager> = SpinLock::new(EnvironmentManager::new());
