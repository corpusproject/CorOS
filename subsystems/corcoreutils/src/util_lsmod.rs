//! CorOS Userland Coreutil: `lsmod`
//! Kernel module table formatter (`Module`, `Size`, `Used by`, dependency chain)
//! and `/proc/modules` generator showing live kernel load address and state (`Live`, `Loading`, `Unloading`).

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmodState {
    Live,
    Loading,
    Unloading,
}

impl KmodState {
    pub const fn as_str(self) -> &'static str {
        match self {
            KmodState::Live => "Live",
            KmodState::Loading => "Loading",
            KmodState::Unloading => "Unloading",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoadedKmodEntry {
    pub name: &'static str,
    pub size_bytes: u32,
    pub ref_count: u32,
    pub dependents: &'static [&'static str],
    pub state: KmodState,
    pub base_addr: u64,
}

/// Formats the standard `lsmod` table (`Module`, `Size`, `Used by` with comma-separated dependent modules).
pub fn format_lsmod_table(modules: &[LoadedKmodEntry]) -> String {
    let mut out = String::from("Module                  Size  Used by\n");
    for m in modules {
        if m.dependents.is_empty() {
            out.push_str(&format!("{:<23} {:>4}  {}\n", m.name, m.size_bytes, m.ref_count));
        } else {
            let deps = m.dependents.join(",");
            out.push_str(&format!(
                "{:<23} {:>4}  {} {}\n",
                m.name, m.size_bytes, m.ref_count, deps
            ));
        }
    }
    out
}

/// Formats `/proc/modules` output (`<name> <size> <refcnt> <deps> <state> 0x<base_addr>`).
pub fn format_proc_modules(modules: &[LoadedKmodEntry]) -> String {
    let mut out = String::new();
    for m in modules {
        let deps = if m.dependents.is_empty() {
            String::from("-")
        } else {
            let mut s = m.dependents.join(",");
            s.push(',');
            s
        };
        out.push_str(&format!(
            "{} {} {} {} {} 0x{:016x}\n",
            m.name,
            m.size_bytes,
            m.ref_count,
            deps,
            m.state.as_str(),
            m.base_addr
        ));
    }
    out
}

pub fn verify_util_lsmod() -> u32 {
    let mut passed = 0u32;

    static STORAGE_DEPS: [&str; 2] = ["ahci_sata", "fat32_vfs"];
    static EMPTY_DEPS: [&str; 0] = [];

    let mods = [
        LoadedKmodEntry {
            name: "cor_block_core",
            size_bytes: 32768,
            ref_count: 2,
            dependents: &STORAGE_DEPS,
            state: KmodState::Live,
            base_addr: 0xFFFF_8000_0010_0000,
        },
        LoadedKmodEntry {
            name: "e1000_eth",
            size_bytes: 49152,
            ref_count: 0,
            dependents: &EMPTY_DEPS,
            state: KmodState::Live,
            base_addr: 0xFFFF_8000_0012_0000,
        },
    ];

    let lsmod_str = format_lsmod_table(&mods);
    if lsmod_str.contains("Module                  Size  Used by\n")
        && lsmod_str.contains("2 ahci_sata,fat32_vfs")
        && lsmod_str.contains("e1000_eth")
    {
        passed += 1;
    }

    let proc_str = format_proc_modules(&mods);
    if proc_str.contains("cor_block_core 32768 2 ahci_sata,fat32_vfs, Live 0xffff800000100000")
        && proc_str.contains("e1000_eth 49152 0 - Live 0xffff800000120000")
    {
        passed += 1;
    }

    passed
}
