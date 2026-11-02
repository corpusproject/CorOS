//! CorOS Userland Coreutil: `free`
//! Physical frame & kernel heap memory usage calculator supporting:
//! - `-b` (bytes), `-k` (kibibytes, default), `-m` (mebibytes), `-g` (gibibytes), `-h` (human-readable)
//! - `-t` (display a `Total:` summary row combining Mem + Swap)
//! - Full Linux `free` columns: `total`, `used`, `free`, `shared`, `buff/cache`, `available`

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryDisplayUnit {
    Bytes,
    KibiBytes,
    MebiBytes,
    GibiBytes,
    HumanReadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeFlags {
    pub unit: MemoryDisplayUnit,
    pub show_total_row: bool,
}

impl FreeFlags {
    pub const fn default_flags() -> Self {
        Self {
            unit: MemoryDisplayUnit::KibiBytes,
            show_total_row: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'b' => flags.unit = MemoryDisplayUnit::Bytes,
                        'k' => flags.unit = MemoryDisplayUnit::KibiBytes,
                        'm' => flags.unit = MemoryDisplayUnit::MebiBytes,
                        'g' => flags.unit = MemoryDisplayUnit::GibiBytes,
                        'h' => flags.unit = MemoryDisplayUnit::HumanReadable,
                        't' => flags.show_total_row = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SystemMemorySnapshot {
    pub total_kib: u64,
    pub free_kib: u64,
    pub shared_kib: u64,
    pub buffers_kib: u64,
    pub cached_kib: u64,
    pub reclaimable_slab_kib: u64,
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
}

impl SystemMemorySnapshot {
    pub const fn buff_cache_kib(&self) -> u64 {
        self.buffers_kib + self.cached_kib + self.reclaimable_slab_kib
    }

    /// Linux procps `used` calculation: `total - free - buff_cache`.
    pub const fn used_kib(&self) -> u64 {
        self.total_kib
            .saturating_sub(self.free_kib)
            .saturating_sub(self.buff_cache_kib())
    }

    /// Available memory before swapping is required (`free + reclaimable_buff_cache - watermark`).
    pub const fn available_kib(&self) -> u64 {
        let reclaimable = (self.buff_cache_kib() * 3) / 4;
        self.free_kib.saturating_add(reclaimable)
    }

    pub const fn swap_used_kib(&self) -> u64 {
        self.swap_total_kib.saturating_sub(self.swap_free_kib)
    }
}

fn format_kib_in_unit(kib: u64, unit: MemoryDisplayUnit) -> String {
    match unit {
        MemoryDisplayUnit::Bytes => format!("{}", kib * 1024),
        MemoryDisplayUnit::KibiBytes => format!("{}", kib),
        MemoryDisplayUnit::MebiBytes => format!("{}", kib / 1024),
        MemoryDisplayUnit::GibiBytes => format!("{}", kib / (1024 * 1024)),
        MemoryDisplayUnit::HumanReadable => {
            if kib >= 1024 * 1024 {
                let gib_tenths = (kib * 10) / (1024 * 1024);
                format!("{}.{}Gi", gib_tenths / 10, gib_tenths % 10)
            } else if kib >= 1024 {
                let mib_tenths = (kib * 10) / 1024;
                format!("{}.{}Mi", mib_tenths / 10, mib_tenths % 10)
            } else {
                format!("{}Ki", kib)
            }
        }
    }
}

/// Renders the `free` memory table for the provided `SystemMemorySnapshot` and `FreeFlags`.
pub fn format_free_report(snap: &SystemMemorySnapshot, flags: FreeFlags) -> String {
    let mut out = String::new();
    out.push_str("               total        used        free      shared  buff/cache   available\n");

    let u = flags.unit;
    out.push_str(&format!(
        "Mem:    {:>12} {:>11} {:>11} {:>11} {:>11} {:>11}\n",
        format_kib_in_unit(snap.total_kib, u),
        format_kib_in_unit(snap.used_kib(), u),
        format_kib_in_unit(snap.free_kib, u),
        format_kib_in_unit(snap.shared_kib, u),
        format_kib_in_unit(snap.buff_cache_kib(), u),
        format_kib_in_unit(snap.available_kib(), u),
    ));

    out.push_str(&format!(
        "Swap:   {:>12} {:>11} {:>11}\n",
        format_kib_in_unit(snap.swap_total_kib, u),
        format_kib_in_unit(snap.swap_used_kib(), u),
        format_kib_in_unit(snap.swap_free_kib, u),
    ));

    if flags.show_total_row {
        let tot_all = snap.total_kib + snap.swap_total_kib;
        let used_all = snap.used_kib() + snap.swap_used_kib();
        let free_all = snap.free_kib + snap.swap_free_kib;
        out.push_str(&format!(
            "Total:  {:>12} {:>11} {:>11}\n",
            format_kib_in_unit(tot_all, u),
            format_kib_in_unit(used_all, u),
            format_kib_in_unit(free_all, u),
        ));
    }

    out
}

pub fn verify_util_free() -> u32 {
    let mut passed = 0u32;

    let snap = SystemMemorySnapshot {
        total_kib: 4 * 1024 * 1024, // 4 GiB
        free_kib: 2 * 1024 * 1024,  // 2 GiB
        shared_kib: 16 * 1024,
        buffers_kib: 64 * 1024,
        cached_kib: 320 * 1024,
        reclaimable_slab_kib: 128 * 1024, // buff/cache = 512 MiB
        swap_total_kib: 1024 * 1024,      // 1 GiB
        swap_free_kib: 1024 * 1024,
    };

    if snap.buff_cache_kib() == 512 * 1024 && snap.used_kib() == 1536 * 1024 {
        passed += 1;
    }

    let mib_report = format_free_report(&snap, FreeFlags::parse_args(&["-mt"]));
    if mib_report.contains("Mem:") && mib_report.contains("4096") && mib_report.contains("1536") && mib_report.contains("Total:") {
        passed += 1;
    }

    let human_report = format_free_report(&snap, FreeFlags::parse_args(&["-h"]));
    if human_report.contains("4.0Gi") && human_report.contains("1.5Gi") && human_report.contains("512.0Mi") {
        passed += 1;
    }

    passed
}
