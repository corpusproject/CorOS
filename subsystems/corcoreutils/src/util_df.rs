//! CorOS Userland Coreutil: `df`
//! Filesystem disk usage calculator & table formatter supporting:
//! - `-h` human-readable binary capacities (`KiB`, `MiB`, `GiB`)
//! - `-i` inode utilization mode (`Inodes`, `IUsed`, `IFree`, `IUse%`)
//! - `-T` print filesystem type column
//! - Total/Used/Available/Percentage calculation & table formatting

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfFlags {
    pub human_readable: bool,
    pub show_inodes: bool,
    pub print_type: bool,
}

impl DfFlags {
    pub const fn default_flags() -> Self {
        Self {
            human_readable: false,
            show_inodes: false,
            print_type: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'h' | 'H' => flags.human_readable = true,
                        'i' => flags.show_inodes = true,
                        'T' => flags.print_type = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Debug)]
pub struct FilesystemStat {
    pub device: &'static str,
    pub fs_type: &'static str,
    pub mount_point: &'static str,
    pub total_kib: u64,
    pub used_kib: u64,
    pub total_inodes: u64,
    pub used_inodes: u64,
}

impl FilesystemStat {
    pub const fn avail_kib(&self) -> u64 {
        self.total_kib.saturating_sub(self.used_kib)
    }

    pub const fn free_inodes(&self) -> u64 {
        self.total_inodes.saturating_sub(self.used_inodes)
    }

    /// Computes ceiling usage percentage `0..=100` matching POSIX `df`.
    pub const fn block_use_percent(&self) -> u64 {
        if self.total_kib == 0 {
            0
        } else {
            ((self.used_kib * 100) + (self.total_kib - 1)) / self.total_kib
        }
    }

    pub const fn inode_use_percent(&self) -> u64 {
        if self.total_inodes == 0 {
            0
        } else {
            ((self.used_inodes * 100) + (self.total_inodes - 1)) / self.total_inodes
        }
    }
}

fn format_kib_human(kib: u64) -> String {
    if kib >= 1024 * 1024 {
        let gib_tenths = (kib * 10) / (1024 * 1024);
        format!("{}.{}G", gib_tenths / 10, gib_tenths % 10)
    } else if kib >= 1024 {
        let mib_tenths = (kib * 10) / 1024;
        format!("{}.{}M", mib_tenths / 10, mib_tenths % 10)
    } else {
        format!("{}K", kib)
    }
}

/// Formats a table of mounted filesystems according to `DfFlags`.
pub fn format_df_table(stats: &[FilesystemStat], flags: DfFlags) -> String {
    let mut out = String::new();

    if flags.show_inodes {
        if flags.print_type {
            out.push_str("Filesystem     Type      Inodes  IUsed  IFree IUse% Mounted on\n");
        } else {
            out.push_str("Filesystem       Inodes  IUsed  IFree IUse% Mounted on\n");
        }
        for s in stats {
            let pct = s.inode_use_percent();
            if flags.print_type {
                out.push_str(&format!(
                    "{:<14} {:<7} {:>8} {:>6} {:>6} {:>4}% {}\n",
                    s.device,
                    s.fs_type,
                    s.total_inodes,
                    s.used_inodes,
                    s.free_inodes(),
                    pct,
                    s.mount_point
                ));
            } else {
                out.push_str(&format!(
                    "{:<14} {:>8} {:>6} {:>6} {:>4}% {}\n",
                    s.device,
                    s.total_inodes,
                    s.used_inodes,
                    s.free_inodes(),
                    pct,
                    s.mount_point
                ));
            }
        }
    } else {
        let size_hdr = if flags.human_readable { "    Size" } else { "1K-blocks" };
        if flags.print_type {
            out.push_str(&format!(
                "Filesystem     Type    {:>9}     Used    Avail Use% Mounted on\n",
                size_hdr
            ));
        } else {
            out.push_str(&format!(
                "Filesystem     {:>9}     Used    Avail Use% Mounted on\n",
                size_hdr
            ));
        }

        for s in stats {
            let pct = s.block_use_percent();
            let (tot_s, used_s, avail_s) = if flags.human_readable {
                (
                    format_kib_human(s.total_kib),
                    format_kib_human(s.used_kib),
                    format_kib_human(s.avail_kib()),
                )
            } else {
                (
                    format!("{}", s.total_kib),
                    format!("{}", s.used_kib),
                    format!("{}", s.avail_kib()),
                )
            };

            if flags.print_type {
                out.push_str(&format!(
                    "{:<14} {:<7} {:>9} {:>8} {:>8} {:>3}% {}\n",
                    s.device, s.fs_type, tot_s, used_s, avail_s, pct, s.mount_point
                ));
            } else {
                out.push_str(&format!(
                    "{:<14} {:>9} {:>8} {:>8} {:>3}% {}\n",
                    s.device, tot_s, used_s, avail_s, pct, s.mount_point
                ));
            }
        }
    }

    out
}

pub fn verify_util_df() -> u32 {
    let mut passed = 0u32;

    let sample = [
        FilesystemStat {
            device: "/dev/sda1",
            fs_type: "vfat",
            mount_point: "/boot/efi",
            total_kib: 65536,
            used_kib: 16384,
            total_inodes: 16384,
            used_inodes: 128,
        },
        FilesystemStat {
            device: "corvfs",
            fs_type: "tmpfs",
            mount_point: "/proc",
            total_kib: 4096,
            used_kib: 128,
            total_inodes: 1024,
            used_inodes: 64,
        },
    ];

    if sample[0].avail_kib() == 49152 && sample[0].block_use_percent() == 25 {
        passed += 1;
    }

    let human_table = format_df_table(&sample, DfFlags::parse_args(&["-hT"]));
    if human_table.contains("vfat") && human_table.contains("64.0M") && human_table.contains("16.0M") && human_table.contains("48.0M") {
        passed += 1;
    }

    let inode_table = format_df_table(&sample, DfFlags::parse_args(&["-i"]));
    if inode_table.contains("Inodes  IUsed  IFree IUse%") && inode_table.contains("16384    128  16256    1%") {
        passed += 1;
    }

    passed
}
