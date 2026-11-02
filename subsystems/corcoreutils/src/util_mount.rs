//! CorOS Userland Coreutil: `mount`
//! Mount table parser & formatter supporting `mount -t <fstype> -o <opts> <device> <dir>`,
//! mount option flags (`ro`, `rw`, `noexec`, `nosuid`, `nodev`, `relatime`, `sync`),
//! and `/proc/mounts` + human-readable `mount` table generation.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountOptionMask {
    pub read_only: bool,
    pub noexec: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub relatime: bool,
    pub synchronous: bool,
}

impl MountOptionMask {
    pub const fn default_rw() -> Self {
        Self {
            read_only: false,
            noexec: false,
            nosuid: false,
            nodev: false,
            relatime: true,
            synchronous: false,
        }
    }

    pub fn parse_csv(csv: &str) -> Self {
        let mut opts = Self::default_rw();
        for token in csv.split(',') {
            match token.trim() {
                "ro" | "rdonly" => opts.read_only = true,
                "rw" => opts.read_only = false,
                "noexec" => opts.noexec = true,
                "exec" => opts.noexec = false,
                "nosuid" => opts.nosuid = true,
                "suid" => opts.nosuid = false,
                "nodev" => opts.nodev = true,
                "dev" => opts.nodev = false,
                "relatime" => opts.relatime = true,
                "noatime" => opts.relatime = false,
                "sync" => opts.synchronous = true,
                "async" => opts.synchronous = false,
                _ => {}
            }
        }
        opts
    }

    pub fn to_csv_string(self) -> String {
        let mut parts: Vec<&'static str> = Vec::new();
        parts.push(if self.read_only { "ro" } else { "rw" });
        if self.nosuid {
            parts.push("nosuid");
        }
        if self.nodev {
            parts.push("nodev");
        }
        if self.noexec {
            parts.push("noexec");
        }
        if self.relatime {
            parts.push("relatime");
        }
        if self.synchronous {
            parts.push("sync");
        }
        parts.join(",")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub source_dev: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: MountOptionMask,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountCommand {
    ShowAll { filter_fstype: Option<String> },
    MountTarget(MountEntry),
}

/// Parses `mount` CLI arguments (`mount`, `mount -t vfat`, or `mount -t vfat -o ro,noexec /dev/sda1 /boot/efi`).
pub fn parse_mount_args(args: &[&str]) -> Result<MountCommand, &'static str> {
    let mut fs_type: Option<String> = None;
    let mut options = MountOptionMask::default_rw();
    let mut positional: Vec<&str> = Vec::new();

    let mut idx = 0;
    while idx < args.len() {
        match args[idx] {
            "-t" if idx + 1 < args.len() => {
                fs_type = Some(String::from(args[idx + 1]));
                idx += 2;
            }
            "-o" if idx + 1 < args.len() => {
                options = MountOptionMask::parse_csv(args[idx + 1]);
                idx += 2;
            }
            "-r" => {
                options.read_only = true;
                idx += 1;
            }
            "-w" => {
                options.read_only = false;
                idx += 1;
            }
            other if !other.starts_with('-') => {
                positional.push(other);
                idx += 1;
            }
            _ => {
                idx += 1;
            }
        }
    }

    if positional.is_empty() {
        return Ok(MountCommand::ShowAll {
            filter_fstype: fs_type,
        });
    }

    if positional.len() != 2 {
        return Err("mount: expected <device> and <mountpoint>");
    }

    Ok(MountCommand::MountTarget(MountEntry {
        source_dev: String::from(positional[0]),
        mount_point: String::from(positional[1]),
        fs_type: fs_type.unwrap_or_else(|| String::from("auto")),
        options,
    }))
}

/// Formats active mount entries in standard `mount` output format (`<dev> on <dir> type <fs> (<opts>)`).
pub fn format_mount_table(entries: &[MountEntry], filter_fstype: Option<&str>) -> String {
    let mut out = String::new();
    for e in entries {
        if let Some(ft) = filter_fstype {
            if e.fs_type != ft {
                continue;
            }
        }
        out.push_str(&format!(
            "{} on {} type {} ({})\n",
            e.source_dev,
            e.mount_point,
            e.fs_type,
            e.options.to_csv_string()
        ));
    }
    out
}

/// Formats `/proc/mounts` compatible output (`<dev> <dir> <fs> <opts> 0 0`).
pub fn format_proc_mounts(entries: &[MountEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&format!(
            "{} {} {} {} 0 0\n",
            e.source_dev,
            e.mount_point,
            e.fs_type,
            e.options.to_csv_string()
        ));
    }
    out
}

pub fn verify_util_mount() -> u32 {
    let mut passed = 0u32;

    let opts = MountOptionMask::parse_csv("ro,noexec,nosuid,sync");
    if opts.read_only && opts.noexec && opts.nosuid && opts.synchronous {
        passed += 1;
    }

    if let Ok(MountCommand::MountTarget(entry)) =
        parse_mount_args(&["-t", "vfat", "-o", "ro,noexec", "/dev/nvme0n1p1", "/boot/efi"])
    {
        if entry.fs_type == "vfat"
            && entry.source_dev == "/dev/nvme0n1p1"
            && entry.mount_point == "/boot/efi"
            && entry.options.read_only
            && entry.options.noexec
        {
            passed += 1;
        }

        let table = format_mount_table(&[entry.clone()], None);
        let proc_m = format_proc_mounts(&[entry]);
        if table.contains("/dev/nvme0n1p1 on /boot/efi type vfat (ro,noexec,relatime)")
            && proc_m.contains("/dev/nvme0n1p1 /boot/efi vfat ro,noexec,relatime 0 0")
        {
            passed += 1;
        }
    }

    passed
}
