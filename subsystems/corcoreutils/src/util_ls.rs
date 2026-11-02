//! CorOS Userland Coreutil: `ls`
//! Directory listing with permissions (`drwxr-xr-x`), human-readable sizes (`KiB`, `MiB`),
//! sorting (`-S` size, `-t` mtime), hidden files (`-a`), recursive traversal (`-R`),
//! and column / long-listing formatters.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    RegularFile,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl EntryKind {
    pub const fn prefix_char(self) -> char {
        match self {
            EntryKind::RegularFile => '-',
            EntryKind::Directory => 'd',
            EntryKind::Symlink => 'l',
            EntryKind::CharDevice => 'c',
            EntryKind::BlockDevice => 'b',
            EntryKind::Fifo => 'p',
            EntryKind::Socket => 's',
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortOrder {
    Alphabetical,
    BySizeDesc,
    ByMtimeDesc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LsFlags {
    pub long_format: bool,
    pub show_all: bool,
    pub human_readable: bool,
    pub recursive: bool,
    pub sort_order: SortOrder,
}

impl LsFlags {
    pub const fn default_flags() -> Self {
        Self {
            long_format: false,
            show_all: false,
            human_readable: false,
            recursive: false,
            sort_order: SortOrder::Alphabetical,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                if rest.starts_with('-') {
                    match rest {
                        "-all" => flags.show_all = true,
                        "-human-readable" => flags.human_readable = true,
                        "-recursive" => flags.recursive = true,
                        _ => {}
                    }
                } else {
                    for ch in rest.chars() {
                        match ch {
                            'l' => flags.long_format = true,
                            'a' => flags.show_all = true,
                            'h' => flags.human_readable = true,
                            'R' => flags.recursive = true,
                            'S' => flags.sort_order = SortOrder::BySizeDesc,
                            't' => flags.sort_order = SortOrder::ByMtimeDesc,
                            _ => {}
                        }
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: &'static str,
    pub kind: EntryKind,
    pub mode: u16,
    pub nlink: u32,
    pub owner: &'static str,
    pub group: &'static str,
    pub size_bytes: u64,
    pub mtime_epoch: u64,
    pub symlink_target: Option<&'static str>,
}

/// Formats a 10-character POSIX permission string such as `drwxr-xr-x` or `-rwsr-xr-x`.
pub fn format_permission_string(kind: EntryKind, mode: u16) -> [u8; 10] {
    let mut out = [b'-'; 10];
    out[0] = kind.prefix_char() as u8;

    // Owner permissions
    if mode & 0o400 != 0 {
        out[1] = b'r';
    }
    if mode & 0o200 != 0 {
        out[2] = b'w';
    }
    out[3] = match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => b's',
        (false, true) => b'S',
        (true, false) => b'x',
        (false, false) => b'-',
    };

    // Group permissions
    if mode & 0o040 != 0 {
        out[4] = b'r';
    }
    if mode & 0o020 != 0 {
        out[5] = b'w';
    }
    out[6] = match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => b's',
        (false, true) => b'S',
        (true, false) => b'x',
        (false, false) => b'-',
    };

    // Other permissions
    if mode & 0o004 != 0 {
        out[7] = b'r';
    }
    if mode & 0o002 != 0 {
        out[8] = b'w';
    }
    out[9] = match (mode & 0o001 != 0, mode & 0o1000 != 0) {
        (true, true) => b't',
        (false, true) => b'T',
        (true, false) => b'x',
        (false, false) => b'-',
    };

    out
}

/// Formats a byte count into human-readable binary units (`B`, `KiB`, `MiB`, `GiB`).
pub fn format_size_human(size_bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;

    if size_bytes >= GIB {
        let whole = size_bytes / GIB;
        let tenth = ((size_bytes % GIB) * 10) / GIB;
        format!("{}.{}GiB", whole, tenth)
    } else if size_bytes >= MIB {
        let whole = size_bytes / MIB;
        let tenth = ((size_bytes % MIB) * 10) / MIB;
        format!("{}.{}MiB", whole, tenth)
    } else if size_bytes >= KIB {
        let whole = size_bytes / KIB;
        let tenth = ((size_bytes % KIB) * 10) / KIB;
        format!("{}.{}KiB", whole, tenth)
    } else {
        format!("{}B", size_bytes)
    }
}

/// Filters and sorts directory entries according to `LsFlags`, then renders either
/// a long listing (`-l`) or space-separated short column listing.
pub fn format_directory_listing(entries: &[DirEntry], flags: LsFlags) -> String {
    let mut visible: Vec<&DirEntry> = entries
        .iter()
        .filter(|e| flags.show_all || !e.name.starts_with('.'))
        .collect();

    visible.sort_by(|a, b| match flags.sort_order {
        SortOrder::Alphabetical => a.name.cmp(b.name),
        SortOrder::BySizeDesc => b.size_bytes.cmp(&a.size_bytes).then_with(|| a.name.cmp(b.name)),
        SortOrder::ByMtimeDesc => b.mtime_epoch.cmp(&a.mtime_epoch).then_with(|| a.name.cmp(b.name)),
    });

    let mut output = String::new();
    if flags.long_format {
        let total_blocks: u64 = visible.iter().map(|e| (e.size_bytes + 1023) / 1024).sum();
        output.push_str(&format!("total {}\n", total_blocks));
        for entry in visible {
            let perm_bytes = format_permission_string(entry.kind, entry.mode);
            let perm_str = core::str::from_utf8(&perm_bytes).unwrap_or("----------");
            let size_col = if flags.human_readable {
                format_size_human(entry.size_bytes)
            } else {
                format!("{}", entry.size_bytes)
            };
            if let Some(target) = entry.symlink_target {
                output.push_str(&format!(
                    "{} {:>2} {:<6} {:<6} {:>8} {} {} -> {}\n",
                    perm_str, entry.nlink, entry.owner, entry.group, size_col, entry.mtime_epoch, entry.name, target
                ));
            } else {
                output.push_str(&format!(
                    "{} {:>2} {:<6} {:<6} {:>8} {} {}\n",
                    perm_str, entry.nlink, entry.owner, entry.group, size_col, entry.mtime_epoch, entry.name
                ));
            }
        }
    } else {
        for (idx, entry) in visible.iter().enumerate() {
            if idx > 0 {
                output.push_str("  ");
            }
            output.push_str(entry.name);
        }
        if !output.is_empty() {
            output.push('\n');
        }
    }
    output
}

pub fn verify_util_ls() -> u32 {
    let mut passed = 0u32;

    let flags = LsFlags::parse_args(&["-laSh"]);
    if flags.long_format && flags.show_all && flags.human_readable && flags.sort_order == SortOrder::BySizeDesc {
        passed += 1;
    }

    let perm = format_permission_string(EntryKind::Directory, 0o755);
    if &perm == b"drwxr-xr-x" {
        passed += 1;
    }

    let sticky = format_permission_string(EntryKind::Directory, 0o1777);
    if &sticky == b"drwxrwxrwt" {
        passed += 1;
    }

    if format_size_human(2048) == "2.0KiB" && format_size_human(5 * 1024 * 1024) == "5.0MiB" {
        passed += 1;
    }

    let sample = [
        DirEntry {
            name: ".profile",
            kind: EntryKind::RegularFile,
            mode: 0o644,
            nlink: 1,
            owner: "root",
            group: "root",
            size_bytes: 512,
            mtime_epoch: 1700000100,
            symlink_target: None,
        },
        DirEntry {
            name: "corkernel.efi",
            kind: EntryKind::RegularFile,
            mode: 0o755,
            nlink: 1,
            owner: "root",
            group: "wheel",
            size_bytes: 4096,
            mtime_epoch: 1700000500,
            symlink_target: None,
        },
        DirEntry {
            name: "boot",
            kind: EntryKind::Directory,
            mode: 0o755,
            nlink: 2,
            owner: "root",
            group: "wheel",
            size_bytes: 1024,
            mtime_epoch: 1700000200,
            symlink_target: None,
        },
    ];

    let short = format_directory_listing(&sample, LsFlags::default_flags());
    if short == "boot  corkernel.efi\n" {
        passed += 1;
    }

    let long_out = format_directory_listing(&sample, LsFlags::parse_args(&["-lhS"]));
    if long_out.contains("-rwxr-xr-x") && long_out.contains("4.0KiB") && !long_out.contains(".profile") {
        passed += 1;
    }

    passed
}
