//! CorOS Userland Coreutil: `find`
//! Directory tree predicate evaluator supporting:
//! - `-name <glob>` wildcard globbing (`*` and `?`)
//! - `-type f|d|l` file type filter
//! - `-size +N|-N|N` byte/block size comparison
//! - `-maxdepth <depth>` tree depth limit
//! - `-perm <octal>` exact permission mode filter

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindFileType {
    RegularFile,
    Directory,
    Symlink,
}

impl FindFileType {
    pub fn from_flag(arg: &str) -> Option<Self> {
        match arg {
            "f" => Some(Self::RegularFile),
            "d" => Some(Self::Directory),
            "l" => Some(Self::Symlink),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeConstraint {
    GreaterThan(u64),
    LessThan(u64),
    Exact(u64),
}

impl SizeConstraint {
    /// Parses a size argument such as `+4096c`, `-10k`, or `512c`.
    pub fn parse(spec: &str) -> Option<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (cmp_kind, num_part) = if let Some(rest) = trimmed.strip_prefix('+') {
            (1i8, rest)
        } else if let Some(rest) = trimmed.strip_prefix('-') {
            (-1i8, rest)
        } else {
            (0i8, trimmed)
        };

        let (digits, mult) = if let Some(d) = num_part.strip_suffix('c') {
            (d, 1u64)
        } else if let Some(d) = num_part.strip_suffix('k') {
            (d, 1024u64)
        } else if let Some(d) = num_part.strip_suffix('M') {
            (d, 1024 * 1024u64)
        } else {
            // Default POSIX 512-byte blocks if no unit suffix
            (num_part, 512u64)
        };

        let val = digits.parse::<u64>().ok()?.saturating_mul(mult);
        Some(match cmp_kind {
            1 => Self::GreaterThan(val),
            -1 => Self::LessThan(val),
            _ => Self::Exact(val),
        })
    }

    pub fn matches(self, size_bytes: u64) -> bool {
        match self {
            Self::GreaterThan(v) => size_bytes > v,
            Self::LessThan(v) => size_bytes < v,
            Self::Exact(v) => size_bytes == v,
        }
    }
}

/// Evaluates shell glob pattern matching (`*` matches 0+ chars, `?` matches any single char).
pub fn glob_match(pattern: &str, candidate: &str) -> bool {
    fn match_bytes(pat: &[u8], text: &[u8]) -> bool {
        if pat.is_empty() {
            return text.is_empty();
        }
        if pat[0] == b'*' {
            // Collapse consecutive '*'
            let mut next_pat = &pat[1..];
            while next_pat.first() == Some(&b'*') {
                next_pat = &next_pat[1..];
            }
            for i in 0..=text.len() {
                if match_bytes(next_pat, &text[i..]) {
                    return true;
                }
            }
            false
        } else if pat[0] == b'?' {
            !text.is_empty() && match_bytes(&pat[1..], &text[1..])
        } else {
            !text.is_empty() && pat[0] == text[0] && match_bytes(&pat[1..], &text[1..])
        }
    }
    match_bytes(pattern.as_bytes(), candidate.as_bytes())
}

#[derive(Clone, Debug, Default)]
pub struct FindPredicates {
    pub name_glob: Option<String>,
    pub file_type: Option<FindFileType>,
    pub size_filter: Option<SizeConstraint>,
    pub max_depth: Option<u32>,
    pub perm_exact: Option<u16>,
}

impl FindPredicates {
    pub fn parse_args(args: &[&str]) -> Self {
        let mut preds = Self::default();
        let mut idx = 0;
        while idx < args.len() {
            match args[idx] {
                "-name" if idx + 1 < args.len() => {
                    preds.name_glob = Some(String::from(args[idx + 1]));
                    idx += 2;
                }
                "-type" if idx + 1 < args.len() => {
                    preds.file_type = FindFileType::from_flag(args[idx + 1]);
                    idx += 2;
                }
                "-size" if idx + 1 < args.len() => {
                    preds.size_filter = SizeConstraint::parse(args[idx + 1]);
                    idx += 2;
                }
                "-maxdepth" if idx + 1 < args.len() => {
                    preds.max_depth = args[idx + 1].parse::<u32>().ok();
                    idx += 2;
                }
                "-perm" if idx + 1 < args.len() => {
                    preds.perm_exact = u16::from_str_radix(args[idx + 1], 8).ok();
                    idx += 2;
                }
                _ => {
                    idx += 1;
                }
            }
        }
        preds
    }
}

#[derive(Clone, Debug)]
pub struct FsTreeNode {
    pub path: &'static str,
    pub basename: &'static str,
    pub depth: u32,
    pub file_type: FindFileType,
    pub size_bytes: u64,
    pub mode: u16,
}

/// Evaluates `FindPredicates` against a list of directory tree nodes and returns matching paths.
pub fn evaluate_find<'a>(nodes: &'a [FsTreeNode], preds: &FindPredicates) -> Vec<&'a str> {
    let mut results = Vec::new();
    for node in nodes {
        if let Some(max_d) = preds.max_depth {
            if node.depth > max_d {
                continue;
            }
        }
        if let Some(ft) = preds.file_type {
            if node.file_type != ft {
                continue;
            }
        }
        if let Some(ref glob) = preds.name_glob {
            if !glob_match(glob.as_str(), node.basename) {
                continue;
            }
        }
        if let Some(sz) = preds.size_filter {
            if !sz.matches(node.size_bytes) {
                continue;
            }
        }
        if let Some(perm) = preds.perm_exact {
            if (node.mode & 0o7777) != perm {
                continue;
            }
        }
        results.push(node.path);
    }
    results
}

pub fn verify_util_find() -> u32 {
    let mut passed = 0u32;

    if glob_match("*.efi", "corkernel.efi")
        && glob_match("boot?.log", "boot1.log")
        && !glob_match("*.efi", "corkernel.bin")
    {
        passed += 1;
    }

    let tree = [
        FsTreeNode {
            path: "/efi",
            basename: "efi",
            depth: 1,
            file_type: FindFileType::Directory,
            size_bytes: 4096,
            mode: 0o755,
        },
        FsTreeNode {
            path: "/efi/coros/corkernel.efi",
            basename: "corkernel.efi",
            depth: 3,
            file_type: FindFileType::RegularFile,
            size_bytes: 262_144,
            mode: 0o755,
        },
        FsTreeNode {
            path: "/efi/coros/boot.log",
            basename: "boot.log",
            depth: 3,
            file_type: FindFileType::RegularFile,
            size_bytes: 512,
            mode: 0o644,
        },
        FsTreeNode {
            path: "/etc/shadow",
            basename: "shadow",
            depth: 2,
            file_type: FindFileType::RegularFile,
            size_bytes: 256,
            mode: 0o600,
        },
    ];

    let preds1 = FindPredicates::parse_args(&["-type", "f", "-name", "*.efi", "-size", "+100k"]);
    let found1 = evaluate_find(&tree, &preds1);
    if found1.as_slice() == ["/efi/coros/corkernel.efi"] {
        passed += 1;
    }

    let preds2 = FindPredicates::parse_args(&["-maxdepth", "2", "-perm", "600"]);
    let found2 = evaluate_find(&tree, &preds2);
    if found2.as_slice() == ["/etc/shadow"] {
        passed += 1;
    }

    passed
}
