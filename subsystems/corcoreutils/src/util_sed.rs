//! CorOS Userland Coreutil: `sed`
//! Non-interactive stream editor supporting:
//! - `s/pattern/replacement/[g]` substitution (first occurrence or global `g`)
//! - `/pattern/d` pattern-matched line deletion and line-number deletion (`3d`, `2,5d`)
//! - Line-range addressing (`1,10s/old/new/g` or single line `4s/old/new/`)
//! - `y/source/dest/` character-by-character transliteration

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SedAddress {
    AllLines,
    SingleLine(usize),
    LineRange(usize, usize),
    PatternMatch(String),
}

impl SedAddress {
    pub fn matches(&self, line_no: usize, line_text: &str) -> bool {
        match self {
            SedAddress::AllLines => true,
            SedAddress::SingleLine(target) => line_no == *target,
            SedAddress::LineRange(start, end) => line_no >= *start && line_no <= *end,
            SedAddress::PatternMatch(pat) => line_text.contains(pat.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SedOperation {
    Substitute {
        pattern: String,
        replacement: String,
        global: bool,
    },
    Delete,
    Transliterate {
        source: Vec<char>,
        dest: Vec<char>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SedCommand {
    pub address: SedAddress,
    pub op: SedOperation,
}

fn parse_leading_address(expr: &str) -> (SedAddress, &str) {
    let trimmed = expr.trim();
    if let Some(rest) = trimmed.strip_prefix('/') {
        if let Some(end_slash) = rest.find('/') {
            let pat = &rest[..end_slash];
            let after = &rest[end_slash + 1..];
            return (SedAddress::PatternMatch(String::from(pat)), after);
        }
    }

    let bytes = trimmed.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == 0 {
        return (SedAddress::AllLines, trimmed);
    }

    let first_num = trimmed[..idx].parse::<usize>().unwrap_or(1);
    let after_first = &trimmed[idx..];
    if let Some(after_comma) = after_first.strip_prefix(',') {
        let cbytes = after_comma.as_bytes();
        let mut idx2 = 0;
        while idx2 < cbytes.len() && cbytes[idx2].is_ascii_digit() {
            idx2 += 1;
        }
        if idx2 > 0 {
            let second_num = after_comma[..idx2].parse::<usize>().unwrap_or(first_num);
            return (SedAddress::LineRange(first_num, second_num), &after_comma[idx2..]);
        }
    }

    (SedAddress::SingleLine(first_num), after_first)
}

impl SedCommand {
    /// Parses a `sed` script command such as `s/foo/bar/g`, `2,4s/a/b/`, `/debug/d`, or `y/abc/ABC/`.
    pub fn parse(expr: &str) -> Option<Self> {
        let (address, rem) = parse_leading_address(expr);
        let rem = rem.trim();
        if rem == "d" {
            return Some(Self {
                address,
                op: SedOperation::Delete,
            });
        }

        if let Some(body) = rem.strip_prefix('s') {
            let mut chars = body.chars();
            let delim = chars.next()?;
            let rest = chars.as_str();
            let mut parts = rest.split(delim);
            let pat = parts.next()?;
            let rep = parts.next()?;
            let flags = parts.next().unwrap_or("");
            let global = flags.contains('g');
            return Some(Self {
                address,
                op: SedOperation::Substitute {
                    pattern: String::from(pat),
                    replacement: String::from(rep),
                    global,
                },
            });
        }

        if let Some(body) = rem.strip_prefix('y') {
            let mut chars = body.chars();
            let delim = chars.next()?;
            let rest = chars.as_str();
            let mut parts = rest.split(delim);
            let src_str = parts.next()?;
            let dst_str = parts.next()?;
            let source: Vec<char> = src_str.chars().collect();
            let dest: Vec<char> = dst_str.chars().collect();
            if source.len() == dest.len() && !source.is_empty() {
                return Some(Self {
                    address,
                    op: SedOperation::Transliterate { source, dest },
                });
            }
        }

        None
    }
}

/// Applies a slice of `SedCommand`s sequentially to every line of `input`.
pub fn execute_sed_stream(commands: &[SedCommand], input: &str) -> String {
    let mut out = String::new();

    'line_loop: for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let mut current = String::from(raw_line);

        for cmd in commands {
            if !cmd.address.matches(line_no, &current) {
                continue;
            }
            match &cmd.op {
                SedOperation::Delete => continue 'line_loop,
                SedOperation::Substitute {
                    pattern,
                    replacement,
                    global,
                } => {
                    if !pattern.is_empty() {
                        current = if *global {
                            current.replace(pattern.as_str(), replacement.as_str())
                        } else {
                            current.replacen(pattern.as_str(), replacement.as_str(), 1)
                        };
                    }
                }
                SedOperation::Transliterate { source, dest } => {
                    let mut mapped = String::with_capacity(current.len());
                    for ch in current.chars() {
                        if let Some(pos) = source.iter().position(|&s| s == ch) {
                            mapped.push(dest[pos]);
                        } else {
                            mapped.push(ch);
                        }
                    }
                    current = mapped;
                }
            }
        }

        out.push_str(&current);
        out.push('\n');
    }

    out
}

pub fn verify_util_sed() -> u32 {
    let mut passed = 0u32;

    let input = "alpha=1 alpha=2\nbeta=debug\ngamma=3 alpha=4\n";

    // Global substitution
    if let Some(cmd) = SedCommand::parse("s/alpha/omega/g") {
        let res = execute_sed_stream(&[cmd], input);
        if res.starts_with("omega=1 omega=2\n") && res.ends_with("gamma=3 omega=4\n") {
            passed += 1;
        }
    }

    // Pattern deletion (/debug/d)
    if let Some(cmd) = SedCommand::parse("/debug/d") {
        let res = execute_sed_stream(&[cmd], input);
        if !res.contains("beta=debug") && res.lines().count() == 2 {
            passed += 1;
        }
    }

    // Line-range substitution (1,2s/=/:/g)
    if let Some(cmd) = SedCommand::parse("1,2s/=/:/g") {
        let res = execute_sed_stream(&[cmd], input);
        if res.contains("alpha:1 alpha:2\nbeta:debug\ngamma=3 alpha=4\n") {
            passed += 1;
        }
    }

    // Transliteration (y/abg/ABG/)
    if let Some(cmd) = SedCommand::parse("y/abg/ABG/") {
        let res = execute_sed_stream(&[cmd], "alpha\nbeta\ngamma\n");
        if res == "AlphA\nBetA\nGAmmA\n" {
            passed += 1;
        }
    }

    passed
}
