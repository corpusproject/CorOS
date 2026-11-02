//! CorOS Userland Coreutil: `grep`
//! Basic Regular Expression (BRE) & pattern matcher supporting:
//! - `^` start-of-line anchor, `$` end-of-line anchor
//! - `.` single-character wildcard, `*` zero-or-more quantifier
//! - `[abc]` and `[^abc]` character classes (plus ranges like `[a-z]`)
//! - Flags: `-i` (case-insensitive), `-v` (invert match), `-n` (line numbers), `-c` (count matches)

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrepFlags {
    pub ignore_case: bool,
    pub invert_match: bool,
    pub line_number: bool,
    pub count_only: bool,
}

impl GrepFlags {
    pub const fn default_flags() -> Self {
        Self {
            ignore_case: false,
            invert_match: false,
            line_number: false,
            count_only: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'i' => flags.ignore_case = true,
                        'v' => flags.invert_match = true,
                        'n' => flags.line_number = true,
                        'c' => flags.count_only = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RegexToken {
    Literal(u8),
    AnyChar,
    CharClass { negated: bool, members: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompiledAtom {
    token: RegexToken,
    zero_or_more: bool,
}

#[derive(Clone, Debug)]
pub struct CompiledRegex {
    anchor_start: bool,
    anchor_end: bool,
    atoms: Vec<CompiledAtom>,
    ignore_case: bool,
}

#[inline]
fn fold_ascii(b: u8, ignore_case: bool) -> u8 {
    if ignore_case && b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

impl CompiledRegex {
    pub fn compile(pattern: &str, ignore_case: bool) -> Self {
        let bytes = pattern.as_bytes();
        let mut idx = 0;
        let anchor_start = if bytes.first() == Some(&b'^') {
            idx += 1;
            true
        } else {
            false
        };

        let mut end_limit = bytes.len();
        let anchor_end = if end_limit > idx && bytes[end_limit - 1] == b'$' {
            end_limit -= 1;
            true
        } else {
            false
        };

        let mut atoms: Vec<CompiledAtom> = Vec::new();
        while idx < end_limit {
            let b = bytes[idx];
            let token = if b == b'.' {
                idx += 1;
                RegexToken::AnyChar
            } else if b == b'[' {
                idx += 1;
                let negated = if idx < end_limit && (bytes[idx] == b'^' || bytes[idx] == b'!') {
                    idx += 1;
                    true
                } else {
                    false
                };
                let mut members = Vec::new();
                while idx < end_limit && bytes[idx] != b']' {
                    if idx + 2 < end_limit && bytes[idx + 1] == b'-' && bytes[idx + 2] != b']' {
                        let start = fold_ascii(bytes[idx], ignore_case);
                        let end = fold_ascii(bytes[idx + 2], ignore_case);
                        let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
                        for c in lo..=hi {
                            members.push(c);
                        }
                        idx += 3;
                    } else {
                        members.push(fold_ascii(bytes[idx], ignore_case));
                        idx += 1;
                    }
                }
                if idx < end_limit && bytes[idx] == b']' {
                    idx += 1;
                }
                RegexToken::CharClass { negated, members }
            } else if b == b'\\' && idx + 1 < end_limit {
                idx += 1;
                let lit = fold_ascii(bytes[idx], ignore_case);
                idx += 1;
                RegexToken::Literal(lit)
            } else {
                idx += 1;
                RegexToken::Literal(fold_ascii(b, ignore_case))
            };

            let zero_or_more = if idx < end_limit && bytes[idx] == b'*' {
                idx += 1;
                true
            } else {
                false
            };

            atoms.push(CompiledAtom { token, zero_or_more });
        }

        Self {
            anchor_start,
            anchor_end,
            atoms,
            ignore_case,
        }
    }

    #[inline]
    fn atom_matches(&self, token: &RegexToken, byte: u8) -> bool {
        let b = fold_ascii(byte, self.ignore_case);
        match token {
            RegexToken::Literal(expected) => b == *expected,
            RegexToken::AnyChar => true,
            RegexToken::CharClass { negated, members } => {
                let found = members.contains(&b);
                if *negated { !found } else { found }
            }
        }
    }

    fn match_here(&self, atoms: &[CompiledAtom], text: &[u8]) -> bool {
        if atoms.is_empty() {
            return if self.anchor_end { text.is_empty() } else { true };
        }

        let first = &atoms[0];
        let rest = &atoms[1..];

        if first.zero_or_more {
            let mut pos = 0;
            loop {
                if self.match_here(rest, &text[pos..]) {
                    return true;
                }
                if pos < text.len() && self.atom_matches(&first.token, text[pos]) {
                    pos += 1;
                } else {
                    break;
                }
            }
            false
        } else if !text.is_empty() && self.atom_matches(&first.token, text[0]) {
            self.match_here(rest, &text[1..])
        } else {
            false
        }
    }

    pub fn is_match(&self, line: &str) -> bool {
        let bytes = line.as_bytes();
        if self.anchor_start {
            return self.match_here(&self.atoms, bytes);
        }
        for start in 0..=bytes.len() {
            if self.match_here(&self.atoms, &bytes[start..]) {
                return true;
            }
        }
        false
    }
}

/// Runs `grep` with `pattern` and `flags` over `input`, returning formatted output lines or match count.
pub fn grep_search(pattern: &str, input: &str, flags: GrepFlags) -> String {
    let regex = CompiledRegex::compile(pattern, flags.ignore_case);
    let mut out = String::new();
    let mut match_count: usize = 0;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let matched = regex.is_match(raw_line);
        let selected = if flags.invert_match { !matched } else { matched };

        if selected {
            match_count += 1;
            if !flags.count_only {
                if flags.line_number {
                    out.push_str(&format!("{}:{}\n", line_no, raw_line));
                } else {
                    out.push_str(raw_line);
                    out.push('\n');
                }
            }
        }
    }

    if flags.count_only {
        out.push_str(&format!("{}\n", match_count));
    }

    out
}

pub fn verify_util_grep() -> u32 {
    let mut passed = 0u32;

    let sample = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\ncoros:x:1000:1000:CorOS Admin:/home/coros:/bin/corosh\n";

    // Test ^ anchor and $ anchor
    let root_only = grep_search("^root.*/sh$", sample, GrepFlags::default_flags());
    if root_only == "root:x:0:0:root:/root:/bin/sh\n" {
        passed += 1;
    }

    // Test character class and case-insensitive flag
    let admin = grep_search("[cC]oros admin", sample, GrepFlags::parse_args(&["-in"]));
    if admin == "3:coros:x:1000:1000:CorOS Admin:/home/coros:/bin/corosh\n" {
        passed += 1;
    }

    // Test invert match (-v) and count (-c)
    let non_root_count = grep_search("^root", sample, GrepFlags::parse_args(&["-vc"]));
    if non_root_count == "2\n" {
        passed += 1;
    }

    // Test wildcard and star quantifier
    let rx = CompiledRegex::compile("^a.*b[0-9]*$", false);
    if rx.is_match("axxxb123") && rx.is_match("ab") && !rx.is_match("axxxb12a") {
        passed += 1;
    }

    passed
}
