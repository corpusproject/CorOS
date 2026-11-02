//! CorOS Userland Coreutil: `cat`
//! Stream and file concatenator supporting `-n` (number all lines), `-b` (number non-blank lines),
//! `-E` (display `$` at end of line), `-T` (display tabs as `^I`), and `-s` (squeeze repeated blank lines).

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatFlags {
    pub number_all: bool,
    pub number_nonblank: bool,
    pub show_ends: bool,
    pub show_tabs: bool,
    pub squeeze_blank: bool,
}

impl CatFlags {
    pub const fn default_flags() -> Self {
        Self {
            number_all: false,
            number_nonblank: false,
            show_ends: false,
            show_tabs: false,
            squeeze_blank: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'n' => flags.number_all = true,
                        'b' => flags.number_nonblank = true,
                        'E' => flags.show_ends = true,
                        'T' => flags.show_tabs = true,
                        's' => flags.squeeze_blank = true,
                        'A' => {
                            flags.show_ends = true;
                            flags.show_tabs = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        // POSIX: -b overrides -n
        if flags.number_nonblank {
            flags.number_all = false;
        }
        flags
    }
}

/// Concatenates one or more text buffers applying `CatFlags` line-by-line across streams.
pub fn concatenate_streams(streams: &[&str], flags: CatFlags) -> String {
    let mut out = String::new();
    let mut line_number: usize = 1;
    let mut prev_was_blank = false;

    for stream in streams {
        for raw_line in stream.split_inclusive('\n') {
            let has_newline = raw_line.ends_with('\n');
            let content = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let content = content.strip_suffix('\r').unwrap_or(content);
            let is_blank = content.is_empty();

            if flags.squeeze_blank && is_blank && prev_was_blank {
                continue;
            }
            prev_was_blank = is_blank;

            if flags.number_nonblank {
                if !is_blank {
                    out.push_str(&format!("{:>6}\t", line_number));
                    line_number += 1;
                }
            } else if flags.number_all {
                out.push_str(&format!("{:>6}\t", line_number));
                line_number += 1;
            }

            if flags.show_tabs {
                for ch in content.chars() {
                    if ch == '\t' {
                        out.push_str("^I");
                    } else {
                        out.push(ch);
                    }
                }
            } else {
                out.push_str(content);
            }

            if flags.show_ends && has_newline {
                out.push('$');
            }
            if has_newline {
                out.push('\n');
            }
        }
    }

    out
}

pub fn verify_util_cat() -> u32 {
    let mut passed = 0u32;

    let flags = CatFlags::parse_args(&["-nbETs"]);
    if flags.number_nonblank && !flags.number_all && flags.show_ends && flags.show_tabs && flags.squeeze_blank {
        passed += 1;
    }

    let plain = concatenate_streams(&["hello\n", "world\n"], CatFlags::default_flags());
    if plain == "hello\nworld\n" {
        passed += 1;
    }

    let squeezed = concatenate_streams(
        &["alpha\n\n\n\nbeta\tgamma\n"],
        CatFlags::parse_args(&["-s", "-b", "-E", "-T"]),
    );
    if squeezed == "     1\talpha$\n$\n     2\tbeta^Igamma$\n" {
        passed += 1;
    }

    let numbered = concatenate_streams(&["a\n\nb\n"], CatFlags::parse_args(&["-n"]));
    if numbered.contains("     1\ta\n") && numbered.contains("     2\t\n") && numbered.contains("     3\tb\n") {
        passed += 1;
    }

    passed
}
