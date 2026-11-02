//! CorOS Userland Coreutil: `awk`
//! Pattern-scanning & field-splitting text processor supporting:
//! - Custom field separator (`-F`) or default whitespace splitting
//! - Positional fields `$0` (whole record), `$1..$9`, plus `NR` (record number) and `NF` (field count)
//! - `BEGIN`, line-matching, and `END` pattern blocks
//! - Numeric `SUM` and `AVG` column accumulation across records

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwkFieldSeparator {
    Whitespace,
    Delimiter(char),
}

impl AwkFieldSeparator {
    pub fn parse_from_args(args: &[&str]) -> Self {
        let mut iter = args.iter().copied();
        while let Some(arg) = iter.next() {
            if arg == "-F" {
                if let Some(next_sep) = iter.next() {
                    if let Some(ch) = next_sep.chars().next() {
                        return Self::Delimiter(ch);
                    }
                }
            } else if let Some(rest) = arg.strip_prefix("-F") {
                if let Some(ch) = rest.chars().next() {
                    return Self::Delimiter(ch);
                }
            }
        }
        Self::Whitespace
    }

    pub fn split_record<'a>(&self, line: &'a str) -> Vec<&'a str> {
        match *self {
            Self::Whitespace => line.split_whitespace().collect(),
            Self::Delimiter(delim) => line.split(delim).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AwkOutputToken {
    Field(usize),
    RecordNumber,
    FieldCount,
    Literal(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AwkAction {
    /// Prints a sequence of tokens for each matching line.
    PrintTokens(Vec<AwkOutputToken>),
    /// Accumulates integer values of the 1-based column index and prints `SUM=<sum> AVG=<avg>` at END.
    AccumulateColumn { col_index: usize },
}

#[derive(Clone, Debug)]
pub struct AwkProgram {
    pub separator: AwkFieldSeparator,
    pub begin_banner: Option<&'static str>,
    pub line_filter_substr: Option<&'static str>,
    pub action: AwkAction,
    pub end_banner: Option<&'static str>,
}

/// Evaluates a single record (`$0`, `$1..$N`, `NR`, `NF`) against a list of `AwkOutputToken`s.
pub fn format_awk_record(line: &str, fields: &[&str], nr: usize, tokens: &[AwkOutputToken]) -> String {
    let mut out = String::new();
    let nf = fields.len();
    for tok in tokens {
        match *tok {
            AwkOutputToken::Field(0) => out.push_str(line),
            AwkOutputToken::Field(idx) => {
                if idx >= 1 && idx <= nf {
                    out.push_str(fields[idx - 1]);
                }
            }
            AwkOutputToken::RecordNumber => out.push_str(&format!("{}", nr)),
            AwkOutputToken::FieldCount => out.push_str(&format!("{}", nf)),
            AwkOutputToken::Literal(s) => out.push_str(s),
        }
    }
    out.push('\n');
    out
}

/// Executes an `AwkProgram` over a multi-line input stream.
pub fn execute_awk(program: &AwkProgram, input: &str) -> String {
    let mut out = String::new();
    if let Some(begin) = program.begin_banner {
        out.push_str(begin);
        out.push('\n');
    }

    let mut nr: usize = 0;
    let mut sum_acc: i64 = 0;
    let mut sum_count: i64 = 0;

    for raw_line in input.lines() {
        nr += 1;
        if let Some(filter) = program.line_filter_substr {
            if !raw_line.contains(filter) {
                continue;
            }
        }
        let fields = program.separator.split_record(raw_line);
        match &program.action {
            AwkAction::PrintTokens(tokens) => {
                out.push_str(&format_awk_record(raw_line, &fields, nr, tokens));
            }
            AwkAction::AccumulateColumn { col_index } => {
                if *col_index >= 1 && *col_index <= fields.len() {
                    if let Ok(val) = fields[*col_index - 1].trim().parse::<i64>() {
                        sum_acc += val;
                        sum_count += 1;
                    }
                }
            }
        }
    }

    if let AwkAction::AccumulateColumn { .. } = program.action {
        let avg = if sum_count > 0 { sum_acc / sum_count } else { 0 };
        out.push_str(&format!("SUM={} AVG={} COUNT={}\n", sum_acc, avg, sum_count));
    }

    if let Some(end) = program.end_banner {
        out.push_str(end);
        out.push('\n');
    }

    out
}

pub fn verify_util_awk() -> u32 {
    let mut passed = 0u32;

    let sep = AwkFieldSeparator::parse_from_args(&["-F:"]);
    if sep == AwkFieldSeparator::Delimiter(':') {
        passed += 1;
    }

    let passwd = "root:x:0:0:Admin:/root:/bin/sh\ncoros:x:1000:1000:User:/home/coros:/bin/corosh\n";
    let mut tokens = Vec::new();
    tokens.push(AwkOutputToken::RecordNumber);
    tokens.push(AwkOutputToken::Literal(":"));
    tokens.push(AwkOutputToken::Field(1));
    tokens.push(AwkOutputToken::Literal("->"));
    tokens.push(AwkOutputToken::Field(7));
    tokens.push(AwkOutputToken::Literal(" (NF="));
    tokens.push(AwkOutputToken::FieldCount);
    tokens.push(AwkOutputToken::Literal(")"));

    let prog = AwkProgram {
        separator: sep,
        begin_banner: Some("BEGIN_PASSWD"),
        line_filter_substr: None,
        action: AwkAction::PrintTokens(tokens),
        end_banner: Some("END_PASSWD"),
    };

    let res = execute_awk(&prog, passwd);
    if res.contains("BEGIN_PASSWD\n1:root->/bin/sh (NF=7)\n2:coros->/bin/corosh (NF=7)\nEND_PASSWD\n") {
        passed += 1;
    }

    let metrics = "cpu0 120\ncpu1 180\ncpu2 240\n";
    let sum_prog = AwkProgram {
        separator: AwkFieldSeparator::Whitespace,
        begin_banner: None,
        line_filter_substr: Some("cpu"),
        action: AwkAction::AccumulateColumn { col_index: 2 },
        end_banner: None,
    };
    let sum_out = execute_awk(&sum_prog, metrics);
    if sum_out == "SUM=540 AVG=180 COUNT=3\n" {
        passed += 1;
    }

    passed
}
