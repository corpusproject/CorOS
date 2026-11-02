//! CorOS Userland Coreutil: `kill`
//! POSIX signal name/number resolver (`-9`, `-KILL`, `-SIGKILL`, `-TERM`, `-INT`, `-HUP`, `-STOP`, `-CONT`),
//! full 31-signal table formatter (`kill -l`), and signal dispatch validator.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalDescriptor {
    pub number: u8,
    pub short_name: &'static str,
    pub description: &'static str,
}

/// Complete standard Linux/POSIX x86_64 1..=31 signal table.
pub const POSIX_SIGNALS: [SignalDescriptor; 31] = [
    SignalDescriptor { number: 1, short_name: "HUP", description: "Hangup" },
    SignalDescriptor { number: 2, short_name: "INT", description: "Interrupt" },
    SignalDescriptor { number: 3, short_name: "Quit", description: "Quit" },
    SignalDescriptor { number: 4, short_name: "ILL", description: "Illegal instruction" },
    SignalDescriptor { number: 5, short_name: "TRAP", description: "Trace/breakpoint trap" },
    SignalDescriptor { number: 6, short_name: "ABRT", description: "Aborted" },
    SignalDescriptor { number: 7, short_name: "BUS", description: "Bus error" },
    SignalDescriptor { number: 8, short_name: "FPE", description: "Floating point exception" },
    SignalDescriptor { number: 9, short_name: "KILL", description: "Killed" },
    SignalDescriptor { number: 10, short_name: "USR1", description: "User defined signal 1" },
    SignalDescriptor { number: 11, short_name: "SEGV", description: "Segmentation fault" },
    SignalDescriptor { number: 12, short_name: "USR2", description: "User defined signal 2" },
    SignalDescriptor { number: 13, short_name: "PIPE", description: "Broken pipe" },
    SignalDescriptor { number: 14, short_name: "ALRM", description: "Alarm clock" },
    SignalDescriptor { number: 15, short_name: "TERM", description: "Terminated" },
    SignalDescriptor { number: 16, short_name: "STKFLT", description: "Stack fault" },
    SignalDescriptor { number: 17, short_name: "CHLD", description: "Child exited" },
    SignalDescriptor { number: 18, short_name: "CONT", description: "Continued" },
    SignalDescriptor { number: 19, short_name: "STOP", description: "Stopped (signal)" },
    SignalDescriptor { number: 20, short_name: "TSTP", description: "Stopped" },
    SignalDescriptor { number: 21, short_name: "TTIN", description: "Stopped (tty input)" },
    SignalDescriptor { number: 22, short_name: "TTOU", description: "Stopped (tty output)" },
    SignalDescriptor { number: 23, short_name: "URG", description: "Urgent I/O condition" },
    SignalDescriptor { number: 24, short_name: "XCPU", description: "CPU time limit exceeded" },
    SignalDescriptor { number: 25, short_name: "XFSZ", description: "File size limit exceeded" },
    SignalDescriptor { number: 26, short_name: "VTALRM", description: "Virtual timer expired" },
    SignalDescriptor { number: 27, short_name: "PROF", description: "Profiling timer expired" },
    SignalDescriptor { number: 28, short_name: "WINCH", description: "Window changed" },
    SignalDescriptor { number: 29, short_name: "IO", description: "I/O possible" },
    SignalDescriptor { number: 30, short_name: "PWR", description: "Power failure" },
    SignalDescriptor { number: 31, short_name: "SYS", description: "Bad system call" },
];

/// Resolves a signal spec such as `"9"`, `"-9"`, `"-KILL"`, `"SIGKILL"`, `"TERM"`, or `"-s"` value into its signal number `1..=31`.
pub fn resolve_signal_spec(spec: &str) -> Option<u8> {
    let trimmed = spec.trim();
    let without_dash = trimmed.strip_prefix('-').unwrap_or(trimmed);
    if let Ok(num) = without_dash.parse::<u8>() {
        if (1..=31).contains(&num) {
            return Some(num);
        }
        return None;
    }

    let upper = without_dash.to_ascii_uppercase();
    let clean = upper.strip_prefix("SIG").unwrap_or(&upper);
    for sig in &POSIX_SIGNALS {
        if sig.short_name.eq_ignore_ascii_case(clean) {
            return Some(sig.number);
        }
    }
    None
}

/// Formats the complete 31-signal table (`kill -l`).
pub fn format_signal_list() -> String {
    let mut out = String::new();
    for (idx, sig) in POSIX_SIGNALS.iter().enumerate() {
        out.push_str(&format!("{:>2}) SIG{:<8}", sig.number, sig.short_name.to_ascii_uppercase()));
        if (idx + 1) % 4 == 0 || idx + 1 == POSIX_SIGNALS.len() {
            out.push('\n');
        } else {
            out.push(' ');
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KillCommandAction {
    ListSignals,
    SendSignal { signal: u8, pids: Vec<i32> },
}

/// Parses `kill` command arguments into either `ListSignals` (`-l`) or `SendSignal` (default `SIGTERM` = 15).
pub fn parse_kill_command(args: &[&str]) -> Result<KillCommandAction, &'static str> {
    if args.first() == Some(&"-l") || args.first() == Some(&"--list") {
        return Ok(KillCommandAction::ListSignals);
    }

    let mut signal: u8 = 15; // Default SIGTERM
    let mut pids: Vec<i32> = Vec::new();
    let mut idx = 0;

    while idx < args.len() {
        let arg = args[idx];
        if (arg == "-s" || arg == "--signal") && idx + 1 < args.len() {
            signal = resolve_signal_spec(args[idx + 1]).ok_or("Unknown signal specification")?;
            idx += 2;
            continue;
        }
        if arg.starts_with('-') && pids.is_empty() {
            if let Some(sig) = resolve_signal_spec(arg) {
                signal = sig;
                idx += 1;
                continue;
            }
        }
        let pid = arg.parse::<i32>().map_err(|_| "Invalid PID argument")?;
        if pid == 0 || pid == 1 && signal == 9 {
            return Err("Refusing to send SIGKILL to init (PID 1) or process group 0");
        }
        pids.push(pid);
        idx += 1;
    }

    if pids.is_empty() {
        return Err("kill: not enough arguments");
    }

    Ok(KillCommandAction::SendSignal { signal, pids })
}

pub fn verify_util_kill() -> u32 {
    let mut passed = 0u32;

    if resolve_signal_spec("-9") == Some(9)
        && resolve_signal_spec("-KILL") == Some(9)
        && resolve_signal_spec("SIGTERM") == Some(15)
        && resolve_signal_spec("-HUP") == Some(1)
        && resolve_signal_spec("-CONT") == Some(18)
    {
        passed += 1;
    }

    let list_str = format_signal_list();
    if list_str.contains(" 1) SIGHUP") && list_str.contains(" 9) SIGKILL") && list_str.contains("31) SIGSYS") {
        passed += 1;
    }

    if let Ok(KillCommandAction::SendSignal { signal, pids }) = parse_kill_command(&["-KILL", "104", "205"]) {
        if signal == 9 && pids.as_slice() == [104, 205] {
            passed += 1;
        }
    }

    // Verify PID 1 protection against SIGKILL
    if parse_kill_command(&["-9", "1"]).is_err() {
        passed += 1;
    }

    passed
}
