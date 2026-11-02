//! CorOS Userland Coreutil: `ps`
//! Process table formatter supporting BSD (`ps aux`), POSIX full (`ps -ef`),
//! and custom column projection (`ps -eo pid,ppid,stat,cpu,mem,comm`), plus task state decoding (`R`/`S`/`D`/`Z`/`T`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskRunState {
    Running,
    SleepingInterruptible,
    DiskSleepUninterruptible,
    Zombie,
    StoppedTraced,
}

impl TaskRunState {
    pub const fn code_char(self) -> char {
        match self {
            TaskRunState::Running => 'R',
            TaskRunState::SleepingInterruptible => 'S',
            TaskRunState::DiskSleepUninterruptible => 'D',
            TaskRunState::Zombie => 'Z',
            TaskRunState::StoppedTraced => 'T',
        }
    }

    pub fn format_stat_column(self, high_priority: bool, session_leader: bool, multithreaded: bool) -> String {
        let mut s = String::with_capacity(4);
        s.push(self.code_char());
        if high_priority {
            s.push('<');
        }
        if session_leader {
            s.push('s');
        }
        if multithreaded {
            s.push('l');
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct ProcessDescriptor {
    pub pid: u32,
    pub ppid: u32,
    pub user: &'static str,
    pub state: TaskRunState,
    pub high_priority: bool,
    pub session_leader: bool,
    pub multithreaded: bool,
    pub cpu_tenths: u16,
    pub mem_tenths: u16,
    pub vsz_kib: u64,
    pub rss_kib: u64,
    pub tty: &'static str,
    pub cputime_secs: u64,
    pub command: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PsFormatStyle {
    StandardShort,
    BsdAux,
    PosixEf,
    CustomColumns(Vec<String>),
}

impl PsFormatStyle {
    pub fn parse_args(args: &[&str]) -> Self {
        let mut idx = 0;
        while idx < args.len() {
            let arg = args[idx];
            if arg == "aux" || arg == "-aux" {
                return Self::BsdAux;
            }
            if arg == "-ef" || arg == "-fe" {
                return Self::PosixEf;
            }
            if (arg == "-eo" || arg == "-o") && idx + 1 < args.len() {
                let cols: Vec<String> = args[idx + 1]
                    .split(',')
                    .map(|c| String::from(c.trim()))
                    .collect();
                return Self::CustomColumns(cols);
            }
            idx += 1;
        }
        Self::StandardShort
    }
}

fn format_cputime(secs: u64) -> String {
    let mins = secs / 60;
    let rem_s = secs % 60;
    format!("{:02}:{:02}", mins, rem_s)
}

/// Renders the process table according to `PsFormatStyle`.
pub fn format_process_table(procs: &[ProcessDescriptor], style: &PsFormatStyle) -> String {
    let mut out = String::new();
    match style {
        PsFormatStyle::StandardShort => {
            out.push_str("  PID TTY          TIME CMD\n");
            for p in procs {
                out.push_str(&format!(
                    "{:>5} {:<8} {:>8} {}\n",
                    p.pid,
                    p.tty,
                    format_cputime(p.cputime_secs),
                    p.command
                ));
            }
        }
        PsFormatStyle::BsdAux => {
            out.push_str("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT TIME COMMAND\n");
            for p in procs {
                let stat = p.state.format_stat_column(p.high_priority, p.session_leader, p.multithreaded);
                out.push_str(&format!(
                    "{:<8} {:>5} {:>2}.{:<1} {:>2}.{:<1} {:>6} {:>5} {:<8} {:<4} {:>5} {}\n",
                    p.user,
                    p.pid,
                    p.cpu_tenths / 10,
                    p.cpu_tenths % 10,
                    p.mem_tenths / 10,
                    p.mem_tenths % 10,
                    p.vsz_kib,
                    p.rss_kib,
                    p.tty,
                    stat,
                    format_cputime(p.cputime_secs),
                    p.command
                ));
            }
        }
        PsFormatStyle::PosixEf => {
            out.push_str("UID        PID  PPID  C STIME TTY          TIME CMD\n");
            for p in procs {
                out.push_str(&format!(
                    "{:<8} {:>5} {:>5} {:>2} 00:00 {:<8} {:>8} {}\n",
                    p.user,
                    p.pid,
                    p.ppid,
                    p.cpu_tenths / 10,
                    p.tty,
                    format_cputime(p.cputime_secs),
                    p.command
                ));
            }
        }
        PsFormatStyle::CustomColumns(cols) => {
            for (i, c) in cols.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(&c.to_ascii_uppercase());
            }
            out.push('\n');
            for p in procs {
                for (i, c) in cols.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    match c.as_str() {
                        "pid" => out.push_str(&format!("{}", p.pid)),
                        "ppid" => out.push_str(&format!("{}", p.ppid)),
                        "user" | "uid" => out.push_str(p.user),
                        "stat" | "state" => {
                            out.push_str(&p.state.format_stat_column(
                                p.high_priority,
                                p.session_leader,
                                p.multithreaded,
                            ))
                        }
                        "cpu" | "%cpu" => out.push_str(&format!("{}.{}", p.cpu_tenths / 10, p.cpu_tenths % 10)),
                        "mem" | "%mem" => out.push_str(&format!("{}.{}", p.mem_tenths / 10, p.mem_tenths % 10)),
                        "comm" | "cmd" | "args" => out.push_str(p.command),
                        _ => out.push_str("-"),
                    }
                }
                out.push('\n');
            }
        }
    }
    out
}

pub fn verify_util_ps() -> u32 {
    let mut passed = 0u32;

    let stat = TaskRunState::Running.format_stat_column(true, true, true);
    if stat == "R<sl" {
        passed += 1;
    }

    let procs = [
        ProcessDescriptor {
            pid: 1,
            ppid: 0,
            user: "root",
            state: TaskRunState::SleepingInterruptible,
            high_priority: false,
            session_leader: true,
            multithreaded: false,
            cpu_tenths: 2,
            mem_tenths: 8,
            vsz_kib: 16384,
            rss_kib: 4096,
            tty: "?",
            cputime_secs: 14,
            command: "/sbin/corinit --uefi",
        },
        ProcessDescriptor {
            pid: 42,
            ppid: 1,
            user: "root",
            state: TaskRunState::Running,
            high_priority: true,
            session_leader: false,
            multithreaded: true,
            cpu_tenths: 145,
            mem_tenths: 35,
            vsz_kib: 65536,
            rss_kib: 18432,
            tty: "ttyS0",
            cputime_secs: 95,
            command: "corwm-compositor",
        },
    ];

    let aux_out = format_process_table(&procs, &PsFormatStyle::parse_args(&["aux"]));
    if aux_out.contains("USER       PID %CPU %MEM") && aux_out.contains("R<l") && aux_out.contains("14.5") {
        passed += 1;
    }

    let custom_out = format_process_table(&procs, &PsFormatStyle::parse_args(&["-eo", "pid,ppid,stat,comm"]));
    if custom_out.contains("PID PPID STAT COMM\n1 0 Ss /sbin/corinit --uefi\n42 1 R<l corwm-compositor\n") {
        passed += 1;
    }

    passed
}
