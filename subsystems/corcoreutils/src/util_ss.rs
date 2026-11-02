//! CorOS Userland Coreutil: `ss`
//! Modern `iproute2` socket statistics filter & formatter supporting:
//! - `-t` (TCP sockets), `-u` (UDP sockets), `-a` (all states), `-l` (listening only)
//! - `-s` summary statistics counter (`Total`, `TCP: estab/closed/timewait`, `UDP`)
//! - `Netid`, `State` (`ESTAB`, `LISTEN`, `UNCONN`, `TIME-WAIT`), `Recv-Q`, `Send-Q`, `Local Address:Port`, `Peer Address:Port`

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsState {
    Estab,
    Listen,
    Unconn,
    TimeWait,
    SynSent,
    CloseWait,
}

impl SsState {
    pub const fn as_str(self) -> &'static str {
        match self {
            SsState::Estab => "ESTAB",
            SsState::Listen => "LISTEN",
            SsState::Unconn => "UNCONN",
            SsState::TimeWait => "TIME-WAIT",
            SsState::SynSent => "SYN-SENT",
            SsState::CloseWait => "CLOSE-WAIT",
        }
    }

    pub const fn is_listening(self) -> bool {
        matches!(self, SsState::Listen | SsState::Unconn)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsFlags {
    pub tcp: bool,
    pub udp: bool,
    pub show_all: bool,
    pub listening_only: bool,
    pub summary_only: bool,
}

impl SsFlags {
    pub const fn default_flags() -> Self {
        Self {
            tcp: true,
            udp: true,
            show_all: false,
            listening_only: false,
            summary_only: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        let mut explicit_proto = false;

        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        't' => {
                            if !explicit_proto {
                                flags.udp = false;
                                explicit_proto = true;
                            }
                            flags.tcp = true;
                        }
                        'u' => {
                            if !explicit_proto {
                                flags.tcp = false;
                                explicit_proto = true;
                            }
                            flags.udp = true;
                        }
                        'a' => flags.show_all = true,
                        'l' => flags.listening_only = true,
                        's' => flags.summary_only = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Debug)]
pub struct SsSocketRecord {
    pub is_tcp: bool,
    pub state: SsState,
    pub recv_q: u32,
    pub send_q: u32,
    pub local_addr_port: &'static str,
    pub peer_addr_port: &'static str,
}

/// Formats `ss` socket statistics table or `-s` summary report.
pub fn format_ss_output(records: &[SsSocketRecord], flags: SsFlags) -> String {
    let mut out = String::new();

    if flags.summary_only {
        let total = records.len();
        let tcp_total = records.iter().filter(|r| r.is_tcp).count();
        let tcp_estab = records
            .iter()
            .filter(|r| r.is_tcp && r.state == SsState::Estab)
            .count();
        let tcp_timewait = records
            .iter()
            .filter(|r| r.is_tcp && r.state == SsState::TimeWait)
            .count();
        let udp_total = records.iter().filter(|r| !r.is_tcp).count();

        out.push_str(&format!("Total: {}\n", total));
        out.push_str(&format!(
            "TCP:   {} (estab {}, closed 0, orphaned 0, timewait {})\n",
            tcp_total, tcp_estab, tcp_timewait
        ));
        out.push_str(&format!("UDP:   {}\n", udp_total));
        return out;
    }

    out.push_str("Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port\n");
    for rec in records {
        if rec.is_tcp && !flags.tcp {
            continue;
        }
        if !rec.is_tcp && !flags.udp {
            continue;
        }
        if flags.listening_only && !rec.state.is_listening() {
            continue;
        }
        if !flags.show_all && !flags.listening_only && rec.state.is_listening() {
            continue;
        }

        let netid = if rec.is_tcp { "tcp" } else { "udp" };
        out.push_str(&format!(
            "{:<6} {:<10} {:>6} {:>6} {:<32} {}\n",
            netid,
            rec.state.as_str(),
            rec.recv_q,
            rec.send_q,
            rec.local_addr_port,
            rec.peer_addr_port
        ));
    }

    out
}

pub fn verify_util_ss() -> u32 {
    let mut passed = 0u32;

    let sample = [
        SsSocketRecord {
            is_tcp: true,
            state: SsState::Listen,
            recv_q: 0,
            send_q: 128,
            local_addr_port: "0.0.0.0:80",
            peer_addr_port: "0.0.0.0:*",
        },
        SsSocketRecord {
            is_tcp: true,
            state: SsState::Estab,
            recv_q: 0,
            send_q: 0,
            local_addr_port: "10.0.2.15:49152",
            peer_addr_port: "93.184.216.34:443",
        },
        SsSocketRecord {
            is_tcp: false,
            state: SsState::Unconn,
            recv_q: 0,
            send_q: 0,
            local_addr_port: "0.0.0.0:68",
            peer_addr_port: "0.0.0.0:*",
        },
    ];

    let summary = format_ss_output(&sample, SsFlags::parse_args(&["-s"]));
    if summary.contains("Total: 3")
        && summary.contains("TCP:   2 (estab 1, closed 0, orphaned 0, timewait 0)")
        && summary.contains("UDP:   1")
    {
        passed += 1;
    }

    let tcp_listen = format_ss_output(&sample, SsFlags::parse_args(&["-tl"]));
    if tcp_listen.contains("0.0.0.0:80") && !tcp_listen.contains("93.184.216.34:443") && !tcp_listen.contains("0.0.0.0:68") {
        passed += 1;
    }

    let all_tcp = format_ss_output(&sample, SsFlags::parse_args(&["-ta"]));
    if all_tcp.contains("0.0.0.0:80") && all_tcp.contains("93.184.216.34:443") && !all_tcp.contains("udp") {
        passed += 1;
    }

    passed
}
