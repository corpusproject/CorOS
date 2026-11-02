//! CorOS Userland Coreutil: `netstat`
//! Active socket connection table (`netstat -tulnp`), legacy kernel IPv4 routing table (`netstat -rn`),
//! and network interface packet counter summary (`netstat -i`).

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetstatMode {
    Sockets,
    RoutingTable,
    Interfaces,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetstatFlags {
    pub mode: NetstatMode,
    pub show_tcp: bool,
    pub show_udp: bool,
    pub listening_only: bool,
    pub numeric_hosts: bool,
    pub show_programs: bool,
}

impl NetstatFlags {
    pub const fn default_flags() -> Self {
        Self {
            mode: NetstatMode::Sockets,
            show_tcp: true,
            show_udp: true,
            listening_only: false,
            numeric_hosts: false,
            show_programs: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        let mut explicit_proto = false;

        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'r' => flags.mode = NetstatMode::RoutingTable,
                        'i' => flags.mode = NetstatMode::Interfaces,
                        't' => {
                            if !explicit_proto {
                                flags.show_udp = false;
                                explicit_proto = true;
                            }
                            flags.show_tcp = true;
                        }
                        'u' => {
                            if !explicit_proto {
                                flags.show_tcp = false;
                                explicit_proto = true;
                            }
                            flags.show_udp = true;
                        }
                        'l' => flags.listening_only = true,
                        'a' => flags.listening_only = false,
                        'n' => flags.numeric_hosts = true,
                        'p' => flags.show_programs = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProto {
    Tcp,
    Udp,
}

impl TransportProto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetstatSocketRow {
    pub proto: TransportProto,
    pub recv_q: u32,
    pub send_q: u32,
    pub local_endpoint: &'static str,
    pub remote_endpoint: &'static str,
    pub state: &'static str,
    pub pid: u32,
    pub program: &'static str,
}

#[derive(Clone, Debug)]
pub struct NetstatRouteRow {
    pub destination: &'static str,
    pub gateway: &'static str,
    pub genmask: &'static str,
    pub flags: &'static str,
    pub metric: u32,
    pub iface: &'static str,
}

#[derive(Clone, Debug)]
pub struct NetstatIfaceRow {
    pub iface: &'static str,
    pub mtu: u32,
    pub rx_ok: u64,
    pub rx_err: u64,
    pub tx_ok: u64,
    pub tx_err: u64,
    pub flag_code: &'static str,
}

/// Renders the requested `netstat` view (`-tulnp` sockets, `-rn` routing table, or `-i` interfaces).
pub fn format_netstat_output(
    flags: NetstatFlags,
    sockets: &[NetstatSocketRow],
    routes: &[NetstatRouteRow],
    ifaces: &[NetstatIfaceRow],
) -> String {
    let mut out = String::new();

    match flags.mode {
        NetstatMode::Sockets => {
            out.push_str("Active Internet connections (servers and established)\n");
            if flags.show_programs {
                out.push_str("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n");
            } else {
                out.push_str("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");
            }

            for s in sockets {
                if s.proto == TransportProto::Tcp && !flags.show_tcp {
                    continue;
                }
                if s.proto == TransportProto::Udp && !flags.show_udp {
                    continue;
                }
                if flags.listening_only && s.state != "LISTEN" && s.state != "UNCONN" {
                    continue;
                }

                if flags.show_programs {
                    out.push_str(&format!(
                        "{:<5} {:>6} {:>6} {:<23} {:<23} {:<11} {}/{}\n",
                        s.proto.as_str(),
                        s.recv_q,
                        s.send_q,
                        s.local_endpoint,
                        s.remote_endpoint,
                        s.state,
                        s.pid,
                        s.program
                    ));
                } else {
                    out.push_str(&format!(
                        "{:<5} {:>6} {:>6} {:<23} {:<23} {}\n",
                        s.proto.as_str(),
                        s.recv_q,
                        s.send_q,
                        s.local_endpoint,
                        s.remote_endpoint,
                        s.state
                    ));
                }
            }
        }
        NetstatMode::RoutingTable => {
            out.push_str("Kernel IP routing table\n");
            out.push_str("Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n");
            for r in routes {
                out.push_str(&format!(
                    "{:<15} {:<15} {:<15} {:<5}     0 0          0 {}\n",
                    r.destination, r.gateway, r.genmask, r.flags, r.iface
                ));
            }
        }
        NetstatMode::Interfaces => {
            out.push_str("Kernel Interface table\n");
            out.push_str("Iface      MTU    RX-OK RX-ERR    TX-OK TX-ERR Flg\n");
            for i in ifaces {
                out.push_str(&format!(
                    "{:<8} {:>5} {:>8} {:>6} {:>8} {:>6} {}\n",
                    i.iface, i.mtu, i.rx_ok, i.rx_err, i.tx_ok, i.tx_err, i.flag_code
                ));
            }
        }
    }

    out
}

pub fn verify_util_netstat() -> u32 {
    let mut passed = 0u32;

    let sockets = [
        NetstatSocketRow {
            proto: TransportProto::Tcp,
            recv_q: 0,
            send_q: 0,
            local_endpoint: "0.0.0.0:22",
            remote_endpoint: "0.0.0.0:*",
            state: "LISTEN",
            pid: 55,
            program: "corsshd",
        },
        NetstatSocketRow {
            proto: TransportProto::Tcp,
            recv_q: 0,
            send_q: 128,
            local_endpoint: "10.0.2.15:22",
            remote_endpoint: "10.0.2.2:54322",
            state: "ESTABLISHED",
            pid: 56,
            program: "corsshd",
        },
    ];

    let routes = [NetstatRouteRow {
        destination: "0.0.0.0",
        gateway: "10.0.2.2",
        genmask: "0.0.0.0",
        flags: "UG",
        metric: 100,
        iface: "eth0",
    }];

    let ifaces = [NetstatIfaceRow {
        iface: "eth0",
        mtu: 1500,
        rx_ok: 1420,
        rx_err: 0,
        tx_ok: 980,
        tx_err: 0,
        flag_code: "BMRU",
    }];

    let tulnp = format_netstat_output(NetstatFlags::parse_args(&["-tulnp"]), &sockets, &routes, &ifaces);
    if tulnp.contains("0.0.0.0:22") && tulnp.contains("55/corsshd") && !tulnp.contains("ESTABLISHED") {
        passed += 1;
    }

    let rn = format_netstat_output(NetstatFlags::parse_args(&["-rn"]), &sockets, &routes, &ifaces);
    if rn.contains("Kernel IP routing table") && rn.contains("0.0.0.0         10.0.2.2        0.0.0.0         UG") {
        passed += 1;
    }

    let iface_out = format_netstat_output(NetstatFlags::parse_args(&["-i"]), &sockets, &routes, &ifaces);
    if iface_out.contains("eth0      1500     1420      0      980      0 BMRU") {
        passed += 1;
    }

    passed
}
