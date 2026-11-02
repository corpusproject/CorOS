//! CorOS Userland Coreutil: `ip`
//! Modern `iproute2` network configuration & telemetry engine supporting:
//! - `ip addr` / `ip a`: interface IPv4 CIDR, broadcast address, MAC address, and link flags
//! - `ip link` / `ip l`: L2 MTU, operational state (`UP`, `LOWER_UP`), and MAC hardware address
//! - `ip route` / `ip r`: kernel L3 routing table (`default via ...`, subnet prefix routes)
//! - `ip neigh` / `ip n`: ARP / NDISC neighbor cache (`REACHABLE`, `STALE`, `PERMANENT`)

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpSubcommand {
    Address,
    Link,
    Route,
    Neighbor,
}

impl IpSubcommand {
    pub fn parse_args(args: &[&str]) -> Self {
        for arg in args {
            if arg.starts_with('-') {
                continue;
            }
            return match *arg {
                "a" | "addr" | "address" => Self::Address,
                "l" | "link" => Self::Link,
                "r" | "route" => Self::Route,
                "n" | "neigh" | "neighbor" | "neighbour" => Self::Neighbor,
                _ => Self::Address,
            };
        }
        Self::Address
    }
}

#[derive(Clone, Debug)]
pub struct NetInterfaceRecord {
    pub ifindex: u32,
    pub name: &'static str,
    pub is_loopback: bool,
    pub is_up: bool,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub prefix_len: u8,
    pub broadcast: [u8; 4],
}

#[derive(Clone, Debug)]
pub struct IpRouteRecord {
    pub is_default: bool,
    pub dest_prefix: &'static str,
    pub gateway: Option<[u8; 4]>,
    pub dev: &'static str,
    pub src_ip: [u8; 4],
    pub metric: u32,
}

#[derive(Clone, Debug)]
pub struct IpNeighborRecord {
    pub ipv4: [u8; 4],
    pub dev: &'static str,
    pub lladdr: [u8; 6],
    pub nud_state: &'static str,
}

pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn format_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Computes the IPv4 broadcast address from an IPv4 address and CIDR prefix length (`0..=32`).
pub const fn compute_ipv4_broadcast(ip: [u8; 4], prefix_len: u8) -> [u8; 4] {
    let raw = u32::from_be_bytes(ip);
    let mask = if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        0xFFFF_FFFF
    } else {
        !0u32 << (32 - prefix_len)
    };
    let bcast = raw | !mask;
    bcast.to_be_bytes()
}

/// Executes `ip addr`, `ip link`, `ip route`, or `ip neigh` and returns the formatted `iproute2` output.
pub fn execute_ip_command(
    subcmd: IpSubcommand,
    ifaces: &[NetInterfaceRecord],
    routes: &[IpRouteRecord],
    neighbors: &[IpNeighborRecord],
) -> String {
    let mut out = String::new();

    match subcmd {
        IpSubcommand::Link | IpSubcommand::Address => {
            for iface in ifaces {
                let flags_str = if iface.is_loopback {
                    "LOOPBACK,UP,LOWER_UP"
                } else if iface.is_up {
                    "BROADCAST,MULTICAST,UP,LOWER_UP"
                } else {
                    "BROADCAST,MULTICAST"
                };
                let state_str = if iface.is_loopback {
                    "UNKNOWN"
                } else if iface.is_up {
                    "UP"
                } else {
                    "DOWN"
                };
                out.push_str(&format!(
                    "{}: {}: <{}> mtu {} state {}\n",
                    iface.ifindex, iface.name, flags_str, iface.mtu, state_str
                ));
                let link_type = if iface.is_loopback { "loopback" } else { "ether" };
                out.push_str(&format!("    link/{} {}\n", link_type, format_mac(iface.mac)));

                if subcmd == IpSubcommand::Address {
                    let scope = if iface.is_loopback { "host" } else { "global" };
                    out.push_str(&format!(
                        "    inet {}/{} brd {} scope {} {}\n",
                        format_ipv4(iface.ipv4_addr),
                        iface.prefix_len,
                        format_ipv4(iface.broadcast),
                        scope,
                        iface.name
                    ));
                }
            }
        }
        IpSubcommand::Route => {
            for r in routes {
                if r.is_default {
                    if let Some(gw) = r.gateway {
                        out.push_str(&format!(
                            "default via {} dev {} proto dhcp src {} metric {}\n",
                            format_ipv4(gw),
                            r.dev,
                            format_ipv4(r.src_ip),
                            r.metric
                        ));
                    }
                } else {
                    out.push_str(&format!(
                        "{} dev {} proto kernel scope link src {} metric {}\n",
                        r.dest_prefix,
                        r.dev,
                        format_ipv4(r.src_ip),
                        r.metric
                    ));
                }
            }
        }
        IpSubcommand::Neighbor => {
            for n in neighbors {
                out.push_str(&format!(
                    "{} dev {} lladdr {} {}\n",
                    format_ipv4(n.ipv4),
                    n.dev,
                    format_mac(n.lladdr),
                    n.nud_state
                ));
            }
        }
    }

    out
}

pub fn verify_util_ip() -> u32 {
    let mut passed = 0u32;

    if compute_ipv4_broadcast([10, 0, 2, 15], 24) == [10, 0, 2, 255] {
        passed += 1;
    }

    let ifaces = [
        NetInterfaceRecord {
            ifindex: 1,
            name: "lo",
            is_loopback: true,
            is_up: true,
            mtu: 65536,
            mac: [0, 0, 0, 0, 0, 0],
            ipv4_addr: [127, 0, 0, 1],
            prefix_len: 8,
            broadcast: [127, 255, 255, 255],
        },
        NetInterfaceRecord {
            ifindex: 2,
            name: "eth0",
            is_loopback: false,
            is_up: true,
            mtu: 1500,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            ipv4_addr: [10, 0, 2, 15],
            prefix_len: 24,
            broadcast: [10, 0, 2, 255],
        },
    ];

    let routes = [
        IpRouteRecord {
            is_default: true,
            dest_prefix: "default",
            gateway: Some([10, 0, 2, 2]),
            dev: "eth0",
            src_ip: [10, 0, 2, 15],
            metric: 100,
        },
        IpRouteRecord {
            is_default: false,
            dest_prefix: "10.0.2.0/24",
            gateway: None,
            dev: "eth0",
            src_ip: [10, 0, 2, 15],
            metric: 100,
        },
    ];

    let neigh = [IpNeighborRecord {
        ipv4: [10, 0, 2, 2],
        dev: "eth0",
        lladdr: [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02],
        nud_state: "REACHABLE",
    }];

    let addr_out = execute_ip_command(IpSubcommand::parse_args(&["addr"]), &ifaces, &routes, &neigh);
    if addr_out.contains("inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0")
        && addr_out.contains("link/ether 52:54:00:12:34:56")
    {
        passed += 1;
    }

    let route_out = execute_ip_command(IpSubcommand::parse_args(&["route"]), &ifaces, &routes, &neigh);
    if route_out.contains("default via 10.0.2.2 dev eth0") && route_out.contains("10.0.2.0/24 dev eth0") {
        passed += 1;
    }

    let neigh_out = execute_ip_command(IpSubcommand::parse_args(&["neigh"]), &ifaces, &routes, &neigh);
    if neigh_out == "10.0.2.2 dev eth0 lladdr 52:55:0a:00:02:02 REACHABLE\n" {
        passed += 1;
    }

    passed
}
