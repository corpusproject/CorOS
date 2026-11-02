//! Kernel Network Diagnostic Formatter (`ip addr`, `ip route`, `ss -tulpn`, `netstat -rn`).

use crate::bsd_sockets::{SocketAddrV4, SocketHandleTable, SocketKind, SocketState};
use crate::ethernet_mac::MacAddress;
use crate::ipv4_routing::{Ipv4Addr, Ipv4RoutingTable, RouteNextHop};
use crate::ipv6_core::Ipv6Addr;
use crate::loopback_if::InterfaceStats;
use alloc::fmt::Write;
use alloc::string::String;

/// Snapshot of a kernel network interface for `ip addr` diagnostic reporting.
#[derive(Clone, Debug)]
pub struct NetIfSnapshot {
    pub index: u16,
    pub name: &'static str,
    pub mtu: usize,
    pub admin_up: bool,
    pub is_loopback: bool,
    pub mac: MacAddress,
    pub ipv4: Ipv4Addr,
    pub ipv4_prefix: u8,
    pub ipv6: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub stats: InterfaceStats,
}

/// Formats a slice of `NetIfSnapshot` entries in Linux `ip addr show` output format.
pub fn format_ip_addr(interfaces: &[NetIfSnapshot]) -> String {
    let mut out = String::new();
    for iface in interfaces {
        let flags = match (iface.is_loopback, iface.admin_up) {
            (true, true) => "LOOPBACK,UP,LOWER_UP",
            (true, false) => "LOOPBACK",
            (false, true) => "BROADCAST,MULTICAST,UP,LOWER_UP",
            (false, false) => "BROADCAST,MULTICAST",
        };
        let state = if iface.admin_up { "UNKNOWN" } else { "DOWN" };
        let link_kind = if iface.is_loopback {
            "link/loopback"
        } else {
            "link/ether"
        };
        let _ = writeln!(
            out,
            "{}: {}: <{}> mtu {} state {}",
            iface.index, iface.name, flags, iface.mtu, state
        );
        let _ = writeln!(out, "    {} {}", link_kind, iface.mac);
        let _ = writeln!(
            out,
            "    inet {}/{} scope {} {}",
            iface.ipv4,
            iface.ipv4_prefix,
            if iface.is_loopback { "host" } else { "global" },
            iface.name
        );
        let _ = writeln!(
            out,
            "    inet6 {}/{} scope {}",
            iface.ipv6,
            iface.ipv6_prefix,
            if iface.is_loopback { "host" } else { "link" }
        );
        let _ = writeln!(
            out,
            "    RX: bytes {} packets {}  TX: bytes {} packets {} dropped {}",
            iface.stats.rx_bytes,
            iface.stats.rx_packets,
            iface.stats.tx_bytes,
            iface.stats.tx_packets,
            iface.stats.tx_dropped
        );
    }
    out
}

/// Formats an `Ipv4RoutingTable` in Linux `ip route show` format.
pub fn format_ip_route(fib: &Ipv4RoutingTable, if_name_lookup: fn(u16) -> &'static str) -> String {
    let mut out = String::new();
    for route in fib.entries() {
        let dev = if_name_lookup(route.interface_id);
        if route.prefix_len == 0 {
            match route.next_hop {
                RouteNextHop::Gateway(gw) => {
                    let _ = writeln!(out, "default via {} dev {} metric {}", gw, dev, route.metric);
                }
                RouteNextHop::Connected => {
                    let _ = writeln!(out, "default dev {} scope link metric {}", dev, route.metric);
                }
            }
        } else {
            match route.next_hop {
                RouteNextHop::Gateway(gw) => {
                    let _ = writeln!(
                        out,
                        "{}/{} via {} dev {} metric {}",
                        route.prefix, route.prefix_len, gw, dev, route.metric
                    );
                }
                RouteNextHop::Connected => {
                    let _ = writeln!(
                        out,
                        "{}/{} dev {} proto kernel scope link metric {}",
                        route.prefix, route.prefix_len, dev, route.metric
                    );
                }
            }
        }
    }
    out
}

/// Formats an `Ipv4RoutingTable` in traditional BSD/UNIX `netstat -rn` tabular format.
pub fn format_netstat_rn(fib: &Ipv4RoutingTable, if_name_lookup: fn(u16) -> &'static str) -> String {
    let mut out = String::from(
        "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Iface\n",
    );
    for route in fib.entries() {
        let mask = Ipv4Addr::from_u32(crate::ipv4_routing::RouteEntry::prefix_mask(route.prefix_len));
        let (gw, flags) = match route.next_hop {
            RouteNextHop::Connected => (Ipv4Addr::UNSPECIFIED, if route.prefix_len == 32 { "UH" } else { "U" }),
            RouteNextHop::Gateway(g) => (g, if route.prefix_len == 32 { "UGH" } else { "UG" }),
        };
        let dev = if_name_lookup(route.interface_id);
        let _ = writeln!(
            out,
            "{:<15} {:<15} {:<15} {:<5} {:<6} {}",
            alloc::format!("{}", route.prefix),
            alloc::format!("{}", gw),
            alloc::format!("{}", mask),
            flags,
            route.metric,
            dev
        );
    }
    out
}

/// Formats active sockets in `SocketHandleTable` in `ss -tulpn` diagnostic format.
pub fn format_ss_tulpn(sockets: &SocketHandleTable) -> String {
    let mut out = String::from(
        "Netid  State      Recv-Q Send-Q Local Address:Port   Peer Address:Port\n",
    );
    for s in sockets.sockets() {
        if s.state == SocketState::Closed {
            continue;
        }
        let netid = match s.kind {
            SocketKind::Stream => "tcp",
            SocketKind::Datagram => "udp",
            SocketKind::Raw => "raw",
        };
        let state_str = match s.state {
            SocketState::Unbound => "UNCONN",
            SocketState::Bound => "UNCONN",
            SocketState::Listening => "LISTEN",
            SocketState::Connecting => "SYN-SENT",
            SocketState::Connected => "ESTAB",
            SocketState::Closed => "CLOSED",
        };
        let local = s
            .local_addr
            .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let peer = s
            .remote_addr
            .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let _ = writeln!(
            out,
            "{:<6} {:<10} {:<6} {:<6} {:<20} {}",
            netid,
            state_str,
            s.rx_buf.readable_bytes(),
            s.tx_buf.readable_bytes(),
            alloc::format!("{}:{}", local.ip, local.port),
            alloc::format!("{}:{}", peer.ip, peer.port),
        );
    }
    out
}

/// Runs self-tests for the `netlink_diag` module.
pub fn verify_net_netlink_diag() -> u32 {
    let mut passed = 0u32;

    let snap = [NetIfSnapshot {
        index: 1,
        name: "lo",
        mtu: 65_536,
        admin_up: true,
        is_loopback: true,
        mac: MacAddress::ZERO,
        ipv4: Ipv4Addr::LOCALHOST,
        ipv4_prefix: 8,
        ipv6: Ipv6Addr::LOCALHOST,
        ipv6_prefix: 128,
        stats: InterfaceStats {
            rx_packets: 12,
            rx_bytes: 960,
            tx_packets: 12,
            tx_bytes: 960,
            tx_dropped: 0,
        },
    }];

    // 1. Verify `ip addr` output formatting.
    let ip_a = format_ip_addr(&snap);
    if ip_a.contains("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536")
        && ip_a.contains("inet 127.0.0.1/8 scope host lo")
    {
        passed += 1;
    }

    // 2. Verify `ip route` and `netstat -rn` output formatting.
    let mut fib = Ipv4RoutingTable::new();
    fib.upsert_route(crate::ipv4_routing::RouteEntry::new(
        Ipv4Addr::UNSPECIFIED,
        0,
        RouteNextHop::Gateway(Ipv4Addr::new(10, 0, 2, 2)),
        2,
        100,
    ));
    fib.upsert_route(crate::ipv4_routing::RouteEntry::new(
        Ipv4Addr::new(10, 0, 2, 0),
        24,
        RouteNextHop::Connected,
        2,
        10,
    ));
    fn lookup_if(id: u16) -> &'static str {
        if id == 1 {
            "lo"
        } else {
            "eth0"
        }
    }
    let ip_r = format_ip_route(&fib, lookup_if);
    let ns_r = format_netstat_rn(&fib, lookup_if);
    if ip_r.contains("default via 10.0.2.2 dev eth0 metric 100")
        && ip_r.contains("10.0.2.0/24 dev eth0 proto kernel scope link metric 10")
        && ns_r.contains("255.255.255.0")
    {
        passed += 1;
    }

    // 3. Verify `ss -tulpn` output formatting on active listening and UDP sockets.
    let mut socks = SocketHandleTable::new();
    let tcp_fd = socks.socket(
        crate::bsd_sockets::SocketDomain::Inet,
        SocketKind::Stream,
    );
    let _ = socks.bind(tcp_fd, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443));
    let _ = socks.listen(tcp_fd, 32);

    let ss_out = format_ss_tulpn(&socks);
    if ss_out.contains("tcp") && ss_out.contains("LISTEN") && ss_out.contains("0.0.0.0:443") {
        passed += 1;
    }

    passed
}
