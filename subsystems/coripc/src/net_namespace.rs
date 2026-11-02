//! Network Namespace (`NetNamespace`) container with isolated network interfaces,
//! IPv4 routing table (Longest Prefix Match), and Virtual Ethernet (`VethPair`)
//! cross-namespace bidirectional packet queue with RX/TX byte & packet counters.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

/// Errors returned by Network Namespace and `veth` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetNsError {
    NamespaceNotFound,
    InterfaceNotFound,
    VethPairNotFound,
    InterfaceDown,
    QueueFull,
    NoRouteToHost,
}

/// Statistics tracked per network interface (`rtnl_link_stats64` equivalent).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetIfStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// Network interface descriptor inside a `NetNamespace`.
#[derive(Clone, Debug)]
pub struct NetInterface {
    pub ifindex: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub prefix_len: u8,
    pub mtu: u16,
    pub is_up: bool,
    pub is_loopback: bool,
    /// Optional `(veth_pair_id, endpoint_side)` if this interface is one end of a `VethPair`.
    pub veth_binding: Option<(u32, VethSide)>,
    pub stats: NetIfStats,
}

/// IPv4 route entry inside a `NetNamespace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Route {
    pub dest_network: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub out_ifindex: u32,
    pub metric: u32,
}

impl Ipv4Route {
    #[inline]
    pub fn matches(&self, dst_ip: [u8; 4]) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let shift = 32u32.saturating_sub(self.prefix_len as u32);
        let mask = if shift >= 32 { 0 } else { !0u32 << shift };
        let dst_u32 = u32::from_be_bytes(dst_ip);
        let net_u32 = u32::from_be_bytes(self.dest_network);
        (dst_u32 & mask) == (net_u32 & mask)
    }
}

/// Isolated Network Namespace (`CLONE_NEWNET`).
pub struct NetNamespace {
    pub id: u32,
    pub interfaces: BTreeMap<u32, NetInterface>,
    pub routes: Vec<Ipv4Route>,
    next_ifindex: u32,
}

impl NetNamespace {
    /// Create a fresh Network Namespace pre-populated with an isolated `lo` (`127.0.0.1/8`) interface.
    pub fn new(id: u32) -> Self {
        let mut interfaces = BTreeMap::new();
        interfaces.insert(
            1,
            NetInterface {
                ifindex: 1,
                name: String::from("lo"),
                mac: [0, 0, 0, 0, 0, 0],
                ipv4_addr: [127, 0, 0, 1],
                prefix_len: 8,
                mtu: 65535,
                is_up: true,
                is_loopback: true,
                veth_binding: None,
                stats: NetIfStats::default(),
            },
        );
        let routes = alloc::vec![Ipv4Route {
            dest_network: [127, 0, 0, 0],
            prefix_len: 8,
            gateway: None,
            out_ifindex: 1,
            metric: 0,
        }];
        Self {
            id,
            interfaces,
            routes,
            next_ifindex: 2,
        }
    }

    pub fn add_interface(
        &mut self,
        name: &str,
        mac: [u8; 6],
        ipv4_addr: [u8; 4],
        prefix_len: u8,
        veth_binding: Option<(u32, VethSide)>,
    ) -> u32 {
        let ifindex = self.next_ifindex;
        self.next_ifindex += 1;
        self.interfaces.insert(
            ifindex,
            NetInterface {
                ifindex,
                name: String::from(name),
                mac,
                ipv4_addr,
                prefix_len,
                mtu: 1500,
                is_up: true,
                is_loopback: false,
                veth_binding,
                stats: NetIfStats::default(),
            },
        );
        if prefix_len > 0 {
            let shift = 32u32.saturating_sub(prefix_len as u32);
            let mask = if shift >= 32 { 0 } else { !0u32 << shift };
            let net_u32 = u32::from_be_bytes(ipv4_addr) & mask;
            self.routes.push(Ipv4Route {
                dest_network: net_u32.to_be_bytes(),
                prefix_len,
                gateway: None,
                out_ifindex: ifindex,
                metric: 100,
            });
        }
        ifindex
    }

    pub fn add_route(&mut self, route: Ipv4Route) {
        self.routes.push(route);
    }

    /// Perform Longest Prefix Match (LPM) routing lookup with metric tie-breaking.
    pub fn lookup_route(&self, dst_ip: [u8; 4]) -> Option<Ipv4Route> {
        let mut best: Option<Ipv4Route> = None;
        for route in &self.routes {
            if route.matches(dst_ip) {
                let replace = match best {
                    None => true,
                    Some(cur) => {
                        route.prefix_len > cur.prefix_len
                            || (route.prefix_len == cur.prefix_len && route.metric < cur.metric)
                    }
                };
                if replace {
                    best = Some(*route);
                }
            }
        }
        best
    }
}

/// Endpoint side selector of a `VethPair`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VethSide {
    Alpha,
    Beta,
}

impl VethSide {
    #[inline]
    pub const fn peer(self) -> Self {
        match self {
            Self::Alpha => Self::Beta,
            Self::Beta => Self::Alpha,
        }
    }
}

/// Network frame transmitted over a `VethPair`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPacket {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub payload: Vec<u8>,
}

/// Virtual Ethernet (`veth`) bidirectional cross-namespace tunnel.
pub struct VethPair {
    pub id: u32,
    pub alpha_ns_id: u32,
    pub alpha_ifindex: u32,
    pub beta_ns_id: u32,
    pub beta_ifindex: u32,
    pub max_queue_depth: usize,
    /// Frames sent from Alpha waiting to be received by Beta.
    pub alpha_to_beta_queue: VecDeque<NetPacket>,
    /// Frames sent from Beta waiting to be received by Alpha.
    pub beta_to_alpha_queue: VecDeque<NetPacket>,
}

/// Multi-namespace network fabric managing `NetNamespace` instances and `VethPair` links.
pub struct NetNamespaceFabric {
    namespaces: BTreeMap<u32, NetNamespace>,
    veth_pairs: BTreeMap<u32, VethPair>,
    next_ns_id: u32,
    next_veth_id: u32,
}

impl Default for NetNamespaceFabric {
    fn default() -> Self {
        Self::new()
    }
}

impl NetNamespaceFabric {
    pub const INIT_NET_NS: u32 = 1;

    pub fn new() -> Self {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(Self::INIT_NET_NS, NetNamespace::new(Self::INIT_NET_NS));
        Self {
            namespaces,
            veth_pairs: BTreeMap::new(),
            next_ns_id: 2,
            next_veth_id: 1,
        }
    }

    pub fn create_net_namespace(&mut self) -> u32 {
        let id = self.next_ns_id;
        self.next_ns_id += 1;
        self.namespaces.insert(id, NetNamespace::new(id));
        id
    }

    pub fn get_namespace(&self, ns_id: u32) -> Option<&NetNamespace> {
        self.namespaces.get(&ns_id)
    }

    /// Create a connected `VethPair` bridging `alpha_ns_id` and `beta_ns_id`.
    /// Returns `(veth_pair_id, alpha_ifindex, beta_ifindex)`.
    pub fn create_veth_pair(
        &mut self,
        alpha_ns_id: u32,
        alpha_name: &str,
        alpha_ip: [u8; 4],
        beta_ns_id: u32,
        beta_name: &str,
        beta_ip: [u8; 4],
        prefix_len: u8,
    ) -> Result<(u32, u32, u32), NetNsError> {
        if !self.namespaces.contains_key(&alpha_ns_id)
            || !self.namespaces.contains_key(&beta_ns_id)
        {
            return Err(NetNsError::NamespaceNotFound);
        }

        let veth_id = self.next_veth_id;
        self.next_veth_id += 1;

        let alpha_if = self
            .namespaces
            .get_mut(&alpha_ns_id)
            .ok_or(NetNsError::NamespaceNotFound)?
            .add_interface(
                alpha_name,
                [0x02, 0x42, 0xAC, 0x11, 0x00, (veth_id as u8) * 2],
                alpha_ip,
                prefix_len,
                Some((veth_id, VethSide::Alpha)),
            );

        let beta_if = self
            .namespaces
            .get_mut(&beta_ns_id)
            .ok_or(NetNsError::NamespaceNotFound)?
            .add_interface(
                beta_name,
                [0x02, 0x42, 0xAC, 0x11, 0x00, (veth_id as u8) * 2 + 1],
                beta_ip,
                prefix_len,
                Some((veth_id, VethSide::Beta)),
            );

        self.veth_pairs.insert(
            veth_id,
            VethPair {
                id: veth_id,
                alpha_ns_id,
                alpha_ifindex: alpha_if,
                beta_ns_id,
                beta_ifindex: beta_if,
                max_queue_depth: 256,
                alpha_to_beta_queue: VecDeque::new(),
                beta_to_alpha_queue: VecDeque::new(),
            },
        );
        Ok((veth_id, alpha_if, beta_if))
    }

    /// Transmit a packet from `src_ns_id` using LPM routing and enqueue it into the
    /// peer namespace's `VethPair` queue, updating both TX and RX counters.
    pub fn transmit_packet(
        &mut self,
        src_ns_id: u32,
        packet: NetPacket,
    ) -> Result<(), NetNsError> {
        let (out_ifindex, veth_binding, is_up) = {
            let ns = self
                .namespaces
                .get(&src_ns_id)
                .ok_or(NetNsError::NamespaceNotFound)?;
            let route = ns
                .lookup_route(packet.dst_ip)
                .ok_or(NetNsError::NoRouteToHost)?;
            let iface = ns
                .interfaces
                .get(&route.out_ifindex)
                .ok_or(NetNsError::InterfaceNotFound)?;
            (iface.ifindex, iface.veth_binding, iface.is_up)
        };

        if !is_up {
            return Err(NetNsError::InterfaceDown);
        }

        let pkt_bytes = (packet.payload.len() + 20) as u64;

        let (veth_id, side) = match veth_binding {
            Some(b) => b,
            None => {
                // Loopback delivery inside the same namespace.
                if let Some(ns) = self.namespaces.get_mut(&src_ns_id) {
                    if let Some(iface) = ns.interfaces.get_mut(&out_ifindex) {
                        iface.stats.tx_packets += 1;
                        iface.stats.tx_bytes += pkt_bytes;
                        iface.stats.rx_packets += 1;
                        iface.stats.rx_bytes += pkt_bytes;
                    }
                }
                return Ok(());
            }
        };

        let (peer_ns_id, peer_ifindex) = {
            let pair = self
                .veth_pairs
                .get_mut(&veth_id)
                .ok_or(NetNsError::VethPairNotFound)?;
            let queue = match side {
                VethSide::Alpha => &mut pair.alpha_to_beta_queue,
                VethSide::Beta => &mut pair.beta_to_alpha_queue,
            };
            if queue.len() >= pair.max_queue_depth {
                if let Some(ns) = self.namespaces.get_mut(&src_ns_id) {
                    if let Some(iface) = ns.interfaces.get_mut(&out_ifindex) {
                        iface.stats.tx_dropped += 1;
                    }
                }
                return Err(NetNsError::QueueFull);
            }
            queue.push_back(packet);
            match side {
                VethSide::Alpha => (pair.beta_ns_id, pair.beta_ifindex),
                VethSide::Beta => (pair.alpha_ns_id, pair.alpha_ifindex),
            }
        };

        if let Some(ns) = self.namespaces.get_mut(&src_ns_id) {
            if let Some(iface) = ns.interfaces.get_mut(&out_ifindex) {
                iface.stats.tx_packets += 1;
                iface.stats.tx_bytes += pkt_bytes;
            }
        }
        if let Some(peer_ns) = self.namespaces.get_mut(&peer_ns_id) {
            if let Some(peer_iface) = peer_ns.interfaces.get_mut(&peer_ifindex) {
                peer_iface.stats.rx_packets += 1;
                peer_iface.stats.rx_bytes += pkt_bytes;
            }
        }
        Ok(())
    }

    /// Dequeue the next incoming packet on `veth_id` destined for `receiver_side`.
    pub fn receive_veth_packet(
        &mut self,
        veth_id: u32,
        receiver_side: VethSide,
    ) -> Result<Option<NetPacket>, NetNsError> {
        let pair = self
            .veth_pairs
            .get_mut(&veth_id)
            .ok_or(NetNsError::VethPairNotFound)?;
        let queue = match receiver_side {
            VethSide::Alpha => &mut pair.beta_to_alpha_queue,
            VethSide::Beta => &mut pair.alpha_to_beta_queue,
        };
        Ok(queue.pop_front())
    }
}

/// Self-test exercising `NetNamespace` routing isolation and bidirectional `VethPair` packet exchange.
pub fn self_test() -> bool {
    let mut fabric = NetNamespaceFabric::new();
    let container_ns = fabric.create_net_namespace();

    let (veth_id, host_if, cont_if) = match fabric.create_veth_pair(
        NetNamespaceFabric::INIT_NET_NS,
        "veth-host",
        [10, 200, 1, 1],
        container_ns,
        "eth0",
        [10, 200, 1, 2],
        24,
    ) {
        Ok(res) => res,
        Err(_) => return false,
    };

    // Transmit a request from host namespace to container (10.200.1.2).
    let req = NetPacket {
        src_ip: [10, 200, 1, 1],
        dst_ip: [10, 200, 1, 2],
        payload: alloc::vec![0xCA, 0xFE, 0xBA, 0xBE],
    };
    if fabric
        .transmit_packet(NetNamespaceFabric::INIT_NET_NS, req.clone())
        .is_err()
    {
        return false;
    }

    // Receive on Beta (container side) and reply to Alpha (host side).
    let received = match fabric.receive_veth_packet(veth_id, VethSide::Beta) {
        Ok(Some(pkt)) => pkt,
        _ => return false,
    };
    if received != req {
        return false;
    }

    let reply = NetPacket {
        src_ip: [10, 200, 1, 2],
        dst_ip: [10, 200, 1, 1],
        payload: alloc::vec![0xAC, 0xDC],
    };
    if fabric.transmit_packet(container_ns, reply).is_err() {
        return false;
    }

    // Verify TX/RX packet and byte counters on both ends.
    let host_stats = match fabric
        .get_namespace(NetNamespaceFabric::INIT_NET_NS)
        .and_then(|ns| ns.interfaces.get(&host_if))
    {
        Some(i) => i.stats,
        None => return false,
    };
    let cont_stats = match fabric
        .get_namespace(container_ns)
        .and_then(|ns| ns.interfaces.get(&cont_if))
    {
        Some(i) => i.stats,
        None => return false,
    };

    host_stats.tx_packets == 1
        && host_stats.rx_packets == 1
        && host_stats.tx_bytes == 24
        && cont_stats.rx_packets == 1
        && cont_stats.tx_packets == 1
        && cont_stats.rx_bytes == 24
}
