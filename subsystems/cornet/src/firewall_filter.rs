//! Stateful 5-Tuple Packet-Filtering Firewall, Connection Tracking (`conntrack`), SYN Flood Rate Limiter & Source NAT Masquerading.

use crate::ipv4_routing::{Ipv4Addr, RouteEntry};
use crate::tcp_fsm::{tcp_flags, IPPROTO_TCP};
use alloc::vec::Vec;

/// Verdict returned by a firewall rule or chain evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallAction {
    /// Permit the packet through the chain.
    Accept,
    /// Silently discard the packet.
    Drop,
    /// Discard the packet and emit an ICMP Destination Unreachable / TCP RST response.
    Reject,
}

/// Netfilter-style Hook Chain (`Input`, `Forward`, `Output`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FirewallChain {
    /// Packets destined for the local host.
    Input,
    /// Packets routed through this host to another interface.
    Forward,
    /// Packets originating from local sockets.
    Output,
}

/// Canonical 5-Tuple Connection Tracking Key (`protocol, src_ip, dst_ip, src_port, dst_port`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnTrackKey {
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConnTrackKey {
    /// Returns the reverse-direction 5-tuple matching return traffic for this flow.
    #[inline]
    pub const fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

/// Lifecycle state of a tracked flow in the stateful connection tracking (`conntrack`) table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnTrackState {
    /// Initial packet or `SYN` seen in one direction only.
    New,
    /// Two-way traffic or `SYN + SYN-ACK` observed.
    Established,
    /// TCP `FIN` observed; awaiting final teardown.
    Closing,
}

/// Entry in the stateful connection tracking table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnTrackEntry {
    pub key: ConnTrackKey,
    pub state: ConnTrackState,
    pub packets_seen: u64,
    pub bytes_seen: u64,
}

/// Declarative Packet-Filtering Rule matching CIDR prefixes, protocol, and port ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallRule {
    pub chain: FirewallChain,
    pub src_prefix: Ipv4Addr,
    pub src_prefix_len: u8,
    pub dst_prefix: Ipv4Addr,
    pub dst_prefix_len: u8,
    /// `None` matches any IP protocol; `Some(p)` matches only `protocol == p`.
    pub protocol: Option<u8>,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub action: FirewallAction,
}

impl FirewallRule {
    /// Returns `true` if `key` matches all selectors in this rule.
    pub fn matches(&self, chain: FirewallChain, key: &ConnTrackKey) -> bool {
        if self.chain != chain {
            return false;
        }
        if let Some(proto) = self.protocol {
            if proto != key.protocol {
                return false;
            }
        }
        let src_mask = RouteEntry::prefix_mask(self.src_prefix_len);
        if (key.src_ip.to_u32() & src_mask) != (self.src_prefix.to_u32() & src_mask) {
            return false;
        }
        let dst_mask = RouteEntry::prefix_mask(self.dst_prefix_len);
        if (key.dst_ip.to_u32() & dst_mask) != (self.dst_prefix.to_u32() & dst_mask) {
            return false;
        }
        key.dst_port >= self.dst_port_min && key.dst_port <= self.dst_port_max
    }
}

/// Sliding-Window TCP SYN Flood Rate Limiter protecting listening services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynFloodGuard {
    pub window_duration_ticks: u64,
    pub max_syns_per_window: u32,
    window_start_tick: u64,
    current_syn_count: u32,
    pub dropped_syns: u64,
}

impl SynFloodGuard {
    pub const fn new(window_duration_ticks: u64, max_syns_per_window: u32) -> Self {
        Self {
            window_duration_ticks,
            max_syns_per_window,
            window_start_tick: 0,
            current_syn_count: 0,
            dropped_syns: 0,
        }
    }

    /// Evaluates whether a new incoming TCP `SYN` (without `ACK`) at `now_tick` is permitted.
    pub fn allow_syn(&mut self, now_tick: u64) -> bool {
        if now_tick.saturating_sub(self.window_start_tick) >= self.window_duration_ticks {
            self.window_start_tick = now_tick;
            self.current_syn_count = 0;
        }
        if self.current_syn_count >= self.max_syns_per_window {
            self.dropped_syns += 1;
            false
        } else {
            self.current_syn_count += 1;
            true
        }
    }
}

/// Source NAT (SNAT / Masquerade) Translation Binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnatBinding {
    pub internal_ip: Ipv4Addr,
    pub internal_port: u16,
    pub nat_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub protocol: u8,
}

/// Stateful Firewall Engine combining ACL rules, `conntrack`, SYN flood protection, and Source NAT.
#[derive(Clone, Debug)]
pub struct StatefulFirewall {
    pub default_input_policy: FirewallAction,
    pub default_forward_policy: FirewallAction,
    pub default_output_policy: FirewallAction,
    pub rules: Vec<FirewallRule>,
    pub conntrack: Vec<ConnTrackEntry>,
    pub syn_guard: SynFloodGuard,
    pub masquerade_ip: Option<Ipv4Addr>,
    next_nat_port: u16,
    pub snat_table: Vec<SnatBinding>,
}

impl StatefulFirewall {
    /// Creates a new stateful firewall with default `Drop` on `Input`/`Forward` and `Accept` on `Output`.
    pub const fn new(masquerade_ip: Option<Ipv4Addr>) -> Self {
        Self {
            default_input_policy: FirewallAction::Drop,
            default_forward_policy: FirewallAction::Drop,
            default_output_policy: FirewallAction::Accept,
            rules: Vec::new(),
            conntrack: Vec::new(),
            syn_guard: SynFloodGuard::new(1_000, 128),
            masquerade_ip,
            next_nat_port: 40_000,
            snat_table: Vec::new(),
        }
    }

    /// Appends a rule to the firewall policy list.
    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
    }

    /// Evaluates a packet against `conntrack`, the SYN flood rate limiter, and the chain rules.
    pub fn inspect_packet(
        &mut self,
        chain: FirewallChain,
        key: ConnTrackKey,
        tcp_flags_byte: u8,
        pkt_len: usize,
        now_tick: u64,
    ) -> FirewallAction {
        // 1. Check if this packet belongs to an existing tracked connection (forward or reverse).
        let rev = key.reverse();
        if let Some(entry) = self
            .conntrack
            .iter_mut()
            .find(|e| e.key == key || e.key == rev)
        {
            if (tcp_flags_byte & tcp_flags::RST) != 0 {
                entry.state = ConnTrackState::Closing;
            } else if (tcp_flags_byte & tcp_flags::FIN) != 0 {
                entry.state = ConnTrackState::Closing;
            } else if entry.key == rev && entry.state == ConnTrackState::New {
                entry.state = ConnTrackState::Established;
            }
            entry.packets_seen += 1;
            entry.bytes_seen += pkt_len as u64;
            return FirewallAction::Accept;
        }

        // 2. Apply SYN flood guard on new unestablished TCP SYN packets entering Input/Forward.
        if key.protocol == IPPROTO_TCP
            && (tcp_flags_byte & tcp_flags::SYN) != 0
            && (tcp_flags_byte & tcp_flags::ACK) == 0
            && chain != FirewallChain::Output
            && !self.syn_guard.allow_syn(now_tick)
        {
            return FirewallAction::Drop;
        }

        // 3. Evaluate explicit rules in order.
        let mut verdict = match chain {
            FirewallChain::Input => self.default_input_policy,
            FirewallChain::Forward => self.default_forward_policy,
            FirewallChain::Output => self.default_output_policy,
        };
        for rule in &self.rules {
            if rule.matches(chain, &key) {
                verdict = rule.action;
                break;
            }
        }

        // 4. If accepted, insert a new ConnTrackEntry so return traffic is statefully permitted.
        if verdict == FirewallAction::Accept {
            self.conntrack.push(ConnTrackEntry {
                key,
                state: ConnTrackState::New,
                packets_seen: 1,
                bytes_seen: pkt_len as u64,
            });
        }
        verdict
    }

    /// Rewrites an outbound private-LAN 5-tuple using Source NAT Masquerading.
    pub fn apply_snat_outbound(&mut self, mut key: ConnTrackKey) -> ConnTrackKey {
        let Some(public_ip) = self.masquerade_ip else {
            return key;
        };
        if let Some(b) = self.snat_table.iter().find(|b| {
            b.protocol == key.protocol
                && b.internal_ip == key.src_ip
                && b.internal_port == key.src_port
                && b.remote_ip == key.dst_ip
                && b.remote_port == key.dst_port
        }) {
            key.src_ip = public_ip;
            key.src_port = b.nat_port;
            return key;
        }

        let nat_port = self.next_nat_port;
        self.next_nat_port = if self.next_nat_port == 60_000 {
            40_000
        } else {
            self.next_nat_port + 1
        };
        self.snat_table.push(SnatBinding {
            internal_ip: key.src_ip,
            internal_port: key.src_port,
            nat_port,
            remote_ip: key.dst_ip,
            remote_port: key.dst_port,
            protocol: key.protocol,
        });
        key.src_ip = public_ip;
        key.src_port = nat_port;
        key
    }

    /// Rewrites an inbound reply 5-tuple back to the original private-LAN host if it matches an SNAT binding.
    pub fn apply_dnat_inbound(&self, mut key: ConnTrackKey) -> Option<ConnTrackKey> {
        let public_ip = self.masquerade_ip?;
        if key.dst_ip != public_ip {
            return None;
        }
        for b in &self.snat_table {
            if b.protocol == key.protocol
                && b.nat_port == key.dst_port
                && b.remote_ip == key.src_ip
                && b.remote_port == key.src_port
            {
                key.dst_ip = b.internal_ip;
                key.dst_port = b.internal_port;
                return Some(key);
            }
        }
        None
    }
}

/// Runs self-tests for the `firewall_filter` module.
pub fn verify_net_firewall_filter() -> u32 {
    let mut passed = 0u32;

    let wan_ip = Ipv4Addr::new(203, 0, 113, 5);
    let mut fw = StatefulFirewall::new(Some(wan_ip));
    fw.syn_guard = SynFloodGuard::new(100, 2);

    // Allow inbound TCP port 443 (HTTPS) on Input chain.
    fw.add_rule(FirewallRule {
        chain: FirewallChain::Input,
        src_prefix: Ipv4Addr::UNSPECIFIED,
        src_prefix_len: 0,
        dst_prefix: wan_ip,
        dst_prefix_len: 32,
        protocol: Some(IPPROTO_TCP),
        dst_port_min: 443,
        dst_port_max: 443,
        action: FirewallAction::Accept,
    });

    // 1. Permitted inbound HTTPS flow is accepted, while unpermitted SSH (22) is dropped by default policy.
    let https_flow = ConnTrackKey {
        protocol: IPPROTO_TCP,
        src_ip: Ipv4Addr::new(198, 51, 100, 10),
        dst_ip: wan_ip,
        src_port: 51_234,
        dst_port: 443,
    };
    let ssh_flow = ConnTrackKey {
        dst_port: 22,
        ..https_flow
    };
    if fw.inspect_packet(FirewallChain::Input, https_flow, tcp_flags::SYN, 60, 10)
        == FirewallAction::Accept
        && fw.inspect_packet(FirewallChain::Input, ssh_flow, tcp_flags::SYN, 60, 10)
            == FirewallAction::Drop
    {
        passed += 1;
    }

    // 2. Outbound return traffic on an established flow is statefully accepted even if Output default policy is Drop.
    fw.default_output_policy = FirewallAction::Drop;
    let reply_flow = https_flow.reverse();
    if fw.inspect_packet(
        FirewallChain::Output,
        reply_flow,
        tcp_flags::SYN | tcp_flags::ACK,
        60,
        12,
    ) == FirewallAction::Accept
        && fw.conntrack[0].state == ConnTrackState::Established
    {
        passed += 1;
    }

    // 3. Verify SYN flood rate limiter drops excess SYNs within the same tick window.
    let flood_flow = ConnTrackKey {
        src_port: 60_001,
        ..https_flow
    };
    if fw.inspect_packet(FirewallChain::Input, flood_flow, tcp_flags::SYN, 60, 20)
        == FirewallAction::Drop
        && fw.syn_guard.dropped_syns == 1
    {
        passed += 1;
    }

    // 4. Verify Source NAT masquerading and reverse DNAT demasquerading.
    let lan_flow = ConnTrackKey {
        protocol: IPPROTO_TCP,
        src_ip: Ipv4Addr::new(10, 0, 2, 15),
        dst_ip: Ipv4Addr::new(1, 1, 1, 1),
        src_port: 54_321,
        dst_port: 443,
    };
    let natted = fw.apply_snat_outbound(lan_flow);
    let inbound_reply = natted.reverse();
    if natted.src_ip == wan_ip
        && fw.apply_dnat_inbound(inbound_reply) == Some(lan_flow.reverse())
    {
        passed += 1;
    }

    passed
}
