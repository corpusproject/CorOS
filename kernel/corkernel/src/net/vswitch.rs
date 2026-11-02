//! Open vSwitch (OVS) & Software Defined Networking (SDN) Virtual Switch for CorOS.
//!
//! Provides bare-metal Layer-2 forwarding, OpenFlow-style match-action tables,
//! 802.1Q VLAN trunking/access tagging, MAC learning with aging timers,
//! and RFC 7348 VXLAN overlay encapsulation/decapsulation across UDP 4789.

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::fmt;

/// Maximum number of MAC learning entries
pub const MAX_FDB_ENTRIES: usize = 4096;
/// Default MAC address aging timeout in seconds
pub const DEFAULT_MAC_AGING_SECS: u64 = 300;
/// Standard VXLAN UDP destination port
pub const VXLAN_UDP_PORT: u16 = 4789;
/// 802.1Q EtherType (VLAN-tagged frame)
pub const ETHERTYPE_8021Q: u16 = 0x8100;
/// IPv4 EtherType
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// ARP EtherType
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Port identifier within the virtual switch
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PortId(pub u16);

/// VLAN configuration mode for a bridge port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanMode {
    /// Untagged port; incoming packets tagged with native VLAN, outgoing packets stripped
    Access(u16),
    /// Carries multiple VLAN tags unchanged; optional native VLAN for untagged frames
    Trunk { native_vlan: u16, allowed_vlans: [u64; 64] }, // 4096-bit bitmap
    /// QinQ / 802.1ad Service Provider Tagging
    Dot1qTunnel(u16),
}

impl VlanMode {
    pub fn is_vlan_allowed(&self, vlan_id: u16) -> bool {
        match self {
            VlanMode::Access(native) => *native == vlan_id,
            VlanMode::Trunk { native_vlan, allowed_vlans } => {
                if *native_vlan == vlan_id {
                    return true;
                }
                if vlan_id >= 4096 {
                    return false;
                }
                let idx = (vlan_id / 64) as usize;
                let bit = (vlan_id % 64) as usize;
                (allowed_vlans[idx] & (1u64 << bit)) != 0
            }
            VlanMode::Dot1qTunnel(tunnel_vid) => *tunnel_vid == vlan_id,
        }
    }
}

/// Port traffic and error statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Virtual Ethernet Port configuration and state
#[derive(Debug, Clone)]
pub struct SwitchPort {
    pub id: PortId,
    pub name: [u8; 16],
    pub name_len: usize,
    pub enabled: bool,
    pub vlan_mode: VlanMode,
    pub stats: PortStats,
}

impl SwitchPort {
    pub fn new(id: PortId, name: &str, vlan_mode: VlanMode) -> Self {
        let mut port_name = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(16);
        port_name[..len].copy_from_slice(&bytes[..len]);
        Self {
            id,
            name: port_name,
            name_len: len,
            enabled: true,
            vlan_mode,
            stats: PortStats::default(),
        }
    }
}

/// 802.1Q VLAN Tag Header (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanHeader {
    pub pcp: u8,        // Priority Code Point (3 bits, 0-7)
    pub dei: bool,      // Drop Eligible Indicator (1 bit)
    pub vlan_id: u16,   // VLAN Identifier (12 bits, 0-4095)
    pub inner_ethertype: u16,
}

impl VlanHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let tci = u16::from_be_bytes([buf[0], buf[1]]);
        let pcp = ((tci >> 13) & 0x07) as u8;
        let dei = ((tci >> 12) & 0x01) != 0;
        let vlan_id = tci & 0x0FFF;
        let inner_ethertype = u16::from_be_bytes([buf[2], buf[3]]);
        Some((Self { pcp, dei, vlan_id, inner_ethertype }, 4))
    }

    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut tci = ((self.pcp as u16 & 0x07) << 13) | (self.vlan_id & 0x0FFF);
        if self.dei {
            tci |= 1 << 12;
        }
        buf[0..2].copy_from_slice(&tci.to_be_bytes());
        buf[2..4].copy_from_slice(&self.inner_ethertype.to_be_bytes());
        4
    }
}

/// Forwarding Database (FDB) Entry for Layer-2 MAC Learning
#[derive(Debug, Clone, Copy)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    pub vlan_id: u16,
    pub port_id: PortId,
    pub last_seen_secs: u64,
    pub is_static: bool,
}

/// RFC 7348 VXLAN Packet Header (8 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VxlanHeader {
    pub flags: u8,      // 0x08 = I flag (VNI valid)
    pub reserved1: [u8; 3],
    pub vni: u32,       // 24-bit Virtual Network Identifier
    pub reserved2: u8,
}

impl VxlanHeader {
    pub fn new(vni: u32) -> Self {
        Self {
            flags: 0x08,
            reserved1: [0; 3],
            vni: vni & 0x00FF_FFFF,
            reserved2: 0,
        }
    }

    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 8 {
            return None;
        }
        let flags = buf[0];
        let vni = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
        Some((Self {
            flags,
            reserved1: [buf[1], buf[2], buf[3]],
            vni,
            reserved2: buf[7],
        }, 8))
    }

    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.flags;
        buf[1..4].copy_from_slice(&self.reserved1);
        buf[4] = ((self.vni >> 16) & 0xFF) as u8;
        buf[5] = ((self.vni >> 8) & 0xFF) as u8;
        buf[6] = (self.vni & 0xFF) as u8;
        buf[7] = self.reserved2;
        8
    }
}

/// OpenFlow Match Keys for packet matching pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowMatchKey {
    pub in_port: Option<PortId>,
    pub eth_src: Option<[u8; 6]>,
    pub eth_dst: Option<[u8; 6]>,
    pub eth_type: Option<u16>,
    pub vlan_id: Option<u16>,
    pub ip_src: Option<[u8; 4]>,
    pub ip_dst: Option<[u8; 4]>,
    pub ip_proto: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl FlowMatchKey {
    pub fn matches(&self, packet: &ParsedPacketMeta) -> bool {
        if let Some(port) = self.in_port {
            if port != packet.in_port { return false; }
        }
        if let Some(src) = self.eth_src {
            if src != packet.eth_src { return false; }
        }
        if let Some(dst) = self.eth_dst {
            if dst != packet.eth_dst { return false; }
        }
        if let Some(etype) = self.eth_type {
            if etype != packet.eth_type { return false; }
        }
        if let Some(vid) = self.vlan_id {
            if Some(vid) != packet.vlan_id { return false; }
        }
        if let Some(ip_s) = self.ip_src {
            if Some(ip_s) != packet.ip_src { return false; }
        }
        if let Some(ip_d) = self.ip_dst {
            if Some(ip_d) != packet.ip_dst { return false; }
        }
        if let Some(proto) = self.ip_proto {
            if Some(proto) != packet.ip_proto { return false; }
        }
        if let Some(sp) = self.src_port {
            if Some(sp) != packet.src_port { return false; }
        }
        if let Some(dp) = self.dst_port {
            if Some(dp) != packet.dst_port { return false; }
        }
        true
    }
}

/// Actions applied when a flow match succeeds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    Output(PortId),
    Flood,
    SetVlan(u16),
    PopVlan,
    PushVlan(u16),
    SetIpSrc([u8; 4]),
    SetIpDst([u8; 4]),
    Drop,
    EncapsulateVxlan { vni: u32, remote_ip: [u8; 4], remote_port: u16 },
    SendToController,
}

/// Flow Table Entry with priority, match key, actions and hit counters
#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub id: u64,
    pub priority: u16,
    pub match_key: FlowMatchKey,
    pub actions: Vec<FlowAction>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub idle_timeout_secs: u32,
    pub hard_timeout_secs: u32,
    pub created_secs: u64,
    pub last_matched_secs: u64,
}

/// Parsed metadata for rapid L2/L3/L4 inspection
#[derive(Debug, Clone, Copy, Default)]
pub struct ParsedPacketMeta {
    pub in_port: PortId,
    pub eth_src: [u8; 6],
    pub eth_dst: [u8; 6],
    pub eth_type: u16,
    pub vlan_id: Option<u16>,
    pub ip_src: Option<[u8; 4]>,
    pub ip_dst: Option<[u8; 4]>,
    pub ip_proto: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload_offset: usize,
    pub packet_len: usize,
}

impl ParsedPacketMeta {
    pub fn parse(packet: &[u8], in_port: PortId) -> Option<Self> {
        if packet.len() < 14 {
            return None;
        }

        let mut meta = ParsedPacketMeta {
            in_port,
            eth_dst: [packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]],
            eth_src: [packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]],
            eth_type: u16::from_be_bytes([packet[12], packet[13]]),
            vlan_id: None,
            ip_src: None,
            ip_dst: None,
            ip_proto: None,
            src_port: None,
            dst_port: None,
            payload_offset: 14,
            packet_len: packet.len(),
        };

        let mut offset = 14;
        if meta.eth_type == ETHERTYPE_8021Q && packet.len() >= 18 {
            if let Some((vlan_hdr, vlan_len)) = VlanHeader::parse(&packet[14..]) {
                meta.vlan_id = Some(vlan_hdr.vlan_id);
                meta.eth_type = vlan_hdr.inner_ethertype;
                offset += vlan_len;
            }
        }

        meta.payload_offset = offset;

        // Parse IPv4
        if meta.eth_type == ETHERTYPE_IPV4 && packet.len() >= offset + 20 {
            let ip_hdr = &packet[offset..];
            let ihl = (ip_hdr[0] & 0x0F) as usize * 4;
            if ihl >= 20 && packet.len() >= offset + ihl {
                meta.ip_proto = Some(ip_hdr[9]);
                meta.ip_src = Some([ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]]);
                meta.ip_dst = Some([ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]]);

                let l4_offset = offset + ihl;
                // Parse L4 ports for TCP (6) or UDP (17)
                if (ip_hdr[9] == 6 || ip_hdr[9] == 17) && packet.len() >= l4_offset + 4 {
                    meta.src_port = Some(u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]));
                    meta.dst_port = Some(u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]));
                }
            }
        }

        Some(meta)
    }
}

/// Virtual Open vSwitch Bridge Engine
pub struct VirtualSwitch {
    pub name: [u8; 16],
    pub ports: BTreeMap<PortId, SwitchPort>,
    pub fdb: Vec<FdbEntry>,
    pub flow_table: Vec<FlowEntry>,
    next_flow_id: u64,
}

impl VirtualSwitch {
    pub fn new(name: &str) -> Self {
        let mut sw_name = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(16);
        sw_name[..len].copy_from_slice(&bytes[..len]);

        Self {
            name: sw_name,
            ports: BTreeMap::new(),
            fdb: Vec::new(),
            flow_table: Vec::new(),
            next_flow_id: 1,
        }
    }

    /// Add a port to the virtual switch
    pub fn add_port(&mut self, id: PortId, name: &str, vlan_mode: VlanMode) {
        let port = SwitchPort::new(id, name, vlan_mode);
        self.ports.insert(id, port);
    }

    /// Add an OpenFlow match-action rule
    pub fn add_flow(&mut self, priority: u16, match_key: FlowMatchKey, actions: Vec<FlowAction>) -> u64 {
        let id = self.next_flow_id;
        self.next_flow_id += 1;

        let entry = FlowEntry {
            id,
            priority,
            match_key,
            actions,
            packet_count: 0,
            byte_count: 0,
            idle_timeout_secs: 0,
            hard_timeout_secs: 0,
            created_secs: 0,
            last_matched_secs: 0,
        };

        // Insert sorted by priority descending
        let idx = self.flow_table.iter().position(|f| f.priority < priority).unwrap_or(self.flow_table.len());
        self.flow_table.insert(idx, entry);
        id
    }

    /// Update MAC learning table (FDB)
    pub fn learn_mac(&mut self, mac: [u8; 6], vlan_id: u16, port_id: PortId, current_secs: u64) {
        // Skip multicast and broadcast sources
        if (mac[0] & 0x01) != 0 {
            return;
        }

        if let Some(entry) = self.fdb.iter_mut().find(|e| e.mac == mac && e.vlan_id == vlan_id) {
            if !entry.is_static {
                entry.port_id = port_id;
                entry.last_seen_secs = current_secs;
            }
        } else {
            if self.fdb.len() >= MAX_FDB_ENTRIES {
                // Evict oldest dynamic entry
                if let Some(oldest_idx) = self.fdb.iter().enumerate()
                    .filter(|(_, e)| !e.is_static)
                    .min_by_key(|(_, e)| e.last_seen_secs)
                    .map(|(i, _)| i) 
                {
                    self.fdb.swap_remove(oldest_idx);
                }
            }

            self.fdb.push(FdbEntry {
                mac,
                vlan_id,
                port_id,
                last_seen_secs: current_secs,
                is_static: false,
            });
        }
    }

    /// Lookup destination MAC port
    pub fn lookup_mac(&self, mac: [u8; 6], vlan_id: u16) -> Option<PortId> {
        self.fdb.iter()
            .find(|e| e.mac == mac && e.vlan_id == vlan_id)
            .map(|e| e.port_id)
    }

    /// Clean up expired FDB entries
    pub fn age_fdb(&mut self, current_secs: u64, max_age_secs: u64) {
        self.fdb.retain(|e| e.is_static || (current_secs.saturating_sub(e.last_seen_secs) < max_age_secs));
    }

    /// Process an incoming Ethernet packet through the SDN pipeline
    pub fn process_ingress(
        &mut self,
        in_port_id: PortId,
        packet: &[u8],
        current_secs: u64,
    ) -> Result<Vec<(PortId, Vec<u8>)>, &'static str> {
        let port = match self.ports.get_mut(&in_port_id) {
            Some(p) if p.enabled => p,
            _ => return Err("Port not found or disabled"),
        };

        port.stats.rx_packets += 1;
        port.stats.rx_bytes += packet.len() as u64;

        let meta = match ParsedPacketMeta::parse(packet, in_port_id) {
            Some(m) => m,
            None => {
                if let Some(p) = self.ports.get_mut(&in_port_id) {
                    p.stats.rx_dropped += 1;
                }
                return Err("Malformed ethernet frame");
            }
        };

        // Determine effective VLAN
        let effective_vlan = match port.vlan_mode {
            VlanMode::Access(native) => native,
            VlanMode::Trunk { native_vlan, .. } => meta.vlan_id.unwrap_or(native_vlan),
            VlanMode::Dot1qTunnel(vid) => vid,
        };

        // Check if VLAN is allowed on this port
        if !port.vlan_mode.is_vlan_allowed(effective_vlan) {
            port.stats.rx_dropped += 1;
            return Err("VLAN dropped by port filtering");
        }

        // MAC learning
        self.learn_mac(meta.eth_src, effective_vlan, in_port_id, current_secs);

        // 1. Evaluate OpenFlow pipeline
        let matched_flow = self.flow_table.iter_mut().find(|f| f.match_key.matches(&meta));
        if let Some(flow) = matched_flow {
            flow.packet_count += 1;
            flow.byte_count += packet.len() as u64;
            flow.last_matched_secs = current_secs;
            let actions = flow.actions.clone();

            let mut out_packets = Vec::new();
            for action in actions {
                match action {
                    FlowAction::Drop => return Ok(Vec::new()),
                    FlowAction::Output(out_port) => {
                        if out_port != in_port_id {
                            out_packets.push((out_port, packet.to_vec()));
                        }
                    }
                    FlowAction::Flood => {
                        for (&p_id, p) in &self.ports {
                            if p_id != in_port_id && p.enabled && p.vlan_mode.is_vlan_allowed(effective_vlan) {
                                out_packets.push((p_id, packet.to_vec()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            return Ok(out_packets);
        }

        // 2. Standard L2 Switching Fallback (FDB Forwarding)
        let is_broadcast = meta.eth_dst == [0xFF; 6];
        let is_multicast = (meta.eth_dst[0] & 0x01) != 0;

        let mut outputs = Vec::new();

        if is_broadcast || is_multicast {
            // Flood to all ports in same VLAN
            for (&p_id, p) in &self.ports {
                if p_id != in_port_id && p.enabled && p.vlan_mode.is_vlan_allowed(effective_vlan) {
                    outputs.push((p_id, packet.to_vec()));
                }
            }
        } else if let Some(target_port) = self.lookup_mac(meta.eth_dst, effective_vlan) {
            if target_port != in_port_id {
                if let Some(p) = self.ports.get(&target_port) {
                    if p.enabled && p.vlan_mode.is_vlan_allowed(effective_vlan) {
                        outputs.push((target_port, packet.to_vec()));
                    }
                }
            }
        } else {
            // Unknown unicast flooding
            for (&p_id, p) in &self.ports {
                if p_id != in_port_id && p.enabled && p.vlan_mode.is_vlan_allowed(effective_vlan) {
                    outputs.push((p_id, packet.to_vec()));
                }
            }
        }

        // Update TX statistics
        for (out_p, pkt) in &outputs {
            if let Some(p) = self.ports.get_mut(out_p) {
                p.stats.tx_packets += 1;
                p.stats.tx_bytes += pkt.len() as u64;
            }
        }

        Ok(outputs)
    }

    /// Encapsulate Layer-2 Ethernet Frame into RFC 7348 VXLAN Packet
    pub fn encapsulate_vxlan(vni: u32, inner_frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + inner_frame.len());
        let vxlan_hdr = VxlanHeader::new(vni);
        let mut hdr_bytes = [0u8; 8];
        vxlan_hdr.serialize(&mut hdr_bytes);
        out.extend_from_slice(&hdr_bytes);
        out.extend_from_slice(inner_frame);
        out
    }

    /// Decapsulate RFC 7348 VXLAN packet, extracting inner Ethernet frame and VNI
    pub fn decapsulate_vxlan(vxlan_packet: &[u8]) -> Result<(u32, &[u8]), &'static str> {
        if vxlan_packet.len() < 8 {
            return Err("Packet smaller than 8-byte VXLAN header");
        }
        let (hdr, len) = VxlanHeader::parse(vxlan_packet).ok_or("Invalid VXLAN header")?;
        if (hdr.flags & 0x08) == 0 {
            return Err("VXLAN I flag not set");
        }
        Ok((hdr.vni, &vxlan_packet[len..]))
    }
}

impl fmt::Display for VirtualSwitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_str = core::str::from_utf8(&self.name).unwrap_or("vswitch");
        write!(
            f,
            "VirtualSwitch({}, ports={}, fdb_entries={}, flows={})",
            name_str.trim_matches(char::from(0)),
            self.ports.len(),
            self.fdb.len(),
            self.flow_table.len()
        )
    }
}
