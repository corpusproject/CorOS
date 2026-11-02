//! DHCPv4 (RFC 2131 / RFC 2132) 240-Byte BOOTP Header, Magic Cookie `0x63825363` TLV Options & DORA State Machine.

use crate::ethernet_mac::MacAddress;
use crate::ipv4_routing::Ipv4Addr;
use alloc::vec::Vec;

/// RFC 2131 DHCP Magic Cookie (`0x63825363`: `[99, 130, 83, 99]`).
pub const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;

/// BOOTP `op` code: Client Request (`BOOTREQUEST = 1`).
pub const BOOTREQUEST: u8 = 1;
/// BOOTP `op` code: Server Reply (`BOOTREPLY = 2`).
pub const BOOTREPLY: u8 = 2;

/// DHCP Message Type (RFC 2132 Option 53).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

/// Decoded RFC 2132 DHCP TLV Option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DhcpOption {
    /// Option 1: Subnet Mask (4 bytes).
    SubnetMask(Ipv4Addr),
    /// Option 3: Default Gateway / Router list.
    Router(Vec<Ipv4Addr>),
    /// Option 6: Domain Name Server (DNS) list.
    DnsServers(Vec<Ipv4Addr>),
    /// Option 50: Requested IPv4 Address (4 bytes).
    RequestedIp(Ipv4Addr),
    /// Option 51: IP Address Lease Time in seconds (`u32`).
    LeaseTimeSecs(u32),
    /// Option 53: DHCP Message Type (1 byte).
    MessageType(DhcpMessageType),
    /// Option 54: DHCP Server Identifier (4 bytes).
    ServerIdentifier(Ipv4Addr),
    /// Option 55: Parameter Request List (list of option codes).
    ParameterRequestList(Vec<u8>),
    /// Unrecognized TLV option preserved verbatim.
    Unknown { code: u8, data: Vec<u8> },
}

/// Errors encountered while parsing or serializing a DHCPv4 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpError {
    /// Packet is shorter than the 236-byte BOOTP header + 4-byte Magic Cookie (240 bytes).
    TruncatedHeader,
    /// Bytes `236..240` do not match `0x63825363`.
    InvalidMagicCookie(u32),
    /// Malformed TLV option length extending beyond the packet boundary.
    MalformedOption,
    /// Missing mandatory Option 53 (`DhcpMessageType`).
    MissingMessageType,
}

/// 240-byte DHCPv4 Fixed Header (236-byte BOOTP + 4-byte Magic Cookie) plus TLV options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpPacket {
    /// Message opcode (`1` = `BOOTREQUEST`, `2` = `BOOTREPLY`).
    pub op: u8,
    /// Hardware address type (`1` = Ethernet).
    pub htype: u8,
    /// Hardware address length (`6` for Ethernet).
    pub hlen: u8,
    /// Relay agent hops.
    pub hops: u8,
    /// Transaction ID (`xid`).
    pub xid: u32,
    /// Seconds elapsed since client began address acquisition.
    pub secs: u16,
    /// BOOTP flags (`0x8000` = Broadcast flag).
    pub flags: u16,
    /// Client IP address (`ciaddr`).
    pub ciaddr: Ipv4Addr,
    /// 'Your' (client) IP address offered/assigned by server (`yiaddr`).
    pub yiaddr: Ipv4Addr,
    /// Next server IP address (`siaddr`).
    pub siaddr: Ipv4Addr,
    /// Relay agent IP address (`giaddr`).
    pub giaddr: Ipv4Addr,
    /// Client hardware MAC address (`chaddr`, low 6 bytes of the 16-byte field).
    pub chaddr: MacAddress,
    /// Parsed RFC 2132 TLV options following the `0x63825363` magic cookie.
    pub options: Vec<DhcpOption>,
}

impl DhcpPacket {
    /// Fixed BOOTP header (236 bytes) + 4-byte DHCP Magic Cookie = 240 bytes.
    pub const FIXED_LEN: usize = 240;

    /// Returns the `DhcpMessageType` (Option 53) if present in `options`.
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        for opt in &self.options {
            if let DhcpOption::MessageType(mt) = *opt {
                return Some(mt);
            }
        }
        None
    }

    /// Serializes this `DhcpPacket` (240-byte header + TLV options + `0xFF` End option).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; Self::FIXED_LEN];
        buf[0] = self.op;
        buf[1] = self.htype;
        buf[2] = self.hlen;
        buf[3] = self.hops;
        buf[4..8].copy_from_slice(&self.xid.to_be_bytes());
        buf[8..10].copy_from_slice(&self.secs.to_be_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_be_bytes());
        buf[12..16].copy_from_slice(&self.ciaddr.0);
        buf[16..20].copy_from_slice(&self.yiaddr.0);
        buf[20..24].copy_from_slice(&self.siaddr.0);
        buf[24..28].copy_from_slice(&self.giaddr.0);
        buf[28..34].copy_from_slice(&self.chaddr.0);
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());

        for opt in &self.options {
            match opt {
                DhcpOption::MessageType(mt) => {
                    buf.extend_from_slice(&[53, 1, *mt as u8]);
                }
                DhcpOption::SubnetMask(mask) => {
                    buf.extend_from_slice(&[1, 4]);
                    buf.extend_from_slice(&mask.0);
                }
                DhcpOption::Router(routers) => {
                    buf.push(3);
                    buf.push((routers.len() * 4) as u8);
                    for r in routers {
                        buf.extend_from_slice(&r.0);
                    }
                }
                DhcpOption::DnsServers(servers) => {
                    buf.push(6);
                    buf.push((servers.len() * 4) as u8);
                    for s in servers {
                        buf.extend_from_slice(&s.0);
                    }
                }
                DhcpOption::RequestedIp(ip) => {
                    buf.extend_from_slice(&[50, 4]);
                    buf.extend_from_slice(&ip.0);
                }
                DhcpOption::LeaseTimeSecs(secs) => {
                    buf.extend_from_slice(&[51, 4]);
                    buf.extend_from_slice(&secs.to_be_bytes());
                }
                DhcpOption::ServerIdentifier(srv) => {
                    buf.extend_from_slice(&[54, 4]);
                    buf.extend_from_slice(&srv.0);
                }
                DhcpOption::ParameterRequestList(params) => {
                    buf.push(55);
                    buf.push(params.len() as u8);
                    buf.extend_from_slice(params);
                }
                DhcpOption::Unknown { code, data } => {
                    buf.push(*code);
                    buf.push(data.len() as u8);
                    buf.extend_from_slice(data);
                }
            }
        }
        buf.push(255); // End Option (255)
        buf
    }

    /// Parses a `DhcpPacket` and its TLV option stream from `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, DhcpError> {
        if buf.len() < Self::FIXED_LEN {
            return Err(DhcpError::TruncatedHeader);
        }
        let cookie = u32::from_be_bytes([buf[236], buf[237], buf[238], buf[239]]);
        if cookie != DHCP_MAGIC_COOKIE {
            return Err(DhcpError::InvalidMagicCookie(cookie));
        }

        let mut options = Vec::new();
        let mut idx = Self::FIXED_LEN;
        while idx < buf.len() {
            let code = buf[idx];
            idx += 1;
            if code == 0 {
                // Pad Option (0)
                continue;
            }
            if code == 255 {
                // End Option (255)
                break;
            }
            if idx >= buf.len() {
                return Err(DhcpError::MalformedOption);
            }
            let len = buf[idx] as usize;
            idx += 1;
            if idx + len > buf.len() {
                return Err(DhcpError::MalformedOption);
            }
            let data = &buf[idx..idx + len];
            idx += len;

            let parsed_opt = match (code, len) {
                (1, 4) => DhcpOption::SubnetMask(Ipv4Addr([data[0], data[1], data[2], data[3]])),
                (3, n) if n >= 4 && n % 4 == 0 => {
                    let list = data
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr([c[0], c[1], c[2], c[3]]))
                        .collect();
                    DhcpOption::Router(list)
                }
                (6, n) if n >= 4 && n % 4 == 0 => {
                    let list = data
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr([c[0], c[1], c[2], c[3]]))
                        .collect();
                    DhcpOption::DnsServers(list)
                }
                (50, 4) => DhcpOption::RequestedIp(Ipv4Addr([data[0], data[1], data[2], data[3]])),
                (51, 4) => DhcpOption::LeaseTimeSecs(u32::from_be_bytes([
                    data[0], data[1], data[2], data[3],
                ])),
                (53, 1) => {
                    let mt =
                        DhcpMessageType::from_u8(data[0]).ok_or(DhcpError::MalformedOption)?;
                    DhcpOption::MessageType(mt)
                }
                (54, 4) => {
                    DhcpOption::ServerIdentifier(Ipv4Addr([data[0], data[1], data[2], data[3]]))
                }
                (55, _) => DhcpOption::ParameterRequestList(data.to_vec()),
                _ => DhcpOption::Unknown {
                    code,
                    data: data.to_vec(),
                },
            };
            options.push(parsed_opt);
        }

        Ok(Self {
            op: buf[0],
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: Ipv4Addr([buf[12], buf[13], buf[14], buf[15]]),
            yiaddr: Ipv4Addr([buf[16], buf[17], buf[18], buf[19]]),
            siaddr: Ipv4Addr([buf[20], buf[21], buf[22], buf[23]]),
            giaddr: Ipv4Addr([buf[24], buf[25], buf[26], buf[27]]),
            chaddr: MacAddress([buf[28], buf[29], buf[30], buf[31], buf[32], buf[33]]),
            options,
        })
    }
}

/// Active DHCPv4 Lease Configuration acquired via the DORA handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpLease {
    pub assigned_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub server_id: Ipv4Addr,
    pub lease_time_secs: u32,
    pub t1_renew_secs: u32,
    pub t2_rebind_secs: u32,
}

/// RFC 2131 Section 4.4 DHCPv4 Client State Machine (`Selecting`, `Requesting`, `Bound`, `Renewing`, `Rebinding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpClientState {
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

/// Stateful DHCPv4 DORA Client Engine.
#[derive(Clone, Debug)]
pub struct DhcpClient {
    pub state: DhcpClientState,
    pub client_mac: MacAddress,
    pub xid: u32,
    pub lease: Option<DhcpLease>,
}

impl DhcpClient {
    /// Creates a new `DhcpClient` in the `Selecting` state.
    pub const fn new(client_mac: MacAddress, xid: u32) -> Self {
        Self {
            state: DhcpClientState::Selecting,
            client_mac,
            xid,
            lease: None,
        }
    }

    /// Step 1 of DORA: Builds a broadcast `DHCPDISCOVER` packet.
    pub fn build_discover(&mut self) -> DhcpPacket {
        self.state = DhcpClientState::Selecting;
        DhcpPacket {
            op: BOOTREQUEST,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: self.xid,
            secs: 0,
            flags: 0x8000, // Broadcast
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: self.client_mac,
            options: alloc::vec![
                DhcpOption::MessageType(DhcpMessageType::Discover),
                DhcpOption::ParameterRequestList(alloc::vec![1, 3, 6, 51, 54]),
            ],
        }
    }

    /// Step 2/3 of DORA: Processes a `DHCPOFFER` and transitions `Selecting -> Requesting`,
    /// returning the outbound `DHCPREQUEST` packet.
    pub fn on_offer(&mut self, offer: &DhcpPacket) -> Result<DhcpPacket, DhcpError> {
        if self.state != DhcpClientState::Selecting || offer.xid != self.xid {
            return Err(DhcpError::MissingMessageType);
        }
        if offer.message_type() != Some(DhcpMessageType::Offer) {
            return Err(DhcpError::MissingMessageType);
        }
        let server_id = offer
            .options
            .iter()
            .find_map(|o| match *o {
                DhcpOption::ServerIdentifier(ip) => Some(ip),
                _ => None,
            })
            .unwrap_or(offer.siaddr);

        self.state = DhcpClientState::Requesting;
        Ok(DhcpPacket {
            op: BOOTREQUEST,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: self.xid,
            secs: 0,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: server_id,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: self.client_mac,
            options: alloc::vec![
                DhcpOption::MessageType(DhcpMessageType::Request),
                DhcpOption::RequestedIp(offer.yiaddr),
                DhcpOption::ServerIdentifier(server_id),
            ],
        })
    }

    /// Step 4 of DORA: Processes a `DHCPACK` and transitions `Requesting/Renewing/Rebinding -> Bound`.
    pub fn on_ack(&mut self, ack: &DhcpPacket) -> Result<&DhcpLease, DhcpError> {
        if ack.xid != self.xid || ack.message_type() != Some(DhcpMessageType::Ack) {
            return Err(DhcpError::MissingMessageType);
        }
        let mut subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
        let mut router = None;
        let mut dns_servers = Vec::new();
        let mut server_id = ack.siaddr;
        let mut lease_time_secs = 86_400u32;

        for opt in &ack.options {
            match opt {
                DhcpOption::SubnetMask(m) => subnet_mask = *m,
                DhcpOption::Router(r) => router = r.first().copied(),
                DhcpOption::DnsServers(d) => dns_servers = d.clone(),
                DhcpOption::ServerIdentifier(s) => server_id = *s,
                DhcpOption::LeaseTimeSecs(t) => lease_time_secs = *t,
                _ => {}
            }
        }

        self.lease = Some(DhcpLease {
            assigned_ip: ack.yiaddr,
            subnet_mask,
            router,
            dns_servers,
            server_id,
            lease_time_secs,
            t1_renew_secs: lease_time_secs / 2,
            t2_rebind_secs: (lease_time_secs * 7) / 8,
        });
        self.state = DhcpClientState::Bound;
        Ok(self.lease.as_ref().unwrap())
    }

    /// Advances the lease timer (`Bound -> Renewing -> Rebinding -> Selecting`) based on `elapsed_secs`.
    pub fn advance_lease_timer(&mut self, elapsed_secs: u32) -> DhcpClientState {
        if let Some(lease) = &self.lease {
            if elapsed_secs >= lease.lease_time_secs {
                self.lease = None;
                self.state = DhcpClientState::Selecting;
            } else if elapsed_secs >= lease.t2_rebind_secs {
                self.state = DhcpClientState::Rebinding;
            } else if elapsed_secs >= lease.t1_renew_secs {
                self.state = DhcpClientState::Renewing;
            }
        }
        self.state
    }
}

/// Runs self-tests for the `dhcp_client` module.
pub fn verify_net_dhcp_client() -> u32 {
    let mut passed = 0u32;

    let mac = MacAddress::new(0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF);
    let mut client = DhcpClient::new(mac, 0xCAFE_1234);

    // 1. Discover serialization & Magic Cookie verification.
    let discover = client.build_discover();
    let disc_wire = discover.to_bytes();
    if let Ok(parsed_disc) = DhcpPacket::parse(&disc_wire) {
        if parsed_disc == discover
            && parsed_disc.message_type() == Some(DhcpMessageType::Discover)
        {
            passed += 1;
        }
    }

    // 2. Offer -> Request transition.
    let offer = DhcpPacket {
        op: BOOTREPLY,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: 0xCAFE_1234,
        secs: 0,
        flags: 0x8000,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::new(10, 0, 2, 15),
        siaddr: Ipv4Addr::new(10, 0, 2, 2),
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: alloc::vec![
            DhcpOption::MessageType(DhcpMessageType::Offer),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 2, 2)),
        ],
    };
    if let Ok(req_pkt) = client.on_offer(&offer) {
        if client.state == DhcpClientState::Requesting
            && req_pkt.message_type() == Some(DhcpMessageType::Request)
        {
            passed += 1;
        }
    }

    // 3. Ack -> Bound lease configuration extraction.
    let ack = DhcpPacket {
        op: BOOTREPLY,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: 0xCAFE_1234,
        secs: 0,
        flags: 0,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::new(10, 0, 2, 15),
        siaddr: Ipv4Addr::new(10, 0, 2, 2),
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: alloc::vec![
            DhcpOption::MessageType(DhcpMessageType::Ack),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(alloc::vec![Ipv4Addr::new(10, 0, 2, 2)]),
            DhcpOption::DnsServers(alloc::vec![Ipv4Addr::new(10, 0, 2, 3)]),
            DhcpOption::LeaseTimeSecs(3600),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 2, 2)),
        ],
    };
    if let Ok(lease) = client.on_ack(&ack) {
        if lease.assigned_ip == Ipv4Addr::new(10, 0, 2, 15)
            && lease.router == Some(Ipv4Addr::new(10, 0, 2, 2))
            && lease.t1_renew_secs == 1800
            && client.state == DhcpClientState::Bound
        {
            passed += 1;
        }
    }

    // 4. Verify T1 Renewing and T2 Rebinding state transitions.
    if client.advance_lease_timer(1800) == DhcpClientState::Renewing
        && client.advance_lease_timer(3200) == DhcpClientState::Rebinding
        && client.advance_lease_timer(3600) == DhcpClientState::Selecting
    {
        passed += 1;
    }

    passed
}
