//! RFC 2131 Dynamic Host Configuration Protocol (DHCP) Client for CorOS.
//! 100% in-house implementation supporting:
//! - Automatic IPv4 address leasing via DORA (Discover, Offer, Request, Acknowledge)
//! - Standard DHCP magic cookie (`0x63825363`)
//! - Option parsing (Subnet Mask 1, Router/Gateway 3, DNS 6, Lease Time 51, Message Type 53)
//! - Broadcast framing over UDP ports 67 (server) and 68 (client)

use alloc::vec::Vec;

pub const DHCP_CLIENT_PORT: u16    = 68;
pub const DHCP_SERVER_PORT: u16    = 67;
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// BootP / DHCP Operations
pub const BOOTREQUEST: u8          = 1;
pub const BOOTREPLY: u8            = 2;

// DHCP Message Types (Option 53)
pub const DHCPDISCOVER: u8         = 1;
pub const DHCPOFFER: u8            = 2;
pub const DHCPREQUEST: u8          = 3;
pub const DHCPDECLINE: u8          = 4;
pub const DHCPACK: u8              = 5;
pub const DHCPNAK: u8              = 6;
pub const DHCPRELEASE: u8          = 7;

// DHCP Options
pub const OPT_PAD: u8              = 0;
pub const OPT_SUBNET_MASK: u8      = 1;
pub const OPT_ROUTER: u8           = 3;
pub const OPT_DNS_SERVERS: u8      = 6;
pub const OPT_HOST_NAME: u8        = 12;
pub const OPT_REQUESTED_IP: u8     = 50;
pub const OPT_LEASE_TIME: u8       = 51;
pub const OPT_MESSAGE_TYPE: u8     = 53;
pub const OPT_SERVER_IDENT: u8     = 54;
pub const OPT_PARAM_REQUEST: u8    = 55;
pub const OPT_END: u8              = 255;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct DhcpPacketRaw {
    pub op: u8,               // 1 = BOOTREQUEST, 2 = BOOTREPLY
    pub htype: u8,            // 1 = Ethernet
    pub hlen: u8,             // 6 = MAC address length
    pub hops: u8,             // 0
    pub xid: u32,             // Transaction ID
    pub secs: u16,            // Seconds elapsed
    pub flags: u16,           // 0x8000 = Broadcast
    pub ciaddr: [u8; 4],      // Client IP (if known)
    pub yiaddr: [u8; 4],      // 'Your' IP (assigned by server)
    pub siaddr: [u8; 4],      // Next server IP
    pub giaddr: [u8; 4],      // Relay agent IP
    pub chaddr: [u8; 16],     // Client hardware address
    pub sname: [u8; 64],      // Server host name
    pub file: [u8; 128],      // Boot file name
    pub magic: [u8; 4],       // 0x63, 0x82, 0x53, 0x63
}

#[derive(Clone, Debug, Default)]
pub struct DhcpLease {
    pub assigned_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns_servers: Vec<[u8; 4]>,
    pub server_ip: [u8; 4],
    pub lease_time_secs: u32,
    pub is_valid: bool,
}

pub struct DhcpClient;

impl DhcpClient {
    /// Build a DHCPDISCOVER broadcast packet.
    pub fn build_discover(mac: [u8; 6], xid: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(300);

        let mut raw = DhcpPacketRaw {
            op: BOOTREQUEST,
            htype: 1, // Ethernet
            hlen: 6,
            hops: 0,
            xid: xid.to_be(),
            secs: 0,
            flags: (0x8000u16).to_be(), // Broadcast flag
            ciaddr: [0; 4],
            yiaddr: [0; 4],
            siaddr: [0; 4],
            giaddr: [0; 4],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic: DHCP_MAGIC_COOKIE,
        };
        raw.chaddr[..6].copy_from_slice(&mac);

        let ptr = &raw as *const _ as *const u8;
        unsafe {
            for i in 0..core::mem::size_of::<DhcpPacketRaw>() {
                pkt.push(*ptr.add(i));
            }
        }

        // Option 53: Message Type = DHCPDISCOVER
        pkt.push(OPT_MESSAGE_TYPE);
        pkt.push(1);
        pkt.push(DHCPDISCOVER);

        // Option 55: Parameter Request List (Subnet Mask, Router, DNS)
        pkt.push(OPT_PARAM_REQUEST);
        pkt.push(3);
        pkt.push(OPT_SUBNET_MASK);
        pkt.push(OPT_ROUTER);
        pkt.push(OPT_DNS_SERVERS);

        // Option 255: End
        pkt.push(OPT_END);

        // Pad to at least 300 bytes (standard BOOTP minimum)
        while pkt.len() < 300 {
            pkt.push(0);
        }

        pkt
    }

    /// Build a DHCPREQUEST packet to confirm leased IP from DHCPOFFER.
    pub fn build_request(mac: [u8; 6], requested_ip: [u8; 4], server_ip: [u8; 4], xid: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(300);

        let mut raw = DhcpPacketRaw {
            op: BOOTREQUEST,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: xid.to_be(),
            secs: 0,
            flags: (0x8000u16).to_be(),
            ciaddr: [0; 4],
            yiaddr: [0; 4],
            siaddr: [0; 4],
            giaddr: [0; 4],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic: DHCP_MAGIC_COOKIE,
        };
        raw.chaddr[..6].copy_from_slice(&mac);

        let ptr = &raw as *const _ as *const u8;
        unsafe {
            for i in 0..core::mem::size_of::<DhcpPacketRaw>() {
                pkt.push(*ptr.add(i));
            }
        }

        // Option 53: Message Type = DHCPREQUEST
        pkt.push(OPT_MESSAGE_TYPE);
        pkt.push(1);
        pkt.push(DHCPREQUEST);

        // Option 50: Requested IP Address
        pkt.push(OPT_REQUESTED_IP);
        pkt.push(4);
        pkt.extend_from_slice(&requested_ip);

        // Option 54: Server Identifier
        pkt.push(OPT_SERVER_IDENT);
        pkt.push(4);
        pkt.extend_from_slice(&server_ip);

        // Option 255: End
        pkt.push(OPT_END);

        while pkt.len() < 300 {
            pkt.push(0);
        }

        pkt
    }

    /// Parse a DHCPOFFER or DHCPACK response packet.
    pub fn parse_reply(bytes: &[u8], expected_xid: u32) -> Option<(u8, DhcpLease)> {
        let min_size = core::mem::size_of::<DhcpPacketRaw>();
        if bytes.len() < min_size {
            return None;
        }

        let raw = unsafe { *(bytes.as_ptr() as *const DhcpPacketRaw) };
        if raw.op != BOOTREPLY || u32::from_be(raw.xid) != expected_xid || raw.magic != DHCP_MAGIC_COOKIE {
            return None;
        }

        let mut lease = DhcpLease {
            assigned_ip: raw.yiaddr,
            server_ip: raw.siaddr,
            ..Default::default()
        };

        let mut msg_type = 0u8;
        let mut offset = min_size;

        while offset < bytes.len() {
            let opt = bytes[offset];
            if opt == OPT_END {
                break;
            }
            if opt == OPT_PAD {
                offset += 1;
                continue;
            }

            if offset + 1 >= bytes.len() {
                break;
            }
            let len = bytes[offset + 1] as usize;
            offset += 2;

            if offset + len > bytes.len() {
                break;
            }

            let opt_data = &bytes[offset..offset + len];
            match opt {
                OPT_MESSAGE_TYPE => {
                    if len >= 1 {
                        msg_type = opt_data[0];
                    }
                }
                OPT_SUBNET_MASK => {
                    if len == 4 {
                        lease.subnet_mask.copy_from_slice(opt_data);
                    }
                }
                OPT_ROUTER => {
                    if len >= 4 {
                        lease.gateway.copy_from_slice(&opt_data[..4]);
                    }
                }
                OPT_DNS_SERVERS => {
                    let count = len / 4;
                    for i in 0..count {
                        let mut dns = [0u8; 4];
                        dns.copy_from_slice(&opt_data[i * 4..(i + 1) * 4]);
                        lease.dns_servers.push(dns);
                    }
                }
                OPT_SERVER_IDENT => {
                    if len == 4 {
                        lease.server_ip.copy_from_slice(opt_data);
                    }
                }
                OPT_LEASE_TIME => {
                    if len == 4 {
                        lease.lease_time_secs = u32::from_be_bytes([
                            opt_data[0], opt_data[1], opt_data[2], opt_data[3],
                        ]);
                    }
                }
                _ => {}
            }

            offset += len;
        }

        lease.is_valid = true;
        Some((msg_type, lease))
    }
}
