//! RFC 6335 IANA Service Name and Transport Protocol Port Number Registry Lookup Table.

/// Transport protocol eligibility for an IANA-registered service port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceTransport {
    /// Service operates exclusively over TCP (`IPPROTO_TCP = 6`).
    TcpOnly,
    /// Service operates exclusively over UDP (`IPPROTO_UDP = 17`).
    UdpOnly,
    /// Service is registered for both TCP and UDP.
    TcpAndUdp,
}

impl ServiceTransport {
    /// Returns `true` if this entry applies to TCP.
    #[inline]
    pub const fn supports_tcp(self) -> bool {
        matches!(self, Self::TcpOnly | Self::TcpAndUdp)
    }

    /// Returns `true` if this entry applies to UDP.
    #[inline]
    pub const fn supports_udp(self) -> bool {
        matches!(self, Self::UdpOnly | Self::TcpAndUdp)
    }
}

/// RFC 6335 Section 6 Port Range Classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRangeClass {
    /// System / Well-Known Ports (`0..=1023`).
    WellKnown,
    /// User / Registered Ports (`1024..=49151`).
    Registered,
    /// Dynamic / Private / Ephemeral Ports (`49152..=65535`).
    DynamicEphemeral,
}

/// Classifies any 16-bit TCP/UDP port number per RFC 6335.
#[inline]
pub const fn classify_port_range(port: u16) -> PortRangeClass {
    match port {
        0..=1023 => PortRangeClass::WellKnown,
        1024..=49151 => PortRangeClass::Registered,
        49152..=65535 => PortRangeClass::DynamicEphemeral,
    }
}

/// Entry in the canonical IANA Well-Known & Registered Service Registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IanaServiceEntry {
    pub port: u16,
    pub transport: ServiceTransport,
    pub name: &'static str,
    pub description: &'static str,
}

/// Sorted table of canonical IANA Well-Known and Registered TCP/UDP services.
pub static IANA_SERVICE_REGISTRY: &[IanaServiceEntry] = &[
    IanaServiceEntry {
        port: 7,
        transport: ServiceTransport::TcpAndUdp,
        name: "echo",
        description: "RFC 862 Echo Protocol",
    },
    IanaServiceEntry {
        port: 20,
        transport: ServiceTransport::TcpOnly,
        name: "ftp-data",
        description: "File Transfer Protocol (Data Channel)",
    },
    IanaServiceEntry {
        port: 21,
        transport: ServiceTransport::TcpOnly,
        name: "ftp",
        description: "File Transfer Protocol (Control)",
    },
    IanaServiceEntry {
        port: 22,
        transport: ServiceTransport::TcpOnly,
        name: "ssh",
        description: "Secure Shell (SSH) Protocol",
    },
    IanaServiceEntry {
        port: 23,
        transport: ServiceTransport::TcpOnly,
        name: "telnet",
        description: "Telnet Terminal Protocol",
    },
    IanaServiceEntry {
        port: 25,
        transport: ServiceTransport::TcpOnly,
        name: "smtp",
        description: "Simple Mail Transfer Protocol",
    },
    IanaServiceEntry {
        port: 53,
        transport: ServiceTransport::TcpAndUdp,
        name: "domain",
        description: "Domain Name System (DNS)",
    },
    IanaServiceEntry {
        port: 67,
        transport: ServiceTransport::UdpOnly,
        name: "bootps",
        description: "DHCPv4 / BOOTP Server",
    },
    IanaServiceEntry {
        port: 68,
        transport: ServiceTransport::UdpOnly,
        name: "bootpc",
        description: "DHCPv4 / BOOTP Client",
    },
    IanaServiceEntry {
        port: 69,
        transport: ServiceTransport::UdpOnly,
        name: "tftp",
        description: "Trivial File Transfer Protocol",
    },
    IanaServiceEntry {
        port: 80,
        transport: ServiceTransport::TcpOnly,
        name: "http",
        description: "Hypertext Transfer Protocol",
    },
    IanaServiceEntry {
        port: 88,
        transport: ServiceTransport::TcpAndUdp,
        name: "kerberos",
        description: "Kerberos v5 Authentication",
    },
    IanaServiceEntry {
        port: 110,
        transport: ServiceTransport::TcpOnly,
        name: "pop3",
        description: "Post Office Protocol v3",
    },
    IanaServiceEntry {
        port: 123,
        transport: ServiceTransport::UdpOnly,
        name: "ntp",
        description: "Network Time Protocol (NTP)",
    },
    IanaServiceEntry {
        port: 143,
        transport: ServiceTransport::TcpOnly,
        name: "imap",
        description: "Internet Message Access Protocol",
    },
    IanaServiceEntry {
        port: 161,
        transport: ServiceTransport::UdpOnly,
        name: "snmp",
        description: "Simple Network Management Protocol",
    },
    IanaServiceEntry {
        port: 179,
        transport: ServiceTransport::TcpOnly,
        name: "bgp",
        description: "Border Gateway Protocol (BGP-4)",
    },
    IanaServiceEntry {
        port: 389,
        transport: ServiceTransport::TcpAndUdp,
        name: "ldap",
        description: "Lightweight Directory Access Protocol",
    },
    IanaServiceEntry {
        port: 443,
        transport: ServiceTransport::TcpAndUdp,
        name: "https",
        description: "HTTP over TLS / QUIC (HTTP/3)",
    },
    IanaServiceEntry {
        port: 445,
        transport: ServiceTransport::TcpOnly,
        name: "microsoft-ds",
        description: "SMB2 / SMB3 Direct Host File Sharing",
    },
    IanaServiceEntry {
        port: 500,
        transport: ServiceTransport::UdpOnly,
        name: "isakmp",
        description: "IPsec IKEv2 Key Exchange",
    },
    IanaServiceEntry {
        port: 514,
        transport: ServiceTransport::UdpOnly,
        name: "syslog",
        description: "RFC 5424 System Logging Protocol",
    },
    IanaServiceEntry {
        port: 546,
        transport: ServiceTransport::UdpOnly,
        name: "dhcpv6-client",
        description: "DHCPv6 Client",
    },
    IanaServiceEntry {
        port: 547,
        transport: ServiceTransport::UdpOnly,
        name: "dhcpv6-server",
        description: "DHCPv6 Server",
    },
    IanaServiceEntry {
        port: 636,
        transport: ServiceTransport::TcpOnly,
        name: "ldaps",
        description: "LDAP over TLS/SSL",
    },
    IanaServiceEntry {
        port: 853,
        transport: ServiceTransport::TcpAndUdp,
        name: "domain-s",
        description: "DNS over TLS (DoT) / DNS over QUIC",
    },
    IanaServiceEntry {
        port: 993,
        transport: ServiceTransport::TcpOnly,
        name: "imaps",
        description: "IMAP over TLS/SSL",
    },
    IanaServiceEntry {
        port: 1812,
        transport: ServiceTransport::UdpOnly,
        name: "radius",
        description: "RADIUS Authentication Protocol",
    },
    IanaServiceEntry {
        port: 3306,
        transport: ServiceTransport::TcpOnly,
        name: "mysql",
        description: "MySQL Database Server",
    },
    IanaServiceEntry {
        port: 3389,
        transport: ServiceTransport::TcpAndUdp,
        name: "ms-wbt-server",
        description: "Remote Desktop Protocol (RDP)",
    },
    IanaServiceEntry {
        port: 5353,
        transport: ServiceTransport::UdpOnly,
        name: "mdns",
        description: "Multicast DNS (RFC 6762)",
    },
    IanaServiceEntry {
        port: 5432,
        transport: ServiceTransport::TcpOnly,
        name: "postgresql",
        description: "PostgreSQL Database Wire Protocol",
    },
    IanaServiceEntry {
        port: 6379,
        transport: ServiceTransport::TcpOnly,
        name: "redis",
        description: "Redis Key-Value Datastore",
    },
    IanaServiceEntry {
        port: 8080,
        transport: ServiceTransport::TcpOnly,
        name: "http-alt",
        description: "HTTP Alternate / Proxy Port",
    },
    IanaServiceEntry {
        port: 51820,
        transport: ServiceTransport::UdpOnly,
        name: "wireguard",
        description: "WireGuard VPN Tunnel",
    },
];

/// Performs a binary search in `IANA_SERVICE_REGISTRY` by port number.
pub fn lookup_service_by_port(port: u16) -> Option<&'static IanaServiceEntry> {
    IANA_SERVICE_REGISTRY
        .binary_search_by_key(&port, |e| e.port)
        .ok()
        .map(|idx| &IANA_SERVICE_REGISTRY[idx])
}

/// Looks up an IANA service entry by its canonical short name (case-insensitive, e.g., `"ssh"` or `"https"`).
pub fn lookup_service_by_name(name: &str) -> Option<&'static IanaServiceEntry> {
    IANA_SERVICE_REGISTRY
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
}

/// Runs self-tests for the `iana_services` module.
pub fn verify_net_iana_services() -> u32 {
    let mut passed = 0u32;

    // 1. Verify binary search ordering invariant of IANA_SERVICE_REGISTRY.
    let sorted = IANA_SERVICE_REGISTRY
        .windows(2)
        .all(|w| w[0].port < w[1].port);
    if sorted {
        passed += 1;
    }

    // 2. Verify well-known service lookups by port number (SSH 22, DNS 53, DHCP 67/68, HTTP 80, NTP 123, HTTPS 443, SMB 445, Syslog 514, PostgreSQL 5432).
    if lookup_service_by_port(22).map(|e| e.name) == Some("ssh")
        && lookup_service_by_port(53).map(|e| e.transport) == Some(ServiceTransport::TcpAndUdp)
        && lookup_service_by_port(67).map(|e| e.name) == Some("bootps")
        && lookup_service_by_port(68).map(|e| e.name) == Some("bootpc")
        && lookup_service_by_port(80).map(|e| e.name) == Some("http")
        && lookup_service_by_port(123).map(|e| e.name) == Some("ntp")
        && lookup_service_by_port(443).map(|e| e.name) == Some("https")
        && lookup_service_by_port(445).map(|e| e.name) == Some("microsoft-ds")
        && lookup_service_by_port(514).map(|e| e.name) == Some("syslog")
        && lookup_service_by_port(5432).map(|e| e.name) == Some("postgresql")
    {
        passed += 1;
    }

    // 3. Verify reverse lookup by service name.
    if lookup_service_by_name("HTTPS").map(|e| e.port) == Some(443)
        && lookup_service_by_name("postgresql").map(|e| e.port) == Some(5432)
    {
        passed += 1;
    }

    // 4. Verify RFC 6335 port range classification.
    if classify_port_range(443) == PortRangeClass::WellKnown
        && classify_port_range(5432) == PortRangeClass::Registered
        && classify_port_range(50_000) == PortRangeClass::DynamicEphemeral
    {
        passed += 1;
    }

    passed
}
