//! IPv4 Header Parser/Serializer, RFC 1071 Internet Checksum & Longest-Prefix Match Routing Table.

use alloc::vec::Vec;
use core::fmt;

/// A 32-bit IPv4 network address in network byte order (4 octets).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    /// `0.0.0.0` unspecified address.
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
    /// `127.0.0.1` loopback address.
    pub const LOCALHOST: Self = Self([127, 0, 0, 1]);
    /// `255.255.255.255` limited broadcast address.
    pub const BROADCAST: Self = Self([255, 255, 255, 255]);

    /// Constructs an `Ipv4Addr` from four octets `a.b.c.d`.
    #[inline]
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    /// Converts from a big-endian 32-bit integer.
    #[inline]
    pub const fn from_u32(val: u32) -> Self {
        Self(val.to_be_bytes())
    }

    /// Converts into a host-order `u32` (where `127.0.0.1` is `0x7F00_0001`).
    #[inline]
    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Returns the 4-byte octet representation.
    #[inline]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }

    /// Returns `true` if in `127.0.0.0/8`.
    #[inline]
    pub const fn is_loopback(self) -> bool {
        self.0[0] == 127
    }

    /// Returns `true` if in RFC 1918 private space (`10/8`, `172.16/12`, `192.168/16`).
    #[inline]
    pub const fn is_private(self) -> bool {
        match self.0 {
            [10, ..] => true,
            [172, b, ..] if b >= 16 && b <= 31 => true,
            [192, 168, ..] => true,
            _ => false,
        }
    }

    /// Returns `true` if in link-local `169.254.0.0/16`.
    #[inline]
    pub const fn is_link_local(self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Returns `true` if in multicast `224.0.0.0/4`.
    #[inline]
    pub const fn is_multicast(self) -> bool {
        (self.0[0] & 0xF0) == 224
    }

    /// Returns `true` if `255.255.255.255`.
    #[inline]
    pub const fn is_broadcast(self) -> bool {
        self.to_u32() == 0xFFFF_FFFF
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Computes the RFC 1071 16-bit ones'-complement Internet Checksum over a byte slice.
pub fn rfc1071_checksum(data: &[u8]) -> u16 {
    let sum = ones_complement_sum(data, 0);
    fold_and_invert(sum)
}

/// Accumulates big-endian 16-bit words into a running 32-bit sum.
#[inline]
pub fn ones_complement_sum(data: &[u8], initial: u32) -> u32 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        let word = u16::from_be_bytes([data[i], 0]) as u32;
        sum = sum.wrapping_add(word);
    }
    sum
}

/// Folds a 32-bit ones'-complement accumulator down to 16 bits and returns its bitwise inverse.
#[inline]
pub fn fold_and_invert(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Errors encountered while parsing or validating an IPv4 packet header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4Error {
    /// Buffer shorter than 20 bytes or shorter than `IHL * 4`.
    TruncatedHeader,
    /// Buffer shorter than `total_len` field.
    TruncatedPacket,
    /// Version field is not `4`.
    InvalidVersion(u8),
    /// Internet Header Length (`IHL`) is less than `5` (20 bytes).
    InvalidHeaderLength(u8),
    /// Total length is smaller than header length.
    InvalidTotalLength(u16),
    /// Header checksum verification failed.
    BadChecksum { expected: u16, actual: u16 },
    /// Packet TTL has expired (`<= 1`) during forwarding.
    TtlExpired,
}

/// Standard 20-byte RFC 791 IPv4 Packet Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Internet Header Length in 32-bit words (minimum 5).
    pub ihl: u8,
    /// Differentiated Services Code Point (6 bits).
    pub dscp: u8,
    /// Explicit Congestion Notification (2 bits).
    pub ecn: u8,
    /// Total packet length in bytes (header + payload).
    pub total_len: u16,
    /// Fragment identification number.
    pub identification: u16,
    /// Don't Fragment flag.
    pub dont_fragment: bool,
    /// More Fragments flag.
    pub more_fragments: bool,
    /// Fragment offset in 8-byte blocks (13 bits).
    pub fragment_offset: u16,
    /// Time To Live (hop limit).
    pub ttl: u8,
    /// Upper-layer IP protocol number (e.g., `1` = ICMP, `6` = TCP, `17` = UDP).
    pub protocol: u8,
    /// Header checksum.
    pub header_checksum: u16,
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    /// Minimum IPv4 header length in bytes (no IP options).
    pub const MIN_LEN: usize = 20;

    /// Constructs a new 20-byte IPv4 header with `dont_fragment = true` and `ttl = 64`.
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, protocol: u8, payload_len: u16) -> Self {
        let mut hdr = Self {
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_len: (Self::MIN_LEN as u16).saturating_add(payload_len),
            identification: 0x1337,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            header_checksum: 0,
            src_ip,
            dst_ip,
        };
        hdr.header_checksum = hdr.compute_checksum();
        hdr
    }

    /// Returns the header length in bytes (`ihl * 4`).
    #[inline]
    pub const fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Serializes the 20-byte base header into a stack array, setting checksum to `checksum_field`.
    fn to_raw_bytes(&self, checksum_field: u16) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0] = (4 << 4) | (self.ihl & 0x0F);
        b[1] = ((self.dscp & 0x3F) << 2) | (self.ecn & 0x03);
        b[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        b[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags_frag = ((self.dont_fragment as u16) << 14)
            | ((self.more_fragments as u16) << 13)
            | (self.fragment_offset & 0x1FFF);
        b[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        b[8] = self.ttl;
        b[9] = self.protocol;
        b[10..12].copy_from_slice(&checksum_field.to_be_bytes());
        b[12..16].copy_from_slice(&self.src_ip.0);
        b[16..20].copy_from_slice(&self.dst_ip.0);
        b
    }

    /// Computes the RFC 1071 checksum for this 20-byte header (with the checksum field zeroed).
    pub fn compute_checksum(&self) -> u16 {
        let raw = self.to_raw_bytes(0);
        rfc1071_checksum(&raw)
    }

    /// Serializes this header into `out` (recomputing the checksum automatically).
    pub fn write_to(&mut self, out: &mut [u8]) -> Result<usize, Ipv4Error> {
        if out.len() < Self::MIN_LEN {
            return Err(Ipv4Error::TruncatedHeader);
        }
        self.header_checksum = self.compute_checksum();
        let raw = self.to_raw_bytes(self.header_checksum);
        out[..20].copy_from_slice(&raw);
        Ok(Self::MIN_LEN)
    }

    /// Parses and validates an `Ipv4Header` from `buf`, returning `(header, payload_slice)`.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), Ipv4Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Ipv4Error::TruncatedHeader);
        }
        let version = buf[0] >> 4;
        if version != 4 {
            return Err(Ipv4Error::InvalidVersion(version));
        }
        let ihl = buf[0] & 0x0F;
        if ihl < 5 {
            return Err(Ipv4Error::InvalidHeaderLength(ihl));
        }
        let hdr_len = (ihl as usize) * 4;
        if buf.len() < hdr_len {
            return Err(Ipv4Error::TruncatedHeader);
        }

        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        if (total_len as usize) < hdr_len {
            return Err(Ipv4Error::InvalidTotalLength(total_len));
        }
        if buf.len() < total_len as usize {
            return Err(Ipv4Error::TruncatedPacket);
        }

        // Verify RFC 1071 checksum over the full IHL header bytes.
        if rfc1071_checksum(&buf[..hdr_len]) != 0 {
            let wire_csum = u16::from_be_bytes([buf[10], buf[11]]);
            let mut copy = [0u8; 60];
            copy[..hdr_len].copy_from_slice(&buf[..hdr_len]);
            copy[10] = 0;
            copy[11] = 0;
            let expected = rfc1071_checksum(&copy[..hdr_len]);
            return Err(Ipv4Error::BadChecksum {
                expected,
                actual: wire_csum,
            });
        }

        let dscp = buf[1] >> 2;
        let ecn = buf[1] & 0x03;
        let identification = u16::from_be_bytes([buf[4], buf[5]]);
        let flags_frag = u16::from_be_bytes([buf[6], buf[7]]);
        let dont_fragment = (flags_frag & 0x4000) != 0;
        let more_fragments = (flags_frag & 0x2000) != 0;
        let fragment_offset = flags_frag & 0x1FFF;
        let ttl = buf[8];
        let protocol = buf[9];
        let header_checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let src_ip = Ipv4Addr([buf[12], buf[13], buf[14], buf[15]]);
        let dst_ip = Ipv4Addr([buf[16], buf[17], buf[18], buf[19]]);

        let hdr = Self {
            ihl,
            dscp,
            ecn,
            total_len,
            identification,
            dont_fragment,
            more_fragments,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            src_ip,
            dst_ip,
        };
        Ok((hdr, &buf[hdr_len..total_len as usize]))
    }

    /// Decrements TTL by 1 and updates the header checksum incrementally per RFC 1624.
    pub fn decrement_ttl(&mut self) -> Result<(), Ipv4Error> {
        if self.ttl <= 1 {
            return Err(Ipv4Error::TtlExpired);
        }
        self.ttl -= 1;
        self.header_checksum = self.compute_checksum();
        Ok(())
    }
}

/// Forwarding next-hop semantics for an IPv4 route entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteNextHop {
    /// Destination is directly connected on the specified link interface.
    Connected,
    /// Traffic must be forwarded via the specified gateway router IPv4 address.
    Gateway(Ipv4Addr),
}

/// A CIDR routing table entry (`prefix/prefix_len` -> `next_hop`, `interface_id`, `metric`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    pub next_hop: RouteNextHop,
    pub interface_id: u16,
    pub metric: u32,
}

impl RouteEntry {
    /// Creates a normalized CIDR route entry, masking host bits in `prefix`.
    pub const fn new(
        prefix: Ipv4Addr,
        prefix_len: u8,
        next_hop: RouteNextHop,
        interface_id: u16,
        metric: u32,
    ) -> Self {
        let len = if prefix_len > 32 { 32 } else { prefix_len };
        let mask = Self::prefix_mask(len);
        let masked = Ipv4Addr::from_u32(prefix.to_u32() & mask);
        Self {
            prefix: masked,
            prefix_len: len,
            next_hop,
            interface_id,
            metric,
        }
    }

    /// Computes a 32-bit netmask from a CIDR prefix length (`0..=32`).
    #[inline]
    pub const fn prefix_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            0xFFFF_FFFF
        } else {
            !0u32 << (32 - prefix_len)
        }
    }

    /// Returns `true` if `dst` matches this CIDR subnet.
    #[inline]
    pub const fn matches(&self, dst: Ipv4Addr) -> bool {
        let mask = Self::prefix_mask(self.prefix_len);
        (dst.to_u32() & mask) == self.prefix.to_u32()
    }
}

/// IPv4 Longest-Prefix Match (LPM) Forwarding Information Base (FIB).
#[derive(Clone, Debug, Default)]
pub struct Ipv4RoutingTable {
    routes: Vec<RouteEntry>,
}

impl Ipv4RoutingTable {
    /// Creates an empty IPv4 routing table.
    pub const fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Inserts or updates a CIDR route entry.
    pub fn upsert_route(&mut self, entry: RouteEntry) {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|r| r.prefix == entry.prefix && r.prefix_len == entry.prefix_len && r.interface_id == entry.interface_id)
        {
            *existing = entry;
            return;
        }
        self.routes.push(entry);
    }

    /// Removes all routes matching `prefix/prefix_len`.
    pub fn remove_route(&mut self, prefix: Ipv4Addr, prefix_len: u8) -> bool {
        let norm = RouteEntry::new(prefix, prefix_len, RouteNextHop::Connected, 0, 0);
        let before = self.routes.len();
        self.routes
            .retain(|r| !(r.prefix == norm.prefix && r.prefix_len == norm.prefix_len));
        self.routes.len() < before
    }

    /// Performs a Longest-Prefix Match (LPM) lookup, breaking ties by lowest `metric`.
    pub fn lookup(&self, dst: Ipv4Addr) -> Option<RouteEntry> {
        let mut best: Option<RouteEntry> = None;
        for &route in &self.routes {
            if route.matches(dst) {
                match best {
                    None => best = Some(route),
                    Some(cur) => {
                        if route.prefix_len > cur.prefix_len
                            || (route.prefix_len == cur.prefix_len && route.metric < cur.metric)
                        {
                            best = Some(route);
                        }
                    }
                }
            }
        }
        best
    }

    /// Returns a slice of all configured routes.
    #[inline]
    pub fn entries(&self) -> &[RouteEntry] {
        &self.routes
    }
}

/// Runs self-tests for the `ipv4_routing` module.
pub fn verify_net_ipv4_routing() -> u32 {
    let mut passed = 0u32;

    // 1. Verify RFC 1071 checksum on the canonical RFC 1071 / Wikipedia example IPv4 header.
    let mut hdr = Ipv4Header::new(
        Ipv4Addr::new(10, 0, 2, 15),
        Ipv4Addr::new(93, 184, 216, 34),
        6, // TCP
        16,
    );
    let mut pkt = [0u8; 36];
    if hdr.write_to(&mut pkt[..20]).is_ok() {
        pkt[20..36].copy_from_slice(b"CorOS-IPv4-Check");
        if rfc1071_checksum(&pkt[..20]) == 0 {
            passed += 1;
        }
        if let Ok((parsed, payload)) = Ipv4Header::parse(&pkt) {
            if parsed == hdr && payload == b"CorOS-IPv4-Check" {
                passed += 1;
            }
        }
    }

    // 2. Verify TTL decrement and checksum recalculation.
    if hdr.decrement_ttl().is_ok() && hdr.ttl == 63 && hdr.compute_checksum() == hdr.header_checksum {
        passed += 1;
    }

    // 3. Verify Longest-Prefix Match (LPM) routing table selection.
    let mut fib = Ipv4RoutingTable::new();
    // Default route 0.0.0.0/0 -> 10.0.2.2
    fib.upsert_route(RouteEntry::new(
        Ipv4Addr::UNSPECIFIED,
        0,
        RouteNextHop::Gateway(Ipv4Addr::new(10, 0, 2, 2)),
        1,
        100,
    ));
    // Corporate /16 -> 10.0.2.254
    fib.upsert_route(RouteEntry::new(
        Ipv4Addr::new(10, 0, 0, 0),
        16,
        RouteNextHop::Gateway(Ipv4Addr::new(10, 0, 2, 254)),
        1,
        50,
    ));
    // Directly connected /24 on eth0 (if_id = 1)
    fib.upsert_route(RouteEntry::new(
        Ipv4Addr::new(10, 0, 2, 0),
        24,
        RouteNextHop::Connected,
        1,
        10,
    ));
    // Host route /32 -> VPN tunnel (if_id = 9)
    fib.upsert_route(RouteEntry::new(
        Ipv4Addr::new(10, 0, 2, 99),
        32,
        RouteNextHop::Gateway(Ipv4Addr::new(172, 16, 0, 1)),
        9,
        5,
    ));

    let r_host = fib.lookup(Ipv4Addr::new(10, 0, 2, 99));
    let r_lan = fib.lookup(Ipv4Addr::new(10, 0, 2, 15));
    let r_corp = fib.lookup(Ipv4Addr::new(10, 0, 9, 42));
    let r_wan = fib.lookup(Ipv4Addr::new(1, 1, 1, 1));

    if r_host.map(|r| (r.prefix_len, r.interface_id)) == Some((32, 9))
        && r_lan.map(|r| (r.prefix_len, r.next_hop)) == Some((24, RouteNextHop::Connected))
        && r_corp.map(|r| r.prefix_len) == Some(16)
        && r_wan.map(|r| r.prefix_len) == Some(0)
    {
        passed += 1;
    }

    passed
}
