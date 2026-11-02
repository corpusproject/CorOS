//! RFC 768 User Datagram Protocol (UDP) Engine for CorOS.
//! 100% in-house implementation supporting connectionless datagram framing,
//! pseudo-header checksum verification, and port-based demultiplexing.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16, payload_len: usize) -> Self {
        let total_len = (8 + payload_len) as u16;
        Self {
            src_port: src_port.to_be(),
            dst_port: dst_port.to_be(),
            length: total_len.to_be(),
            checksum: 0,
        }
    }

    pub fn length_bytes(&self) -> usize {
        u16::from_be(self.length) as usize
    }

    pub fn calculate_checksum(&self, src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;

        sum += 17u32; // UDP protocol = 17
        sum += (8 + payload.len()) as u32;

        sum += u16::from_be(self.src_port) as u32;
        sum += u16::from_be(self.dst_port) as u32;
        sum += u16::from_be(self.length) as u32;

        let mut i = 0;
        while i + 1 < payload.len() {
            let w = u16::from_be_bytes([payload[i], payload[i + 1]]);
            sum += w as u32;
            i += 2;
        }
        if i < payload.len() {
            let w = u16::from_be_bytes([payload[i], 0]);
            sum += w as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let res = !(sum as u16);
        if res == 0 { 0xFFFF } else { res }
    }

    pub fn parse(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 8 {
            return None;
        }
        let hdr = unsafe { *(bytes.as_ptr() as *const UdpHeader) };
        let len = hdr.length_bytes();
        if bytes.len() < len || len < 8 {
            return None;
        }
        let payload = &bytes[8..len];
        Some((hdr, payload))
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        let ptr = self as *const _ as *const u8;
        unsafe {
            for i in 0..8 {
                buf[i] = *ptr.add(i);
            }
        }
        buf
    }
}

// -----------------------------------------------------------------------------
// UDP Socket Registry
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub data: Vec<u8>,
}

pub struct UdpSocketTable {
    bound_ports: BTreeMap<u16, Vec<UdpDatagram>>,
}

impl UdpSocketTable {
    pub const fn new() -> Self {
        Self {
            bound_ports: BTreeMap::new(),
        }
    }

    pub fn bind(&mut self, port: u16) -> bool {
        if self.bound_ports.contains_key(&port) {
            false
        } else {
            self.bound_ports.insert(port, Vec::new());
            true
        }
    }

    pub fn unbind(&mut self, port: u16) {
        self.bound_ports.remove(&port);
    }

    pub fn deliver(&mut self, dst_port: u16, datagram: UdpDatagram) -> bool {
        if let Some(queue) = self.bound_ports.get_mut(&dst_port) {
            queue.push(datagram);
            true
        } else {
            false
        }
    }

    pub fn recv(&mut self, port: u16) -> Option<UdpDatagram> {
        if let Some(queue) = self.bound_ports.get_mut(&port) {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        None
    }
}
