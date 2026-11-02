//! RFC 9293 11-State TCP Finite State Machine, 20-Byte Header Codec, Modular Sequence Arithmetic & Congestion Control.

use crate::ipv4_routing::{fold_and_invert, ones_complement_sum, Ipv4Addr};
use alloc::vec::Vec;

/// IP protocol number for TCP (`6`).
pub const IPPROTO_TCP: u8 = 6;

/// TCP Header Control Flags (low 8 bits of byte 13 in the TCP header).
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// 32-bit modular TCP Sequence Number (RFC 9293 Section 3.4, modulo $2^{32}$ comparisons).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TcpSeq(pub u32);

impl TcpSeq {
    /// Adds `delta` modulo $2^{32}$.
    #[inline]
    pub const fn wrapping_add(self, delta: u32) -> Self {
        Self(self.0.wrapping_add(delta))
    }

    /// Returns `true` if `self < other` in modular 32-bit sequence space (`(self - other) as i32 < 0`).
    #[inline]
    pub const fn before(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    /// Returns `true` if `self <= other` in modular 32-bit sequence space.
    #[inline]
    pub const fn before_or_eq(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) <= 0
    }

    /// Returns `true` if `self > other` in modular 32-bit sequence space.
    #[inline]
    pub const fn after(self, other: Self) -> bool {
        (self.0.wrapping_sub(other.0) as i32) > 0
    }

    /// Returns `true` if `self` lies within `[start, end)` in modular sequence space.
    #[inline]
    pub const fn in_window(self, start: Self, end: Self) -> bool {
        !self.before(start) && self.before(end)
    }
}

/// The 11 canonical connection states of the RFC 9293 TCP Finite State Machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Errors encountered while parsing a TCP segment or driving the TCP state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpError {
    /// Segment buffer is shorter than 20 bytes or `data_offset * 4`.
    TruncatedHeader,
    /// Data offset nibble is less than `5` (20 bytes).
    InvalidDataOffset(u8),
    /// TCP pseudo-header + segment checksum verification failed.
    BadChecksum { expected: u16, actual: u16 },
    /// Operation is invalid in the current `TcpState`.
    InvalidStateTransition(TcpState),
    /// Peer reset the connection (`RST` received).
    ConnectionReset,
}

/// 20-byte RFC 9293 TCP Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: TcpSeq,
    pub ack_num: TcpSeq,
    /// Header length in 32-bit words (`5..=15`).
    pub data_offset: u8,
    /// Bitmask of `tcp_flags::*`.
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Minimum TCP header length in bytes (no TCP options).
    pub const MIN_LEN: usize = 20;

    /// Constructs a new 20-byte `TcpHeader` with `data_offset = 5`.
    pub const fn new(
        src_port: u16,
        dst_port: u16,
        seq_num: TcpSeq,
        ack_num: TcpSeq,
        flags: u8,
        window_size: u16,
    ) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset: 5,
            flags,
            window_size,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Returns the number of sequence space bytes consumed by this segment (`payload.len() + SYN + FIN`).
    #[inline]
    pub const fn segment_seq_len(&self, payload_len: usize) -> u32 {
        let mut n = payload_len as u32;
        if (self.flags & tcp_flags::SYN) != 0 {
            n += 1;
        }
        if (self.flags & tcp_flags::FIN) != 0 {
            n += 1;
        }
        n
    }

    fn to_raw_bytes(&self, checksum_field: u16) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        b[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        b[4..8].copy_from_slice(&self.seq_num.0.to_be_bytes());
        b[8..12].copy_from_slice(&self.ack_num.0.to_be_bytes());
        b[12] = (self.data_offset & 0x0F) << 4;
        b[13] = self.flags;
        b[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        b[16..18].copy_from_slice(&checksum_field.to_be_bytes());
        b[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        b
    }

    /// Computes the TCP checksum over an IPv4 12-byte pseudo-header, TCP header, and payload.
    pub fn compute_checksum_ipv4(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> u16 {
        let tcp_len = (Self::MIN_LEN + payload.len()) as u16;
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip.0);
        pseudo[4..8].copy_from_slice(&dst_ip.0);
        pseudo[8] = 0;
        pseudo[9] = IPPROTO_TCP;
        pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());

        let mut sum = ones_complement_sum(&pseudo, 0);
        sum = ones_complement_sum(&self.to_raw_bytes(0), sum);
        sum = ones_complement_sum(payload, sum);
        fold_and_invert(sum)
    }

    /// Serializes this TCP segment (20-byte header + payload) with a valid IPv4 checksum.
    pub fn to_bytes_ipv4(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> Vec<u8> {
        self.checksum = self.compute_checksum_ipv4(src_ip, dst_ip, payload);
        let mut out = Vec::with_capacity(Self::MIN_LEN + payload.len());
        out.extend_from_slice(&self.to_raw_bytes(self.checksum));
        out.extend_from_slice(payload);
        out
    }

    /// Parses and validates an IPv4 TCP segment from `buf`, returning `(header, payload_slice)`.
    pub fn parse_ipv4<'a>(
        buf: &'a [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Result<(Self, &'a [u8]), TcpError> {
        if buf.len() < Self::MIN_LEN {
            return Err(TcpError::TruncatedHeader);
        }
        let data_offset = buf[12] >> 4;
        if data_offset < 5 {
            return Err(TcpError::InvalidDataOffset(data_offset));
        }
        let hdr_len = (data_offset as usize) * 4;
        if buf.len() < hdr_len {
            return Err(TcpError::TruncatedHeader);
        }

        let wire_csum = u16::from_be_bytes([buf[16], buf[17]]);
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip.0);
        pseudo[4..8].copy_from_slice(&dst_ip.0);
        pseudo[8] = 0;
        pseudo[9] = IPPROTO_TCP;
        pseudo[10..12].copy_from_slice(&(buf.len() as u16).to_be_bytes());

        let sum = ones_complement_sum(buf, ones_complement_sum(&pseudo, 0));
        if fold_and_invert(sum) != 0 {
            let mut copy = buf.to_vec();
            copy[16] = 0;
            copy[17] = 0;
            let expected = fold_and_invert(ones_complement_sum(
                &copy,
                ones_complement_sum(&pseudo, 0),
            ));
            return Err(TcpError::BadChecksum {
                expected,
                actual: wire_csum,
            });
        }

        let hdr = Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            seq_num: TcpSeq(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]])),
            ack_num: TcpSeq(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]])),
            data_offset,
            flags: buf[13],
            window_size: u16::from_be_bytes([buf[14], buf[15]]),
            checksum: wire_csum,
            urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
        };
        Ok((hdr, &buf[hdr_len..]))
    }
}

/// TCP Reno / NewReno Congestion Control & RFC 6298 Smoothed RTT (SRTT) Estimator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpCongestionControl {
    /// Maximum Segment Size in bytes (default 1460 for Ethernet IPv4).
    pub mss: u32,
    /// Congestion window in bytes (`cwnd`).
    pub cwnd: u32,
    /// Slow-start threshold in bytes (`ssthresh`).
    pub ssthresh: u32,
    /// Duplicate ACK counter for Fast Retransmit / Fast Recovery.
    pub dup_acks: u8,
    /// Smoothed Round-Trip Time in microseconds (`srtt`).
    pub srtt_us: u64,
    /// Round-Trip Time variation in microseconds (`rttvar`).
    pub rttvar_us: u64,
    /// Retransmission Timeout in microseconds (`rto`).
    pub rto_us: u64,
}

impl TcpCongestionControl {
    /// Creates a new congestion controller initialized to RFC 5681 / RFC 6928 initial window (`IW = 10 * MSS`).
    pub const fn new(mss: u32) -> Self {
        Self {
            mss,
            cwnd: mss * 10,
            ssthresh: 65_535,
            dup_acks: 0,
            srtt_us: 0,
            rttvar_us: 0,
            rto_us: 1_000_000, // 1.0 second initial RTO per RFC 6298
        }
    }

    /// Updates `cwnd` upon receipt of a new cumulative ACK advancing `acked_bytes`.
    pub fn on_new_ack(&mut self, acked_bytes: u32) {
        self.dup_acks = 0;
        if self.cwnd < self.ssthresh {
            // Slow Start: exponential increase by acked_bytes (up to 1 MSS per ACK).
            let inc = if acked_bytes > self.mss {
                self.mss
            } else {
                acked_bytes
            };
            self.cwnd = self.cwnd.saturating_add(inc);
        } else {
            // Congestion Avoidance: additive increase ~ (MSS * MSS) / cwnd per ACK.
            let inc = ((self.mss as u64 * self.mss as u64) / (self.cwnd.max(1) as u64)).max(1) as u32;
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    /// Handles a duplicate ACK, triggering Fast Retransmit / Fast Recovery on the 3rd dup ACK.
    /// Returns `true` if Fast Retransmit should be triggered now.
    pub fn on_duplicate_ack(&mut self) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.ssthresh = (self.cwnd / 2).max(self.mss * 2);
            self.cwnd = self.ssthresh + 3 * self.mss;
            true
        } else if self.dup_acks > 3 {
            self.cwnd = self.cwnd.saturating_add(self.mss);
            false
        } else {
            false
        }
    }

    /// Resets `cwnd` to `1 * MSS` and halves `ssthresh` upon a retransmission timeout (RTO).
    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mss * 2);
        self.cwnd = self.mss;
        self.dup_acks = 0;
        self.rto_us = (self.rto_us.saturating_mul(2)).min(60_000_000);
    }

    /// Updates `srtt_us`, `rttvar_us`, and `rto_us` from a fresh RTT measurement `rtt_sample_us` (RFC 6298).
    pub fn update_rtt(&mut self, rtt_sample_us: u64) {
        if self.srtt_us == 0 {
            self.srtt_us = rtt_sample_us;
            self.rttvar_us = rtt_sample_us / 2;
        } else {
            let diff = self.srtt_us.abs_diff(rtt_sample_us);
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R'|
            self.rttvar_us = (self.rttvar_us * 3 + diff) / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R'
            self.srtt_us = (self.srtt_us * 7 + rtt_sample_us) / 8;
        }
        let k_rttvar = (4 * self.rttvar_us).max(1_000);
        self.rto_us = (self.srtt_us + k_rttvar).clamp(200_000, 60_000_000);
    }
}

/// RFC 9293 Transmission Control Block (TCB) managing the 11-state TCP Finite State Machine.
#[derive(Clone, Debug)]
pub struct TcpControlBlock {
    pub state: TcpState,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    /// Send Unacknowledged (`SND.UNA`).
    pub snd_una: TcpSeq,
    /// Send Next (`SND.NXT`).
    pub snd_nxt: TcpSeq,
    /// Send Window (`SND.WND`).
    pub snd_wnd: u16,
    /// Initial Send Sequence Number (`ISS`).
    pub iss: TcpSeq,
    /// Receive Next (`RCV.NXT`).
    pub rcv_nxt: TcpSeq,
    /// Receive Window (`RCV.WND`).
    pub rcv_wnd: u16,
    /// Initial Receive Sequence Number (`IRS`).
    pub irs: TcpSeq,
    /// Congestion window and RTT estimator.
    pub congestion: TcpCongestionControl,
    /// In-order received application byte stream.
    pub rx_buffer: Vec<u8>,
}

impl TcpControlBlock {
    /// Creates a new TCB in the `Closed` state.
    pub const fn new(local_ip: Ipv4Addr, local_port: u16, iss: TcpSeq) -> Self {
        Self {
            state: TcpState::Closed,
            local_ip,
            local_port,
            remote_ip: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 65_535,
            iss,
            rcv_nxt: TcpSeq(0),
            rcv_wnd: 65_535,
            irs: TcpSeq(0),
            congestion: TcpCongestionControl::new(1460),
            rx_buffer: Vec::new(),
        }
    }

    /// Transitions `Closed -> Listen` for a passive server endpoint.
    pub fn listen(&mut self) -> Result<(), TcpError> {
        if self.state != TcpState::Closed {
            return Err(TcpError::InvalidStateTransition(self.state));
        }
        self.state = TcpState::Listen;
        Ok(())
    }

    /// Initiates an active open (`Closed -> SynSent`) and returns the outbound `SYN` header.
    pub fn connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Result<TcpHeader, TcpError> {
        if self.state != TcpState::Closed {
            return Err(TcpError::InvalidStateTransition(self.state));
        }
        self.remote_ip = remote_ip;
        self.remote_port = remote_port;
        self.snd_una = self.iss;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.state = TcpState::SynSent;

        Ok(TcpHeader::new(
            self.local_port,
            self.remote_port,
            self.iss,
            TcpSeq(0),
            tcp_flags::SYN,
            self.rcv_wnd,
        ))
    }

    /// Initiates an active close (`Established -> FinWait1` or `CloseWait -> LastAck`),
    /// returning the outbound `FIN | ACK` segment header.
    pub fn close(&mut self) -> Result<TcpHeader, TcpError> {
        match self.state {
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            other => return Err(TcpError::InvalidStateTransition(other)),
        }
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        Ok(TcpHeader::new(
            self.local_port,
            self.remote_port,
            seq,
            self.rcv_nxt,
            tcp_flags::FIN | tcp_flags::ACK,
            self.rcv_wnd,
        ))
    }

    /// Builds a data segment (`PSH | ACK`) in `Established` state and advances `SND.NXT`.
    pub fn send_data(&mut self, payload_len: usize) -> Result<TcpHeader, TcpError> {
        if self.state != TcpState::Established {
            return Err(TcpError::InvalidStateTransition(self.state));
        }
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(payload_len as u32);
        Ok(TcpHeader::new(
            self.local_port,
            self.remote_port,
            seq,
            self.rcv_nxt,
            tcp_flags::PSH | tcp_flags::ACK,
            self.rcv_wnd,
        ))
    }

    /// Processes an incoming TCP segment and drives the RFC 9293 state machine,
    /// returning an optional response `TcpHeader` to transmit.
    pub fn on_segment(
        &mut self,
        from_ip: Ipv4Addr,
        hdr: &TcpHeader,
        payload: &[u8],
    ) -> Result<Option<TcpHeader>, TcpError> {
        if (hdr.flags & tcp_flags::RST) != 0 {
            self.state = TcpState::Closed;
            return Err(TcpError::ConnectionReset);
        }

        match self.state {
            TcpState::Closed => Ok(Some(TcpHeader::new(
                self.local_port,
                hdr.src_port,
                hdr.ack_num,
                hdr.seq_num.wrapping_add(hdr.segment_seq_len(payload.len())),
                tcp_flags::RST | tcp_flags::ACK,
                0,
            ))),

            TcpState::Listen => {
                if (hdr.flags & tcp_flags::SYN) != 0 && (hdr.flags & tcp_flags::ACK) == 0 {
                    self.remote_ip = from_ip;
                    self.remote_port = hdr.src_port;
                    self.irs = hdr.seq_num;
                    self.rcv_nxt = hdr.seq_num.wrapping_add(1);
                    self.snd_una = self.iss;
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.iss,
                        self.rcv_nxt,
                        tcp_flags::SYN | tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                }
                Ok(None)
            }

            TcpState::SynSent => {
                let syn_set = (hdr.flags & tcp_flags::SYN) != 0;
                let ack_set = (hdr.flags & tcp_flags::ACK) != 0;
                if syn_set && ack_set && hdr.ack_num == self.snd_nxt {
                    self.snd_una = hdr.ack_num;
                    self.irs = hdr.seq_num;
                    self.rcv_nxt = hdr.seq_num.wrapping_add(1);
                    self.snd_wnd = hdr.window_size;
                    self.state = TcpState::Established;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                } else if syn_set && !ack_set {
                    // Simultaneous open: SynSent -> SynReceived
                    self.irs = hdr.seq_num;
                    self.rcv_nxt = hdr.seq_num.wrapping_add(1);
                    self.state = TcpState::SynReceived;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.iss,
                        self.rcv_nxt,
                        tcp_flags::SYN | tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                }
                Ok(None)
            }

            TcpState::SynReceived => {
                if (hdr.flags & tcp_flags::ACK) != 0 && hdr.ack_num == self.snd_nxt {
                    self.snd_una = hdr.ack_num;
                    self.snd_wnd = hdr.window_size;
                    self.state = TcpState::Established;
                }
                Ok(None)
            }

            TcpState::Established => {
                if (hdr.flags & tcp_flags::ACK) != 0 {
                    if hdr.ack_num.after(self.snd_una) && hdr.ack_num.before_or_eq(self.snd_nxt) {
                        let newly_acked = hdr.ack_num.0.wrapping_sub(self.snd_una.0);
                        self.snd_una = hdr.ack_num;
                        self.congestion.on_new_ack(newly_acked);
                    } else if hdr.ack_num == self.snd_una && payload.is_empty() {
                        let _ = self.congestion.on_duplicate_ack();
                    }
                }

                let mut need_ack = false;
                if !payload.is_empty() && hdr.seq_num == self.rcv_nxt {
                    self.rx_buffer.extend_from_slice(payload);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
                    need_ack = true;
                }

                if (hdr.flags & tcp_flags::FIN) != 0 {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = TcpState::CloseWait;
                    need_ack = true;
                }

                if need_ack {
                    Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        tcp_flags::ACK,
                        self.rcv_wnd,
                    )))
                } else {
                    Ok(None)
                }
            }

            TcpState::FinWait1 => {
                let ack_our_fin =
                    (hdr.flags & tcp_flags::ACK) != 0 && hdr.ack_num == self.snd_nxt;
                let peer_fin = (hdr.flags & tcp_flags::FIN) != 0;
                if ack_our_fin && peer_fin {
                    self.snd_una = hdr.ack_num;
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = TcpState::TimeWait;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                } else if ack_our_fin {
                    self.snd_una = hdr.ack_num;
                    self.state = TcpState::FinWait2;
                    return Ok(None);
                } else if peer_fin {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = TcpState::Closing;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                }
                Ok(None)
            }

            TcpState::FinWait2 => {
                if (hdr.flags & tcp_flags::FIN) != 0 {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = TcpState::TimeWait;
                    return Ok(Some(TcpHeader::new(
                        self.local_port,
                        self.remote_port,
                        self.snd_nxt,
                        self.rcv_nxt,
                        tcp_flags::ACK,
                        self.rcv_wnd,
                    )));
                }
                Ok(None)
            }

            TcpState::Closing => {
                if (hdr.flags & tcp_flags::ACK) != 0 && hdr.ack_num == self.snd_nxt {
                    self.snd_una = hdr.ack_num;
                    self.state = TcpState::TimeWait;
                }
                Ok(None)
            }

            TcpState::LastAck => {
                if (hdr.flags & tcp_flags::ACK) != 0 && hdr.ack_num == self.snd_nxt {
                    self.snd_una = hdr.ack_num;
                    self.state = TcpState::Closed;
                }
                Ok(None)
            }

            TcpState::CloseWait | TcpState::TimeWait => Ok(None),
        }
    }
}

/// Runs self-tests for the `tcp_fsm` module.
pub fn verify_net_tcp_fsm() -> u32 {
    let mut passed = 0u32;

    let cli_ip = Ipv4Addr::new(10, 0, 2, 15);
    let srv_ip = Ipv4Addr::new(10, 0, 2, 1);
    let mut client = TcpControlBlock::new(cli_ip, 50_000, TcpSeq(1_000));
    let mut server = TcpControlBlock::new(srv_ip, 443, TcpSeq(9_000));

    // 1. Full 3-way handshake: Listen + Connect(SYN) -> SynReceived(SYN|ACK) -> Established(ACK).
    let _ = server.listen();
    if let Ok(mut syn_hdr) = client.connect(srv_ip, 443) {
        let syn_wire = syn_hdr.to_bytes_ipv4(cli_ip, srv_ip, &[]);
        if let Ok((parsed_syn, _)) = TcpHeader::parse_ipv4(&syn_wire, cli_ip, srv_ip) {
            if let Ok(Some(syn_ack)) = server.on_segment(cli_ip, &parsed_syn, &[]) {
                if let Ok(Some(ack_hdr)) = client.on_segment(srv_ip, &syn_ack, &[]) {
                    let _ = server.on_segment(cli_ip, &ack_hdr, &[]);
                }
            }
        }
    }
    if client.state == TcpState::Established && server.state == TcpState::Established {
        passed += 1;
    }

    // 2. Payload transfer and congestion window growth.
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let cwnd_before = client.congestion.cwnd;
    if let Ok(mut data_hdr) = client.send_data(payload.len()) {
        let wire = data_hdr.to_bytes_ipv4(cli_ip, srv_ip, payload);
        if let Ok((parsed_hdr, parsed_body)) = TcpHeader::parse_ipv4(&wire, cli_ip, srv_ip) {
            if let Ok(Some(srv_ack)) = server.on_segment(cli_ip, &parsed_hdr, parsed_body) {
                let _ = client.on_segment(srv_ip, &srv_ack, &[]);
            }
        }
    }
    if server.rx_buffer == payload && client.congestion.cwnd > cwnd_before {
        passed += 1;
    }

    // 3. Full 4-way teardown: FinWait1 -> FinWait2 / CloseWait -> LastAck -> TimeWait / Closed.
    if let Ok(fin1) = client.close() {
        if let Ok(Some(ack1)) = server.on_segment(cli_ip, &fin1, &[]) {
            let _ = client.on_segment(srv_ip, &ack1, &[]);
            if client.state == TcpState::FinWait2 && server.state == TcpState::CloseWait {
                if let Ok(fin2) = server.close() {
                    if let Ok(Some(ack2)) = client.on_segment(srv_ip, &fin2, &[]) {
                        let _ = server.on_segment(cli_ip, &ack2, &[]);
                    }
                }
            }
        }
    }
    if client.state == TcpState::TimeWait && server.state == TcpState::Closed {
        passed += 1;
    }

    // 4. Modular 32-bit sequence wraparound arithmetic across 0xFFFF_FFFF -> 0x0000_0005.
    let s1 = TcpSeq(0xFFFF_FFF0);
    let s2 = s1.wrapping_add(0x20);
    if s1.before(s2) && s2.after(s1) {
        passed += 1;
    }

    passed
}
