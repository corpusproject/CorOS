//! eXpress Data Path (`XDP`) High-Speed Packet Processing Pipeline.
//!
//! Provides `XdpAction` verdicts (`Aborted`, `Drop`, `Pass`, `Tx`, `Redirect`),
//! `XdpContext` packet frame buffer with headroom/tailroom management,
//! `bpf_xdp_adjust_head` / `bpf_xdp_adjust_tail` zero-copy encapsulation, and
//! an `XdpPipeline` runner with per-verdict packet and byte counters.

use crate::bpf_insn::BpfInsn;
use crate::bpf_vm::{BpfVm, VmError};
use alloc::vec;
use alloc::vec::Vec;

/// Default headroom reserved before `data` for zero-copy L2/VLAN/VXLAN encapsulation.
pub const XDP_DEFAULT_HEADROOM: usize = 128;
/// Default tailroom reserved after `data_end`.
pub const XDP_DEFAULT_TAILROOM: usize = 128;

/// Standard Linux XDP verdict codes (`enum xdp_action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XdpAction {
    /// Internal program error or exception (`XDP_ABORTED = 0`).
    Aborted = 0,
    /// Silently drop packet at NIC driver ring (`XDP_DROP = 1`).
    Drop = 1,
    /// Pass packet up to normal OS network stack (`XDP_PASS = 2`).
    Pass = 2,
    /// Bounce packet back out the same ingress NIC interface (`XDP_TX = 3`).
    Tx = 3,
    /// Redirect packet to another NIC `ifindex`, CPU map, or AF_XDP socket (`XDP_REDIRECT = 4`).
    Redirect = 4,
}

impl XdpAction {
    pub const fn from_u64(raw: u64) -> Self {
        match raw {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            _ => Self::Aborted,
        }
    }
}

/// Error returned by `XdpContext` headroom/tailroom adjustments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpError {
    HeadroomUnderflow,
    TailroomOverflow,
    EmptyPacketSlice,
}

/// Packet frame buffer with pre-allocated headroom and tailroom for XDP execution.
pub struct XdpContext {
    frame: Vec<u8>,
    data_offset: usize,
    data_end_offset: usize,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub redirect_target_ifindex: u32,
}

impl XdpContext {
    /// Construct an `XdpContext` wrapping `packet_bytes` with pre-allocated headroom and tailroom.
    pub fn from_packet(packet_bytes: &[u8], ingress_ifindex: u32, rx_queue_index: u32) -> Self {
        let total_cap = XDP_DEFAULT_HEADROOM + packet_bytes.len() + XDP_DEFAULT_TAILROOM;
        let mut frame = vec![0u8; total_cap];
        let data_offset = XDP_DEFAULT_HEADROOM;
        let data_end_offset = data_offset + packet_bytes.len();
        frame[data_offset..data_end_offset].copy_from_slice(packet_bytes);
        Self {
            frame,
            data_offset,
            data_end_offset,
            ingress_ifindex,
            rx_queue_index,
            redirect_target_ifindex: 0,
        }
    }

    #[inline]
    pub fn packet_len(&self) -> usize {
        self.data_end_offset.saturating_sub(self.data_offset)
    }

    #[inline]
    pub fn packet_slice(&self) -> &[u8] {
        &self.frame[self.data_offset..self.data_end_offset]
    }

    #[inline]
    pub fn packet_slice_mut(&mut self) -> &mut [u8] {
        &mut self.frame[self.data_offset..self.data_end_offset]
    }

    /// Move `data` pointer by `delta` bytes (`bpf_xdp_adjust_head`).
    /// Negative `delta` grows the packet header into headroom (encapsulation);
    /// positive `delta` strips header bytes (decapsulation).
    pub fn bpf_xdp_adjust_head(&mut self, delta: i32) -> Result<(), XdpError> {
        let new_start = (self.data_offset as isize) + (delta as isize);
        if new_start < 0 || (new_start as usize) >= self.data_end_offset {
            return Err(XdpError::HeadroomUnderflow);
        }
        self.data_offset = new_start as usize;
        Ok(())
    }

    /// Move `data_end` pointer by `delta` bytes (`bpf_xdp_adjust_tail`).
    pub fn bpf_xdp_adjust_tail(&mut self, delta: i32) -> Result<(), XdpError> {
        let new_end = (self.data_end_offset as isize) + (delta as isize);
        if new_end <= (self.data_offset as isize) || (new_end as usize) > self.frame.len() {
            return Err(XdpError::TailroomOverflow);
        }
        self.data_end_offset = new_end as usize;
        Ok(())
    }

    /// Prepend an 802.1Q 4-byte VLAN tag onto the Ethernet frame in-place using `bpf_xdp_adjust_head`.
    pub fn push_vlan_tag(&mut self, vlan_id: u16) -> Result<(), XdpError> {
        if self.packet_len() < 14 {
            return Err(XdpError::EmptyPacketSlice);
        }
        let mut mac_hdr = [0u8; 12];
        mac_hdr.copy_from_slice(&self.packet_slice()[0..12]);
        self.bpf_xdp_adjust_head(-4)?;
        let pkt = self.packet_slice_mut();
        pkt[0..12].copy_from_slice(&mac_hdr);
        // TPID = 0x8100 (802.1Q)
        pkt[12] = 0x81;
        pkt[13] = 0x00;
        let tci = (vlan_id & 0x0fff).to_be_bytes();
        pkt[14] = tci[0];
        pkt[15] = tci[1];
        Ok(())
    }
}

/// Cumulative XDP ring telemetry counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XdpStats {
    pub aborted_pkts: u64,
    pub dropped_pkts: u64,
    pub passed_pkts: u64,
    pub tx_pkts: u64,
    pub redirected_pkts: u64,
    pub processed_bytes: u64,
}

/// High-speed XDP execution pipeline attaching an eBPF program to an ingress interface.
pub struct XdpPipeline {
    prog: Vec<BpfInsn>,
    vm: BpfVm,
    pub stats: XdpStats,
}

impl XdpPipeline {
    pub fn new(prog: Vec<BpfInsn>) -> Self {
        Self {
            prog,
            vm: BpfVm::new(),
            stats: XdpStats::default(),
        }
    }

    /// Execute the attached XDP eBPF program on `ctx` and update telemetry counters.
    pub fn process_packet(&mut self, ctx: &mut XdpContext) -> Result<XdpAction, VmError> {
        let pkt_bytes = ctx.packet_len() as u64;
        let raw_ret = self.vm.execute(&self.prog, ctx.packet_slice_mut())?;
        let action = XdpAction::from_u64(raw_ret);

        self.stats.processed_bytes = self.stats.processed_bytes.wrapping_add(pkt_bytes);
        match action {
            XdpAction::Aborted => self.stats.aborted_pkts += 1,
            XdpAction::Drop => self.stats.dropped_pkts += 1,
            XdpAction::Pass => self.stats.passed_pkts += 1,
            XdpAction::Tx => self.stats.tx_pkts += 1,
            XdpAction::Redirect => self.stats.redirected_pkts += 1,
        }
        Ok(action)
    }
}
