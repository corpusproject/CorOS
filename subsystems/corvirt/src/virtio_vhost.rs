//! Host-side VirtIO & `vhost` Split Virtqueue Backend (`VirtqDesc`, `VirtqAvail`, `VirtqUsed`)
//! supporting zero-copy descriptor chain walking in guest physical memory for
//! `vhost-net` packet transmission/reception and `vhost-blk` sector I/O.

use alloc::vec::Vec;

/// VirtIO Split Queue Descriptor flags (`VRING_DESC_F_*`).
pub mod virtq_desc_flags {
    pub const VRING_DESC_F_NEXT: u16 = 1 << 0;
    pub const VRING_DESC_F_WRITE: u16 = 1 << 1;
    pub const VRING_DESC_F_INDIRECT: u16 = 1 << 2;
}

/// VirtIO 16-byte Split Queue Descriptor (`struct virtq_desc`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtqDesc {
    pub addr_gpa: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl VirtqDesc {
    pub const fn has_next(self) -> bool {
        (self.flags & virtq_desc_flags::VRING_DESC_F_NEXT) != 0
    }

    pub const fn is_device_writable(self) -> bool {
        (self.flags & virtq_desc_flags::VRING_DESC_F_WRITE) != 0
    }
}

/// VirtIO Available Ring element (`struct virtq_avail`).
#[derive(Debug, Clone)]
pub struct VirtqAvailRing {
    pub flags: u16,
    pub idx: u16,
    pub ring: Vec<u16>,
    pub used_event: u16,
}

impl VirtqAvailRing {
    pub fn new(queue_size: u16) -> Self {
        let mut ring = Vec::with_capacity(queue_size as usize);
        ring.resize(queue_size as usize, 0);
        Self {
            flags: 0,
            idx: 0,
            ring,
            used_event: 0,
        }
    }

    /// Guest driver publishes a descriptor chain head index into the available ring.
    pub fn publish_head(&mut self, head_desc_index: u16) {
        let qsz = self.ring.len();
        if qsz > 0 {
            let slot = (self.idx as usize) % qsz;
            self.ring[slot] = head_desc_index;
            self.idx = self.idx.wrapping_add(1);
        }
    }
}

/// VirtIO Used Ring element (`struct virtq_used_elem`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// VirtIO Used Ring (`struct virtq_used`).
#[derive(Debug, Clone)]
pub struct VirtqUsedRing {
    pub flags: u16,
    pub idx: u16,
    pub ring: Vec<VirtqUsedElem>,
    pub avail_event: u16,
}

impl VirtqUsedRing {
    pub fn new(queue_size: u16) -> Self {
        let mut ring = Vec::with_capacity(queue_size as usize);
        ring.resize(queue_size as usize, VirtqUsedElem::default());
        Self {
            flags: 0,
            idx: 0,
            ring,
            avail_event: 0,
        }
    }

    /// Host `vhost` backend records a completed descriptor chain in the used ring.
    pub fn push_used(&mut self, head_id: u16, bytes_written: u32) {
        let qsz = self.ring.len();
        if qsz > 0 {
            let slot = (self.idx as usize) % qsz;
            self.ring[slot] = VirtqUsedElem {
                id: head_id as u32,
                len: bytes_written,
            };
            self.idx = self.idx.wrapping_add(1);
        }
    }
}

/// Segment of a walked descriptor chain resolved by the host `vhost` backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedChainSegment {
    pub desc_index: u16,
    pub gpa: u64,
    pub len: u32,
    pub device_writable: bool,
}

/// VirtIO Block request types (`VIRTIO_BLK_T_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VirtioBlkReqType {
    ReadIn = 0,
    WriteOut = 1,
    Flush = 4,
    GetId = 8,
    Discard = 11,
}

/// VirtIO Block 16-byte request header (`struct virtio_blk_req_hdr`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

impl VirtioBlkReqHeader {
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let req_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let reserved = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let sector = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Some(Self {
            req_type,
            reserved,
            sector,
        })
    }
}

/// Host-side `vhost` Split Virtqueue processor.
#[derive(Debug, Clone)]
pub struct VhostSplitQueue {
    pub queue_size: u16,
    pub descriptors: Vec<VirtqDesc>,
    pub avail: VirtqAvailRing,
    pub used: VirtqUsedRing,
    pub last_avail_idx: u16,
    pub event_idx_enabled: bool,
    pub processed_chains_count: u64,
}

impl VhostSplitQueue {
    /// Creates a new `VhostSplitQueue` with a power-of-two `queue_size`.
    pub fn new(queue_size: u16, event_idx_enabled: bool) -> Self {
        let mut descriptors = Vec::with_capacity(queue_size as usize);
        descriptors.resize(queue_size as usize, VirtqDesc::default());
        Self {
            queue_size,
            descriptors,
            avail: VirtqAvailRing::new(queue_size),
            used: VirtqUsedRing::new(queue_size),
            last_avail_idx: 0,
            event_idx_enabled,
            processed_chains_count: 0,
        }
    }

    /// Walks and validates the next available descriptor chain, protecting against malicious circular descriptor loops.
    pub fn pop_next_avail_chain(
        &mut self,
    ) -> Result<Option<(u16, Vec<ResolvedChainSegment>)>, &'static str> {
        if self.last_avail_idx == self.avail.idx {
            return Ok(None);
        }
        let qsz = self.queue_size as usize;
        if qsz == 0 {
            return Err("Virtqueue size is zero");
        }
        let avail_slot = (self.last_avail_idx as usize) % qsz;
        let head_idx = self.avail.ring[avail_slot];
        if (head_idx as usize) >= qsz {
            return Err("Available ring head descriptor index out of bounds");
        }
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);

        let mut segments = Vec::new();
        let mut curr = head_idx;
        let mut hops = 0usize;

        loop {
            if (curr as usize) >= qsz {
                return Err("Descriptor chain index out of bounds");
            }
            if hops >= qsz {
                return Err("Descriptor chain loop detected in guest virtqueue");
            }
            let d = self.descriptors[curr as usize];
            segments.push(ResolvedChainSegment {
                desc_index: curr,
                gpa: d.addr_gpa,
                len: d.len,
                device_writable: d.is_device_writable(),
            });
            hops += 1;

            if d.has_next() {
                curr = d.next;
            } else {
                break;
            }
        }

        if self.event_idx_enabled {
            self.used.avail_event = self.last_avail_idx;
        }
        Ok(Some((head_idx, segments)))
    }

    /// Completes a descriptor chain and determines whether an IRQ (`eventfd` kick) must be injected into the guest.
    pub fn complete_chain(&mut self, head_idx: u16, total_written_bytes: u32) -> bool {
        let old_used_idx = self.used.idx;
        self.used.push_used(head_idx, total_written_bytes);
        let new_used_idx = self.used.idx;
        self.processed_chains_count += 1;

        if !self.event_idx_enabled {
            // Legacy interrupt suppression via VRING_AVAIL_F_NO_INTERRUPT (bit 0)
            (self.avail.flags & 1) == 0
        } else {
            // VIRTIO_RING_F_EVENT_IDX notification condition:
            // Notify iff (new_used_idx - used_event - 1) < (new_used_idx - old_used_idx)
            let used_event = self.avail.used_event;
            new_used_idx.wrapping_sub(used_event).wrapping_sub(1)
                < new_used_idx.wrapping_sub(old_used_idx)
        }
    }

    /// Processes a pending `vhost-blk` request chain against a flat Guest RAM buffer and a virtual disk sector array.
    pub fn process_vhost_blk_request(
        &mut self,
        guest_ram: &mut [u8],
        disk_storage: &mut [u8],
    ) -> Result<Option<(u16, bool)>, &'static str> {
        let Some((head_idx, segments)) = self.pop_next_avail_chain()? else {
            return Ok(None);
        };
        if segments.len() < 2 {
            return Err("vhost-blk chain requires at least header and status descriptors");
        }

        // First segment: 16-byte VirtioBlkReqHeader (device read-only)
        let hdr_seg = segments[0];
        if hdr_seg.device_writable || hdr_seg.len < 16 {
            return Err("Invalid vhost-blk header descriptor");
        }
        let hdr_start = hdr_seg.gpa as usize;
        if hdr_start.saturating_add(16) > guest_ram.len() {
            return Err("Header GPA out of guest RAM bounds");
        }
        let hdr = VirtioBlkReqHeader::from_le_bytes(&guest_ram[hdr_start..hdr_start + 16])
            .ok_or("Failed to decode vhost-blk header")?;

        let mut total_written = 0u32;
        let mut status_code: u8 = 0; // VIRTIO_BLK_S_OK = 0

        // Middle segments: data payload
        let mut disk_offset = (hdr.sector as usize).saturating_mul(512);
        for data_seg in &segments[1..segments.len() - 1] {
            let gpa_start = data_seg.gpa as usize;
            let len = data_seg.len as usize;
            if gpa_start.saturating_add(len) > guest_ram.len()
                || disk_offset.saturating_add(len) > disk_storage.len()
            {
                status_code = 1; // VIRTIO_BLK_S_IOERR
                break;
            }
            match hdr.req_type {
                0 => {
                    // VIRTIO_BLK_T_IN (read from disk into guest memory)
                    if !data_seg.device_writable {
                        status_code = 1;
                        break;
                    }
                    guest_ram[gpa_start..gpa_start + len]
                        .copy_from_slice(&disk_storage[disk_offset..disk_offset + len]);
                    total_written = total_written.saturating_add(data_seg.len);
                }
                1 => {
                    // VIRTIO_BLK_T_OUT (write from guest memory to disk)
                    disk_storage[disk_offset..disk_offset + len]
                        .copy_from_slice(&guest_ram[gpa_start..gpa_start + len]);
                }
                _ => {
                    status_code = 2; // VIRTIO_BLK_S_UNSUPP
                }
            }
            disk_offset += len;
        }

        // Final segment: 1-byte status trailer (device writable)
        let status_seg = segments[segments.len() - 1];
        let status_gpa = status_seg.gpa as usize;
        if !status_seg.device_writable || status_gpa >= guest_ram.len() {
            return Err("Invalid vhost-blk status descriptor");
        }
        guest_ram[status_gpa] = status_code;
        total_written = total_written.saturating_add(1);

        let should_kick = self.complete_chain(head_idx, total_written);
        Ok(Some((head_idx, should_kick)))
    }
}
