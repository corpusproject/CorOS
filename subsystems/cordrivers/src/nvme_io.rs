//! CorOS Hardware Driver Module: `nvme_io`
//!
//! NVMe I/O Queue Pair state machine, PRP1/PRP2 physical page list builder,
//! NVM Command Set (`Flush`, `Write`, `Read`, `DatasetManagement` / TRIM)
//! command builders, and MMIO doorbell calculator.

use crate::nvme_admin::{nvme_regs, NvmeCqe, NvmeSqe};

/// NVM I/O Command Set Opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmIoOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetManagement = 0x09,
    Verify = 0x0C,
}

/// 16-byte Range Entry for the NVMe `Dataset Management` (Deallocate / TRIM) command.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeDsmRange {
    pub context_attributes: u32,
    pub length_in_logical_blocks: u32,
    pub starting_lba: u64,
}

impl NvmeDsmRange {
    #[inline]
    pub const fn new(starting_lba: u64, length_in_logical_blocks: u32) -> Self {
        Self {
            context_attributes: 0,
            length_in_logical_blocks,
            starting_lba,
        }
    }
}

/// PRP (Physical Region Page) layout descriptor for an NVMe DMA transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmePrpSetup {
    pub prp1: u64,
    pub prp2: u64,
    /// Number of 64-bit physical page entries written into the auxiliary PRP list page (0 if not needed).
    pub prp_list_entries: usize,
}

/// Computes `PRP1`, `PRP2`, and populates `prp_list_page` (up to 512 entries = 2 MiB for 4 KiB pages)
/// for a physically contiguous or page-aligned scatter transfer starting at `first_phys_addr`.
pub fn build_contiguous_prp(
    first_phys_addr: u64,
    transfer_bytes: usize,
    prp_list_phys: u64,
    prp_list_out: &mut [u64; 512],
) -> NvmePrpSetup {
    const PAGE_SIZE: u64 = 4096;
    if transfer_bytes == 0 {
        return NvmePrpSetup {
            prp1: first_phys_addr,
            prp2: 0,
            prp_list_entries: 0,
        };
    }

    let offset_in_first_page = first_phys_addr & (PAGE_SIZE - 1);
    let first_page_bytes = (PAGE_SIZE - offset_in_first_page) as usize;

    if transfer_bytes <= first_page_bytes {
        return NvmePrpSetup {
            prp1: first_phys_addr,
            prp2: 0,
            prp_list_entries: 0,
        };
    }

    let remaining = transfer_bytes - first_page_bytes;
    let extra_pages = (remaining + (PAGE_SIZE as usize - 1)) / (PAGE_SIZE as usize);
    let second_page_phys = (first_phys_addr & !(PAGE_SIZE - 1)) + PAGE_SIZE;

    if extra_pages == 1 {
        NvmePrpSetup {
            prp1: first_phys_addr,
            prp2: second_page_phys,
            prp_list_entries: 0,
        }
    } else {
        let count = extra_pages.min(prp_list_out.len());
        let mut idx = 0;
        while idx < count {
            prp_list_out[idx] = second_page_phys + (idx as u64) * PAGE_SIZE;
            idx += 1;
        }
        NvmePrpSetup {
            prp1: first_phys_addr,
            prp2: prp_list_phys,
            prp_list_entries: count,
        }
    }
}

/// Builds an NVM `Read` (`0x02`) or `Write` (`0x01`) 64-byte Submission Queue Entry.
#[inline]
pub const fn build_rw_sqe(
    opcode: NvmIoOpcode,
    command_id: u16,
    nsid: u32,
    start_lba: u64,
    num_blocks: u16,
    prp1: u64,
    prp2: u64,
    force_unit_access: bool,
) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.opcode = opcode as u8;
    sqe.command_id = command_id;
    sqe.nsid = nsid;
    sqe.prp1 = prp1;
    sqe.prp2 = prp2;
    sqe.cdw10 = (start_lba & 0xFFFF_FFFF) as u32;
    sqe.cdw11 = (start_lba >> 32) as u32;
    let nlb_0based = (num_blocks.saturating_sub(1)) as u32;
    let fua_bit = if force_unit_access { 1u32 << 30 } else { 0 };
    sqe.cdw12 = fua_bit | nlb_0based;
    sqe
}

/// Builds an NVM `Flush` (`0x00`) command for `nsid`.
#[inline]
pub const fn build_flush_sqe(command_id: u16, nsid: u32) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.opcode = NvmIoOpcode::Flush as u8;
    sqe.command_id = command_id;
    sqe.nsid = nsid;
    sqe
}

/// Builds an NVM `Dataset Management` (`0x09`) TRIM / Deallocate command.
#[inline]
pub const fn build_dsm_deallocate_sqe(
    command_id: u16,
    nsid: u32,
    range_list_prp1: u64,
    num_ranges: u8,
) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.opcode = NvmIoOpcode::DatasetManagement as u8;
    sqe.command_id = command_id;
    sqe.nsid = nsid;
    sqe.prp1 = range_list_prp1;
    sqe.cdw10 = (num_ranges.saturating_sub(1)) as u32;
    sqe.cdw11 = 1 << 2; // Attribute: Deallocate (AD)
    sqe
}

/// NVMe I/O Queue Pair state machine tracking Submission Queue Tail, Completion Queue Head,
///expected Phase Tag, and Doorbell register offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeIoQueuePair {
    pub qid: u16,
    pub depth: u16,
    pub sq_tail: u16,
    pub sq_head: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
    pub next_cid: u16,
    pub doorbell_stride_shift: u8,
    pub completed_commands: u64,
}

impl NvmeIoQueuePair {
    /// Creates a new I/O Queue Pair (`qid >= 1`, `depth >= 2`).
    #[inline]
    pub const fn new(qid: u16, depth: u16, doorbell_stride_shift: u8) -> Self {
        Self {
            qid,
            depth,
            sq_tail: 0,
            sq_head: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 1,
            doorbell_stride_shift,
            completed_commands: 0,
        }
    }

    /// Computes the BAR0 MMIO byte offset for the Submission Queue `qid` Tail Doorbell.
    #[inline]
    pub const fn sq_tail_doorbell_offset(&self) -> usize {
        let index = (2 * (self.qid as usize)) << (self.doorbell_stride_shift as usize);
        nvme_regs::DOORBELL_BASE + index * 4
    }

    /// Computes the BAR0 MMIO byte offset for the Completion Queue `qid` Head Doorbell.
    #[inline]
    pub const fn cq_head_doorbell_offset(&self) -> usize {
        let index = (2 * (self.qid as usize) + 1) << (self.doorbell_stride_shift as usize);
        nvme_regs::DOORBELL_BASE + index * 4
    }

    /// Returns the number of free slots remaining in the Submission Queue ring.
    #[inline]
    pub const fn available_sq_slots(&self) -> u16 {
        let used = if self.sq_tail >= self.sq_head {
            self.sq_tail - self.sq_head
        } else {
            self.depth - (self.sq_head - self.sq_tail)
        };
        self.depth.saturating_sub(1).saturating_sub(used)
    }

    /// Enqueues a Submission Queue Entry into `sq_ring` and returns `(assigned_cid, new_sq_tail)`.
    pub fn submit(&mut self, sq_ring: &mut [NvmeSqe], mut sqe: NvmeSqe) -> Option<(u16, u16)> {
        if self.available_sq_slots() == 0 || (self.sq_tail as usize) >= sq_ring.len() {
            return None;
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == 0 {
            self.next_cid = 1;
        }
        sqe.command_id = cid;
        sq_ring[self.sq_tail as usize] = sqe;
        self.sq_tail = (self.sq_tail + 1) % self.depth;
        Some((cid, self.sq_tail))
    }

    /// Polls the next Completion Queue Entry in `cq_ring` if its Phase Tag matches `self.cq_phase`.
    pub fn poll_completion(&mut self, cq_ring: &[NvmeCqe]) -> Option<NvmeCqe> {
        let idx = self.cq_head as usize;
        if idx >= cq_ring.len() {
            return None;
        }
        let cqe = cq_ring[idx];
        if cqe.phase_tag() != self.cq_phase {
            return None;
        }
        self.sq_head = cqe.sq_head % self.depth;
        self.cq_head += 1;
        if self.cq_head >= self.depth {
            self.cq_head = 0;
            self.cq_phase = !self.cq_phase;
        }
        self.completed_commands += 1;
        Some(cqe)
    }
}

/// Self-test for `nvme_io` queue pair ring wrap-around, PRP list generation, and doorbell offsets.
pub fn verify_driver_module_nvme_io() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Doorbell register offset calculation (qid = 2, DSTRD = 0 -> 4B stride)
    let mut qp = NvmeIoQueuePair::new(2, 4, 0);
    if qp.sq_tail_doorbell_offset() == 0x1010 && qp.cq_head_doorbell_offset() == 0x1014 {
        passed += 1;
    }

    // 2. Verify multi-page PRP list generation (16 KiB = 4 pages: 1 in PRP1, 3 in PRP list)
    let mut prp_list = [0u64; 512];
    let prp = build_contiguous_prp(0x1000_0000, 16 * 1024, 0x2000_0000, &mut prp_list);
    if prp.prp1 == 0x1000_0000
        && prp.prp2 == 0x2000_0000
        && prp.prp_list_entries == 3
        && prp_list[0] == 0x1000_1000
        && prp_list[2] == 0x1000_3000
    {
        passed += 1;
    }

    // 3. Verify Read/Write SQE submission and CQ phase bit inversion on ring wrap
    let mut sq_ring = [NvmeSqe::zeroed(); 4];
    let mut cq_ring = [NvmeCqe {
        result: 0,
        rsvd: 0,
        sq_head: 0,
        sq_id: 2,
        command_id: 0,
        status_and_phase: 0,
    }; 4];

    let rw = build_rw_sqe(
        NvmIoOpcode::Read,
        0,
        1,
        0x0001_0000_0040,
        8,
        prp.prp1,
        prp.prp2,
        true,
    );
    if let Some((cid, new_tail)) = qp.submit(&mut sq_ring, rw) {
        if cid == 1 && new_tail == 1 && (sq_ring[0].cdw12 & 0xFFFF) == 7 {
            passed += 1;
        }
    }

    // Simulate 4 completions to wrap the 4-entry CQ ring and invert `cq_phase`
    for i in 0..4 {
        cq_ring[i] = NvmeCqe {
            result: 0,
            rsvd: 0,
            sq_head: ((i + 1) % 4) as u16,
            sq_id: 2,
            command_id: (i + 1) as u16,
            status_and_phase: 0x0001, // Phase = true
        };
        let _ = qp.poll_completion(&cq_ring);
    }
    if !qp.cq_phase && qp.completed_commands == 4 {
        passed += 1;
    }

    passed
}
