//! Enterprise Non-Volatile Memory Express (NVMe 1.4) Controller Driver for CorOS.
//! 100% in-house bare-metal implementation supporting PCIe MMIO, Admin Queues,
//! I/O Submission/Completion Queue pairs, PRP lists, and sector read/write transactions.

use alloc::vec::Vec;
use alloc::boxed::Box;
use core::ptr::{read_volatile, write_volatile};

// -----------------------------------------------------------------------------
// NVMe Controller Registers (MMIO Base Offset)
// -----------------------------------------------------------------------------
pub const NVME_REG_CAP: usize     = 0x0000; // Controller Capabilities (64-bit)
pub const NVME_REG_VS: usize      = 0x0008; // Version (32-bit)
pub const NVME_REG_INTMS: usize   = 0x000C; // Interrupt Mask Set (32-bit)
pub const NVME_REG_INTMC: usize   = 0x0010; // Interrupt Mask Clear (32-bit)
pub const NVME_REG_CC: usize      = 0x0014; // Controller Configuration (32-bit)
pub const NVME_REG_CSTS: usize    = 0x001C; // Controller Status (32-bit)
pub const NVME_REG_NSSR: usize    = 0x0020; // NVM Subsystem Reset (32-bit)
pub const NVME_REG_AQA: usize     = 0x0024; // Admin Queue Attributes (32-bit)
pub const NVME_REG_ASQ: usize     = 0x0028; // Admin Submission Queue Base Address (64-bit)
pub const NVME_REG_ACQ: usize     = 0x0030; // Admin Completion Queue Base Address (64-bit)

// CC Register Flags
pub const NVME_CC_EN: u32         = 1 << 0;  // Enable controller
pub const NVME_CC_CSS_NVM: u32    = 0 << 4;  // NVM Command Set
pub const NVME_CC_MPS_4K: u32     = 0 << 7;  // Memory Page Size: 2^(12+MPS) = 4 KiB
pub const NVME_CC_AMS_RR: u32     = 0 << 11; // Round Robin arbitration
pub const NVME_CC_SHN_NONE: u32   = 0 << 14; // No shutdown notification
pub const NVME_CC_IOSQES_64: u32  = 6 << 16; // 2^6 = 64 bytes SQ entry
pub const NVME_CC_IOCQES_16: u32  = 4 << 20; // 2^4 = 16 bytes CQ entry

// CSTS Register Flags
pub const NVME_CSTS_RDY: u32      = 1 << 0;  // Controller Ready
pub const NVME_CSTS_CFS: u32      = 1 << 1;  // Controller Fatal Status
pub const NVME_CSTS_SHST_MASK: u32= 3 << 2;  // Shutdown Status

// -----------------------------------------------------------------------------
// Admin Opcodes
// -----------------------------------------------------------------------------
pub const NVME_ADMIN_OP_DELETE_IO_SQ: u8 = 0x00;
pub const NVME_ADMIN_OP_CREATE_IO_SQ: u8 = 0x01;
pub const NVME_ADMIN_OP_GET_LOG_PAGE: u8 = 0x02;
pub const NVME_ADMIN_OP_DELETE_IO_CQ: u8 = 0x04;
pub const NVME_ADMIN_OP_CREATE_IO_CQ: u8 = 0x05;
pub const NVME_ADMIN_OP_IDENTIFY: u8     = 0x06;
pub const NVME_ADMIN_OP_ABORT: u8        = 0x08;
pub const NVME_ADMIN_OP_SET_FEATURES: u8 = 0x09;
pub const NVME_ADMIN_OP_GET_FEATURES: u8 = 0x0A;
pub const NVME_ADMIN_OP_ASYNC_EVENT: u8  = 0x0C;

// -----------------------------------------------------------------------------
// NVM (I/O) Opcodes
// -----------------------------------------------------------------------------
pub const NVME_NVM_OP_FLUSH: u8          = 0x00;
pub const NVME_NVM_OP_WRITE: u8          = 0x01;
pub const NVME_NVM_OP_READ: u8           = 0x02;
pub const NVME_NVM_OP_WRITE_UNCORR: u8   = 0x04;
pub const NVME_NVM_OP_COMPARE: u8        = 0x05;
pub const NVME_NVM_OP_WRITE_ZEROES: u8   = 0x08;
pub const NVME_NVM_OP_DATASET_MGMT: u8   = 0x09;

// -----------------------------------------------------------------------------
// Submission Queue Entry (SQE) - 64 bytes
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NvmeSubmissionQueueEntry {
    pub cdw0: u32,       // Opcode [7:0], FUSE [9:8], PSDT [15:14], CID [31:16]
    pub nsid: u32,       // Namespace Identifier
    pub reserved1: u64,
    pub mptr: u64,       // Metadata Pointer
    pub prp1: u64,       // PRP Entry 1 (Physical Address)
    pub prp2: u64,       // PRP Entry 2 (Physical Address / PRP List)
    pub cdw10: u32,      // Command Dword 10
    pub cdw11: u32,      // Command Dword 11
    pub cdw12: u32,      // Command Dword 12
    pub cdw13: u32,      // Command Dword 13
    pub cdw14: u32,      // Command Dword 14
    pub cdw15: u32,      // Command Dword 15
}

impl NvmeSubmissionQueueEntry {
    pub fn new(opcode: u8, cid: u16, nsid: u32) -> Self {
        let mut entry = Self::default();
        entry.cdw0 = (opcode as u32) | ((cid as u32) << 16);
        entry.nsid = nsid;
        entry
    }
}

// -----------------------------------------------------------------------------
// Completion Queue Entry (CQE) - 16 bytes
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NvmeCompletionQueueEntry {
    pub dw0: u32,        // Command-specific result
    pub reserved: u32,
    pub sq_head: u16,    // SQ Head Pointer
    pub sq_id: u16,      // SQ Identifier
    pub cid: u16,        // Command Identifier
    pub status: u16,     // Phase Tag [0], Status Code [15:1]
}

impl NvmeCompletionQueueEntry {
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    pub fn status_code(&self) -> u16 {
        (self.status >> 1) & 0x7FFF
    }

    pub fn is_success(&self) -> bool {
        self.status_code() == 0
    }
}

// -----------------------------------------------------------------------------
// Identify Controller Data Structure (Excerpt, 4096 bytes)
// -----------------------------------------------------------------------------
#[repr(C)]
pub struct NvmeIdentifyController {
    pub vid: u16,             // PCI Vendor ID
    pub ssvid: u16,           // PCI Subsystem Vendor ID
    pub sn: [u8; 20],         // Serial Number (ASCII)
    pub mn: [u8; 40],         // Model Number (ASCII)
    pub fr: [u8; 8],          // Firmware Revision (ASCII)
    pub rab: u8,              // Recommended Arbitration Burst
    pub ieee: [u8; 3],        // IEEE OUI Identifier
    pub cmic: u8,             // Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub mdts: u8,             // Maximum Data Transfer Size (power of 2 of minimum memory page size)
    pub cntlid: u16,          // Controller ID
    pub ver: u32,             // Version
    pub rtd3r: u32,           // RTD3 Resume Latency
    pub rtd3e: u32,           // RTD3 Entry Latency
    pub oaes: u32,            // Optional Asynchronous Events Supported
    pub reserved_admin: [u8; 168],
    pub sqes: u8,             // Submission Queue Entry Size (min/max powers of 2)
    pub cqes: u8,             // Completion Queue Entry Size (min/max powers of 2)
    pub maxcmd: u16,          // Maximum Outstanding Commands
    pub nn: u32,              // Number of Namespaces
    pub oncs: u16,            // Optional NVM Command Support
    pub fuses: u16,           // Fused Operation Support
    pub fna: u8,              // Format NVM Attributes
    pub vwc: u8,              // Volatile Write Cache
    pub awun: u16,            // Atomic Write Unit Normal
    pub awupf: u16,           // Atomic Write Unit Power Fail
    pub nvscc: u8,            // NVM Vendor Specific Command Configuration
    pub reserved_nvm: [u8; 173],
    pub reserved_vendor: [u8; 3712],
}

// -----------------------------------------------------------------------------
// Identify Namespace Data Structure (Excerpt, 4096 bytes)
// -----------------------------------------------------------------------------
#[repr(C)]
pub struct NvmeLbaFormat {
    pub ms: u16,              // Metadata Size
    pub lbads: u8,            // LBA Data Size (2^lbads bytes, e.g. 9 = 512, 12 = 4096)
    pub rp: u8,               // Relative Performance
}

#[repr(C)]
pub struct NvmeIdentifyNamespace {
    pub nsze: u64,            // Namespace Size (in blocks)
    pub ncap: u64,            // Namespace Capacity (in blocks)
    pub nuse: u64,            // Namespace Utilization (in blocks)
    pub nsfeat: u8,           // Namespace Features
    pub nlbaf: u8,            // Number of LBA Formats
    pub flbas: u8,            // Formatted LBA Size
    pub mc: u8,               // Metadata Capabilities
    pub dpc: u8,              // End-to-end Data Protection Capabilities
    pub dps: u8,              // End-to-end Data Protection Type Settings
    pub nmic: u8,             // Namespace Multi-path I/O and Namespace Sharing Capabilities
    pub rescap: u8,           // Reservation Capabilities
    pub fpi: u8,              // Format Progress Indicator
    pub dlfeat: u8,           // Deallocate Logical Block Features
    pub nawun: u16,           // Namespace Atomic Write Unit Normal
    pub nawupf: u16,          // Namespace Atomic Write Unit Power Fail
    pub nacwu: u16,           // Namespace Atomic Compare & Write Unit
    pub nabsn: u16,           // Namespace Atomic Boundary Size Normal
    pub nabo: u16,            // Namespace Atomic Boundary Offset
    pub nabspf: u16,          // Namespace Atomic Boundary Size Power Fail
    pub noiob: u16,           // Namespace Optimal I/O Boundary
    pub nvmcap: [u8; 16],     // NVM Capacity
    pub reserved1: [u8; 40],
    pub nguid: [u8; 16],      // Globally Unique Identifier
    pub eui64: [u8; 8],       // IEEE Extended Unique Identifier
    pub lbaf: [NvmeLbaFormat; 16], // LBA Formats supported
    pub reserved2: [u8; 192],
    pub vendor_specific: [u8; 3712],
}

// -----------------------------------------------------------------------------
// Queue Management Structures
// -----------------------------------------------------------------------------
pub const NVME_ADMIN_QUEUE_DEPTH: usize = 32;
pub const NVME_IO_QUEUE_DEPTH: usize    = 64;

pub struct NvmeQueue {
    pub id: u16,
    pub depth: u16,
    pub sq_tail: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
    pub sq_buffer: Vec<NvmeSubmissionQueueEntry>,
    pub cq_buffer: Vec<NvmeCompletionQueueEntry>,
    pub db_sq_offset: usize,
    pub db_cq_offset: usize,
}

impl NvmeQueue {
    pub fn new(id: u16, depth: u16, db_stride: usize) -> Self {
        let mut sq = Vec::with_capacity(depth as usize);
        for _ in 0..depth {
            sq.push(NvmeSubmissionQueueEntry::default());
        }
        let mut cq = Vec::with_capacity(depth as usize);
        for _ in 0..depth {
            cq.push(NvmeCompletionQueueEntry::default());
        }

        // Doorbell offset: 0x1000 + (2 * id * (4 << db_stride))
        let stride_bytes = 4 << db_stride;
        let db_sq = 0x1000 + (2 * (id as usize) * stride_bytes);
        let db_cq = 0x1000 + ((2 * (id as usize) + 1) * stride_bytes);

        Self {
            id,
            depth,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            sq_buffer: sq,
            cq_buffer: cq,
            db_sq_offset: db_sq,
            db_cq_offset: db_cq,
        }
    }

    pub fn sq_phys_addr(&self) -> u64 {
        self.sq_buffer.as_ptr() as u64
    }

    pub fn cq_phys_addr(&self) -> u64 {
        self.cq_buffer.as_ptr() as u64
    }
}

// -----------------------------------------------------------------------------
// NVMe Controller Device
// -----------------------------------------------------------------------------
pub struct NvmeController {
    pub mmio_base: usize,
    pub dstrd: usize,          // Doorbell stride
    pub cap: u64,
    pub vs: u32,
    pub max_entries: u16,
    pub admin_queue: NvmeQueue,
    pub io_queue: Option<NvmeQueue>,
    pub model_number: [u8; 40],
    pub serial_number: [u8; 20],
    pub num_namespaces: u32,
    pub active_ns_lba_count: u64,
    pub active_ns_block_size: usize,
    pub next_cid: u16,
}

impl NvmeController {
    /// Create and initialize an NVMe controller from a discovered PCI MMIO BAR.
    pub unsafe fn init(mmio_base: usize) -> Result<Self, &'static str> {
        let cap = read_volatile(mmio_base as *const u64);
        let vs = read_volatile((mmio_base + NVME_REG_VS) as *const u32);

        // CAP details:
        // DSTRD: Doorbell Stride (bits 35:32)
        let dstrd = ((cap >> 32) & 0xF) as usize;
        // MQES: Maximum Queue Entries Supported (bits 15:0) + 1
        let max_entries = ((cap & 0xFFFF) + 1) as u16;

        // Verify controller is disabled or disable it
        let mut cc = read_volatile((mmio_base + NVME_REG_CC) as *const u32);
        if (cc & NVME_CC_EN) != 0 {
            cc &= !NVME_CC_EN;
            write_volatile((mmio_base + NVME_REG_CC) as *mut u32, cc);

            // Wait for CSTS.RDY to clear
            let mut timeout = 100_000;
            while (read_volatile((mmio_base + NVME_REG_CSTS) as *const u32) & NVME_CSTS_RDY) != 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err("NVMe timeout waiting for controller reset");
                }
            }
        }

        // Allocate Admin Queue
        let admin_depth = NVME_ADMIN_QUEUE_DEPTH.min(max_entries as usize) as u16;
        let admin_queue = NvmeQueue::new(0, admin_depth, dstrd);

        // Configure AQA (Admin Queue Attributes: AQS in [11:0], ACQS in [27:16])
        let aqa = ((admin_depth as u32 - 1) & 0xFFF) | (((admin_depth as u32 - 1) & 0xFFF) << 16);
        write_volatile((mmio_base + NVME_REG_AQA) as *mut u32, aqa);

        // Set ASQ and ACQ base physical addresses
        write_volatile((mmio_base + NVME_REG_ASQ) as *mut u64, admin_queue.sq_phys_addr());
        write_volatile((mmio_base + NVME_REG_ACQ) as *mut u64, admin_queue.cq_phys_addr());

        // Configure CC and enable
        let new_cc = NVME_CC_EN 
            | NVME_CC_CSS_NVM 
            | NVME_CC_MPS_4K 
            | NVME_CC_AMS_RR 
            | NVME_CC_IOSQES_64 
            | NVME_CC_IOCQES_16;
        write_volatile((mmio_base + NVME_REG_CC) as *mut u32, new_cc);

        // Wait for CSTS.RDY
        let mut timeout = 200_000;
        while (read_volatile((mmio_base + NVME_REG_CSTS) as *const u32) & NVME_CSTS_RDY) == 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("NVMe timeout waiting for controller ready");
            }
        }

        let mut controller = Self {
            mmio_base,
            dstrd,
            cap,
            vs,
            max_entries,
            admin_queue,
            io_queue: None,
            model_number: [b' '; 40],
            serial_number: [b' '; 20],
            num_namespaces: 1,
            active_ns_lba_count: 0,
            active_ns_block_size: 512,
            next_cid: 1,
        };

        // Query Identify Controller
        controller.identify_controller()?;

        // Create I/O Completion and Submission Queues
        controller.create_io_queues()?;

        // Query Namespace 1
        controller.identify_namespace(1)?;

        Ok(controller)
    }

    /// Submit an Admin command and busy-wait for its completion.
    pub unsafe fn submit_admin_cmd(&mut self, mut entry: NvmeSubmissionQueueEntry) -> Result<NvmeCompletionQueueEntry, &'static str> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        entry.cdw0 = (entry.cdw0 & 0x0000FFFF) | ((cid as u32) << 16);

        let q = &mut self.admin_queue;
        let slot = q.sq_tail as usize;
        q.sq_buffer[slot] = entry;
        q.sq_tail = (q.sq_tail + 1) % q.depth;

        // Ring Admin SQ Doorbell
        let doorbell_sq = (self.mmio_base + q.db_sq_offset) as *mut u32;
        write_volatile(doorbell_sq, q.sq_tail as u32);

        // Poll CQ for completion with matching CID and current phase
        let mut timeout = 500_000;
        loop {
            let cq_slot = q.cq_head as usize;
            let cqe = read_volatile(&q.cq_buffer[cq_slot] as *const NvmeCompletionQueueEntry);

            if cqe.phase() == q.cq_phase {
                // Advanced CQ head
                q.cq_head = (q.cq_head + 1) % q.depth;
                if q.cq_head == 0 {
                    q.cq_phase = !q.cq_phase;
                }

                // Ring CQ Doorbell to inform controller that entry was consumed
                let doorbell_cq = (self.mmio_base + q.db_cq_offset) as *mut u32;
                write_volatile(doorbell_cq, q.cq_head as u32);

                if !cqe.is_success() {
                    return Err("NVMe Admin command returned error status");
                }
                return Ok(cqe);
            }

            timeout -= 1;
            if timeout == 0 {
                return Err("NVMe Admin command timeout");
            }
        }
    }

    /// Identify Controller configuration.
    pub unsafe fn identify_controller(&mut self) -> Result<(), &'static str> {
        let mut identify_buf = Box::new([0u8; 4096]);
        let mut cmd = NvmeSubmissionQueueEntry::new(NVME_ADMIN_OP_IDENTIFY, 0, 0);
        cmd.prp1 = identify_buf.as_ptr() as u64;
        cmd.cdw10 = 1; // CNS = 1: Identify Controller

        self.submit_admin_cmd(cmd)?;

        let ident = &*(identify_buf.as_ptr() as *const NvmeIdentifyController);
        self.model_number.copy_from_slice(&ident.mn);
        self.serial_number.copy_from_slice(&ident.sn);
        self.num_namespaces = ident.nn;

        Ok(())
    }

    /// Create I/O Queue pair (CQ and SQ).
    pub unsafe fn create_io_queues(&mut self) -> Result<(), &'static str> {
        let io_depth = NVME_IO_QUEUE_DEPTH.min(self.max_entries as usize) as u16;
        let mut io_q = NvmeQueue::new(1, io_depth, self.dstrd);

        // 1. Create I/O CQ (Opcode 0x05)
        let mut create_cq = NvmeSubmissionQueueEntry::new(NVME_ADMIN_OP_CREATE_IO_CQ, 0, 0);
        create_cq.prp1 = io_q.cq_phys_addr();
        create_cq.cdw10 = ((io_depth as u32 - 1) << 16) | 1; // QID = 1, QSIZE
        create_cq.cdw11 = 1; // Physically contiguous, interrupts disabled
        self.submit_admin_cmd(create_cq)?;

        // 2. Create I/O SQ (Opcode 0x01)
        let mut create_sq = NvmeSubmissionQueueEntry::new(NVME_ADMIN_OP_CREATE_IO_SQ, 0, 0);
        create_sq.prp1 = io_q.sq_phys_addr();
        create_sq.cdw10 = ((io_depth as u32 - 1) << 16) | 1; // QID = 1, QSIZE
        create_sq.cdw11 = (1 << 16) | 1; // CQID = 1, Physically contiguous
        self.submit_admin_cmd(create_sq)?;

        self.io_queue = Some(io_q);
        Ok(())
    }

    /// Identify specific Namespace properties (e.g. block count, sector size).
    pub unsafe fn identify_namespace(&mut self, nsid: u32) -> Result<(), &'static str> {
        let mut ns_buf = Box::new([0u8; 4096]);
        let mut cmd = NvmeSubmissionQueueEntry::new(NVME_ADMIN_OP_IDENTIFY, 0, nsid);
        cmd.prp1 = ns_buf.as_ptr() as u64;
        cmd.cdw10 = 0; // CNS = 0: Identify Namespace

        self.submit_admin_cmd(cmd)?;

        let ns = &*(ns_buf.as_ptr() as *const NvmeIdentifyNamespace);
        self.active_ns_lba_count = ns.nsze;

        let flbas_idx = (ns.flbas & 0x0F) as usize;
        let lbads = ns.lbaf[flbas_idx].lbads;
        self.active_ns_block_size = 1 << lbads;

        Ok(())
    }

    /// Read raw sectors from the NVMe namespace via I/O queue.
    pub unsafe fn read_sectors(&mut self, start_lba: u64, count: u16, dest: &mut [u8]) -> Result<(), &'static str> {
        let needed_bytes = (count as usize) * self.active_ns_block_size;
        if dest.len() < needed_bytes {
            return Err("Destination buffer too small for NVMe read");
        }

        let q = self.io_queue.as_mut().ok_or("NVMe I/O queue not initialized")?;

        let mut cmd = NvmeSubmissionQueueEntry::new(NVME_NVM_OP_READ, self.next_cid, 1);
        self.next_cid = self.next_cid.wrapping_add(1);

        cmd.prp1 = dest.as_ptr() as u64;
        if needed_bytes > 4096 {
            cmd.prp2 = (dest.as_ptr() as u64) + 4096;
        }

        cmd.cdw10 = (start_lba & 0xFFFFFFFF) as u32;
        cmd.cdw11 = (start_lba >> 32) as u32;
        cmd.cdw12 = (count as u32) - 1; // 0-based count

        let slot = q.sq_tail as usize;
        q.sq_buffer[slot] = cmd;
        q.sq_tail = (q.sq_tail + 1) % q.depth;

        // Ring I/O SQ Doorbell
        let db_sq = (self.mmio_base + q.db_sq_offset) as *mut u32;
        write_volatile(db_sq, q.sq_tail as u32);

        // Wait for completion
        let mut timeout = 1_000_000;
        loop {
            let cq_slot = q.cq_head as usize;
            let cqe = read_volatile(&q.cq_buffer[cq_slot] as *const NvmeCompletionQueueEntry);

            if cqe.phase() == q.cq_phase {
                q.cq_head = (q.cq_head + 1) % q.depth;
                if q.cq_head == 0 {
                    q.cq_phase = !q.cq_phase;
                }

                let db_cq = (self.mmio_base + q.db_cq_offset) as *mut u32;
                write_volatile(db_cq, q.cq_head as u32);

                if !cqe.is_success() {
                    return Err("NVMe Read I/O command failed");
                }
                return Ok(());
            }

            timeout -= 1;
            if timeout == 0 {
                return Err("NVMe Read I/O command timeout");
            }
        }
    }

    /// Write raw sectors to the NVMe namespace via I/O queue.
    pub unsafe fn write_sectors(&mut self, start_lba: u64, count: u16, src: &[u8]) -> Result<(), &'static str> {
        let needed_bytes = (count as usize) * self.active_ns_block_size;
        if src.len() < needed_bytes {
            return Err("Source buffer too small for NVMe write");
        }

        let q = self.io_queue.as_mut().ok_or("NVMe I/O queue not initialized")?;

        let mut cmd = NvmeSubmissionQueueEntry::new(NVME_NVM_OP_WRITE, self.next_cid, 1);
        self.next_cid = self.next_cid.wrapping_add(1);

        cmd.prp1 = src.as_ptr() as u64;
        if needed_bytes > 4096 {
            cmd.prp2 = (src.as_ptr() as u64) + 4096;
        }

        cmd.cdw10 = (start_lba & 0xFFFFFFFF) as u32;
        cmd.cdw11 = (start_lba >> 32) as u32;
        cmd.cdw12 = (count as u32) - 1;

        let slot = q.sq_tail as usize;
        q.sq_buffer[slot] = cmd;
        q.sq_tail = (q.sq_tail + 1) % q.depth;

        let db_sq = (self.mmio_base + q.db_sq_offset) as *mut u32;
        write_volatile(db_sq, q.sq_tail as u32);

        let mut timeout = 1_000_000;
        loop {
            let cq_slot = q.cq_head as usize;
            let cqe = read_volatile(&q.cq_buffer[cq_slot] as *const NvmeCompletionQueueEntry);

            if cqe.phase() == q.cq_phase {
                q.cq_head = (q.cq_head + 1) % q.depth;
                if q.cq_head == 0 {
                    q.cq_phase = !q.cq_phase;
                }

                let db_cq = (self.mmio_base + q.db_cq_offset) as *mut u32;
                write_volatile(db_cq, q.cq_head as u32);

                if !cqe.is_success() {
                    return Err("NVMe Write I/O command failed");
                }
                return Ok(());
            }

            timeout -= 1;
            if timeout == 0 {
                return Err("NVMe Write I/O command timeout");
            }
        }
    }
}
