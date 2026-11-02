//! CorOS Hardware Driver Module: `nvme_admin`
//!
//! NVM Express 1.4 Base Specification Controller Register Layout (`CAP`, `VS`, `CC`,
//! `CSTS`, `AQA`, `ASQ`, `ACQ`), 64-byte Admin Submission Queue Entry (`NvmeSqe`),
//! 16-byte Completion Queue Entry (`NvmeCqe`), and Admin Queue command builders.

/// NVMe Controller MMIO Register offsets in BAR0.
pub mod nvme_regs {
    /// Controller Capabilities (64-bit).
    pub const CAP: usize = 0x0000;
    /// Version (32-bit).
    pub const VS: usize = 0x0008;
    /// Interrupt Mask Set (32-bit).
    pub const INTMS: usize = 0x000C;
    /// Interrupt Mask Clear (32-bit).
    pub const INTMC: usize = 0x0010;
    /// Controller Configuration (32-bit).
    pub const CC: usize = 0x0014;
    /// Controller Status (32-bit).
    pub const CSTS: usize = 0x001C;
    /// NVM Subsystem Reset (32-bit).
    pub const NSSR: usize = 0x0020;
    /// Admin Queue Attributes (32-bit).
    pub const AQA: usize = 0x0024;
    /// Admin Submission Queue Base Address (64-bit).
    pub const ASQ: usize = 0x0028;
    /// Admin Completion Queue Base Address (64-bit).
    pub const ACQ: usize = 0x0030;
    /// Doorbell base offset (`0x1000`).
    pub const DOORBELL_BASE: usize = 0x1000;
}

/// Decoded NVMe `CAP` (Controller Capabilities, 64-bit) register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeCapabilities {
    /// Maximum Queue Entries Supported (1-based count, decoded from `MQES + 1`).
    pub max_queue_entries: u16,
    /// Contiguous Queues Required (`CQR`).
    pub contiguous_queues_required: bool,
    /// Timeout in 500ms units (`TO`).
    pub timeout_500ms: u8,
    /// Doorbell Stride exponent (`DSTRD`, stride in bytes is `4 << dstrd`).
    pub doorbell_stride_shift: u8,
    /// Memory Page Size Minimum (`MPSMIN`, `4096 << mpsmin`).
    pub mps_min_shift: u8,
    /// Memory Page Size Maximum (`MPSMAX`, `4096 << mpsmax`).
    pub mps_max_shift: u8,
}

impl NvmeCapabilities {
    #[inline]
    pub const fn from_raw(cap: u64) -> Self {
        let mqes = (cap & 0xFFFF) as u16;
        let cqr = ((cap >> 16) & 0x01) != 0;
        let to = ((cap >> 24) & 0xFF) as u8;
        let dstrd = ((cap >> 32) & 0x0F) as u8;
        let mpsmin = ((cap >> 48) & 0x0F) as u8;
        let mpsmax = ((cap >> 52) & 0x0F) as u8;
        Self {
            max_queue_entries: mqes.saturating_add(1),
            contiguous_queues_required: cqr,
            timeout_500ms: to,
            doorbell_stride_shift: dstrd,
            mps_min_shift: mpsmin,
            mps_max_shift: mpsmax,
        }
    }

    /// Returns the byte distance between successive doorbell registers (`4 << DSTRD`).
    #[inline]
    pub const fn doorbell_stride_bytes(&self) -> usize {
        4usize << (self.doorbell_stride_shift as usize)
    }
}

/// NVMe Controller Configuration (`CC`) builder.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeControllerConfig(pub u32);

impl NvmeControllerConfig {
    /// Standard I/O Submission Queue Entry size exponent (`6` -> `2^6 = 64` bytes).
    pub const IOSQES_64B: u32 = 6 << 16;
    /// Standard I/O Completion Queue Entry size exponent (`4` -> `2^4 = 16` bytes).
    pub const IOCQES_16B: u32 = 4 << 20;
    /// Enable bit (`EN`).
    pub const ENABLE: u32 = 1 << 0;

    #[inline]
    pub const fn standard_enabled(mps_shift: u8) -> Self {
        let mps_bits = ((mps_shift & 0x0F) as u32) << 7;
        Self(Self::ENABLE | mps_bits | Self::IOSQES_64B | Self::IOCQES_16B)
    }
}

/// NVMe Controller Status (`CSTS`) bitflags.
pub mod nvme_csts {
    pub const RDY: u32 = 1 << 0;
    pub const CFS: u32 = 1 << 1;
    pub const SHST_MASK: u32 = 0b11 << 2;
    pub const SHST_COMPLETE: u32 = 0b10 << 2;
}

/// NVMe Admin Command Opcodes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeAdminOpcode {
    DeleteIoSq = 0x00,
    CreateIoSq = 0x01,
    GetLogPage = 0x02,
    DeleteIoCq = 0x04,
    CreateIoCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
    NamespaceManagement = 0x0D,
    FirmwareCommit = 0x10,
    FirmwareImageDownload = 0x11,
}

/// 64-byte NVMe Submission Queue Entry (`NvmeSqe`), common command format.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeSqe {
    /// Opcode (`CDW0[7:0]`).
    pub opcode: u8,
    /// Fused operation & PRP/SGL selection (`CDW0[15:8]`).
    pub flags: u8,
    /// Command Identifier (`CDW0[31:16]`).
    pub command_id: u16,
    /// Namespace Identifier (`NSID`).
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    /// Metadata Pointer (`MPTR`).
    pub mptr: u64,
    /// Data Pointer PRP Entry 1 (`PRP1`).
    pub prp1: u64,
    /// Data Pointer PRP Entry 2 or PRP List Pointer (`PRP2`).
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl NvmeSqe {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            command_id: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Builds an Admin `Identify Controller` (`CNS = 0x01`) command.
    #[inline]
    pub const fn identify_controller(command_id: u16, prp1_phys: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = NvmeAdminOpcode::Identify as u8;
        sqe.command_id = command_id;
        sqe.prp1 = prp1_phys;
        sqe.cdw10 = 0x01; // CNS = 0x01 (Identify Controller)
        sqe
    }

    /// Builds an Admin `Identify Namespace` (`CNS = 0x00`) command for `nsid`.
    #[inline]
    pub const fn identify_namespace(command_id: u16, nsid: u32, prp1_phys: u64) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = NvmeAdminOpcode::Identify as u8;
        sqe.command_id = command_id;
        sqe.nsid = nsid;
        sqe.prp1 = prp1_phys;
        sqe.cdw10 = 0x00; // CNS = 0x00 (Identify Namespace)
        sqe
    }

    /// Builds an Admin `Create I/O Completion Queue` (`0x05`) command.
    #[inline]
    pub const fn create_io_cq(
        command_id: u16,
        cqid: u16,
        queue_depth: u16,
        prp1_phys: u64,
        interrupt_vector: u16,
        interrupts_enabled: bool,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = NvmeAdminOpcode::CreateIoCq as u8;
        sqe.command_id = command_id;
        sqe.prp1 = prp1_phys;
        let qsize_0based = (queue_depth.saturating_sub(1) as u32) << 16;
        sqe.cdw10 = qsize_0based | (cqid as u32);
        let ien_bit = if interrupts_enabled { 1u32 << 1 } else { 0 };
        let pc_bit = 1u32 << 0; // Physically Contiguous
        sqe.cdw11 = ((interrupt_vector as u32) << 16) | ien_bit | pc_bit;
        sqe
    }

    /// Builds an Admin `Create I/O Submission Queue` (`0x01`) command.
    #[inline]
    pub const fn create_io_sq(
        command_id: u16,
        sqid: u16,
        cqid: u16,
        queue_depth: u16,
        prp1_phys: u64,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = NvmeAdminOpcode::CreateIoSq as u8;
        sqe.command_id = command_id;
        sqe.prp1 = prp1_phys;
        let qsize_0based = (queue_depth.saturating_sub(1) as u32) << 16;
        sqe.cdw10 = qsize_0based | (sqid as u32);
        let pc_bit = 1u32 << 0; // Physically Contiguous
        sqe.cdw11 = ((cqid as u32) << 16) | pc_bit;
        sqe
    }

    /// Builds an Admin `Set Features - Number of Queues` (`Feature ID = 0x07`) command.
    #[inline]
    pub const fn set_feature_number_of_queues(
        command_id: u16,
        num_sq: u16,
        num_cq: u16,
    ) -> Self {
        let mut sqe = Self::zeroed();
        sqe.opcode = NvmeAdminOpcode::SetFeatures as u8;
        sqe.command_id = command_id;
        sqe.cdw10 = 0x07; // Feature ID 0x07: Number of Queues
        let nsqr = num_sq.saturating_sub(1) as u32;
        let ncqr = (num_cq.saturating_sub(1) as u32) << 16;
        sqe.cdw11 = ncqr | nsqr;
        sqe
    }
}

/// 16-byte NVMe Completion Queue Entry (`NvmeCqe`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeCqe {
    /// Command-specific result (`DW0`).
    pub result: u32,
    /// Reserved (`DW1`).
    pub rsvd: u32,
    /// Submission Queue Head Pointer (`DW2[15:0]`).
    pub sq_head: u16,
    /// Submission Queue Identifier (`DW2[31:16]`).
    pub sq_id: u16,
    /// Command Identifier (`DW3[15:0]`).
    pub command_id: u16,
    /// Phase Tag (`bit 0`) and Status Field (`bits 15:1`).
    pub status_and_phase: u16,
}

impl NvmeCqe {
    /// Extracts the Phase Tag (`P`) bit.
    #[inline]
    pub const fn phase_tag(&self) -> bool {
        (self.status_and_phase & 0x0001) != 0
    }

    /// Extracts the 8-bit Status Code (`SC`, bits `8:1` of `status_and_phase`).
    #[inline]
    pub const fn status_code(&self) -> u8 {
        ((self.status_and_phase >> 1) & 0xFF) as u8
    }

    /// Extracts the 3-bit Status Code Type (`SCT`, bits `11:9` of `status_and_phase`).
    #[inline]
    pub const fn status_code_type(&self) -> u8 {
        ((self.status_and_phase >> 9) & 0x07) as u8
    }

    /// Returns `true` if the command completed with Generic Command Status Success (`SCT=0, SC=0`).
    #[inline]
    pub const fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }
}

/// Parsed subset of the 4096-byte NVMe Identify Controller structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeIdentifyControllerSummary {
    pub pci_vendor_id: u16,
    pub pci_subsystem_vendor_id: u16,
    pub serial_number: [u8; 20],
    pub model_number: [u8; 40],
    pub max_data_transfer_shift: u8,
    pub number_of_namespaces: u32,
}

impl NvmeIdentifyControllerSummary {
    /// Extracts key controller parameters from a 4096-byte Identify Controller buffer.
    pub fn from_identify_buffer(buf: &[u8; 4096]) -> Self {
        let vid = u16::from_le_bytes([buf[0], buf[1]]);
        let ssvid = u16::from_le_bytes([buf[2], buf[3]]);
        let mut sn = [0u8; 20];
        sn.copy_from_slice(&buf[4..24]);
        let mut mn = [0u8; 40];
        mn.copy_from_slice(&buf[24..64]);
        let mdts = buf[77];
        let nn = u32::from_le_bytes([buf[516], buf[517], buf[518], buf[519]]);
        Self {
            pci_vendor_id: vid,
            pci_subsystem_vendor_id: ssvid,
            serial_number: sn,
            model_number: mn,
            max_data_transfer_shift: mdts,
            number_of_namespaces: nn,
        }
    }
}

/// Encodes the Admin Queue Attributes (`AQA`) register for the given Admin SQ and CQ depths (`2..=4096`).
#[inline]
pub const fn encode_aqa_register(asq_depth: u16, acq_depth: u16) -> u32 {
    let asqs = (asq_depth.saturating_sub(1) & 0x0FFF) as u32;
    let acqs = ((acq_depth.saturating_sub(1) & 0x0FFF) as u32) << 16;
    acqs | asqs
}

/// Self-test for `nvme_admin` register encoding, `NvmeSqe`/`NvmeCqe` layout, and Admin commands.
pub fn verify_driver_module_nvme_admin() -> u32 {
    let mut passed = 0u32;

    // 1. Verify architectural sizes of NvmeSqe (64B) and NvmeCqe (16B)
    if core::mem::size_of::<NvmeSqe>() == 64 && core::mem::size_of::<NvmeCqe>() == 16 {
        passed += 1;
    }

    // 2. Verify CAP register decoding
    let raw_cap: u64 = 0x0020_0001_2801_03FF; // MQES=1023 (1024), CQR=1, TO=40, DSTRD=1 (8B stride)
    let cap = NvmeCapabilities::from_raw(raw_cap);
    if cap.max_queue_entries == 1024
        && cap.contiguous_queues_required
        && cap.doorbell_stride_bytes() == 8
    {
        passed += 1;
    }

    // 3. Verify Admin Create I/O SQ and CQ command construction
    let cq_cmd = NvmeSqe::create_io_cq(10, 1, 256, 0x8000_4000, 3, true);
    let sq_cmd = NvmeSqe::create_io_sq(11, 1, 1, 256, 0x8000_8000);
    if cq_cmd.opcode == 0x05
        && (cq_cmd.cdw10 >> 16) == 255
        && (cq_cmd.cdw10 & 0xFFFF) == 1
        && sq_cmd.opcode == 0x01
        && (sq_cmd.cdw11 >> 16) == 1
    {
        passed += 1;
    }

    // 4. Verify CQE phase tag and status decoding
    let cqe = NvmeCqe {
        result: 0x0007_0007,
        rsvd: 0,
        sq_head: 4,
        sq_id: 0,
        command_id: 10,
        status_and_phase: 0x0001, // Phase=1, Status=0 (Success)
    };
    if cqe.phase_tag() && cqe.is_success() && encode_aqa_register(64, 64) == 0x003F_003F {
        passed += 1;
    }

    passed
}
