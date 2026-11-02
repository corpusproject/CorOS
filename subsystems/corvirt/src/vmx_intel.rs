//! Intel VT-x (`VMX`) Virtual Machine Control Structure (`VMCS`) architecture,
//! execution control bitmasks, VM-Exit reason decoding, and CR0/CR4 fixed-bit validation.

use alloc::collections::BTreeMap;

/// VMCS Field Encoding according to Intel SDM Vol. 3C, Appendix B.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VmcsField {
    // 16-bit Control Fields
    VirtualProcessorId = 0x0000_0000,
    PostedInterruptNotificationVector = 0x0000_0002,
    EptpIndex = 0x0000_0004,

    // 16-bit Guest-State Fields
    GuestEsSelector = 0x0000_0800,
    GuestCsSelector = 0x0000_0802,
    GuestSsSelector = 0x0000_0804,
    GuestDsSelector = 0x0000_0806,
    GuestFsSelector = 0x0000_0808,
    GuestGsSelector = 0x0000_080A,
    GuestLdtrSelector = 0x0000_080C,
    GuestTrSelector = 0x0000_080E,
    GuestInterruptStatus = 0x0000_0810,
    PmlIndex = 0x0000_0812,

    // 16-bit Host-State Fields
    HostEsSelector = 0x0000_0C00,
    HostCsSelector = 0x0000_0C02,
    HostSsSelector = 0x0000_0C04,
    HostDsSelector = 0x0000_0C06,
    HostFsSelector = 0x0000_0C08,
    HostGsSelector = 0x0000_0C0A,
    HostTrSelector = 0x0000_0C0C,

    // 64-bit Control Fields
    IoBitmapA = 0x0000_2000,
    IoBitmapB = 0x0000_2002,
    MsrBitmap = 0x0000_2004,
    VmExitMsrStoreAddr = 0x0000_2006,
    VmExitMsrLoadAddr = 0x0000_2008,
    VmEntryMsrLoadAddr = 0x0000_200A,
    TscOffset = 0x0000_2010,
    VirtualApicPageAddr = 0x0000_2012,
    ApicAccessAddr = 0x0000_2014,
    EptPointer = 0x0000_201A,
    PmlAddress = 0x0000_200E,

    // 64-bit Read-Only Data Field
    GuestPhysicalAddress = 0x0000_2400,

    // 64-bit Guest-State Fields
    VmcsLinkPointer = 0x0000_2800,
    GuestIa32Debugctl = 0x0000_2802,
    GuestIa32Pat = 0x0000_2804,
    GuestIa32Efer = 0x0000_2806,
    GuestIa32PerfGlobalCtrl = 0x0000_2808,
    GuestPdpteBase = 0x0000_280A,

    // 64-bit Host-State Fields
    HostIa32Pat = 0x0000_2C00,
    HostIa32Efer = 0x0000_2C02,
    HostIa32PerfGlobalCtrl = 0x0000_2C04,

    // 32-bit Control Fields
    PinBasedVmExecControls = 0x0000_4000,
    PrimaryProcBasedVmExecControls = 0x0000_4002,
    ExceptionBitmap = 0x0000_4004,
    PageFaultErrorCodeMask = 0x0000_4006,
    PageFaultErrorCodeMatch = 0x0000_4008,
    CrTargetCount = 0x0000_400A,
    VmExitControls = 0x0000_400C,
    VmExitMsrStoreCount = 0x0000_400E,
    VmExitMsrLoadCount = 0x0000_4010,
    VmEntryControls = 0x0000_4012,
    VmEntryMsrLoadCount = 0x0000_4014,
    VmEntryInterruptionInfoField = 0x0000_4016,
    VmEntryExceptionErrorCode = 0x0000_4018,
    VmEntryInstructionLength = 0x0000_401A,
    TprThreshold = 0x0000_401C,
    SecondaryProcBasedVmExecControls = 0x0000_401E,
    PleGap = 0x0000_4020,
    PleWindow = 0x0000_4022,

    // 32-bit Read-Only Data Fields
    VmInstructionError = 0x0000_4400,
    VmExitReasonField = 0x0000_4402,
    VmExitInterruptionInfo = 0x0000_4404,
    VmExitInterruptionErrorCode = 0x0000_4406,
    IdtVectoringInfoField = 0x0000_4408,
    IdtVectoringErrorCode = 0x0000_440A,
    VmExitInstructionLength = 0x0000_440C,
    VmExitInstructionInfo = 0x0000_440E,

    // 32-bit Guest-State Fields
    GuestEsLimit = 0x0000_4800,
    GuestCsLimit = 0x0000_4802,
    GuestSsLimit = 0x0000_4804,
    GuestDsLimit = 0x0000_4806,
    GuestFsLimit = 0x0000_4808,
    GuestGsLimit = 0x0000_480A,
    GuestLdtrLimit = 0x0000_480C,
    GuestTrLimit = 0x0000_480E,
    GuestGdtrLimit = 0x0000_4810,
    GuestIdtrLimit = 0x0000_4812,
    GuestEsArBytes = 0x0000_4814,
    GuestCsArBytes = 0x0000_4816,
    GuestSsArBytes = 0x0000_4818,
    GuestDsArBytes = 0x0000_481A,
    GuestFsArBytes = 0x0000_481C,
    GuestGsArBytes = 0x0000_481E,
    GuestLdtrArBytes = 0x0000_4820,
    GuestTrArBytes = 0x0000_4822,
    GuestInterruptibilityInfo = 0x0000_4824,
    GuestActivityState = 0x0000_4826,
    GuestSysenterCs = 0x0000_482A,
    VmxPreemptionTimerValue = 0x0000_482E,

    // 32-bit Host-State Field
    HostIa32SysenterCs = 0x0000_4C00,

    // Natural-Width Control Fields
    Cr0GuestHostMask = 0x0000_6000,
    Cr4GuestHostMask = 0x0000_6002,
    Cr0ReadShadow = 0x0000_6004,
    Cr4ReadShadow = 0x0000_6006,

    // Natural-Width Read-Only Data Fields
    ExitQualification = 0x0000_6400,
    GuestLinearAddress = 0x0000_640A,

    // Natural-Width Guest-State Fields
    GuestCr0 = 0x0000_6800,
    GuestCr3 = 0x0000_6802,
    GuestCr4 = 0x0000_6804,
    GuestEsBase = 0x0000_6806,
    GuestCsBase = 0x0000_6808,
    GuestSsBase = 0x0000_680A,
    GuestDsBase = 0x0000_680C,
    GuestFsBase = 0x0000_680E,
    GuestGsBase = 0x0000_6810,
    GuestLdtrBase = 0x0000_6812,
    GuestTrBase = 0x0000_6814,
    GuestGdtrBase = 0x0000_6816,
    GuestIdtrBase = 0x0000_6818,
    GuestDr7 = 0x0000_681A,
    GuestRsp = 0x0000_681C,
    GuestRip = 0x0000_681E,
    GuestRflags = 0x0000_6820,
    GuestPendingDbgExceptions = 0x0000_6822,
    GuestSysenterEsp = 0x0000_6824,
    GuestSysenterEip = 0x0000_6826,

    // Natural-Width Host-State Fields
    HostCr0 = 0x0000_6C00,
    HostCr3 = 0x0000_6C02,
    HostCr4 = 0x0000_6C04,
    HostFsBase = 0x0000_6C06,
    HostGsBase = 0x0000_6C08,
    HostTrBase = 0x0000_6C0A,
    HostGdtrBase = 0x0000_6C0C,
    HostIdtrBase = 0x0000_6C0E,
    HostIa32SysenterEsp = 0x0000_6C10,
    HostIa32SysenterEip = 0x0000_6C12,
    HostRsp = 0x0000_6C14,
    HostRip = 0x0000_6C16,
}

impl VmcsField {
    /// Returns the field width category in bits (16, 32, 64, or 64 for natural width on x86_64).
    pub const fn bit_width(self) -> u8 {
        match ((self as u32) >> 13) & 0x3 {
            0 => 16,
            1 => 64,
            2 => 32,
            _ => 64, // Natural width on x86_64
        }
    }

    /// Returns whether this field is a read-only VMCS data field.
    pub const fn is_read_only(self) -> bool {
        (((self as u32) >> 10) & 0x3) == 1
    }
}

/// Pin-Based VM-Execution Controls bitmask constants.
pub mod pin_controls {
    pub const EXTERNAL_INTERRUPT_EXITING: u32 = 1 << 0;
    pub const NMI_EXITING: u32 = 1 << 3;
    pub const VIRTUAL_NMIS: u32 = 1 << 5;
    pub const ACTIVATE_VMX_PREEMPTION_TIMER: u32 = 1 << 6;
    pub const PROCESS_POSTED_INTERRUPTS: u32 = 1 << 7;
}

/// Primary Processor-Based VM-Execution Controls bitmask constants.
pub mod primary_proc_controls {
    pub const INTERRUPT_WINDOW_EXITING: u32 = 1 << 2;
    pub const USE_TSC_OFFSETTING: u32 = 1 << 3;
    pub const HLT_EXITING: u32 = 1 << 7;
    pub const INVLPG_EXITING: u32 = 1 << 9;
    pub const MWAIT_EXITING: u32 = 1 << 10;
    pub const RDPMC_EXITING: u32 = 1 << 11;
    pub const RDTSC_EXITING: u32 = 1 << 12;
    pub const CR3_LOAD_EXITING: u32 = 1 << 15;
    pub const CR3_STORE_EXITING: u32 = 1 << 16;
    pub const CR8_LOAD_EXITING: u32 = 1 << 19;
    pub const CR8_STORE_EXITING: u32 = 1 << 20;
    pub const USE_TPR_SHADOW: u32 = 1 << 21;
    pub const NMI_WINDOW_EXITING: u32 = 1 << 22;
    pub const MOV_DR_EXITING: u32 = 1 << 23;
    pub const UNCONDITIONAL_IO_EXITING: u32 = 1 << 24;
    pub const USE_IO_BITMAPS: u32 = 1 << 25;
    pub const MONITOR_TRAP_FLAG: u32 = 1 << 27;
    pub const USE_MSR_BITMAPS: u32 = 1 << 28;
    pub const MONITOR_EXITING: u32 = 1 << 29;
    pub const PAUSE_EXITING: u32 = 1 << 30;
    pub const ACTIVATE_SECONDARY_CONTROLS: u32 = 1 << 31;
}

/// Secondary Processor-Based VM-Execution Controls bitmask constants.
pub mod secondary_proc_controls {
    pub const VIRTUALIZE_APIC_ACCESSES: u32 = 1 << 0;
    pub const ENABLE_EPT: u32 = 1 << 1;
    pub const DESCRIPTOR_TABLE_EXITING: u32 = 1 << 2;
    pub const ENABLE_RDTSCP: u32 = 1 << 3;
    pub const VIRTUALIZE_X2APIC_MODE: u32 = 1 << 4;
    pub const ENABLE_VPID: u32 = 1 << 5;
    pub const WBINVD_EXITING: u32 = 1 << 6;
    pub const UNRESTRICTED_GUEST: u32 = 1 << 7;
    pub const APIC_REGISTER_VIRTUALIZATION: u32 = 1 << 8;
    pub const VIRTUAL_INTERRUPT_DELIVERY: u32 = 1 << 9;
    pub const PAUSE_LOOP_EXITING: u32 = 1 << 10;
    pub const RDRAND_EXITING: u32 = 1 << 11;
    pub const ENABLE_INVPCID: u32 = 1 << 12;
    pub const ENABLE_VM_FUNCTIONS: u32 = 1 << 13;
    pub const VMCS_SHADOWING: u32 = 1 << 14;
    pub const ENABLE_PML: u32 = 1 << 17;
    pub const EPT_VIOLATION_VE: u32 = 1 << 18;
    pub const ENABLE_XSAVES_XRSTORS: u32 = 1 << 20;
}

/// Decoded Intel VT-x VM-Exit Reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitReason {
    ExceptionOrNmi,
    ExternalInterrupt,
    TripleFault,
    InitSignal,
    InterruptWindow,
    NmiWindow,
    TaskSwitch,
    Cpuid,
    Hlt,
    Invd,
    Invlpg,
    Rdpmc,
    Rdtsc,
    Vmcall,
    Vmclear,
    Vmlaunch,
    Vmptrld,
    Vmptrst,
    Vmread,
    Vmresume,
    Vmwrite,
    Vmxoff,
    Vmxon,
    ControlRegisterAccess {
        cr_number: u8,
        is_write: bool,
        gpr: u8,
    },
    MovDr,
    IoInstruction {
        port: u16,
        size_bytes: u8,
        is_in: bool,
        is_string: bool,
        is_rep: bool,
    },
    Rdmsr,
    Wrmsr,
    InvalidGuestState,
    MsrLoadingFailure,
    Mwait,
    MonitorTrapFlag,
    Monitor,
    Pause,
    MachineCheckFailure,
    TprBelowThreshold,
    ApicAccess,
    VirtualizedEoi,
    GdtrIdtrAccess,
    LdtrTrAccess,
    EptViolation {
        read_access: bool,
        write_access: bool,
        exec_access: bool,
        gpa_readable: bool,
        gpa_writable: bool,
        gpa_executable: bool,
    },
    EptMisconfig,
    Invept,
    Rdtscp,
    VmxPreemptionTimerExpired,
    Invvpid,
    Wbinvd,
    Xsetbv,
    ApicWrite,
    Rdrand,
    Invpcid,
    Vmfunc,
    Unknown(u16),
}

impl VmExitReason {
    /// Decodes a raw 32-bit VM-Exit reason field and the natural-width Exit Qualification.
    pub fn decode(raw_reason: u32, exit_qualification: u64) -> Self {
        let basic_reason = (raw_reason & 0xFFFF) as u16;
        match basic_reason {
            0 => Self::ExceptionOrNmi,
            1 => Self::ExternalInterrupt,
            2 => Self::TripleFault,
            3 => Self::InitSignal,
            7 => Self::InterruptWindow,
            8 => Self::NmiWindow,
            9 => Self::TaskSwitch,
            10 => Self::Cpuid,
            12 => Self::Hlt,
            13 => Self::Invd,
            14 => Self::Invlpg,
            15 => Self::Rdpmc,
            16 => Self::Rdtsc,
            18 => Self::Vmcall,
            19 => Self::Vmclear,
            20 => Self::Vmlaunch,
            21 => Self::Vmptrld,
            22 => Self::Vmptrst,
            23 => Self::Vmread,
            24 => Self::Vmresume,
            25 => Self::Vmwrite,
            26 => Self::Vmxoff,
            27 => Self::Vmxon,
            28 => {
                let cr_number = (exit_qualification & 0xF) as u8;
                let access_type = (exit_qualification >> 4) & 0x3;
                let is_write = access_type == 0;
                let gpr = ((exit_qualification >> 8) & 0xF) as u8;
                Self::ControlRegisterAccess {
                    cr_number,
                    is_write,
                    gpr,
                }
            }
            29 => Self::MovDr,
            30 => {
                let size_code = (exit_qualification & 0x7) as u8;
                let size_bytes = match size_code {
                    0 => 1,
                    1 => 2,
                    3 => 4,
                    _ => 1,
                };
                let is_in = ((exit_qualification >> 3) & 1) != 0;
                let is_string = ((exit_qualification >> 4) & 1) != 0;
                let is_rep = ((exit_qualification >> 5) & 1) != 0;
                let port = ((exit_qualification >> 16) & 0xFFFF) as u16;
                Self::IoInstruction {
                    port,
                    size_bytes,
                    is_in,
                    is_string,
                    is_rep,
                }
            }
            31 => Self::Rdmsr,
            32 => Self::Wrmsr,
            33 => Self::InvalidGuestState,
            34 => Self::MsrLoadingFailure,
            36 => Self::Mwait,
            37 => Self::MonitorTrapFlag,
            39 => Self::Monitor,
            40 => Self::Pause,
            41 => Self::MachineCheckFailure,
            43 => Self::TprBelowThreshold,
            44 => Self::ApicAccess,
            45 => Self::VirtualizedEoi,
            46 => Self::GdtrIdtrAccess,
            47 => Self::LdtrTrAccess,
            48 => Self::EptViolation {
                read_access: (exit_qualification & (1 << 0)) != 0,
                write_access: (exit_qualification & (1 << 1)) != 0,
                exec_access: (exit_qualification & (1 << 2)) != 0,
                gpa_readable: (exit_qualification & (1 << 3)) != 0,
                gpa_writable: (exit_qualification & (1 << 4)) != 0,
                gpa_executable: (exit_qualification & (1 << 5)) != 0,
            },
            49 => Self::EptMisconfig,
            50 => Self::Invept,
            51 => Self::Rdtscp,
            52 => Self::VmxPreemptionTimerExpired,
            53 => Self::Invvpid,
            54 => Self::Wbinvd,
            55 => Self::Xsetbv,
            56 => Self::ApicWrite,
            57 => Self::Rdrand,
            58 => Self::Invpcid,
            59 => Self::Vmfunc,
            other => Self::Unknown(other),
        }
    }
}

/// Hardware CR0 and CR4 fixed-bits validator for VMX operation (`IA32_VMX_CR0_FIXED0/1`, `IA32_VMX_CR4_FIXED0/1`).
#[derive(Debug, Clone, Copy)]
pub struct VmxCrFixedValidator {
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub unrestricted_guest_supported: bool,
}

impl VmxCrFixedValidator {
    /// Creates a standard Intel VT-x fixed-bits validator profile.
    pub const fn standard_vtx_profile(unrestricted_guest_supported: bool) -> Self {
        // PE (bit 0), NE (bit 5), PG (bit 31) required unless unrestricted guest is active.
        let cr0_fixed0 = (1 << 0) | (1 << 5) | (1 << 31);
        let cr0_fixed1 = 0xFFFF_FFFF;
        // VMXE (bit 13) must be 1 in VMX operation.
        let cr4_fixed0 = 1 << 13;
        let cr4_fixed1 = 0x0037_67FF;
        Self {
            cr0_fixed0,
            cr0_fixed1,
            cr4_fixed0,
            cr4_fixed1,
            unrestricted_guest_supported,
        }
    }

    /// Sanitizes and validates a candidate guest CR0 value.
    pub fn sanitize_guest_cr0(&self, candidate_cr0: u64, unrestricted_guest_enabled: bool) -> u64 {
        let mut required_ones = self.cr0_fixed0;
        if unrestricted_guest_enabled && self.unrestricted_guest_supported {
            // PE (bit 0) and PG (bit 31) may be 0 in unrestricted guest mode.
            required_ones &= !((1 << 0) | (1 << 31));
        }
        (candidate_cr0 | required_ones) & self.cr0_fixed1
    }

    /// Checks whether a guest CR0 value satisfies all VMX fixed bit constraints.
    pub fn is_valid_guest_cr0(&self, cr0: u64, unrestricted_guest_enabled: bool) -> bool {
        self.sanitize_guest_cr0(cr0, unrestricted_guest_enabled) == cr0
    }

    /// Sanitizes and validates a candidate guest CR4 value.
    pub fn sanitize_guest_cr4(&self, candidate_cr4: u64) -> u64 {
        (candidate_cr4 | self.cr4_fixed0) & self.cr4_fixed1
    }

    /// Checks whether a guest CR4 value satisfies all VMX fixed bit constraints.
    pub fn is_valid_guest_cr4(&self, cr4: u64) -> bool {
        self.sanitize_guest_cr4(cr4) == cr4
    }
}

/// Virtual Machine Control Structure (`VMCS`) region representation.
#[derive(Debug, Clone)]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub launched: bool,
    fields: BTreeMap<VmcsField, u64>,
}

impl VmcsRegion {
    /// Creates a new unlaunched VMCS region initialized with a revision identifier.
    pub fn new(revision_id: u32) -> Self {
        Self {
            revision_id: revision_id & 0x7FFF_FFFF,
            abort_indicator: 0,
            launched: false,
            fields: BTreeMap::new(),
        }
    }

    /// Emulates `VMWRITE` to a VMCS field, enforcing field width truncation and read-only checks.
    pub fn vmwrite(&mut self, field: VmcsField, value: u64) -> Result<(), u32> {
        if field.is_read_only() {
            // VMInstructionError 12: VMWRITE to read-only VMCS component
            self.fields.insert(VmcsField::VmInstructionError, 12);
            return Err(12);
        }
        let masked = match field.bit_width() {
            16 => value & 0xFFFF,
            32 => value & 0xFFFF_FFFF,
            _ => value,
        };
        self.fields.insert(field, masked);
        Ok(())
    }

    /// Internal hypervisor write that can populate read-only VM-Exit fields during a simulated exit.
    pub fn record_vmexit(
        &mut self,
        raw_reason: u32,
        qualification: u64,
        guest_phys_addr: u64,
        instruction_len: u32,
    ) {
        self.fields.insert(VmcsField::VmExitReasonField, raw_reason as u64);
        self.fields.insert(VmcsField::ExitQualification, qualification);
        self.fields.insert(VmcsField::GuestPhysicalAddress, guest_phys_addr);
        self.fields.insert(VmcsField::VmExitInstructionLength, instruction_len as u64);
    }

    /// Emulates `VMREAD` from a VMCS field.
    pub fn vmread(&self, field: VmcsField) -> u64 {
        self.fields.get(&field).copied().unwrap_or(0)
    }

    /// Validates the VMCS control and guest-state area prior to `VMLAUNCH` / `VMRESUME`.
    pub fn verify_vm_entry_state(&self, validator: &VmxCrFixedValidator) -> Result<(), u32> {
        let primary = self.vmread(VmcsField::PrimaryProcBasedVmExecControls) as u32;
        let secondary = if (primary & primary_proc_controls::ACTIVATE_SECONDARY_CONTROLS) != 0 {
            self.vmread(VmcsField::SecondaryProcBasedVmExecControls) as u32
        } else {
            0
        };
        let unrestricted = (secondary & secondary_proc_controls::UNRESTRICTED_GUEST) != 0;
        let guest_cr0 = self.vmread(VmcsField::GuestCr0);
        let guest_cr4 = self.vmread(VmcsField::GuestCr4);

        if !validator.is_valid_guest_cr0(guest_cr0, unrestricted) {
            return Err(33); // InvalidGuestState
        }
        if !validator.is_valid_guest_cr4(guest_cr4) {
            return Err(33);
        }
        if (secondary & secondary_proc_controls::ENABLE_EPT) != 0
            && self.vmread(VmcsField::EptPointer) == 0
        {
            return Err(7); // Invalid control field
        }
        Ok(())
    }
}
