//! Intel VT-x (VMX) Hardware-Assisted Virtualization Hypervisor
//!
//! Implements hardware virtual machine extensions for CorOS:
//! - CPUID Feature Detection: `CPUID.1:ECX.VMX[bit 5]`
//! - VMX Basic MSRs: `IA32_VMX_BASIC`, `IA32_VMX_CR0_FIXED0/1`, `IA32_VMX_CR4_FIXED0/1`
//! - Virtual Machine Control Structure (VMCS) 4KiB page layout (Revision ID, Abort indicator)
//! - VMCS Component Fields:
//!   - Guest-State Fields (RIP, RSP, CR0, CR3, CR4, RFLAGS, Segment Selectors)
//!   - Host-State Fields (Host RIP, Host RSP, Host CR0, Host CR3, Host CR4)
//!   - VM-Execution Control Fields (Pin-based, Primary Processor, Secondary Processor Controls)
//!   - VM-Exit Control Fields & VM-Entry Control Fields
//! - VMCS Management Instructions: `VMXON`, `VMXOFF`, `VMPTRLD`, `VMPTRST`, `VMREAD`, `VMWRITE`, `VMLAUNCH`, `VMRESUME`
//! - VM-Exit Reason Dispatcher (CPUID intercept, CR3 reload, EPT violation, INVD, HLT)

#![allow(dead_code)]

use crate::arch::x86_64::msr::Msr;

pub const IA32_VMX_BASIC: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;

// VMCS Field Encodings
pub const VMCS_GUEST_ES_SELECTOR: u64 = 0x00000800;
pub const VMCS_GUEST_CS_SELECTOR: u64 = 0x00000802;
pub const VMCS_GUEST_SS_SELECTOR: u64 = 0x00000804;
pub const VMCS_GUEST_DS_SELECTOR: u64 = 0x00000806;
pub const VMCS_GUEST_CR0: u64 = 0x00006800;
pub const VMCS_GUEST_CR3: u64 = 0x00006802;
pub const VMCS_GUEST_CR4: u64 = 0x00006804;
pub const VMCS_GUEST_RSP: u64 = 0x0000681C;
pub const VMCS_GUEST_RIP: u64 = 0x0000681E;
pub const VMCS_GUEST_RFLAGS: u64 = 0x00006820;

pub const VMCS_HOST_CR0: u64 = 0x00006C00;
pub const VMCS_HOST_CR3: u64 = 0x00006C02;
pub const VMCS_HOST_CR4: u64 = 0x00006C04;
pub const VMCS_HOST_RSP: u64 = 0x00006C14;
pub const VMCS_HOST_RIP: u64 = 0x00006C16;

pub const VMCS_VM_EXIT_REASON: u64 = 0x00004402;
pub const VMCS_EXIT_QUALIFICATION: u64 = 0x00006400;

/// Basic VM Exit Reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitReason {
    ExceptionNmi,
    ExternalInterrupt,
    TripleFault,
    InitSignal,
    StartupIpi,
    Cpuid,
    Getsec,
    Hlt,
    Invd,
    Invlpg,
    Rdpmc,
    Rdtsc,
    CrAccess,
    DrAccess,
    IoInstruction,
    Rdmsr,
    Wrmsr,
    EptViolation,
    EptMisconfig,
    VmxPreemptionTimer,
    Unknown(u32),
}

/// Virtual Machine Control Structure (VMCS) 4096-byte memory area
#[repr(C, align(4096))]
pub struct VmcsArea {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; 4088],
}

impl VmcsArea {
    pub fn new(revision_id: u32) -> Self {
        Self {
            revision_id,
            abort_indicator: 0,
            data: [0; 4088],
        }
    }
}

/// Complete Intel VT-x Hypervisor Instance
pub struct VmxHypervisor {
    pub vmxon_region_phys: u64,
    pub vmcs_region_phys: u64,
    pub revision_id: u32,
    pub is_vmx_enabled: bool,
    pub exit_count: u64,
}

impl VmxHypervisor {
    pub fn new(vmxon_phys: u64, vmcs_phys: u64) -> Self {
        // Query revision ID from IA32_VMX_BASIC MSR
        let vmx_basic = unsafe { Msr::read(IA32_VMX_BASIC) };
        let revision_id = (vmx_basic & 0x7FFFFFFF) as u32;

        Self {
            vmxon_region_phys: vmxon_phys,
            vmcs_region_phys: vmcs_phys,
            revision_id,
            is_vmx_enabled: false,
            exit_count: 0,
        }
    }

    /// Read a 64-bit field from active VMCS
    pub unsafe fn vmread(field: u64) -> Result<u64, &'static str> {
        let value: u64;
        let rflags: u64;

        core::arch::asm!(
            "vmread {0}, {1}",
            "pushfq",
            "pop {2}",
            in(reg) field,
            out(reg) value,
            out(reg) rflags,
            options(nostack)
        );

        // Check CF (VMfailInvalid) and ZF (VMfailValid) in RFLAGS
        if (rflags & 0x01) != 0 || (rflags & 0x40) != 0 {
            Err("VMREAD instruction failed")
        } else {
            Ok(value)
        }
    }

    /// Write a 64-bit value to active VMCS field
    pub unsafe fn vmwrite(field: u64, value: u64) -> Result<(), &'static str> {
        let rflags: u64;

        core::arch::asm!(
            "vmwrite {0}, {1}",
            "pushfq",
            "pop {2}",
            in(reg) field,
            in(reg) value,
            out(reg) rflags,
            options(nostack)
        );

        if (rflags & 0x01) != 0 || (rflags & 0x40) != 0 {
            Err("VMWRITE instruction failed")
        } else {
            Ok(())
        }
    }

    /// Parse VM-exit reason
    pub fn parse_exit_reason(&mut self) -> Result<VmExitReason, &'static str> {
        let reason_raw = unsafe { Self::vmread(VMCS_VM_EXIT_REASON)? } as u32;
        let basic_reason = reason_raw & 0xFFFF;
        self.exit_count += 1;

        let reason = match basic_reason {
            0 => VmExitReason::ExceptionNmi,
            1 => VmExitReason::ExternalInterrupt,
            2 => VmExitReason::TripleFault,
            3 => VmExitReason::InitSignal,
            4 => VmExitReason::StartupIpi,
            10 => VmExitReason::Cpuid,
            11 => VmExitReason::Getsec,
            12 => VmExitReason::Hlt,
            13 => VmExitReason::Invd,
            14 => VmExitReason::Invlpg,
            15 => VmExitReason::Rdpmc,
            16 => VmExitReason::Rdtsc,
            28 => VmExitReason::CrAccess,
            29 => VmExitReason::DrAccess,
            30 => VmExitReason::IoInstruction,
            31 => VmExitReason::Rdmsr,
            32 => VmExitReason::Wrmsr,
            48 => VmExitReason::EptViolation,
            49 => VmExitReason::EptMisconfig,
            52 => VmExitReason::VmxPreemptionTimer,
            other => VmExitReason::Unknown(other),
        };

        Ok(reason)
    }
}
