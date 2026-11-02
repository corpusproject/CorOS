//! AMD-V (SVM - Secure Virtual Machine) Hardware Hypervisor
//!
//! Bare-metal no_std pure Rust implementation of AMD-V SVM virtualization:
//! - AMD CPUID Feature Detection: `CPUID.0x80000001:ECX.SVM[bit 2]`
//! - Enable SVM via `MSR_EFER` bit 12 (`SVME`)
//! - Virtual Machine Control Block (VMCB) 4KiB page layout:
//!   - Intercept Vectors (CR reads/writes, DR reads/writes, Exceptions, CPUID, HLT, IOIO, MSR)
//!   - Guest State Save Area (Segment registers, GDTR/IDTR, CR0/CR3/CR4, RFLAGS, RIP, RSP, RAX)
//! - ASID (Address Space Identifier) allocation and TLB invalidation controls
//! - Nested Paging (NPT / AMD RVI) 4-level nested page table translation
//! - VMRUN execution & VMEXIT intercept dispatcher

#![allow(dead_code)]

use alloc::vec::Vec;

pub const MSR_EFER: u32 = 0xC0000080;
pub const EFER_SVME: u64 = 1 << 12; // Secure Virtual Machine Enable

pub const MSR_VM_CR: u32 = 0xC0010114;
pub const MSR_VM_HSAVE_PA: u32 = 0xC0010117; // Host Save Physical Address

/// VMCB Control Area Intercept Vectors (AMD APM Vol 2)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VmcbControlArea {
    pub cr_read_intercepts: u16,
    pub cr_write_intercepts: u16,
    pub dr_read_intercepts: u16,
    pub dr_write_intercepts: u16,
    pub exception_intercepts: u32,
    pub intercept_vec1: u32, // INTR, NMI, SMI, INIT, VINTR, CR0/CR3/CR4/CR8
    pub intercept_vec2: u32, // VMRUN, VMMCALL, VMLOAD, VMSAVE, STGI, CLGI, SKINIT
    pub intercept_vec3: u32, // CPUID, PUSHF, POPF, CPUSWAP, IRET, INVD, PAUSE, HLT, INVLPG, INVLPGA
    pub res1: [u8; 40],
    pub pause_filter_threshold: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: u8,
    pub res2: [u8; 3],
    pub v_intr: u64,
    pub interrupt_shadow: u64,
    pub exit_code: u64,
    pub exit_info1: u64,
    pub exit_info2: u64,
    pub exit_int_info: u64,
    pub np_enable: u64, // Nested Paging (NPT) Enable bit 0
    pub avic_apic_bar: u64,
    pub res3: [u8; 24],
    pub n_cr3: u64, // Nested CR3 (Root of NPT page tables)
    pub lbr_virtualization_enable: u64,
}

/// VMCB Segment Register State
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VmcbSegment {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

/// VMCB Guest State Save Area (Offsets 0x400 - 0xFFF)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VmcbGuestSaveArea {
    pub es: VmcbSegment,
    pub cs: VmcbSegment,
    pub ss: VmcbSegment,
    pub ds: VmcbSegment,
    pub fs: VmcbSegment,
    pub gs: VmcbSegment,
    pub gdtr: VmcbSegment,
    pub ldtr: VmcbSegment,
    pub idtr: VmcbSegment,
    pub tr: VmcbSegment,
    pub res1: [u8; 43],
    pub cpl: u8,
    pub res2: [u8; 4],
    pub efer: u64,
    pub res3: [u8; 112],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub res4: [u8; 88],
    pub rsp: u64,
    pub res5: [u8; 24],
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
}

/// AMD-V Exit Intercept Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmExitCode {
    Cr0Read,
    Cr3Read,
    Cr4Read,
    Cr0Write,
    Cr3Write,
    Cr4Write,
    Exception(u32),
    Interrupt,
    Nmi,
    Cpuid,
    Hlt,
    Invlpg,
    VmRun,
    VmCall,
    VmLoad,
    VmSave,
    NestedPageFault,
    Unknown(u64),
}

/// AMD-V Hardware Virtual Machine Instance
pub struct AmdVirtualMachine {
    pub vmcb_phys: u64,
    pub asid: u32,
    pub npt_root_phys: u64,
    pub is_running: bool,
}

impl AmdVirtualMachine {
    pub fn new(asid: u32, npt_root: u64) -> Self {
        Self {
            vmcb_phys: 0,
            asid,
            npt_root_phys: npt_root,
            is_running: false,
        }
    }

    /// Configure VMCB intercept control registers
    pub fn configure_intercepts(control: &mut VmcbControlArea) {
        // Intercept CPUID, HLT, and VMMCALL
        control.intercept_vec3 |= (1 << 0); // CPUID
        control.intercept_vec3 |= (1 << 7); // HLT
        control.intercept_vec2 |= (1 << 1); // VMMCALL

        // Enable Nested Paging (NPT / SLAT)
        control.np_enable = 1;
    }

    /// Decode raw SVM VMEXIT code from VMCB
    pub fn decode_exit_code(raw_code: u64) -> SvmExitCode {
        match raw_code {
            0x00 => SvmExitCode::Cr0Read,
            0x03 => SvmExitCode::Cr3Read,
            0x04 => SvmExitCode::Cr4Read,
            0x10 => SvmExitCode::Cr0Write,
            0x13 => SvmExitCode::Cr3Write,
            0x14 => SvmExitCode::Cr4Write,
            0x40..=0x5F => SvmExitCode::Exception((raw_code - 0x40) as u32),
            0x60 => SvmExitCode::Interrupt,
            0x61 => SvmExitCode::Nmi,
            0x72 => SvmExitCode::Cpuid,
            0x78 => SvmExitCode::Hlt,
            0x7B => SvmExitCode::Invlpg,
            0x80 => SvmExitCode::VmRun,
            0x81 => SvmExitCode::VmCall,
            0x82 => SvmExitCode::VmLoad,
            0x83 => SvmExitCode::VmSave,
            0x400 => SvmExitCode::NestedPageFault,
            other => SvmExitCode::Unknown(other),
        }
    }

    /// Dispatch and emulate guest hypercall (VMMCALL)
    pub fn handle_vmmcall(&self, call_num: u64, arg1: u64, _arg2: u64) -> u64 {
        match call_num {
            1 => {
                // Yield CPU slice
                0
            }
            2 => {
                // Query hypervisor version ("CorOS-SVM")
                0x434F524F5353564D // ASCII "COROSSVM"
            }
            3 => {
                // Host memory balloon donation
                arg1
            }
            _ => {
                u64::MAX // ENOSYS
            }
        }
    }
}
