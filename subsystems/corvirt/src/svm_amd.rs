//! AMD-V (`SVM`) Virtual Machine Control Block (`VMCB`), intercept bitmasks,
//! `#VMEXIT` exitcode decoding, Guest ASID allocation, and Nested Paging (`NPT`) configuration.

use alloc::vec::Vec;

/// General instruction intercept bitmasks in VMCB Control Area word 3 (`general_intercepts_word1`).
pub mod svm_intercepts_word1 {
    pub const INTERCEPT_INTR: u32 = 1 << 0;
    pub const INTERCEPT_NMI: u32 = 1 << 1;
    pub const INTERCEPT_SMI: u32 = 1 << 2;
    pub const INTERCEPT_INIT: u32 = 1 << 3;
    pub const INTERCEPT_VINTR: u32 = 1 << 4;
    pub const INTERCEPT_CR0_SEL_WRITE: u32 = 1 << 5;
    pub const INTERCEPT_IDTR_READ: u32 = 1 << 6;
    pub const INTERCEPT_GDTR_READ: u32 = 1 << 7;
    pub const INTERCEPT_LDTR_READ: u32 = 1 << 8;
    pub const INTERCEPT_TR_READ: u32 = 1 << 9;
    pub const INTERCEPT_IDTR_WRITE: u32 = 1 << 10;
    pub const INTERCEPT_GDTR_WRITE: u32 = 1 << 11;
    pub const INTERCEPT_LDTR_WRITE: u32 = 1 << 12;
    pub const INTERCEPT_TR_WRITE: u32 = 1 << 13;
    pub const INTERCEPT_RDTSC: u32 = 1 << 14;
    pub const INTERCEPT_RDPMC: u32 = 1 << 15;
    pub const INTERCEPT_PUSHF: u32 = 1 << 16;
    pub const INTERCEPT_POPF: u32 = 1 << 17;
    pub const INTERCEPT_CPUID: u32 = 1 << 18;
    pub const INTERCEPT_RSM: u32 = 1 << 19;
    pub const INTERCEPT_IRET: u32 = 1 << 20;
    pub const INTERCEPT_INTN: u32 = 1 << 21;
    pub const INTERCEPT_INVD: u32 = 1 << 22;
    pub const INTERCEPT_PAUSE: u32 = 1 << 23;
    pub const INTERCEPT_HLT: u32 = 1 << 24;
    pub const INTERCEPT_INVLPG: u32 = 1 << 25;
    pub const INTERCEPT_INVLPGA: u32 = 1 << 26;
    pub const INTERCEPT_IOIO_PROT: u32 = 1 << 27;
    pub const INTERCEPT_MSR_PROT: u32 = 1 << 28;
    pub const INTERCEPT_TASK_SWITCH: u32 = 1 << 29;
    pub const INTERCEPT_FERR_FREEZE: u32 = 1 << 30;
    pub const INTERCEPT_SHUTDOWN: u32 = 1 << 31;
}

/// General instruction intercept bitmasks in VMCB Control Area word 4 (`general_intercepts_word2`).
pub mod svm_intercepts_word2 {
    pub const INTERCEPT_VMRUN: u32 = 1 << 0;
    pub const INTERCEPT_VMMCALL: u32 = 1 << 1;
    pub const INTERCEPT_VMLOAD: u32 = 1 << 2;
    pub const INTERCEPT_VMSAVE: u32 = 1 << 3;
    pub const INTERCEPT_STGI: u32 = 1 << 4;
    pub const INTERCEPT_CLGI: u32 = 1 << 5;
    pub const INTERCEPT_SKINIT: u32 = 1 << 6;
    pub const INTERCEPT_RDTSCP: u32 = 1 << 7;
    pub const INTERCEPT_ICEBP: u32 = 1 << 8;
    pub const INTERCEPT_WBINVD: u32 = 1 << 9;
    pub const INTERCEPT_MONITOR: u32 = 1 << 10;
    pub const INTERCEPT_MWAIT: u32 = 1 << 11;
    pub const INTERCEPT_XSETBV: u32 = 1 << 13;
    pub const INTERCEPT_RDPRU: u32 = 1 << 14;
}

/// TLB control commands in the VMCB Control Area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlbControlCommand {
    DoNothing = 0x00,
    FlushEntireTlb = 0x01,
    FlushGuestTlbEntries = 0x03,
    FlushGuestNonGlobalEntries = 0x07,
}

/// Nested Paging control flags in VMCB offset `0x090`.
pub mod np_control_flags {
    pub const NP_ENABLE: u64 = 1 << 0;
    pub const SEV_ENABLE: u64 = 1 << 1;
    pub const SEV_ES_ENABLE: u64 = 1 << 2;
    pub const GMH_ENABLE: u64 = 1 << 3;
}

/// AMD-V VMCB Control Area (first 1024 bytes of the 4 KiB VMCB page).
#[derive(Debug, Clone)]
pub struct VmcbControlArea {
    pub cr_read_intercepts: u16,
    pub cr_write_intercepts: u16,
    pub dr_read_intercepts: u16,
    pub dr_write_intercepts: u16,
    pub exception_intercepts: u32,
    pub general_intercepts_word1: u32,
    pub general_intercepts_word2: u32,
    pub pause_filter_threshold: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: TlbControlCommand,
    pub v_tpr: u8,
    pub v_irq: bool,
    pub v_intr_prio: u8,
    pub v_ign_tpr: bool,
    pub v_intr_masking: bool,
    pub v_intr_vector: u8,
    pub interrupt_shadow: bool,
    pub exit_code: u64,
    pub exit_info1: u64,
    pub exit_info2: u64,
    pub exit_int_info: u64,
    pub np_enable_flags: u64,
    pub avic_apic_bar: u64,
    pub ghcb_pa: u64,
    pub event_inj: u64,
    pub n_cr3: u64,
    pub lbr_virtualization_enable: bool,
    pub vmcb_clean_bits: u32,
    pub next_rip: u64,
}

impl VmcbControlArea {
    /// Creates a new VMCB Control Area with architectural mandatory `VMRUN` intercept set.
    pub fn new(guest_asid: u32) -> Self {
        Self {
            cr_read_intercepts: 0,
            cr_write_intercepts: 0,
            dr_read_intercepts: 0,
            dr_write_intercepts: 0,
            exception_intercepts: 0,
            general_intercepts_word1: svm_intercepts_word1::INTERCEPT_CPUID
                | svm_intercepts_word1::INTERCEPT_HLT
                | svm_intercepts_word1::INTERCEPT_IOIO_PROT
                | svm_intercepts_word1::INTERCEPT_MSR_PROT,
            general_intercepts_word2: svm_intercepts_word2::INTERCEPT_VMRUN
                | svm_intercepts_word2::INTERCEPT_VMMCALL,
            pause_filter_threshold: 0,
            pause_filter_count: 0,
            iopm_base_pa: 0,
            msrpm_base_pa: 0,
            tsc_offset: 0,
            guest_asid,
            tlb_control: TlbControlCommand::DoNothing,
            v_tpr: 0,
            v_irq: false,
            v_intr_prio: 0,
            v_ign_tpr: false,
            v_intr_masking: true,
            v_intr_vector: 0,
            interrupt_shadow: false,
            exit_code: 0,
            exit_info1: 0,
            exit_info2: 0,
            exit_int_info: 0,
            np_enable_flags: 0,
            avic_apic_bar: 0,
            ghcb_pa: 0,
            event_inj: 0,
            n_cr3: 0,
            lbr_virtualization_enable: false,
            vmcb_clean_bits: 0,
            next_rip: 0,
        }
    }

    /// Enables Nested Paging (`NP_ENABLE`) and binds the host Nested Page Table root physical address (`nCR3`).
    pub fn configure_nested_paging(&mut self, nested_cr3_pa: u64, enable_sev: bool) {
        self.n_cr3 = nested_cr3_pa & 0x000F_FFFF_FFFF_F000;
        self.np_enable_flags |= np_control_flags::NP_ENABLE;
        if enable_sev {
            self.np_enable_flags |= np_control_flags::SEV_ENABLE;
        }
        // Invalidate VMCB clean bit for Nested Paging (bit 4).
        self.vmcb_clean_bits &= !(1 << 4);
    }

    /// Enables or disables CR read and write intercepts for a specific control register index (`0..=15`).
    pub fn set_cr_intercept(&mut self, cr_index: u8, intercept_read: bool, intercept_write: bool) {
        if cr_index < 16 {
            let mask = 1u16 << cr_index;
            if intercept_read {
                self.cr_read_intercepts |= mask;
            } else {
                self.cr_read_intercepts &= !mask;
            }
            if intercept_write {
                self.cr_write_intercepts |= mask;
            } else {
                self.cr_write_intercepts &= !mask;
            }
            // Invalidate VMCB clean bit for Intercepts (bit 0).
            self.vmcb_clean_bits &= !(1 << 0);
        }
    }

    /// Validates that the VMCB control configuration satisfies AMD-V `VMRUN` consistency rules.
    pub fn validate_consistency(&self) -> Result<(), &'static str> {
        if (self.general_intercepts_word2 & svm_intercepts_word2::INTERCEPT_VMRUN) == 0 {
            return Err("VMRUN intercept must be enabled in VMCB");
        }
        if self.guest_asid == 0 {
            return Err("Guest ASID 0 is reserved for the host");
        }
        if (self.np_enable_flags & np_control_flags::NP_ENABLE) != 0 && self.n_cr3 == 0 {
            return Err("Nested Paging enabled with null nCR3 root");
        }
        Ok(())
    }
}

/// Segment descriptor register representation in the AMD-V VMCB State Save Area.
#[derive(Debug, Clone, Copy, Default)]
pub struct SvmSegmentRegister {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

/// AMD-V VMCB State Save Area (offset `0x400` in the VMCB page).
#[derive(Debug, Clone, Default)]
pub struct VmcbStateSaveArea {
    pub es: SvmSegmentRegister,
    pub cs: SvmSegmentRegister,
    pub ss: SvmSegmentRegister,
    pub ds: SvmSegmentRegister,
    pub fs: SvmSegmentRegister,
    pub gs: SvmSegmentRegister,
    pub gdtr: SvmSegmentRegister,
    pub ldtr: SvmSegmentRegister,
    pub idtr: SvmSegmentRegister,
    pub tr: SvmSegmentRegister,
    pub cpl: u8,
    pub efer: u64,
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub rsp: u64,
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
    pub g_pat: u64,
}

/// Decoded AMD-V `#VMEXIT` exit reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmExitCode {
    CrRead(u8),
    CrWrite(u8),
    DrRead(u8),
    DrWrite(u8),
    Exception(u8),
    PhysicalIntr,
    Nmi,
    Smi,
    Init,
    VirtualIntr,
    Cpuid,
    Hlt,
    Invlpg,
    Invlpga,
    Ioio {
        port: u16,
        is_in: bool,
        size_bytes: u8,
        is_string: bool,
        is_rep: bool,
    },
    Msr {
        is_write: bool,
    },
    Shutdown,
    Vmrun,
    Vmmcall,
    Vmload,
    Vmsave,
    NestedPageFault {
        fault_gpa: u64,
        error_code: u64,
        is_write: bool,
        is_user: bool,
        is_instruction_fetch: bool,
    },
    AvicIncompleteIpi,
    AvicNoAccel,
    VmexitInvalid,
    Unknown(u64),
}

impl SvmExitCode {
    /// Decodes a raw 64-bit VMCB `EXITCODE`, `EXITINFO1`, and `EXITINFO2`.
    pub fn decode(exit_code: u64, exit_info1: u64, exit_info2: u64) -> Self {
        match exit_code {
            0x00..=0x0F => Self::CrRead(exit_code as u8),
            0x10..=0x1F => Self::CrWrite((exit_code - 0x10) as u8),
            0x20..=0x2F => Self::DrRead((exit_code - 0x20) as u8),
            0x30..=0x3F => Self::DrWrite((exit_code - 0x30) as u8),
            0x40..=0x5F => Self::Exception((exit_code - 0x40) as u8),
            0x60 => Self::PhysicalIntr,
            0x61 => Self::Nmi,
            0x62 => Self::Smi,
            0x63 => Self::Init,
            0x64 => Self::VirtualIntr,
            0x72 => Self::Cpuid,
            0x78 => Self::Hlt,
            0x79 => Self::Invlpg,
            0x7A => Self::Invlpga,
            0x7B => {
                let is_in = (exit_info1 & (1 << 0)) != 0;
                let is_string = (exit_info1 & (1 << 2)) != 0;
                let is_rep = (exit_info1 & (1 << 3)) != 0;
                let size_bytes = if (exit_info1 & (1 << 4)) != 0 {
                    1
                } else if (exit_info1 & (1 << 5)) != 0 {
                    2
                } else if (exit_info1 & (1 << 6)) != 0 {
                    4
                } else {
                    1
                };
                let port = ((exit_info1 >> 16) & 0xFFFF) as u16;
                Self::Ioio {
                    port,
                    is_in,
                    size_bytes,
                    is_string,
                    is_rep,
                }
            }
            0x7C => Self::Msr {
                is_write: (exit_info1 & 1) != 0,
            },
            0x7F => Self::Shutdown,
            0x80 => Self::Vmrun,
            0x81 => Self::Vmmcall,
            0x82 => Self::Vmload,
            0x83 => Self::Vmsave,
            0x400 => Self::NestedPageFault {
                fault_gpa: exit_info2,
                error_code: exit_info1,
                is_write: (exit_info1 & (1 << 1)) != 0,
                is_user: (exit_info1 & (1 << 2)) != 0,
                is_instruction_fetch: (exit_info1 & (1 << 4)) != 0,
            },
            0x401 => Self::AvicIncompleteIpi,
            0x402 => Self::AvicNoAccel,
            0xFFFF_FFFF_FFFF_FFFF => Self::VmexitInvalid,
            other => Self::Unknown(other),
        }
    }
}

/// Hardware Address Space Identifier (`ASID`) allocator for AMD-V guests with generation-based TLB rollover.
#[derive(Debug, Clone)]
pub struct SvmAsidAllocator {
    max_asid: u32,
    next_asid: u32,
    generation: u64,
    active_bitmap: Vec<u64>,
}

impl SvmAsidAllocator {
    /// Creates an ASID allocator supporting hardware ASIDs in `1..=max_asid` (ASID 0 is reserved for host).
    pub fn new(max_asid: u32) -> Self {
        let clamped_max = max_asid.max(2);
        let words = ((clamped_max as usize) + 64) / 64;
        let mut active_bitmap = Vec::with_capacity(words);
        active_bitmap.resize(words, 0);
        // Reserve ASID 0 for host
        active_bitmap[0] |= 1;
        Self {
            max_asid: clamped_max,
            next_asid: 1,
            generation: 1,
            active_bitmap,
        }
    }

    /// Allocates an ASID and returns `(asid, generation, requires_global_tlb_flush)`.
    pub fn allocate_asid(&mut self) -> (u32, u64, bool) {
        for _ in 1..=self.max_asid {
            let candidate = self.next_asid;
            self.next_asid = if self.next_asid >= self.max_asid {
                1
            } else {
                self.next_asid + 1
            };

            let word_idx = (candidate / 64) as usize;
            let bit_idx = candidate % 64;
            if (self.active_bitmap[word_idx] & (1u64 << bit_idx)) == 0 {
                self.active_bitmap[word_idx] |= 1u64 << bit_idx;
                return (candidate, self.generation, false);
            }
        }

        // All ASIDs exhausted: bump generation, clear bitmap (except ASID 0), and request full TLB flush.
        for word in self.active_bitmap.iter_mut() {
            *word = 0;
        }
        self.active_bitmap[0] |= 1; // Keep ASID 0 reserved
        self.generation += 1;
        let assigned = 1;
        self.active_bitmap[0] |= 1 << assigned;
        self.next_asid = if self.max_asid >= 2 { 2 } else { 1 };
        (assigned, self.generation, true)
    }

    /// Releases a previously allocated ASID back to the pool.
    pub fn release_asid(&mut self, asid: u32) {
        if asid >= 1 && asid <= self.max_asid {
            let word_idx = (asid / 64) as usize;
            let bit_idx = asid % 64;
            self.active_bitmap[word_idx] &= !(1u64 << bit_idx);
        }
    }
}
