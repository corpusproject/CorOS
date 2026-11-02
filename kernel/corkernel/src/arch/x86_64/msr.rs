//! x86_64 Model Specific Registers (MSR) Architecture for CorOS.
//! 100% in-house implementation supporting RDMSR/WRMSR instructions,
//! hardware performance profiling, temperature monitoring, and system call configuration.

use core::arch::asm;

// Standard Architecture MSRs
pub const IA32_APIC_BASE: u32        = 0x0000_001B;
pub const IA32_PERF_STATUS: u32      = 0x0000_0198;
pub const IA32_THERM_STATUS: u32     = 0x0000_019C;
pub const IA32_SYSENTER_CS: u32      = 0x0000_0174;
pub const IA32_SYSENTER_ESP: u32     = 0x0000_0175;
pub const IA32_SYSENTER_EIP: u32     = 0x0000_0176;
pub const IA32_PAT: u32              = 0x0000_0277;
pub const IA32_TSC_DEADLINE: u32     = 0x0000_06E0;

// Long Mode & Syscall MSRs
pub const IA32_EFER: u32             = 0xC000_0080;
pub const IA32_STAR: u32             = 0xC000_0081;
pub const IA32_LSTAR: u32            = 0xC000_0082;
pub const IA32_CSTAR: u32            = 0xC000_0083;
pub const IA32_FMASK: u32            = 0xC000_0084;
pub const IA32_FS_BASE: u32          = 0xC000_0100;
pub const IA32_GS_BASE: u32          = 0xC000_0101;
pub const IA32_KERNEL_GS_BASE: u32   = 0xC000_0102;
pub const IA32_TSC_AUX: u32          = 0xC000_0103;

// EFER Bit Flags
pub const EFER_SCE: u64              = 1 << 0;  // System Call Extensions (SYSCALL/SYSRET)
pub const EFER_LME: u64              = 1 << 8;  // Long Mode Enable
pub const EFER_LMA: u64              = 1 << 10; // Long Mode Active
pub const EFER_NXE: u64              = 1 << 11; // No-Execute Enable (DEP)
pub const EFER_SVME: u64             = 1 << 12; // Secure Virtual Machine (AMD SVM)
pub const EFER_FFXSR: u64            = 1 << 14; // Fast FXSAVE/FXRSTOR

pub struct Msr;

impl Msr {
    /// Read a 64-bit value from an MSR using the RDMSR instruction.
    #[inline(always)]
    pub unsafe fn read(msr: u32) -> u64 {
        let low: u32;
        let high: u32;
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
        ((high as u64) << 32) | (low as u64)
    }

    /// Write a 64-bit value to an MSR using the WRMSR instruction.
    #[inline(always)]
    pub unsafe fn write(msr: u32, value: u64) {
        let low = (value & 0xFFFF_FFFF) as u32;
        let high = (value >> 32) as u32;
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }

    /// Read CPU core temperature relative to TjMax (in degrees Celsius).
    pub unsafe fn read_temperature_celsius() -> Option<u32> {
        let therm = Self::read(IA32_THERM_STATUS);
        if (therm & (1 << 31)) != 0 {
            // Valid bit is set
            let delta = ((therm >> 16) & 0x7F) as u32;
            let tj_max = 100u32; // Standard 100C junction max
            Some(tj_max.saturating_sub(delta))
        } else {
            None
        }
    }

    /// Configure userland Fast System Call interface (SYSCALL / SYSRET).
    pub unsafe fn setup_syscall_lstar(kernel_syscall_handler: usize, cs_selector: u16, ss_selector: u16) {
        // 1. Enable SCE bit in EFER
        let efer = Self::read(IA32_EFER);
        Self::write(IA32_EFER, efer | EFER_SCE | EFER_NXE);

        // 2. Program LSTAR with 64-bit rip of syscall entrypoint
        Self::write(IA32_LSTAR, kernel_syscall_handler as u64);

        // 3. Program STAR: User CS/SS in bits 63:48, Kernel CS/SS in bits 47:32
        let star = ((cs_selector as u64) << 32) | (((ss_selector as u64) + 8) << 48);
        Self::write(IA32_STAR, star);

        // 4. Program FMASK to clear RFLAGS bits on syscall entry (e.g. IF, TF, DF, AC)
        let rflags_mask = 0x0000_4700u64; // Mask IF (bit 9), DF (bit 10), TF (bit 8), AC (bit 18)
        Self::write(IA32_FMASK, rflags_mask);
    }
}
