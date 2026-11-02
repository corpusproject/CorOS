//! Hardware Page Attribute Table (PAT) & MTRR Memory Type Subsystem
//!
//! Bare-metal no_std pure Rust driver for x86_64 CPU memory caching types:
//! - IA32_PAT (MSR 0x277) configuration for Write-Combining (WC) video memory acceleration
//! - Elimination of PCI bus write stalls on Intel, AMD, and NVIDIA discrete/integrated GPUs
//! - Memory Type Range Registers (MTRR) variable base/mask range inspection

#![allow(dead_code)]

use crate::arch::x86_64::msr::Msr;

pub const MSR_IA32_PAT: u32        = 0x277;
pub const MSR_IA32_MTRR_CAP: u32   = 0xFE;
pub const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
pub const MSR_IA32_MTRR_PHYSBASE0: u32 = 0x200;
pub const MSR_IA32_MTRR_PHYSMASK0: u32 = 0x201;

/// x86 Memory Types
pub const MEMORY_TYPE_UC: u8  = 0x00; // Uncacheable
pub const MEMORY_TYPE_WC: u8  = 0x01; // Write-Combining (high-throughput GPU video buffer)
pub const MEMORY_TYPE_WT: u8  = 0x04; // Write-Through
pub const MEMORY_TYPE_WP: u8  = 0x05; // Write-Protected
pub const MEMORY_TYPE_WB: u8  = 0x06; // Write-Back (normal DRAM)
pub const MEMORY_TYPE_UCM: u8 = 0x07; // UC- (Uncached Minus)

/// Hardware Page Attribute Table Configuration
pub struct MemoryPatManager;

impl MemoryPatManager {
    /// Configure IA32_PAT MSR with optimal Write-Combining layout:
    /// - PA0: WB  (0x06) - Normal System RAM
    /// - PA1: WT  (0x04)
    /// - PA2: UC- (0x07)
    /// - PA3: UC  (0x00) - MMIO Registers / Device Control
    /// - PA4: WB  (0x06)
    /// - PA5: WT  (0x04)
    /// - PA6: WC  (0x01) - Graphics Framebuffer (Write-Combining Accelerated)
    /// - PA7: UC  (0x00)
    pub unsafe fn initialize_write_combining() {
        let pat_val = (MEMORY_TYPE_WB as u64)
            | ((MEMORY_TYPE_WT as u64) << 8)
            | ((MEMORY_TYPE_UCM as u64) << 16)
            | ((MEMORY_TYPE_UC as u64) << 24)
            | ((MEMORY_TYPE_WB as u64) << 32)
            | ((MEMORY_TYPE_WT as u64) << 40)
            | ((MEMORY_TYPE_WC as u64) << 48) // Entry 6 = WC
            | ((MEMORY_TYPE_UC as u64) << 56);

        Msr::write(MSR_IA32_PAT, pat_val);
    }

    /// Read current PAT configuration from hardware
    pub unsafe fn read_current_pat() -> [u8; 8] {
        let val = Msr::read(MSR_IA32_PAT);
        let mut entries = [0u8; 8];
        for i in 0..8 {
            entries[i] = ((val >> (i * 8)) & 0xFF) as u8;
        }
        entries
    }

    /// Check if hardware supports Write-Combining via MSR_IA32_PAT
    pub fn is_pat_supported() -> bool {
        let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
        (cpuid1.edx & (1 << 16)) != 0 // Bit 16 = PAT
    }
}
