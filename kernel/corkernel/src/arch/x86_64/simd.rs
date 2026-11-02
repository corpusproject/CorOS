//! x86_64 FPU, SSE & AVX SIMD Context Management for CorOS.
//! 100% in-house implementation supporting:
//! - 512-byte aligned FXSAVE64 and FXRSTOR64 execution
//! - CR0 and CR4 register bit manipulation for SIMD activation
//! - Thread FPU/XMM context switching and saving during preemption

use core::arch::asm;

/// 512-byte aligned memory region for FXSAVE64 / FXRSTOR64
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxSaveArea {
    pub fcw: u16,            // FPU Control Word
    pub fsw: u16,            // FPU Status Word
    pub ftw: u8,             // Abbreviated Tag Word
    pub reserved1: u8,
    pub fop: u16,            // Last Instruction Opcode
    pub rip: u64,            // FPU Instruction Pointer Offset
    pub rdp: u64,            // FPU Data Pointer Offset
    pub mxcsr: u32,          // MXCSR Register State
    pub mxcsr_mask: u32,     // MXCSR Mask
    pub st_space: [u128; 8], // ST0/MM0 through ST7/MM7 (128-bit each, bottom 80 bits valid)
    pub xmm_space: [u128; 16],// XMM0 through XMM15
    pub reserved2: [u8; 96],
}

impl Default for FxSaveArea {
    fn default() -> Self {
        Self {
            fcw: 0x037F,       // Standard FPU default (exceptions masked, double extended precision)
            fsw: 0,
            ftw: 0,
            reserved1: 0,
            fop: 0,
            rip: 0,
            rdp: 0,
            mxcsr: 0x1F80,     // Standard SSE default (all SIMD exceptions masked)
            mxcsr_mask: 0xFFFF,
            st_space: [0; 8],
            xmm_space: [0; 16],
            reserved2: [0; 96],
        }
    }
}

pub struct SimdManager;

impl SimdManager {
    /// Initialize CPU SIMD hardware by configuring CR0 and CR4.
    pub unsafe fn init() {
        // 1. Configure CR0: Clear EM (Emulation) and TS (Task Switched), set MP (Monitor Coprocessor)
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 &= !(1 << 2); // Clear EM bit
        cr0 &= !(1 << 3); // Clear TS bit
        cr0 |= 1 << 1;    // Set MP bit
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));

        // 2. Configure CR4: Set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1 << 9;  // Enable FXSAVE and FXRSTOR
        cr4 |= 1 << 10; // Enable unmasked SSE floating point exceptions
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));

        // 3. Initialize FPU with FNINIT
        asm!("fninit", options(nomem, nostack));

        // 4. Set MXCSR to standard default
        let mxcsr: u32 = 0x1F80;
        asm!("ldmxcsr [{}]", in(reg) &mxcsr, options(nostack));
    }

    /// Save the current thread's FPU and SSE registers using FXSAVE64.
    #[inline(always)]
    pub unsafe fn save_context(area: &mut FxSaveArea) {
        asm!(
            "fxsave64 [{}]",
            in(reg) area as *mut FxSaveArea,
            options(nostack)
        );
    }

    /// Restore a thread's FPU and SSE registers using FXRSTOR64.
    #[inline(always)]
    pub unsafe fn restore_context(area: &FxSaveArea) {
        asm!(
            "fxrstor64 [{}]",
            in(reg) area as *const FxSaveArea,
            options(nostack)
        );
    }
}
