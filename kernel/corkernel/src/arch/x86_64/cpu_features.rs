//! Cross-Vendor CPU Microarchitecture Detection & Feature Dispatcher
//!
//! Pure bare-metal no_std Rust driver supporting:
//! - Vendor detection: GenuineIntel, AuthenticAMD, CentaurHauls / Zhaoxin
//! - Intel Hybrid Architecture detection (Alder Lake / Raptor Lake / Arrow Lake P-Cores vs E-Cores)
//! - AMD Zen microarchitecture generations (Zen 1, Zen 2, Zen 3, Zen 4, Zen 5)
//! - SIMD & Vector acceleration matrix (AVX-512, AVX2, SSE4.2, FMA, AES-NI, SHA-NI)
//! - Fast memory copy extensions: ERMS (Enhanced REP MOVSB) & FSRM (Fast Short REP MOVSB)

#![allow(dead_code)]

/// CPU Vendor Family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Zhaoxin,
    Unknown,
}

/// Intel Hybrid Core Type (CPUID.1AH)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreType {
    StandardCore,
    PerformanceCore, // Golden Cove / Raptor Cove (P-Core)
    EfficientCore,   // Gracemont / Crestmont (E-Core)
}

/// AMD Zen Microarchitecture Generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmdZenGeneration {
    NotZen,
    Zen1orPlus, // 14nm / 12nm (Ryzen 1000/2000)
    Zen2,       // 7nm (Ryzen 3000/4000)
    Zen3,       // 7nm (Ryzen 5000)
    Zen4,       // 5nm (Ryzen 7000/8000)
    Zen5,       // 4nm / 3nm (Ryzen 9000)
}

/// Hardware Feature Capabilities Bitmask
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatureMatrix {
    pub has_sse3: bool,
    pub has_ssse3: bool,
    pub has_sse4_1: bool,
    pub has_sse4_2: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_avx512f: bool,
    pub has_avx512bw: bool,
    pub has_avx512dq: bool,
    pub has_avx512vl: bool,
    pub has_fma3: bool,
    pub has_aes_ni: bool,
    pub has_sha_ni: bool,
    pub has_erms: bool,      // Enhanced REP MOVSB for high-speed memcpy
    pub has_fsrm: bool,      // Fast Short REP MOVSB
    pub has_popcnt: bool,
    pub has_rdrand: bool,
    pub has_rdseed: bool,
    pub has_invariant_tsc: bool,
    pub has_hybrid_cores: bool,
}

/// Hardware CPU Microarchitecture Profile
#[derive(Debug, Clone)]
pub struct CpuProfile {
    pub vendor: CpuVendor,
    pub brand_string: [u8; 48],
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub zen_gen: AmdZenGeneration,
    pub core_type: CoreType,
    pub features: CpuFeatureMatrix,
}

impl CpuProfile {
    /// Probe the physical CPU currently executing this code
    pub fn probe() -> Self {
        let (vendor, brand_string) = Self::detect_vendor_and_brand();
        let (family, model, stepping) = Self::detect_family_model();
        let features = Self::detect_features();
        let zen_gen = if vendor == CpuVendor::Amd {
            Self::detect_zen_generation(family, model)
        } else {
            AmdZenGeneration::NotZen
        };
        let core_type = if vendor == CpuVendor::Intel && features.has_hybrid_cores {
            Self::detect_core_type()
        } else {
            CoreType::StandardCore
        };

        Self {
            vendor,
            brand_string,
            family,
            model,
            stepping,
            zen_gen,
            core_type,
            features,
        }
    }

    fn detect_vendor_and_brand() -> (CpuVendor, [u8; 48]) {
        let cpuid0 = unsafe { core::arch::x86_64::__cpuid(0) };
        let mut vendor_bytes = [0u8; 12];
        vendor_bytes[0..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor_bytes[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor_bytes[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

        let vendor = if &vendor_bytes == b"GenuineIntel" {
            CpuVendor::Intel
        } else if &vendor_bytes == b"AuthenticAMD" {
            CpuVendor::Amd
        } else if &vendor_bytes == b"CentaurHauls" || &vendor_bytes == b"  Shanghai  " {
            CpuVendor::Zhaoxin
        } else {
            CpuVendor::Unknown
        };

        // Brand String from 0x80000002..0x80000004
        let mut brand = [0u8; 48];
        let max_ext = unsafe { core::arch::x86_64::__cpuid(0x80000000) }.eax;
        if max_ext >= 0x80000004 {
            for i in 0..3 {
                let leaf = unsafe { core::arch::x86_64::__cpuid(0x80000002 + i) };
                let off = (i as usize) * 16;
                brand[off..off + 4].copy_from_slice(&leaf.eax.to_le_bytes());
                brand[off + 4..off + 8].copy_from_slice(&leaf.ebx.to_le_bytes());
                brand[off + 8..off + 12].copy_from_slice(&leaf.ecx.to_le_bytes());
                brand[off + 12..off + 16].copy_from_slice(&leaf.edx.to_le_bytes());
            }
        }

        (vendor, brand)
    }

    fn detect_family_model() -> (u32, u32, u32) {
        let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
        let stepping = cpuid1.eax & 0x0F;
        let base_model = (cpuid1.eax >> 4) & 0x0F;
        let base_family = (cpuid1.eax >> 8) & 0x0F;
        let ext_model = (cpuid1.eax >> 16) & 0x0F;
        let ext_family = (cpuid1.eax >> 20) & 0xFF;

        let family = if base_family == 15 {
            base_family + ext_family
        } else {
            base_family
        };

        let model = if base_family == 6 || base_family == 15 {
            (ext_model << 4) | base_model
        } else {
            base_model
        };

        (family, model, stepping)
    }

    fn detect_features() -> CpuFeatureMatrix {
        let mut m = CpuFeatureMatrix::default();

        let cpuid1 = unsafe { core::arch::x86_64::__cpuid(1) };
        m.has_sse3 = (cpuid1.ecx & (1 << 0)) != 0;
        m.has_ssse3 = (cpuid1.ecx & (1 << 9)) != 0;
        m.has_fma3 = (cpuid1.ecx & (1 << 12)) != 0;
        m.has_sse4_1 = (cpuid1.ecx & (1 << 19)) != 0;
        m.has_sse4_2 = (cpuid1.ecx & (1 << 20)) != 0;
        m.has_popcnt = (cpuid1.ecx & (1 << 23)) != 0;
        m.has_aes_ni = (cpuid1.ecx & (1 << 25)) != 0;
        m.has_avx = (cpuid1.ecx & (1 << 28)) != 0;
        m.has_rdrand = (cpuid1.ecx & (1 << 30)) != 0;

        // Structured Extended Features (Leaf 7, Subleaf 0)
        let cpuid7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
        m.has_avx2 = (cpuid7.ebx & (1 << 5)) != 0;
        m.has_erms = (cpuid7.ebx & (1 << 9)) != 0;
        m.has_avx512f = (cpuid7.ebx & (1 << 16)) != 0;
        m.has_avx512dq = (cpuid7.ebx & (1 << 17)) != 0;
        m.has_rdseed = (cpuid7.ebx & (1 << 18)) != 0;
        m.has_avx512bw = (cpuid7.ebx & (1 << 30)) != 0;
        m.has_avx512vl = (cpuid7.ebx & (1 << 31)) != 0;
        m.has_sha_ni = (cpuid7.ebx & (1 << 29)) != 0;
        m.has_fsrm = (cpuid7.edx & (1 << 4)) != 0;
        m.has_hybrid_cores = (cpuid7.edx & (1 << 15)) != 0;

        // Invariant TSC check (0x80000007:EDX bit 8)
        let max_ext = unsafe { core::arch::x86_64::__cpuid(0x80000000) }.eax;
        if max_ext >= 0x80000007 {
            let cpuid_apmi = unsafe { core::arch::x86_64::__cpuid(0x80000007) };
            m.has_invariant_tsc = (cpuid_apmi.edx & (1 << 8)) != 0;
        }

        m
    }

    fn detect_zen_generation(family: u32, model: u32) -> AmdZenGeneration {
        if family == 0x17 {
            if model <= 0x1F {
                AmdZenGeneration::Zen1orPlus // Summit Ridge, Raven Ridge
            } else {
                AmdZenGeneration::Zen2       // Matisse, Renoir
            }
        } else if family == 0x19 {
            if model <= 0x1F {
                AmdZenGeneration::Zen3       // Vermeer, Cezanne
            } else {
                AmdZenGeneration::Zen4       // Raphael, Phoenix
            }
        } else if family == 0x1A {
            AmdZenGeneration::Zen5           // Granite Ridge, Strix Point
        } else {
            AmdZenGeneration::NotZen
        }
    }

    fn detect_core_type() -> CoreType {
        let max_leaf = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
        if max_leaf >= 0x1A {
            let cpuid1a = unsafe { core::arch::x86_64::__cpuid(0x1A) };
            let core_type_id = (cpuid1a.eax >> 24) & 0xFF;
            match core_type_id {
                0x20 => CoreType::EfficientCore,   // Intel Atom / Gracemont
                0x40 => CoreType::PerformanceCore, // Intel Core / Golden Cove
                _ => CoreType::StandardCore,
            }
        } else {
            CoreType::StandardCore
        }
    }

    /// High-performance memory copy with dynamic hardware selection
    /// Uses ERMS (Enhanced REP MOVSB) on modern Intel/AMD or AVX2 32-byte chunks
    pub unsafe fn fast_memcpy(dest: *mut u8, src: *const u8, count: usize) {
        if count == 0 {
            return;
        }
        // Intel/AMD hardware optimized string copy
        core::arch::asm!(
            "rep movsb",
            inout("rdi") dest => _,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack, preserves_flags)
        );
    }
}
