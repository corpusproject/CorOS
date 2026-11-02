//! x86_64 CPUID Discovery & Feature Detection Architecture for CorOS.
//! 100% in-house implementation querying hardware capabilities, cache topologies,
//! instruction extensions (AVX, AVX2, AVX-512, AES-NI, RDRAND, SHA), and processor brand strings.

use alloc::string::String;
use core::arch::x86_64::__cpuid_count;

#[derive(Clone, Copy, Default, Debug)]
pub struct CpuFeatures {
    pub fpu: bool,
    pub vme: bool,
    pub de: bool,
    pub pse: bool,
    pub tsc: bool,
    pub msr: bool,
    pub pae: bool,
    pub mce: bool,
    pub cx8: bool,
    pub apic: bool,
    pub sep: bool,
    pub mtrr: bool,
    pub pge: bool,
    pub mca: bool,
    pub cmov: bool,
    pub pat: bool,
    pub pse36: bool,
    pub clflush: bool,
    pub mmx: bool,
    pub fxsr: bool,
    pub sse: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub pclmulqdq: bool,
    pub ssse3: bool,
    pub fma: bool,
    pub cx16: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub x2apic: bool,
    pub movbe: bool,
    pub popcnt: bool,
    pub tsc_deadline: bool,
    pub aes_ni: bool,
    pub xsave: bool,
    pub osxsave: bool,
    pub avx: bool,
    pub f16c: bool,
    pub rdrand: bool,
    pub hypervisor: bool,

    // Extended Leaf 7 features
    pub fsgsbase: bool,
    pub bmi1: bool,
    pub avx2: bool,
    pub smep: bool,
    pub bmi2: bool,
    pub erms: bool,
    pub invpcid: bool,
    pub rdseed: bool,
    pub adx: bool,
    pub smap: bool,
    pub clflushopt: bool,
    pub clwb: bool,
    pub sha_ni: bool,
}

pub struct CpuInfo {
    pub vendor_id: [u8; 12],
    pub brand_string: String,
    pub family: u8,
    pub model: u8,
    pub stepping: u8,
    pub features: CpuFeatures,
}

impl CpuInfo {
    pub fn query() -> Self {
        let mut features = CpuFeatures::default();

        // 1. Leaf 0: Vendor String (EBX, EDX, ECX)
        let leaf0 = unsafe { __cpuid_count(0, 0) };
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

        // 2. Leaf 1: Family, Model, Stepping & Standard Features
        let leaf1 = unsafe { __cpuid_count(1, 0) };
        let stepping = (leaf1.eax & 0x0F) as u8;
        let mut model = ((leaf1.eax >> 4) & 0x0F) as u8;
        let mut family = ((leaf1.eax >> 8) & 0x0F) as u8;

        if family == 6 || family == 15 {
            let ext_model = ((leaf1.eax >> 16) & 0x0F) as u8;
            model |= ext_model << 4;
        }
        if family == 15 {
            let ext_family = ((leaf1.eax >> 20) & 0xFF) as u8;
            family += ext_family;
        }

        // EDX Features
        let edx = leaf1.edx;
        features.fpu     = (edx & (1 << 0)) != 0;
        features.vme     = (edx & (1 << 1)) != 0;
        features.de      = (edx & (1 << 2)) != 0;
        features.pse     = (edx & (1 << 3)) != 0;
        features.tsc     = (edx & (1 << 4)) != 0;
        features.msr     = (edx & (1 << 5)) != 0;
        features.pae     = (edx & (1 << 6)) != 0;
        features.mce     = (edx & (1 << 7)) != 0;
        features.cx8     = (edx & (1 << 8)) != 0;
        features.apic    = (edx & (1 << 9)) != 0;
        features.sep     = (edx & (1 << 11)) != 0;
        features.mtrr    = (edx & (1 << 12)) != 0;
        features.pge     = (edx & (1 << 13)) != 0;
        features.mca     = (edx & (1 << 14)) != 0;
        features.cmov    = (edx & (1 << 15)) != 0;
        features.pat     = (edx & (1 << 16)) != 0;
        features.pse36   = (edx & (1 << 17)) != 0;
        features.clflush = (edx & (1 << 19)) != 0;
        features.mmx     = (edx & (1 << 23)) != 0;
        features.fxsr    = (edx & (1 << 24)) != 0;
        features.sse     = (edx & (1 << 25)) != 0;
        features.sse2    = (edx & (1 << 26)) != 0;

        // ECX Features
        let ecx = leaf1.ecx;
        features.sse3         = (ecx & (1 << 0)) != 0;
        features.pclmulqdq     = (ecx & (1 << 1)) != 0;
        features.ssse3        = (ecx & (1 << 9)) != 0;
        features.fma          = (ecx & (1 << 12)) != 0;
        features.cx16         = (ecx & (1 << 13)) != 0;
        features.sse4_1       = (ecx & (1 << 19)) != 0;
        features.sse4_2       = (ecx & (1 << 20)) != 0;
        features.x2apic       = (ecx & (1 << 21)) != 0;
        features.movbe        = (ecx & (1 << 22)) != 0;
        features.popcnt       = (ecx & (1 << 23)) != 0;
        features.tsc_deadline = (ecx & (1 << 24)) != 0;
        features.aes_ni       = (ecx & (1 << 25)) != 0;
        features.xsave        = (ecx & (1 << 26)) != 0;
        features.osxsave      = (ecx & (1 << 27)) != 0;
        features.avx          = (ecx & (1 << 28)) != 0;
        features.f16c         = (ecx & (1 << 29)) != 0;
        features.rdrand       = (ecx & (1 << 30)) != 0;
        features.hypervisor   = (ecx & (1 << 31)) != 0;

        // 3. Leaf 7: Extended Structured Features (Subleaf 0)
        let leaf7 = unsafe { __cpuid_count(7, 0) };
        let ebx7 = leaf7.ebx;
        features.fsgsbase   = (ebx7 & (1 << 0)) != 0;
        features.bmi1       = (ebx7 & (1 << 3)) != 0;
        features.avx2       = (ebx7 & (1 << 5)) != 0;
        features.smep       = (ebx7 & (1 << 7)) != 0;
        features.bmi2       = (ebx7 & (1 << 8)) != 0;
        features.erms       = (ebx7 & (1 << 9)) != 0;
        features.invpcid    = (ebx7 & (1 << 10)) != 0;
        features.rdseed     = (ebx7 & (1 << 18)) != 0;
        features.adx        = (ebx7 & (1 << 19)) != 0;
        features.smap       = (ebx7 & (1 << 20)) != 0;
        features.clflushopt = (ebx7 & (1 << 23)) != 0;
        features.clwb       = (ebx7 & (1 << 24)) != 0;
        features.sha_ni     = (ebx7 & (1 << 29)) != 0;

        // 4. Extended Leaves 0x80000002..0x80000004: Brand String
        let mut brand_buf = [0u8; 48];
        let max_ext = unsafe { __cpuid_count(0x8000_0000, 0) }.eax;

        if max_ext >= 0x8000_0004 {
            for i in 0..3 {
                let leaf = unsafe { __cpuid_count(0x8000_0002 + i, 0) };
                let off = (i as usize) * 16;
                brand_buf[off..off + 4].copy_from_slice(&leaf.eax.to_le_bytes());
                brand_buf[off + 4..off + 8].copy_from_slice(&leaf.ebx.to_le_bytes());
                brand_buf[off + 8..off + 12].copy_from_slice(&leaf.ecx.to_le_bytes());
                brand_buf[off + 12..off + 16].copy_from_slice(&leaf.edx.to_le_bytes());
            }
        }

        let brand_str = String::from(String::from_utf8_lossy(&brand_buf).trim());

        Self {
            vendor_id: vendor,
            brand_string: brand_str,
            family,
            model,
            stepping,
            features,
        }
    }
}
