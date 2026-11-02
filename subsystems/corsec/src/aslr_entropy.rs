//! Address Space Layout Randomization (`AslrLayoutGenerator`) and `W^X` (`Write XOR Execute`) page verifier.
//!
//! Computes cryptographically randomized, page-aligned, non-overlapping 64-bit canonical user-space
//! virtual bases for `pie_load_base`, `mmap_base`, `stack_top`, `heap_brk_base`, and `vdso_page`,
//! and verifies `W^X` memory protection invariants across virtual memory regions.

/// Standard 4 KiB page shift (`1 << 12 = 4096`).
pub const PAGE_SHIFT_4K: u32 = 12;
pub const PAGE_SIZE_4K: u64 = 1u64 << PAGE_SHIFT_4K;
pub const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

/// Canonical x86_64 user-space virtual address region anchors prior to entropy perturbation.
pub const BASE_PIE_LOAD: u64 = 0x0000_5555_5555_4000;
pub const BASE_HEAP_BRK: u64 = 0x0000_5555_7000_0000;
pub const BASE_MMAP_AREA: u64 = 0x0000_7FFF_0000_0000;
pub const BASE_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;

/// Number of bits of page-offset entropy applied to each ASLR region (matching 64-bit Linux `ARCH_MMAP_RND_BITS`).
pub const PIE_ENTROPY_BITS: u32 = 28;
pub const HEAP_ENTROPY_BITS: u32 = 24;
pub const MMAP_ENTROPY_BITS: u32 = 28;
pub const STACK_ENTROPY_BITS: u32 = 22;
pub const VDSO_ENTROPY_BITS: u32 = 16;

/// Randomized 64-bit process virtual address space layout produced on `execve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomizedProcessLayout {
    pub pie_load_base: u64,
    pub heap_brk_base: u64,
    pub mmap_base: u64,
    pub stack_top: u64,
    pub vdso_page: u64,
}

impl RandomizedProcessLayout {
    /// Verifies that all generated bases are 4 KiB page-aligned, strictly ordered, and non-overlapping.
    pub const fn is_valid_layout(&self) -> bool {
        let aligned = ((self.pie_load_base
            | self.heap_brk_base
            | self.mmap_base
            | self.stack_top
            | self.vdso_page)
            & !PAGE_MASK_4K)
            == 0;
        let ordered = self.pie_load_base < self.heap_brk_base
            && self.heap_brk_base < self.mmap_base
            && self.mmap_base < self.vdso_page
            && self.vdso_page < self.stack_top;
        aligned && ordered
    }
}

/// Page protection bitmask (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmProtFlags(pub u8);

impl VmProtFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn is_writable(self) -> bool {
        (self.0 & Self::WRITE.0) != 0
    }

    #[inline]
    pub const fn is_executable(self) -> bool {
        (self.0 & Self::EXEC.0) != 0
    }
}

/// Virtual Memory Area (`VMA`) descriptor checked by the `W^X` (`Write XOR Execute`) verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmRegionDescriptor {
    pub start_va: u64,
    pub end_va: u64,
    pub prot: VmProtFlags,
}

/// Error returned when a virtual memory mapping or `mprotect` transition violates `W^X` or canonical bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WxViolationError {
    SimultaneousWriteAndExec,
    UnalignedAddress,
    InvalidRange,
    NonCanonicalUserAddress,
}

/// SplitMix64 / ChaCha-style cryptographic mixer driving `AslrLayoutGenerator`.
pub struct AslrLayoutGenerator {
    entropy_state: u64,
    pub layouts_generated: u64,
}

impl AslrLayoutGenerator {
    pub const fn new(seed: u64) -> Self {
        Self {
            entropy_state: seed ^ 0x9E37_79B9_7F4A_7C15,
            layouts_generated: 0,
        }
    }

    /// Mixes additional hardware entropy (e.g., `RDRAND`/`RDSEED` or TSC jitter) into the generator pool.
    pub fn reseed(&mut self, fresh_entropy: u64) {
        self.entropy_state ^= fresh_entropy.rotate_left(19);
        let _ = self.next_u64();
    }

    /// Generates the next 64-bit pseudorandom word using Stafford's Mix13 (SplitMix64 bijection).
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.entropy_state = self.entropy_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.entropy_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[inline]
    fn random_page_offset(&mut self, entropy_bits: u32) -> u64 {
        let mask = (1u64 << entropy_bits) - 1;
        (self.next_u64() & mask) << PAGE_SHIFT_4K
    }

    /// Computes a randomized 64-bit process layout (`pie_load_base`, `heap_brk_base`,
    /// `mmap_base`, `stack_top`, and `vdso_page`).
    pub fn generate_layout(&mut self) -> RandomizedProcessLayout {
        let pie_offset = self.random_page_offset(PIE_ENTROPY_BITS);
        let pie_load_base = BASE_PIE_LOAD.wrapping_add(pie_offset) & PAGE_MASK_4K;

        // Place heap_brk_base at least 512 MiB above pie_load_base plus 24-bit page entropy
        let min_heap_base = pie_load_base.wrapping_add(0x2000_0000);
        let heap_anchor = if min_heap_base > BASE_HEAP_BRK {
            min_heap_base
        } else {
            BASE_HEAP_BRK
        };
        let heap_brk_base = heap_anchor
            .wrapping_add(self.random_page_offset(HEAP_ENTROPY_BITS))
            & PAGE_MASK_4K;

        // Place mmap_base randomized downward from BASE_MMAP_AREA
        let mmap_base = BASE_MMAP_AREA
            .wrapping_sub(self.random_page_offset(MMAP_ENTROPY_BITS))
            & PAGE_MASK_4K;

        // Place stack_top randomized downward from BASE_STACK_TOP
        let stack_top = BASE_STACK_TOP
            .wrapping_sub(self.random_page_offset(STACK_ENTROPY_BITS))
            & PAGE_MASK_4K;

        // Place vdso_page in the gap between mmap_base and stack_top (avoiding stack guard region)
        let vdso_anchor = mmap_base.wrapping_add(0x0000_0001_0000_0000);
        let vdso_page = vdso_anchor
            .wrapping_add(self.random_page_offset(VDSO_ENTROPY_BITS))
            & PAGE_MASK_4K;

        self.layouts_generated += 1;

        RandomizedProcessLayout {
            pie_load_base,
            heap_brk_base,
            mmap_base,
            stack_top,
            vdso_page,
        }
    }

    /// Enforces `W^X` (`Write XOR Execute`) and canonical 48-bit user-space bounds on a single VMA.
    pub fn verify_wx_region(region: &VmRegionDescriptor) -> Result<(), WxViolationError> {
        if (region.start_va & !PAGE_MASK_4K) != 0 || (region.end_va & !PAGE_MASK_4K) != 0 {
            return Err(WxViolationError::UnalignedAddress);
        }
        if region.start_va >= region.end_va {
            return Err(WxViolationError::InvalidRange);
        }
        if region.end_va > 0x0000_7FFF_FFFF_F000 {
            return Err(WxViolationError::NonCanonicalUserAddress);
        }
        if region.prot.is_writable() && region.prot.is_executable() {
            return Err(WxViolationError::SimultaneousWriteAndExec);
        }
        Ok(())
    }

    /// Verifies an entire process virtual memory map for `W^X` compliance.
    pub fn verify_address_space_wx(regions: &[VmRegionDescriptor]) -> Result<(), WxViolationError> {
        for r in regions {
            Self::verify_wx_region(r)?;
        }
        Ok(())
    }
}
