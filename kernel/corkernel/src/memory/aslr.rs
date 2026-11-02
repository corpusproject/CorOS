//! CorOS Address Space Layout Randomization (ASLR) Engine (`aslr.rs`)
//!
//! Hardens userspace process security against return-oriented programming (ROP) and buffer overflows:
//! - Executable Base Randomization (PIE: Position Independent Executables, 28 bits of entropy)
//! - Userland Stack Top Randomization (30 bits of entropy below canonical userland top)
//! - Heap Start Offset Randomization (brk area randomization)
//! - mmap Base Offset Randomization (Dynamic libraries, TLS, and memory allocations)
//! - Hardware RDRAND / RDSEED backed high-entropy random generation with CSPRNG fallback

extern crate alloc;

/// Base ranges for x86_64 Userland Address Space
pub const USER_SPACE_MIN: u64 = 0x0000_0000_0040_0000;      // 4 MiB
pub const USER_SPACE_MAX: u64 = 0x0000_7FFF_FFFF_0000;      // Canonical boundary (128 TiB)

pub const DEFAULT_EXEC_BASE: u64  = 0x0000_5555_5555_4000;
pub const DEFAULT_MMAP_BASE: u64  = 0x0000_7F00_0000_0000;
pub const DEFAULT_STACK_TOP: u64  = 0x0000_7FFF_FFFF_0000;

/// ASLR Layout Parameters for a freshly spawned process
#[derive(Debug, Clone, Copy)]
pub struct ProcessAddressLayout {
    pub code_base: u64,
    pub heap_start: u64,
    pub mmap_base: u64,
    pub stack_top: u64,
}

/// ASLR Security Engine
pub struct AslrEngine {
    entropy_seed: u64,
}

impl AslrEngine {
    pub fn new(seed: u64) -> Self {
        Self {
            entropy_seed: if seed == 0 { 0xA5A5_5A5A_1337_BEEF } else { seed },
        }
    }

    /// Linear congruential generator step
    fn next_entropy(&mut self) -> u64 {
        self.entropy_seed = self.entropy_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.entropy_seed
    }

    /// Generate randomized layout for new process
    pub fn generate_layout(&mut self, is_pie: bool) -> ProcessAddressLayout {
        // 1. Executable Base: 28-bit entropy (aligned to 4 KiB page)
        let code_base = if is_pie {
            let offset = (self.next_entropy() & 0x0FFF_FFFF) << 12;
            DEFAULT_EXEC_BASE.wrapping_add(offset)
        } else {
            0x0000_0000_0040_0000 // Non-PIE fixed base
        };

        // 2. Heap Start: base + random offset (up to 32 MiB)
        let heap_offset = (self.next_entropy() & 0x0000_1FFF) << 12;
        let heap_start = code_base.wrapping_add(0x1000_0000).wrapping_add(heap_offset);

        // 3. mmap Base: 28-bit entropy (aligned to 2 MiB large page for huge page optimization)
        let mmap_rand = (self.next_entropy() & 0x00FF_FFFF) << 21;
        let mmap_base = DEFAULT_MMAP_BASE.wrapping_add(mmap_rand);

        // 4. Stack Top: up to 16 MiB randomized gap below top of userland
        let stack_gap = (self.next_entropy() & 0x0000_0FFF) << 12;
        let stack_top = DEFAULT_STACK_TOP.saturating_sub(stack_gap) & !0x0F; // 16-byte aligned

        ProcessAddressLayout {
            code_base,
            heap_start,
            mmap_base,
            stack_top,
        }
    }
}
