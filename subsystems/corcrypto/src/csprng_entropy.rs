//! Hardware `RDRAND` / `RDSEED` entropy harvester combined with a fast-key-erasure
//! ChaCha20-backed Cryptographically Secure Pseudo-Random Number Generator (`CsprngPool`).

use crate::chacha20_poly1305::chacha20_block;
use crate::constant_time::{ct_eq_32, zeroize_slice};
use crate::sha256_engine::Sha256;

/// Queries x86_64 `CPUID` leaf 1 ECX bit 30 to check hardware `RDRAND` support.
#[inline]
pub fn has_rdrand() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let leaf1 = core::arch::x86_64::__cpuid(1);
        (leaf1.ecx & (1 << 30)) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Queries x86_64 `CPUID` leaf 7 subleaf 0 EBX bit 18 to check hardware `RDSEED` support.
#[inline]
pub fn has_rdseed() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let leaf0 = core::arch::x86_64::__cpuid(0);
        if leaf0.eax < 7 {
            return false;
        }
        let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
        (leaf7.ebx & (1 << 18)) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Attempts up to 10 retries to read a 64-bit hardware random word via `RDRAND`.
#[inline]
pub fn try_rdrand_u64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if !has_rdrand() {
            return None;
        }
        let mut val = 0u64;
        let mut ok: u8;
        let mut retries = 0;
        while retries < 10 {
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc {ok}",
                    val = out(reg) val,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack)
                );
            }
            if ok != 0 {
                return Some(val);
            }
            retries += 1;
        }
        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Attempts up to 32 retries to read a 64-bit hardware entropy seed via `RDSEED`.
#[inline]
pub fn try_rdseed_u64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if !has_rdseed() {
            return None;
        }
        let mut val = 0u64;
        let mut ok: u8;
        let mut retries = 0;
        while retries < 32 {
            unsafe {
                core::arch::asm!(
                    "rdseed {val}",
                    "setc {ok}",
                    val = out(reg) val,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack)
                );
            }
            if ok != 0 {
                return Some(val);
            }
            retries += 1;
        }
        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Reads the processor time-stamp counter (`RDTSC`) as an auxiliary high-resolution jitter source.
#[inline]
pub fn read_tsc_jitter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0x9E37_79B9_7F4A_7C15
    }
}

/// Harvests 32 bytes of raw hardware entropy by combining `RDSEED`, `RDRAND`, and `RDTSC` jitter
/// conditioned through SHA-256.
pub fn harvest_hardware_entropy(generation: u64) -> [u8; 32] {
    let mut conditioner = Sha256::new();
    conditioner.update(b"CorOS-Hardware-Entropy-v1");
    conditioner.update(&generation.to_le_bytes());

    let mut sample = 0u32;
    while sample < 8 {
        let tsc_before = read_tsc_jitter();
        let hw_seed = try_rdseed_u64()
            .or_else(try_rdrand_u64)
            .unwrap_or_else(|| {
                // SplitMix64 mixing of TSC when running in an emulator without RDRAND/RDSEED
                let mut z = tsc_before
                    .wrapping_add((sample as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
                    .wrapping_add(generation.rotate_left(17));
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            });
        let tsc_after = read_tsc_jitter();

        conditioner.update(&tsc_before.to_le_bytes());
        conditioner.update(&hw_seed.to_le_bytes());
        conditioner.update(&tsc_after.to_le_bytes());
        sample += 1;
    }

    conditioner.finalize()
}

/// Fast-key-erasure ChaCha20 CSPRNG pool with periodic hardware entropy reseeding.
pub struct CsprngPool {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    reseed_generation: u64,
    bytes_since_reseed: usize,
}

impl Drop for CsprngPool {
    fn drop(&mut self) {
        zeroize_slice(&mut self.key);
        zeroize_slice(&mut self.nonce);
    }
}

impl CsprngPool {
    /// Initializes a new CSPRNG pool seeded from hardware entropy and an initial domain label.
    pub fn new(domain_seed: &[u8]) -> Self {
        let mut pool = Self {
            key: [0u8; 32],
            nonce: *b"CorOS-CSPRNG",
            counter: 1,
            reseed_generation: 1,
            bytes_since_reseed: 0,
        };
        pool.reseed(domain_seed);
        pool
    }

    /// Mixes fresh hardware entropy and `additional_input` into the CSPRNG key using SHA-256,
    /// then performs a fast-key-erasure ratchet step.
    pub fn reseed(&mut self, additional_input: &[u8]) {
        let mut hw = harvest_hardware_entropy(self.reseed_generation);
        let mut mixer = Sha256::new();
        mixer.update(&self.key);
        mixer.update(&hw);
        mixer.update(&self.reseed_generation.to_le_bytes());
        mixer.update(additional_input);
        self.key = mixer.finalize();

        zeroize_slice(&mut hw);
        self.nonce[0..8].copy_from_slice(&self.reseed_generation.to_le_bytes());
        self.counter = 1;
        self.reseed_generation = self.reseed_generation.wrapping_add(1);
        self.bytes_since_reseed = 0;
    }

    /// Fills `dest` with cryptographically strong pseudo-random bytes, ratcheting the internal
    /// ChaCha20 key immediately after every request for forward secrecy (fast key erasure).
    pub fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        if self.bytes_since_reseed >= 65536 {
            self.reseed(b"coros-periodic-auto-reseed");
        }

        while !dest.is_empty() {
            let mut block = chacha20_block(&self.key, self.counter, &self.nonce);
            self.counter = self.counter.wrapping_add(1);

            let take = dest.len().min(64);
            dest[..take].copy_from_slice(&block[..take]);
            dest = &mut dest[take..];
            self.bytes_since_reseed = self.bytes_since_reseed.wrapping_add(take);
            zeroize_slice(&mut block);
        }

        // Fast-key-erasure ratchet: derive next key from a dedicated keystream block
        let mut ratchet_block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);
        self.key.copy_from_slice(&ratchet_block[0..32]);
        self.nonce[8..12].copy_from_slice(&ratchet_block[32..36]);
        zeroize_slice(&mut ratchet_block);
    }

    /// Generates a random 64-bit unsigned integer from the CSPRNG pool.
    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Runs self-tests for hardware entropy harvesting and the fast-key-erasure ChaCha20 CSPRNG pool.
pub fn run_csprng_self_test() -> u32 {
    let mut passed = 0u32;

    let mut pool = CsprngPool::new(b"coros-self-test-entropy-domain");
    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    pool.fill_bytes(&mut out_a);
    pool.fill_bytes(&mut out_b);

    // Output must neither be all-zero nor repeat across ratchet steps
    if !ct_eq_32(&out_a, &[0u8; 32]) && !ct_eq_32(&out_b, &[0u8; 32]) && !ct_eq_32(&out_a, &out_b) {
        passed += 1;
    }

    // Reseed must alter key state and produce distinct 64-bit random words
    pool.reseed(b"extra-user-entropy-seed");
    let w1 = pool.next_u64();
    let w2 = pool.next_u64();
    if w1 != w2 && (w1 != 0 || w2 != 0) {
        passed += 1;
    }

    passed
}
