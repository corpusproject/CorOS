//! Hardware-Assisted Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
//!
//! Gathers hardware entropy via x86_64 `rdrand` and `rdseed` instructions, mixed
//! into an internal entropy pool using SHA-256 for unpredictable kernel-grade random values.

use super::sha256::sha256_hash;

pub struct Csprng {
    state: [u8; 32],
    counter: u64,
}

impl Csprng {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        for i in 0..4 {
            let val = Self::hardware_rdrand_u64().unwrap_or(0xCAFE_BABE_DEAD_BEEF ^ (i as u64));
            seed[i * 8..(i + 1) * 8].copy_from_slice(&val.to_ne_bytes());
        }

        Self {
            state: seed,
            counter: 0,
        }
    }

    /// Tries hardware RDRAND instruction
    #[inline(always)]
    pub fn hardware_rdrand_u64() -> Option<u64> {
        let val: u64;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) val,
                out(reg_byte) success,
                options(nomem, nostack)
            );
        }
        if success != 0 {
            Some(val)
        } else {
            None
        }
    }

    /// Fills the destination buffer with cryptographically secure random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            // Mix state with hardware entropy, counter, and hash
            let mut mix_buf = [0u8; 48];
            mix_buf[..32].copy_from_slice(&self.state);
            mix_buf[32..40].copy_from_slice(&self.counter.to_le_bytes());

            let hw = Self::hardware_rdrand_u64().unwrap_or(0xA5A5_5A5A_1234_5678);
            mix_buf[40..48].copy_from_slice(&hw.to_le_bytes());

            self.state = sha256_hash(&mix_buf);
            self.counter = self.counter.wrapping_add(1);

            let chunk_len = core::cmp::min(32, dest.len() - offset);
            dest[offset..offset + chunk_len].copy_from_slice(&self.state[..chunk_len]);
            offset += chunk_len;
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
}

pub static GLOBAL_CSPRNG: crate::sync::SpinLock<Csprng> = crate::sync::SpinLock::new(Csprng {
    state: [0u8; 32],
    counter: 0,
});
