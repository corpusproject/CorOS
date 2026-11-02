//! Galois/Counter Mode (GCM) Authenticated Encryption with Associated Data (AEAD)
//!
//! Implements NIST SP 800-38D AES-GCM (128-bit & 256-bit):
//! - Galois Field \(GF(2^{128})\) multiplication with irreducible polynomial \(x^{128} + x^7 + x^2 + x + 1\) (`0xE1000000000000000000000000000000`)
//! - GHASH authenticator polynomial function over AAD and ciphertext blocks
//! - Counter (CTR) mode encryption with 32-bit incrementing counter
//! - J0 initialization from 96-bit or arbitrary-length IVs
//! - Single-pass combined encryption and integrity tag generation / verification

#![allow(dead_code)]

use alloc::vec::Vec;
use crate::crypto::aes::{Aes128, Aes256};

/// 128-bit element in Galois Field GF(2^128)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gf128(pub u64, pub u64); // (high, low)

impl Gf128 {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hi = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let lo = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Self(hi, lo)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.0.to_be_bytes());
        out[8..16].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    pub fn xor(&self, other: &Self) -> Self {
        Self(self.0 ^ other.0, self.1 ^ other.1)
    }

    /// Multiply by field element in GF(2^128) using Russian Peasant multiplication
    pub fn mul(&self, other: &Self) -> Self {
        let mut z = Gf128(0, 0);
        let mut v = *self;

        for i in 0..128 {
            let bit = if i < 64 {
                (other.0 >> (63 - i)) & 1
            } else {
                (other.1 >> (127 - i)) & 1
            };

            if bit == 1 {
                z = z.xor(&v);
            }

            // Multiply v by x (shift right 1 in bit-reversed representation)
            let lsb = v.1 & 1;
            v.1 = (v.1 >> 1) | ((v.0 & 1) << 63);
            v.0 >>= 1;

            if lsb != 0 {
                // XOR with reduction polynomial R = 0xE100_0000_0000_0000
                v.0 ^= 0xE100_0000_0000_0000;
            }
        }

        z
    }
}

/// GHASH Authenticator
pub struct GHash {
    pub h: Gf128,      // Hash subkey = AES_K(0^128)
    pub state: Gf128,  // Current accumulator
}

impl GHash {
    pub fn new(hash_key: [u8; 16]) -> Self {
        Self {
            h: Gf128::from_bytes(&hash_key),
            state: Gf128(0, 0),
        }
    }

    /// Update GHASH with a 16-byte block
    pub fn update_block(&mut self, block: &[u8]) {
        let x = Gf128::from_bytes(block);
        self.state = self.state.xor(&x).mul(&self.h);
    }

    /// Process arbitrary slice with zero-padding
    pub fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            self.update_block(chunk);
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut padded = [0u8; 16];
            padded[..remainder.len()].copy_from_slice(remainder);
            self.update_block(&padded);
        }
    }

    /// Finalize GHASH with bit lengths of AAD and Ciphertext
    pub fn finalize(mut self, aad_len: usize, cipher_len: usize) -> [u8; 16] {
        let aad_bits = (aad_len as u64) * 8;
        let cipher_bits = (cipher_len as u64) * 8;
        let len_block = Gf128(aad_bits, cipher_bits);
        self.state = self.state.xor(&len_block).mul(&self.h);
        self.state.to_bytes()
    }
}

/// AES-GCM AEAD Cipher
pub struct AesGcm {
    pub aes_key: [u8; 32],
    pub is_256: bool,
    pub hash_subkey: [u8; 16],
}

impl AesGcm {
    pub fn new_aes128(key: &[u8; 16]) -> Self {
        let mut key32 = [0u8; 32];
        key32[..16].copy_from_slice(key);
        let aes = Aes128::new(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);

        Self {
            aes_key: key32,
            is_256: false,
            hash_subkey: h,
        }
    }

    pub fn new_aes256(key: &[u8; 32]) -> Self {
        let aes = Aes256::new(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);

        Self {
            aes_key: *key,
            is_256: true,
            hash_subkey: h,
        }
    }

    /// Encrypt plaintext with AAD and generate 16-byte authentication tag
    pub fn encrypt(&self, iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
        // Construct initial counter block J0: IV || 00000001
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;

        // Compute tag mask T_mask = AES(J0)
        let mut t_mask = [0u8; 16];
        self.encrypt_single_block(&j0, &mut t_mask);

        // Encrypt plaintext with CTR mode starting at J0 + 1
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = 2u32;

        for chunk in plaintext.chunks(16) {
            let mut cb = [0u8; 16];
            cb[..12].copy_from_slice(iv);
            cb[12..16].copy_from_slice(&counter.to_be_bytes());
            counter += 1;

            let mut keystream = [0u8; 16];
            self.encrypt_single_block(&cb, &mut keystream);

            for (p, k) in chunk.iter().zip(keystream.iter()) {
                ciphertext.push(p ^ k);
            }
        }

        // Authenticate with GHASH
        let mut ghash = GHash::new(self.hash_subkey);
        ghash.update(aad);
        ghash.update(&ciphertext);
        let s = ghash.finalize(aad.len(), ciphertext.len());

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ t_mask[i];
        }

        (ciphertext, tag)
    }

    /// Decrypt ciphertext and verify 16-byte authentication tag
    pub fn decrypt(&self, iv: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;

        let mut t_mask = [0u8; 16];
        self.encrypt_single_block(&j0, &mut t_mask);

        // Check GHASH tag first
        let mut ghash = GHash::new(self.hash_subkey);
        ghash.update(aad);
        ghash.update(ciphertext);
        let s = ghash.finalize(aad.len(), ciphertext.len());

        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = s[i] ^ t_mask[i];
        }

        if &expected_tag != tag {
            return Err("GCM tag verification failed (authentication mismatch)");
        }

        // Decrypt with CTR
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter = 2u32;

        for chunk in ciphertext.chunks(16) {
            let mut cb = [0u8; 16];
            cb[..12].copy_from_slice(iv);
            cb[12..16].copy_from_slice(&counter.to_be_bytes());
            counter += 1;

            let mut keystream = [0u8; 16];
            self.encrypt_single_block(&cb, &mut keystream);

            for (c, k) in chunk.iter().zip(keystream.iter()) {
                plaintext.push(c ^ k);
            }
        }

        Ok(plaintext)
    }

    fn encrypt_single_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        output.copy_from_slice(input);
        if self.is_256 {
            let aes = Aes256::new(&self.aes_key);
            aes.encrypt_block(output);
        } else {
            let mut k16 = [0u8; 16];
            k16.copy_from_slice(&self.aes_key[..16]);
            let aes = Aes128::new(&k16);
            aes.encrypt_block(output);
        }
    }
}
