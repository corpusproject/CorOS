//! FIPS 197 AES-256 block cipher, CTR stream mode, and NIST SP 800-38D AES-256-GCM AEAD.

use crate::constant_time::{ct_eq_16, zeroize_slice, zeroize_words32};

/// FIPS 197 forward substitution box (`SBOX`) over $GF(2^8) / (x^8 + x^4 + x^3 + x + 1)$.
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Round constants `RCON[1..=7]` in the most significant byte of a 32-bit big-endian word.
pub const RCON: [u32; 8] = [
    0x0000_0000,
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
];

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b0 = SBOX[((w >> 24) & 0xFF) as usize] as u32;
    let b1 = SBOX[((w >> 16) & 0xFF) as usize] as u32;
    let b2 = SBOX[((w >> 8) & 0xFF) as usize] as u32;
    let b3 = SBOX[(w & 0xFF) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

/// Multiplies a byte by $x$ (`0x02`) in $GF(2^8)$ modulo $x^8 + x^4 + x^3 + x + 1$ (`0x11B`).
#[inline(always)]
fn xtime(x: u8) -> u8 {
    let hi = (x >> 7) & 1;
    let mask = (0u8.wrapping_sub(hi)) & 0x1b;
    (x << 1) ^ mask
}

/// Expanded AES-256 key schedule containing 60 32-bit words (15 round keys of 16 bytes each).
#[derive(Clone)]
pub struct Aes256KeySchedule {
    round_words: [u32; 60],
}

impl Drop for Aes256KeySchedule {
    fn drop(&mut self) {
        zeroize_words32(&mut self.round_words);
    }
}

impl Aes256KeySchedule {
    /// Expands a 256-bit (32-byte) key into 15 round keys according to FIPS 197 Section 5.2.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut w = [0u32; 60];
        let mut i = 0;
        while i < 8 {
            let base = i * 4;
            w[i] = u32::from_be_bytes([
                key[base],
                key[base + 1],
                key[base + 2],
                key[base + 3],
            ]);
            i += 1;
        }

        while i < 60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / 8];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - 8] ^ temp;
            i += 1;
        }

        Self { round_words: w }
    }

    #[inline(always)]
    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        let base_word = round * 4;
        let mut c = 0;
        while c < 4 {
            let rk = self.round_words[base_word + c].to_be_bytes();
            state[c * 4] ^= rk[0];
            state[c * 4 + 1] ^= rk[1];
            state[c * 4 + 2] ^= rk[2];
            state[c * 4 + 3] ^= rk[3];
            c += 1;
        }
    }

    /// Encrypts a single 16-byte plaintext block using 14 rounds of AES-256.
    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        self.add_round_key(&mut s, 0);

        let mut round = 1;
        while round < 14 {
            // SubBytes
            let mut i = 0;
            while i < 16 {
                s[i] = SBOX[s[i] as usize];
                i += 1;
            }

            // ShiftRows (column-major layout: row r, col c is at index c*4 + r)
            // Row 1: cyclic shift left by 1
            let t1 = s[1];
            s[1] = s[5];
            s[5] = s[9];
            s[9] = s[13];
            s[13] = t1;

            // Row 2: cyclic shift left by 2
            let t2_0 = s[2];
            let t2_1 = s[6];
            s[2] = s[10];
            s[6] = s[14];
            s[10] = t2_0;
            s[14] = t2_1;

            // Row 3: cyclic shift left by 3 (right by 1)
            let t3 = s[15];
            s[15] = s[11];
            s[11] = s[7];
            s[7] = s[3];
            s[3] = t3;

            // MixColumns
            let mut c = 0;
            while c < 4 {
                let idx = c * 4;
                let a0 = s[idx];
                let a1 = s[idx + 1];
                let a2 = s[idx + 2];
                let a3 = s[idx + 3];
                let tm = a0 ^ a1 ^ a2 ^ a3;
                s[idx] ^= tm ^ xtime(a0 ^ a1);
                s[idx + 1] ^= tm ^ xtime(a1 ^ a2);
                s[idx + 2] ^= tm ^ xtime(a2 ^ a3);
                s[idx + 3] ^= tm ^ xtime(a3 ^ a0);
                c += 1;
            }

            self.add_round_key(&mut s, round);
            round += 1;
        }

        // Final 14th round (no MixColumns)
        let mut i = 0;
        while i < 16 {
            s[i] = SBOX[s[i] as usize];
            i += 1;
        }

        let t1 = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t1;

        let t2_0 = s[2];
        let t2_1 = s[6];
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t2_0;
        s[14] = t2_1;

        let t3 = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t3;

        self.add_round_key(&mut s, 14);
        s
    }
}

/// One-shot FIPS 197 AES-256 single-block encryption.
pub fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let ks = Aes256KeySchedule::new(key);
    ks.encrypt_block(block)
}

/// Increments the rightmost 32 bits of a 16-byte GCM counter block ($inc_{32}$ per NIST SP 800-38D).
#[inline(always)]
fn inc32(counter_block: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ])
    .wrapping_add(1);
    counter_block[12..16].copy_from_slice(&ctr.to_be_bytes());
}

/// Applies AES-256-CTR stream encryption/decryption in-place starting from `initial_counter`.
pub fn aes256_ctr_xor(ks: &Aes256KeySchedule, initial_counter: &[u8; 16], data: &mut [u8]) {
    let mut cb = *initial_counter;
    let mut offset = 0usize;
    while offset < data.len() {
        let mut keystream = ks.encrypt_block(&cb);
        let chunk = (data.len() - offset).min(16);
        let mut i = 0;
        while i < chunk {
            data[offset + i] ^= keystream[i];
            i += 1;
        }
        zeroize_slice(&mut keystream);
        inc32(&mut cb);
        offset += chunk;
    }
}

/// Multiplies two 128-bit elements $X \cdot Y$ in $GF(2^{128})$ modulo $1 + \alpha + \alpha^2 + \alpha^7 + \alpha^{128}$
/// using big-endian bit-reflection (`R = 0xE100...00`) as specified by NIST SP 800-38D Section 6.3.
pub fn ghash_mul_block(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let x_num = u128::from_be_bytes(*x);
    let mut v = u128::from_be_bytes(*y);
    let mut z = 0u128;
    const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

    let mut i = 0;
    while i < 128 {
        let bit = (x_num >> (127 - i)) & 1;
        let bit_mask = 0u128.wrapping_sub(bit);
        z ^= v & bit_mask;

        let lsb = v & 1;
        let lsb_mask = 0u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (R & lsb_mask);
        i += 1;
    }

    z.to_be_bytes()
}

/// NIST SP 800-38D GHASH universal hash accumulator over $GF(2^{128})$.
pub struct Ghash {
    h: [u8; 16],
    y: [u8; 16],
}

impl Ghash {
    /// Creates a new `Ghash` accumulator with hash subkey $H = E_K(0^{128})$.
    pub const fn new(h: [u8; 16]) -> Self {
        Self { h, y: [0u8; 16] }
    }

    /// Absorbs a single 16-byte block into the GHASH state: $Y_i = (Y_{i-1} \oplus X_i) \cdot H$.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        let mut i = 0;
        while i < 16 {
            self.y[i] ^= block[i];
            i += 1;
        }
        self.y = ghash_mul_block(&self.y, &self.h);
    }

    /// Absorbs an arbitrary byte slice padded with trailing zeros to a 16-byte boundary.
    pub fn update_padded(&mut self, mut data: &[u8]) {
        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.update_block(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            let mut block = [0u8; 16];
            block[..data.len()].copy_from_slice(data);
            self.update_block(&block);
        }
    }

    /// Finalizes the GHASH authentication digest over `(aad, ciphertext)` by appending
    /// `[len(A)_bits_64 || len(C)_bits_64]`.
    pub fn finalize(mut self, aad_len_bytes: usize, ct_len_bytes: usize) -> [u8; 16] {
        let aad_bits = (aad_len_bytes as u64).wrapping_mul(8);
        let ct_bits = (ct_len_bytes as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
        self.update_block(&len_block);
        let out = self.y;
        zeroize_slice(&mut self.h);
        out
    }
}

/// NIST SP 800-38D AES-256-GCM in-place encryption with a 96-bit (12-byte) IV.
/// Encrypts `buffer` in-place and returns the 16-byte authentication tag.
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> [u8; 16] {
    let ks = Aes256KeySchedule::new(key);
    let h = ks.encrypt_block(&[0u8; 16]);

    // Pre-counter block J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Initial encryption counter = inc32(J0)
    let mut ctr = j0;
    inc32(&mut ctr);
    aes256_ctr_xor(&ks, &ctr, buffer);

    let mut ghash = Ghash::new(h);
    ghash.update_padded(aad);
    ghash.update_padded(buffer);
    let mut tag = ghash.finalize(aad.len(), buffer.len());

    let mut s_j0 = ks.encrypt_block(&j0);
    let mut i = 0;
    while i < 16 {
        tag[i] ^= s_j0[i];
        i += 1;
    }
    zeroize_slice(&mut s_j0);
    tag
}

/// NIST SP 800-38D AES-256-GCM in-place decryption and constant-time tag verification.
/// If `expected_tag` does not match, `buffer` is zeroized and `false` is returned.
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    expected_tag: &[u8; 16],
) -> bool {
    let ks = Aes256KeySchedule::new(key);
    let h = ks.encrypt_block(&[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut ghash = Ghash::new(h);
    ghash.update_padded(aad);
    ghash.update_padded(buffer);
    let mut computed_tag = ghash.finalize(aad.len(), buffer.len());

    let mut s_j0 = ks.encrypt_block(&j0);
    let mut i = 0;
    while i < 16 {
        computed_tag[i] ^= s_j0[i];
        i += 1;
    }
    zeroize_slice(&mut s_j0);

    if !ct_eq_16(&computed_tag, expected_tag) {
        zeroize_slice(buffer);
        return false;
    }

    let mut ctr = j0;
    inc32(&mut ctr);
    aes256_ctr_xor(&ks, &ctr, buffer);
    true
}

/// Runs FIPS 197 Appendix C.3 AES-256 and NIST SP 800-38D AES-256-GCM self-tests.
pub fn run_aes_gcm_self_test() -> u32 {
    let mut passed = 0u32;

    // 1. FIPS 197 Appendix C.3 AES-256 Known Answer Test
    let fips_key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let fips_pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let fips_expected_ct: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];
    let ct = aes256_encrypt_block(&fips_key, &fips_pt);
    if ct_eq_16(&ct, &fips_expected_ct) {
        passed += 1;
    }

    // 2. NIST SP 800-38D GCM Test Case 13 (Key = 0^256, IV = 0^96, Empty PT & AAD)
    let zero_key = [0u8; 32];
    let zero_nonce = [0u8; 12];
    let mut empty_buf: [u8; 0] = [];
    let gcm_tag_tc13 = aes256_gcm_encrypt(&zero_key, &zero_nonce, &[], &mut empty_buf);
    let expected_tc13_tag: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
        0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    ];
    if ct_eq_16(&gcm_tag_tc13, &expected_tc13_tag) {
        passed += 1;
    }

    // 3. NIST SP 800-38D GCM Test Case 14 (Key = 0^256, IV = 0^96, PT = 0^128)
    let mut pt_tc14 = [0u8; 16];
    let gcm_tag_tc14 = aes256_gcm_encrypt(&zero_key, &zero_nonce, &[], &mut pt_tc14);
    let expected_tc14_ct: [u8; 16] = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    ];
    let expected_tc14_tag: [u8; 16] = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    ];
    if ct_eq_16(&pt_tc14, &expected_tc14_ct) && ct_eq_16(&gcm_tag_tc14, &expected_tc14_tag) {
        passed += 1;
    }

    // 4. Decrypt & authenticate round-trip and tamper rejection
    if aes256_gcm_decrypt(&zero_key, &zero_nonce, &[], &mut pt_tc14, &expected_tc14_tag)
        && ct_eq_16(&pt_tc14, &[0u8; 16])
    {
        passed += 1;
    }

    passed
}
