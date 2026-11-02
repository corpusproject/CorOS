//! RFC 8439 ChaCha20 20-round stream cipher, Poly1305 130-bit prime field MAC,
//! and combined ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).

use crate::constant_time::{ct_eq_16, ct_eq_slice, ct_select_u64, zeroize_slice, zeroize_words32};

/// ChaCha20 128-bit state constant `"expand 32-byte k"` in little-endian 32-bit words.
pub const CHACHA20_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// RFC 8439 Section 2.1 ChaCha20 Quarter Round on indices `(a, b, c, d)` of the 16-word state.
#[inline(always)]
pub fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Computes a single 64-byte ChaCha20 keystream block for `(key, counter, nonce)` per RFC 8439 Section 2.3.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = CHACHA20_CONSTANTS[0];
    initial[1] = CHACHA20_CONSTANTS[1];
    initial[2] = CHACHA20_CONSTANTS[2];
    initial[3] = CHACHA20_CONSTANTS[3];

    let mut i = 0;
    while i < 8 {
        let base = i * 4;
        initial[4 + i] = u32::from_le_bytes([
            key[base],
            key[base + 1],
            key[base + 2],
            key[base + 3],
        ]);
        i += 1;
    }

    initial[12] = counter;
    initial[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    initial[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    initial[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let mut working = initial;
    let mut dbl_round = 0;
    while dbl_round < 10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
        dbl_round += 1;
    }

    let mut out = [0u8; 64];
    let mut w = 0;
    while w < 16 {
        let word = working[w].wrapping_add(initial[w]);
        out[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
        w += 1;
    }

    zeroize_words32(&mut initial);
    zeroize_words32(&mut working);
    out
}

/// Applies the ChaCha20 keystream in-place by XORing `data` starting at block `initial_counter`.
pub fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter = initial_counter;
    let mut offset = 0usize;
    while offset < data.len() {
        let mut ks = chacha20_block(key, counter, nonce);
        let chunk = (data.len() - offset).min(64);
        let mut i = 0;
        while i < chunk {
            data[offset + i] ^= ks[i];
            i += 1;
        }
        zeroize_slice(&mut ks);
        counter = counter.wrapping_add(1);
        offset += chunk;
    }
}

/// RFC 8439 Section 2.5 Poly1305 one-time authenticator over $GF(2^{130}-5)$ using 5x 26-bit limbs.
pub struct Poly1305 {
    r: [u64; 5],
    h: [u64; 5],
    pad: [u64; 4],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    /// Initializes a Poly1305 authenticator with a 32-byte one-time key `(r || s)`.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);
        // Clamp r according to RFC 8439 Section 2.5
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let r_val = u128::from_le_bytes(r_bytes);
        let r0 = (r_val & 0x03ff_ffff) as u64;
        let r1 = ((r_val >> 26) & 0x03ff_ffff) as u64;
        let r2 = ((r_val >> 52) & 0x03ff_ffff) as u64;
        let r3 = ((r_val >> 78) & 0x03ff_ffff) as u64;
        let r4 = ((r_val >> 104) & 0x03ff_ffff) as u64;

        let pad0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]) as u64;
        let pad1 = u32::from_le_bytes([key[20], key[21], key[22], key[23]]) as u64;
        let pad2 = u32::from_le_bytes([key[24], key[25], key[26], key[27]]) as u64;
        let pad3 = u32::from_le_bytes([key[28], key[29], key[30], key[31]]) as u64;

        zeroize_slice(&mut r_bytes);

        Self {
            r: [r0, r1, r2, r3, r4],
            h: [0u64; 5],
            pad: [pad0, pad1, pad2, pad3],
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    #[inline]
    fn process_block(&mut self, block: &[u8; 16], hibit: u64) {
        let m_val = u128::from_le_bytes(*block);
        let mut h0 = self.h[0] + ((m_val & 0x03ff_ffff) as u64);
        let mut h1 = self.h[1] + (((m_val >> 26) & 0x03ff_ffff) as u64);
        let mut h2 = self.h[2] + (((m_val >> 52) & 0x03ff_ffff) as u64);
        let mut h3 = self.h[3] + (((m_val >> 78) & 0x03ff_ffff) as u64);
        let mut h4 = self.h[4] + (((m_val >> 104) & 0x03ff_ffff) as u64) + hibit;

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x03ff_ffff;
        d1 += c;

        c = d1 >> 26;
        h1 = d1 & 0x03ff_ffff;
        d2 += c;

        c = d2 >> 26;
        h2 = d2 & 0x03ff_ffff;
        d3 += c;

        c = d3 >> 26;
        h3 = d3 & 0x03ff_ffff;
        d4 += c;

        c = d4 >> 26;
        h4 = d4 & 0x03ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        self.h = [h0, h1, h2, h3, h4];
    }

    /// Absorbs arbitrary bytes into the Poly1305 accumulator.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            if data.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..16].copy_from_slice(&data[..needed]);
            let block = self.buffer;
            self.process_block(&block, 1u64 << 24);
            self.buffer_len = 0;
            data = &data[needed..];
        }

        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.process_block(&block, 1u64 << 24);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalizes the accumulator mod $2^{130}-5$, adds the one-time pad $s \bmod 2^{128}$,
    /// and returns the 16-byte authentication tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 1;
            self.process_block(&block, 0);
        }

        // Full carry propagation
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute g = h + 5 (to test if h >= 2^130 - 5)
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;

        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // If g4 did not borrow (bit 63 == 0), then h >= 2^130 - 5, so select g; else select h.
        let use_g = ((g4 >> 63) ^ 1) & 1;
        h0 = ct_select_u64(use_g, g0, h0);
        h1 = ct_select_u64(use_g, g1, h1);
        h2 = ct_select_u64(use_g, g2, h2);
        h3 = ct_select_u64(use_g, g3, h3);
        h4 = ct_select_u64(use_g, g4 & 0x03ff_ffff, h4);

        // Reassemble h into four 32-bit words
        let w0 = (h0 | (h1 << 26)) & 0xffff_ffff;
        let w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
        let w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
        let w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

        // Add pad s mod 2^128
        let mut f = w0 + self.pad[0];
        let out0 = f as u32;
        f = w1 + self.pad[1] + (f >> 32);
        let out1 = f as u32;
        f = w2 + self.pad[2] + (f >> 32);
        let out2 = f as u32;
        f = w3 + self.pad[3] + (f >> 32);
        let out3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&out0.to_le_bytes());
        tag[4..8].copy_from_slice(&out1.to_le_bytes());
        tag[8..12].copy_from_slice(&out2.to_le_bytes());
        tag[12..16].copy_from_slice(&out3.to_le_bytes());

        zeroize_slice(&mut self.buffer);
        tag
    }
}

/// Computes the 16-byte Poly1305 tag over `msg` using the 32-byte one-time key `key`.
pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    mac.update(msg);
    mac.finalize()
}

/// Derives the 32-byte Poly1305 one-time key using ChaCha20 with `counter = 0` per RFC 8439 Section 2.6.
pub fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    zeroize_slice(&mut block0);
    otk
}

fn compute_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(otk);
    mac.update(aad);
    let aad_rem = aad.len() % 16;
    if aad_rem != 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..16 - aad_rem]);
    }
    mac.update(ciphertext);
    let ct_rem = ciphertext.len() % 16;
    if ct_rem != 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..16 - ct_rem]);
    }
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

/// RFC 8439 Section 2.8 ChaCha20-Poly1305 AEAD in-place encryption.
/// Encrypts `buffer` in-place using `(key, nonce)` and returns the 16-byte authentication tag.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> [u8; 16] {
    let mut otk = poly1305_key_gen(key, nonce);
    chacha20_xor(key, 1, nonce, buffer);
    let tag = compute_aead_tag(&otk, aad, buffer);
    zeroize_slice(&mut otk);
    tag
}

/// RFC 8439 Section 2.8 ChaCha20-Poly1305 AEAD in-place decryption and verification.
/// Verifies `expected_tag` in constant time before decrypting `buffer`.
/// If verification fails, `buffer` is zeroized and `false` is returned.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    expected_tag: &[u8; 16],
) -> bool {
    let mut otk = poly1305_key_gen(key, nonce);
    let computed_tag = compute_aead_tag(&otk, aad, buffer);
    zeroize_slice(&mut otk);

    if !ct_eq_16(&computed_tag, expected_tag) {
        zeroize_slice(buffer);
        return false;
    }

    chacha20_xor(key, 1, nonce, buffer);
    true
}

/// Runs RFC 8439 Known Answer Tests for ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD.
pub fn run_chacha20_poly1305_self_test() -> u32 {
    let mut passed = 0u32;

    // 1. RFC 8439 Section 2.3.2 Test Vector for ChaCha20 Block Function
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let block = chacha20_block(&key, 1, &nonce);
    let expected_first_16: [u8; 16] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
    ];
    if ct_eq_slice(&block[..16], &expected_first_16) {
        passed += 1;
    }

    // 2. RFC 8439 Section 2.5.2 Poly1305 Test Vector
    let poly_key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ];
    let poly_msg = b"Cryptographic Forum Research Group";
    let poly_expected: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    ];
    if ct_eq_16(&poly1305_mac(&poly_key, poly_msg), &poly_expected) {
        passed += 1;
    }

    // 3. AEAD round-trip and tamper rejection test
    let aead_key = [0x42u8; 32];
    let aead_nonce = [0x24u8; 12];
    let aad = b"coros-aead-header-v1";
    let plaintext = b"Confidential kernel IPC frame payload";
    let mut buf = *plaintext;
    let tag = chacha20_poly1305_encrypt(&aead_key, &aead_nonce, aad, &mut buf);
    if !ct_eq_slice(&buf, plaintext) {
        let mut decrypted = buf;
        if chacha20_poly1305_decrypt(&aead_key, &aead_nonce, aad, &mut decrypted, &tag)
            && ct_eq_slice(&decrypted, plaintext)
        {
            passed += 1;
        }
    }

    let mut tampered = buf;
    tampered[0] ^= 0x80;
    if !chacha20_poly1305_decrypt(&aead_key, &aead_nonce, aad, &mut tampered, &tag) {
        passed += 1;
    }

    passed
}
