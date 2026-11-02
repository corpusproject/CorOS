//! RFC 7693 BLAKE2b cryptographic hash and keyed MAC implementation.

use crate::constant_time::{ct_eq_slice, zeroize_slice, zeroize_words64};

/// BLAKE2b initialization vector (identical to SHA-512 `H0`).
pub const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// RFC 7693 Section 2.7 message word permutation schedule $\sigma_{0..9}$ (repeated for rounds 10..11).
pub const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b quarter-round mixing function $G(v, a, b, c, d, x, y)$.
#[inline(always)]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// RFC 7693 Section 3.2 compression function $F(h, m, t, f)$.
pub fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t0: u64, t1: u64, is_last: bool) {
    let mut m = [0u64; 16];
    let mut i = 0;
    while i < 16 {
        let base = i * 8;
        m[i] = u64::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        ]);
        i += 1;
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2B_IV);

    v[12] ^= t0;
    v[13] ^= t1;
    if is_last {
        v[14] = !v[14];
    }

    let mut r = 0;
    while r < 12 {
        let s = &SIGMA[r];
        blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        r += 1;
    }

    let mut j = 0;
    while j < 8 {
        h[j] ^= v[j] ^ v[j + 8];
        j += 1;
    }

    zeroize_words64(&mut v);
    zeroize_words64(&mut m);
}

/// Streaming RFC 7693 BLAKE2b state supporting digest lengths `1..=64` and optional keys `0..=64`.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    t0: u64,
    t1: u64,
    out_len: usize,
}

impl Blake2b {
    /// Creates an unkeyed BLAKE2b instance with the requested output length `out_len` (`1..=64`).
    pub fn new(out_len: usize) -> Self {
        Self::with_key(out_len, &[])
    }

    /// Creates a keyed or unkeyed BLAKE2b instance.
    /// `out_len` is clamped to `1..=64`, and `key` length is clamped to `0..=64`.
    pub fn with_key(out_len: usize, key: &[u8]) -> Self {
        let nn = out_len.clamp(1, 64);
        let kk = key.len().min(64);

        let mut h = BLAKE2B_IV;
        let param_word: u64 = 0x0101_0000 ^ ((kk as u64) << 8) ^ (nn as u64);
        h[0] ^= param_word;

        let mut state = Self {
            h,
            buffer: [0u8; 128],
            buffer_len: 0,
            t0: 0,
            t1: 0,
            out_len: nn,
        };

        if kk > 0 {
            state.buffer[..kk].copy_from_slice(&key[..kk]);
            state.buffer_len = 128;
        }

        state
    }

    #[inline(always)]
    fn increment_counter(&mut self, inc: u64) {
        let (new_t0, carry) = self.t0.overflowing_add(inc);
        self.t0 = new_t0;
        if carry {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    /// Absorbs input data into the BLAKE2b state, keeping up to 128 bytes buffered
    /// so the final block flag can be set accurately on `finalize`.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.buffer_len == 128 {
            self.increment_counter(128);
            let block = self.buffer;
            blake2b_compress(&mut self.h, &block, self.t0, self.t1, false);
            self.buffer_len = 0;
        }

        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;
            if data.len() > needed {
                self.buffer[self.buffer_len..128].copy_from_slice(&data[..needed]);
                self.increment_counter(128);
                let block = self.buffer;
                blake2b_compress(&mut self.h, &block, self.t0, self.t1, false);
                self.buffer_len = 0;
                data = &data[needed..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while data.len() > 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.increment_counter(128);
            blake2b_compress(&mut self.h, &block, self.t0, self.t1, false);
            data = &data[128..];
        }

        self.buffer[..data.len()].copy_from_slice(data);
        self.buffer_len = data.len();
    }

    /// Finalizes the BLAKE2b computation and writes `out_len` bytes into `out`.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        self.increment_counter(self.buffer_len as u64);
        let mut i = self.buffer_len;
        while i < 128 {
            self.buffer[i] = 0;
            i += 1;
        }
        let block = self.buffer;
        blake2b_compress(&mut self.h, &block, self.t0, self.t1, true);

        let mut full_bytes = [0u8; 64];
        let mut w = 0;
        while w < 8 {
            full_bytes[w * 8..w * 8 + 8].copy_from_slice(&self.h[w].to_le_bytes());
            w += 1;
        }

        let copy_len = out.len().min(self.out_len);
        out[..copy_len].copy_from_slice(&full_bytes[..copy_len]);

        zeroize_words64(&mut self.h);
        zeroize_slice(&mut self.buffer);
        zeroize_slice(&mut full_bytes);
    }

    /// Finalizes the BLAKE2b state and returns the full 64-byte output array.
    pub fn finalize_64(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.finalize_into(&mut out);
        out
    }

    /// Finalizes the BLAKE2b state and returns the first 32 bytes.
    pub fn finalize_32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_into(&mut out);
        out
    }
}

/// Computes the 64-byte BLAKE2b-512 digest of `data` in one shot.
pub fn blake2b_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b::new(64);
    hasher.update(data);
    hasher.finalize_64()
}

/// Computes the 32-byte BLAKE2b-256 digest of `data` in one shot.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::new(32);
    hasher.update(data);
    hasher.finalize_32()
}

/// Computes a 32-byte keyed BLAKE2b MAC over `data` using `key`.
pub fn blake2b_mac_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::with_key(32, key);
    hasher.update(data);
    hasher.finalize_32()
}

/// Runs RFC 7693 Appendix A Known Answer Tests for BLAKE2b.
pub fn run_blake2b_self_test() -> u32 {
    let mut passed = 0u32;

    // RFC 7693 Appendix A: BLAKE2b-512("abc")
    let abc_expected: [u8; 64] = [
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
    ];
    if ct_eq_slice(&blake2b_512(b"abc"), &abc_expected) {
        passed += 1;
    }

    // BLAKE2b-512("")
    let empty_expected: [u8; 64] = [
        0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
        0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
        0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
        0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
        0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
        0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
        0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
        0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
    ];
    if ct_eq_slice(&blake2b_512(b""), &empty_expected) {
        passed += 1;
    }

    // Keyed BLAKE2b-256 MAC consistency check
    let key = b"coros-kernel-blake2b-mac-key-32b";
    let mac1 = blake2b_mac_256(key, b"boot-manifest-payload");
    let mac2 = blake2b_mac_256(key, b"boot-manifest-payload");
    let mac_diff = blake2b_mac_256(key, b"boot-manifest-payload-tampered");
    if ct_eq_slice(&mac1, &mac2) && !ct_eq_slice(&mac1, &mac_diff) {
        passed += 1;
    }

    passed
}
