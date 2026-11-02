//! FIPS 180-4 SHA-256 streaming cryptographic hash function and RFC 2104 HMAC-SHA256.

use crate::constant_time::{ct_eq_32, zeroize_slice, zeroize_words32};

/// Initial hash values $H^{(0)}$ for SHA-256 (first 32 bits of the fractional parts of the
/// square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17, 19).
pub const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants $K_{0..63}$ for SHA-256 (first 32 bits of the fractional parts of the
/// cube roots of the first 64 prime numbers).
pub const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Compresses a single 64-byte message block into the 256-bit state `state`.
pub fn sha256_compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let mut t = 0;
    while t < 16 {
        let base = t * 4;
        w[t] = u32::from_be_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
        t += 1;
    }
    while t < 64 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
        t += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    let mut r = 0;
    while r < 64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K256[r])
            .wrapping_add(w[r]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        r += 1;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);

    zeroize_words32(&mut w);
}

/// Streaming FIPS 180-4 SHA-256 hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Creates a new SHA-256 streaming hasher initialized with `SHA256_H0`.
    pub const fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    /// Absorbs arbitrary message bytes into the SHA-256 state.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
            let block = self.buffer;
            sha256_compress_block(&mut self.state, &block);
            self.buffer_len = 0;
            data = &data[needed..];
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            sha256_compress_block(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Pads the message according to FIPS 180-4 and returns the 32-byte SHA-256 digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            let mut i = self.buffer_len;
            while i < 64 {
                self.buffer[i] = 0;
                i += 1;
            }
            let block = self.buffer;
            sha256_compress_block(&mut self.state, &block);
            self.buffer_len = 0;
        }

        let mut i = self.buffer_len;
        while i < 56 {
            self.buffer[i] = 0;
            i += 1;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buffer;
        sha256_compress_block(&mut self.state, &final_block);

        let mut out = [0u8; 32];
        let mut w = 0;
        while w < 8 {
            out[w * 4..w * 4 + 4].copy_from_slice(&self.state[w].to_be_bytes());
            w += 1;
        }

        zeroize_words32(&mut self.state);
        zeroize_slice(&mut self.buffer);
        out
    }
}

/// Computes the 32-byte SHA-256 digest of `data` in one shot.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the 32-byte SHA-256 digest of two concatenated slices `a || b`.
pub fn sha256_digest_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize()
}

/// Streaming RFC 2104 HMAC-SHA256 engine.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    outer_key_pad: [u8; 64],
}

impl HmacSha256 {
    /// Initializes an HMAC-SHA256 instance with an arbitrary-length `key`.
    pub fn new(key: &[u8]) -> Self {
        let mut normalized_key = [0u8; 64];
        if key.len() > 64 {
            let hashed = sha256_digest(key);
            normalized_key[..32].copy_from_slice(&hashed);
        } else {
            normalized_key[..key.len()].copy_from_slice(key);
        }

        let mut inner_key_pad = [0x36u8; 64];
        let mut outer_key_pad = [0x5cu8; 64];
        let mut i = 0;
        while i < 64 {
            inner_key_pad[i] ^= normalized_key[i];
            outer_key_pad[i] ^= normalized_key[i];
            i += 1;
        }

        let mut inner = Sha256::new();
        inner.update(&inner_key_pad);

        zeroize_slice(&mut normalized_key);
        zeroize_slice(&mut inner_key_pad);

        Self {
            inner,
            outer_key_pad,
        }
    }

    /// Absorbs message bytes into the inner SHA-256 state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the inner and outer hashes and returns the 32-byte authentication tag.
    pub fn finalize(mut self) -> [u8; 32] {
        let mut inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        let mac = outer.finalize();
        zeroize_slice(&mut inner_hash);
        zeroize_slice(&mut self.outer_key_pad);
        mac
    }
}

/// Computes RFC 2104 `HMAC-SHA256(key, data)` in one shot.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

/// Runs FIPS 180-4 SHA-256 and RFC 4231 HMAC-SHA256 self-tests.
pub fn run_sha256_self_test() -> u32 {
    let mut passed = 0u32;

    // FIPS 180-4 empty string ""
    let empty_expected: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ];
    if ct_eq_32(&sha256_digest(b""), &empty_expected) {
        passed += 1;
    }

    // FIPS 180-4 "abc"
    let abc_expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    if ct_eq_32(&sha256_digest(b"abc"), &abc_expected) {
        passed += 1;
    }

    // Multi-block streaming test: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let multi_msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let multi_expected: [u8; 32] = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    ];
    let mut streamer = Sha256::new();
    streamer.update(&multi_msg[..19]);
    streamer.update(&multi_msg[19..41]);
    streamer.update(&multi_msg[41..]);
    if ct_eq_32(&streamer.finalize(), &multi_expected) {
        passed += 1;
    }

    // RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    let hmac_expected: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    ];
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    if ct_eq_32(&mac, &hmac_expected) {
        passed += 1;
    }

    passed
}
