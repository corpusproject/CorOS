//! FIPS 180-4 SHA-512 64-bit word cryptographic hash engine and RFC 4231 HMAC-SHA512.

use crate::constant_time::{ct_eq_slice, zeroize_slice, zeroize_words64};

/// Initial 64-bit hash state $H^{(0)}$ for SHA-512.
pub const SHA512_H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// All 80 FIPS 180-4 64-bit round constants $K_{0..79}$ for SHA-512.
pub const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[inline(always)]
fn ch64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0_64(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline(always)]
fn big_sigma1_64(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline(always)]
fn small_sigma0_64(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline(always)]
fn small_sigma1_64(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// Compresses a single 128-byte block into the 512-bit SHA-512 state.
pub fn sha512_compress_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    let mut t = 0;
    while t < 16 {
        let base = t * 8;
        w[t] = u64::from_be_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        ]);
        t += 1;
    }
    while t < 80 {
        w[t] = small_sigma1_64(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0_64(w[t - 15]))
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
    while r < 80 {
        let t1 = h
            .wrapping_add(big_sigma1_64(e))
            .wrapping_add(ch64(e, f, g))
            .wrapping_add(K512[r])
            .wrapping_add(w[r]);
        let t2 = big_sigma0_64(a).wrapping_add(maj64(a, b, c));
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

    zeroize_words64(&mut w);
}

/// Streaming FIPS 180-4 SHA-512 hasher.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_bytes_lo: u64,
    total_bytes_hi: u64,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Creates a new SHA-512 streaming hasher initialized with `SHA512_H0`.
    pub const fn new() -> Self {
        Self {
            state: SHA512_H0,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_bytes_lo: 0,
            total_bytes_hi: 0,
        }
    }

    /// Absorbs arbitrary message bytes into the SHA-512 state.
    pub fn update(&mut self, mut data: &[u8]) {
        let (new_lo, carry) = self.total_bytes_lo.overflowing_add(data.len() as u64);
        self.total_bytes_lo = new_lo;
        if carry {
            self.total_bytes_hi = self.total_bytes_hi.wrapping_add(1);
        }

        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;
            if data.len() < needed {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..128].copy_from_slice(&data[..needed]);
            let block = self.buffer;
            sha512_compress_block(&mut self.state, &block);
            self.buffer_len = 0;
            data = &data[needed..];
        }

        while data.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            sha512_compress_block(&mut self.state, &block);
            data = &data[128..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Pads the message to a multiple of 1024 bits and outputs the 64-byte SHA-512 digest.
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len_lo = self.total_bytes_lo << 3;
        let bit_len_hi = (self.total_bytes_hi << 3) | (self.total_bytes_lo >> 61);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 112 {
            let mut i = self.buffer_len;
            while i < 128 {
                self.buffer[i] = 0;
                i += 1;
            }
            let block = self.buffer;
            sha512_compress_block(&mut self.state, &block);
            self.buffer_len = 0;
        }

        let mut i = self.buffer_len;
        while i < 112 {
            self.buffer[i] = 0;
            i += 1;
        }
        self.buffer[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
        self.buffer[120..128].copy_from_slice(&bit_len_lo.to_be_bytes());
        let final_block = self.buffer;
        sha512_compress_block(&mut self.state, &final_block);

        let mut out = [0u8; 64];
        let mut w = 0;
        while w < 8 {
            out[w * 8..w * 8 + 8].copy_from_slice(&self.state[w].to_be_bytes());
            w += 1;
        }

        zeroize_words64(&mut self.state);
        zeroize_slice(&mut self.buffer);
        out
    }
}

/// Computes the 64-byte SHA-512 digest of `data` in one shot.
pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes RFC 2104 `HMAC-SHA512(key, data)` using a 128-byte block size.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut normalized_key = [0u8; 128];
    if key.len() > 128 {
        let hashed = sha512_digest(key);
        normalized_key[..64].copy_from_slice(&hashed);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 128];
    let mut outer_pad = [0x5cu8; 128];
    let mut i = 0;
    while i < 128 {
        inner_pad[i] ^= normalized_key[i];
        outer_pad[i] ^= normalized_key[i];
        i += 1;
    }

    let mut inner = Sha512::new();
    inner.update(&inner_pad);
    inner.update(data);
    let mut inner_digest = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    let mac = outer.finalize();

    zeroize_slice(&mut normalized_key);
    zeroize_slice(&mut inner_pad);
    zeroize_slice(&mut outer_pad);
    zeroize_slice(&mut inner_digest);
    mac
}

/// Runs FIPS 180-4 SHA-512 and RFC 4231 HMAC-SHA512 self-tests.
pub fn run_sha512_self_test() -> u32 {
    let mut passed = 0u32;

    // FIPS 180-4 SHA-512("")
    let empty_expected: [u8; 64] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    ];
    if ct_eq_slice(&sha512_digest(b""), &empty_expected) {
        passed += 1;
    }

    // FIPS 180-4 SHA-512("abc")
    let abc_expected: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    ];
    if ct_eq_slice(&sha512_digest(b"abc"), &abc_expected) {
        passed += 1;
    }

    // RFC 4231 Test Case 2 for HMAC-SHA512: Key = "Jefe", Data = "what do ya want for nothing?"
    let hmac_expected: [u8; 64] = [
        0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2,
        0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
        0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
        0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
        0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a,
        0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
        0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
        0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
    ];
    let tag = hmac_sha512(b"Jefe", b"what do ya want for nothing?");
    if ct_eq_slice(&tag, &hmac_expected) {
        passed += 1;
    }

    passed
}
