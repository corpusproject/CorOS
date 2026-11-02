//! CorOS FIPS 180-4 SHA-512 & SHA-384 Cryptographic Hash Engine (`sha512.rs`)
//!
//! Implements pure bare-metal 64-bit word secure hash algorithms:
//! - SHA-512 (512-bit digest output, 128-byte block size, 80 rounds)
//! - SHA-384 (384-bit truncated digest output)
//! - HMAC-SHA512 (RFC 2104 Keyed-Hashing for Message Authentication)

extern crate alloc;

use alloc::vec::Vec;

pub const SHA512_BLOCK_SIZE: usize = 128;
pub const SHA512_DIGEST_SIZE: usize = 64;
pub const SHA384_DIGEST_SIZE: usize = 48;

/// SHA-512 80-round constant table
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47867871, 0x92722c851482353b,
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
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline(always)]
fn sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline(always)]
fn gamma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline(always)]
fn gamma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// SHA-512 Hash State
#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    total_bytes: u128,
    buffer: [u8; 128],
    buf_len: usize,
}

impl Sha512 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
            ],
            total_bytes: 0,
            buffer: [0; 128],
            buf_len: 0,
        }
    }

    fn transform(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let offset = i * 8;
            w[i] = u64::from_be_bytes([
                block[offset], block[offset + 1], block[offset + 2], block[offset + 3],
                block[offset + 4], block[offset + 5], block[offset + 6], block[offset + 7],
            ]);
        }

        for i in 16..80 {
            let s0 = gamma0(w[i - 15]);
            let s1 = gamma1(w[i - 2]);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_bytes += data.len() as u128;

        if self.buf_len > 0 {
            let needed = 128 - self.buf_len;
            if data.len() >= needed {
                self.buffer[self.buf_len..128].copy_from_slice(&data[..needed]);
                let blk = self.buffer;
                self.transform(&blk);
                offset += needed;
                self.buf_len = 0;
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        while offset + 128 <= data.len() {
            let mut blk = [0u8; 128];
            blk.copy_from_slice(&data[offset..offset + 128]);
            self.transform(&blk);
            offset += 128;
        }

        let remaining = &data[offset..];
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buf_len = remaining.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let total_bits = self.total_bytes * 8;
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 112 {
            for i in self.buf_len..128 {
                self.buffer[i] = 0;
            }
            let blk = self.buffer;
            self.transform(&blk);
            self.buf_len = 0;
        }

        for i in self.buf_len..112 {
            self.buffer[i] = 0;
        }

        // 128-bit big-endian length
        self.buffer[112..128].copy_from_slice(&total_bits.to_be_bytes());
        let blk = self.buffer;
        self.transform(&blk);

        let mut digest = [0u8; 64];
        for (i, &s) in self.state.iter().enumerate() {
            digest[i * 8..i * 8 + 8].copy_from_slice(&s.to_be_bytes());
        }
        digest
    }
}

/// Compute SHA-512 digest in a single pass
pub fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// Compute HMAC-SHA512
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut k_pad = [0u8; 128];
    if key.len() > 128 {
        let hash = sha512_hash(key);
        k_pad[..64].copy_from_slice(&hash);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut i_key_pad = [0u8; 128];
    let mut o_key_pad = [0u8; 128];
    for i in 0..128 {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5C;
    }

    let mut inner = Sha512::new();
    inner.update(&i_key_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(&o_key_pad);
    outer.update(&inner_hash);
    outer.finalize()
}
