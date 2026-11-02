//! FIPS 180-4 SHA-256 and HMAC-SHA256 Implementation for CorOS
//!
//! Fully self-contained, no_std, high-performance 256-bit secure cryptographic hash.

use alloc::vec::Vec;

pub const SHA256_BLOCK_SIZE: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut len = data.len();
        let buf_idx = (self.count as usize) & 0x3F;
        self.count += len as u64;

        if buf_idx > 0 {
            let left = 64 - buf_idx;
            if len >= left {
                self.buffer[buf_idx..64].copy_from_slice(&data[..left]);
                let block = self.buffer;
                self.process_block(&block);
                offset += left;
                len -= left;
            } else {
                self.buffer[buf_idx..buf_idx + len].copy_from_slice(data);
                return;
            }
        }

        while len >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.process_block(&block);
            offset += 64;
            len -= 64;
        }

        if len > 0 {
            self.buffer[..len].copy_from_slice(&data[offset..offset + len]);
        }
    }

    pub fn finalize(mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let total_bits = self.count * 8;
        let buf_idx = (self.count as usize) & 0x3F;

        // Append 0x80 byte
        self.buffer[buf_idx] = 0x80;
        let mut idx = buf_idx + 1;

        if idx > 56 {
            for b in &mut self.buffer[idx..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            idx = 0;
        }

        for b in &mut self.buffer[idx..56] {
            *b = 0;
        }

        // Append 64-bit big-endian length
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut digest = [0u8; 32];
        for i in 0..8 {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
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

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
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
}

pub fn sha256_hash(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// HMAC-SHA256 Message Authentication Code (RFC 2104)
pub struct HmacSha256 {
    inner_hasher: Sha256,
    outer_key_pad: [u8; 64],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let digest = sha256_hash(key);
            k[..32].copy_from_slice(&digest);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut i_pad = [0x36u8; 64];
        let mut o_pad = [0x5Cu8; 64];
        for i in 0..64 {
            i_pad[i] ^= k[i];
            o_pad[i] ^= k[i];
        }

        let mut inner = Sha256::new();
        inner.update(&i_pad);

        Self {
            inner_hasher: inner,
            outer_key_pad: o_pad,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner_hasher.update(data);
    }

    pub fn finalize(self) -> [u8; SHA256_DIGEST_SIZE] {
        let inner_hash = self.inner_hasher.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_hash);
        outer.finalize()
    }
}
