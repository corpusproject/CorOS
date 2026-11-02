//! CorOS RFC 8439 Poly1305 One-Time Authenticator MAC (`poly1305.rs`)
//!
//! Implements high-speed 128-bit MAC using 130-bit polynomial evaluation:
//! - 256-bit Key split into 16-byte evaluator `r` and 16-byte secret offset `s`
//! - Key Clamping (clearing specific bits in `r` to prevent small subgroups)
//! - 130-bit Accumulator arithmetic modulo prime $2^{130} - 5$
//! - Constant-time execution and addition of secret `s`
//! - Authenticates arbitrary length messages (16-byte chunk processing)

extern crate alloc;

pub const POLY1305_BLOCK_SIZE: usize = 16;
pub const POLY1305_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;

/// Poly1305 State
#[derive(Clone, Copy)]
pub struct Poly1305 {
    // r components clamped (5 x 26-bit limbs for arithmetic)
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,

    // 5 * r for reduction
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,

    // Accumulator (5 x 26-bit limbs)
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,

    // Key s components
    pad: [u32; 4],
    buffer: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        // Read r: key[0..16]
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        // Clamp r: r &= 0x0ffffffc0fffffff0ffffffc0fffffff
        let r0 = t0 & 0x3ffffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
        let r4 = (t3 >> 8) & 0x00fffff;

        // Read s: key[16..32]
        let s0 = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        let s1_pad = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        let s2_pad = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        let s3_pad = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self {
            r0,
            r1,
            r2,
            r3,
            r4,
            s1: r1 * 5,
            s2: r2 * 5,
            s3: r3 * 5,
            s4: r4 * 5,
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            pad: [s0, s1_pad, s2_pad, s3_pad],
            buffer: [0; 16],
            buf_len: 0,
        }
    }

    fn process_block(&mut self, block: &[u8], is_final: bool) {
        let hibit = if is_final { 0u32 } else { 1u32 << 24 };

        let mut b = [0u8; 16];
        b[..block.len()].copy_from_slice(block);
        if is_final {
            b[block.len()] = 1;
        }

        let t0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let t1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let t2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let t3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);

        self.h0 += t0 & 0x3ffffff;
        self.h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        self.h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        self.h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        self.h4 += (t3 >> 8) | hibit;

        // Multiply h * r modulo 2^130 - 5
        let d0 = (self.h0 as u64) * (self.r0 as u64)
            + (self.h1 as u64) * (self.s4 as u64)
            + (self.h2 as u64) * (self.s3 as u64)
            + (self.h3 as u64) * (self.s2 as u64)
            + (self.h4 as u64) * (self.s1 as u64);

        let d1 = (self.h0 as u64) * (self.r1 as u64)
            + (self.h1 as u64) * (self.r0 as u64)
            + (self.h2 as u64) * (self.s4 as u64)
            + (self.h3 as u64) * (self.s3 as u64)
            + (self.h4 as u64) * (self.s2 as u64);

        let d2 = (self.h0 as u64) * (self.r2 as u64)
            + (self.h1 as u64) * (self.r1 as u64)
            + (self.h2 as u64) * (self.r0 as u64)
            + (self.h3 as u64) * (self.s4 as u64)
            + (self.h4 as u64) * (self.s3 as u64);

        let d3 = (self.h0 as u64) * (self.r3 as u64)
            + (self.h1 as u64) * (self.r2 as u64)
            + (self.h2 as u64) * (self.r1 as u64)
            + (self.h3 as u64) * (self.r0 as u64)
            + (self.h4 as u64) * (self.s4 as u64);

        let d4 = (self.h0 as u64) * (self.r4 as u64)
            + (self.h1 as u64) * (self.r3 as u64)
            + (self.h2 as u64) * (self.r2 as u64)
            + (self.h3 as u64) * (self.r1 as u64)
            + (self.h4 as u64) * (self.r0 as u64);

        // Carry reduction
        let mut c: u64;
        c = d0 >> 26; self.h0 = (d0 & 0x3ffffff) as u32;
        let d1 = d1 + c; c = d1 >> 26; self.h1 = (d1 & 0x3ffffff) as u32;
        let d2 = d2 + c; c = d2 >> 26; self.h2 = (d2 & 0x3ffffff) as u32;
        let d3 = d3 + c; c = d3 >> 26; self.h3 = (d3 & 0x3ffffff) as u32;
        let d4 = d4 + c; c = d4 >> 26; self.h4 = (d4 & 0x3ffffff) as u32;
        self.h0 += (c * 5) as u32;
        c = (self.h0 >> 26) as u64; self.h0 &= 0x3ffffff;
        self.h1 += c as u32;
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() >= needed {
                self.buffer[self.buf_len..16].copy_from_slice(&data[..needed]);
                let blk = self.buffer;
                self.process_block(&blk, false);
                offset += needed;
                self.buf_len = 0;
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        while offset + 16 <= data.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&data[offset..offset + 16]);
            self.process_block(&blk, false);
            offset += 16;
        }

        let remaining = &data[offset..];
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buf_len = remaining.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut blk = [0u8; 16];
            blk[..self.buf_len].copy_from_slice(&self.buffer[..self.buf_len]);
            self.process_block(&blk[..self.buf_len], true);
        }

        // Full carry
        let mut c: u32;
        c = self.h1 >> 26; self.h1 &= 0x3ffffff;
        self.h2 += c; c = self.h2 >> 26; self.h2 &= 0x3ffffff;
        self.h3 += c; c = self.h3 >> 26; self.h3 &= 0x3ffffff;
        self.h4 += c; c = self.h4 >> 26; self.h4 &= 0x3ffffff;
        self.h0 += c * 5; c = self.h0 >> 26; self.h0 &= 0x3ffffff;
        self.h1 += c;

        // Compute h + -p to check for wrap
        let g0 = self.h0.wrapping_add(5); c = g0 >> 26;
        let g1 = self.h1.wrapping_add(c); c = g1 >> 26;
        let g2 = self.h2.wrapping_add(c); c = g2 >> 26;
        let g3 = self.h3.wrapping_add(c); c = g3 >> 26;
        let g4 = self.h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if g4 borrowed, else g
        let mask = ((g4 >> 31) as u32).wrapping_sub(1);
        let g0 = g0 & 0x3ffffff;
        let g1 = g1 & 0x3ffffff;
        let g2 = g2 & 0x3ffffff;
        let g3 = g3 & 0x3ffffff;

        self.h0 = (self.h0 & !mask) | (g0 & mask);
        self.h1 = (self.h1 & !mask) | (g1 & mask);
        self.h2 = (self.h2 & !mask) | (g2 & mask);
        self.h3 = (self.h3 & !mask) | (g3 & mask);
        self.h4 = (self.h4 & !mask) | (g4 & mask);

        // Convert back to 32-bit words
        let f0 = ((self.h0) | (self.h1 << 26)) as u64 + self.pad[0] as u64;
        let f1 = ((self.h1 >> 6) | (self.h2 << 20)) as u64 + self.pad[1] as u64 + (f0 >> 32);
        let f2 = ((self.h2 >> 12) | (self.h3 << 14)) as u64 + self.pad[2] as u64 + (f1 >> 32);
        let f3 = ((self.h3 >> 18) | (self.h4 << 8)) as u64 + self.pad[3] as u64 + (f2 >> 32);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        tag
    }
}

/// Compute Poly1305 MAC over message
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(message);
    p.finalize()
}
