//! RFC 8439 ChaCha20 Stream Cipher for CorOS
//!
//! Provides ultra-fast 256-bit software symmetric encryption without cache timing leaks.

use alloc::vec::Vec;

pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// Initialize with 256-bit (32 byte) key, 96-bit (12 byte) nonce, and 32-bit initial counter
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];

        // Constants: "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        // Block counter
        state[12] = counter;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        Self { state }
    }

    #[inline(always)]
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]); x[d] ^= x[a]; x[d] = x[d].rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]); x[b] ^= x[c]; x[b] = x[b].rotate_left(7);
    }

    fn generate_block(&mut self) -> [u8; 64] {
        let mut x = self.state;

        // 10 double rounds (20 rounds total)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut x, 0, 4, 8, 12);
            Self::quarter_round(&mut x, 1, 5, 9, 13);
            Self::quarter_round(&mut x, 2, 6, 10, 14);
            Self::quarter_round(&mut x, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut x, 0, 5, 10, 15);
            Self::quarter_round(&mut x, 1, 6, 11, 12);
            Self::quarter_round(&mut x, 2, 7, 8, 13);
            Self::quarter_round(&mut x, 3, 4, 9, 14);
        }

        let mut block = [0u8; 64];
        for i in 0..16 {
            let sum = x[i].wrapping_add(self.state[i]);
            block[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
        }

        // Increment block counter
        self.state[12] = self.state[12].wrapping_add(1);

        block
    }

    /// Encrypts or decrypts arbitrary data (XOR stream cipher)
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut offset = 0;

        while offset < data.len() {
            let keystream = self.generate_block();
            let chunk_len = core::cmp::min(64, data.len() - offset);
            for i in 0..chunk_len {
                out.push(data[offset + i] ^ keystream[i]);
            }
            offset += chunk_len;
        }

        out
    }

    /// Encrypts or decrypts arbitrary data in-place without heap allocations
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.generate_block();
            let chunk_len = core::cmp::min(64, data.len() - offset);
            for i in 0..chunk_len {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk_len;
        }
    }
}

