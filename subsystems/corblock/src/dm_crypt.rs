//! `dm_crypt.rs` — LUKS2 / dm-crypt block device encryption engine for CorOS.
//! Implements IEEE 1619 XTS mode with Galois Field GF(2^128) tweak updates,
//! 128-bit block cipher processing, and LUKS2 metadata parsing.

use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;
pub const AES_BLOCK_SIZE: usize = 16;
pub const LUKS2_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// Errors occurring in the dm-crypt / LUKS2 subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptError {
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidSectorSize(u32),
    BufferLengthMismatch,
    KeyLengthInvalid,
    KeyslotInactive,
    DecryptionFailed,
    StorageError,
}

/// AES S-Box lookup table (Rijndael forward S-box).
#[rustfmt::skip]
const SBOX: [u8; 256] = [
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

/// AES Inverse S-Box lookup table.
#[rustfmt::skip]
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES Rcon constants.
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xtime(b: u8) -> u8 {
    if (b & 0x80) != 0 {
        (b << 1) ^ 0x1b
    } else {
        b << 1
    }
}

/// AES-128 core implementation (10 rounds, 128-bit key, 128-bit block).
#[derive(Debug, Clone)]
pub struct Aes128Cipher {
    round_keys: [[u8; 16]; 11],
}

impl Aes128Cipher {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = [[0u8; 16]; 11];
        round_keys[0].copy_from_slice(key);

        for round in 1..=10 {
            let mut temp = [
                round_keys[round - 1][12],
                round_keys[round - 1][13],
                round_keys[round - 1][14],
                round_keys[round - 1][15],
            ];

            // RotWord & SubWord
            let k0 = SBOX[temp[1] as usize] ^ RCON[round];
            let k1 = SBOX[temp[2] as usize];
            let k2 = SBOX[temp[3] as usize];
            let k3 = SBOX[temp[0] as usize];
            temp = [k0, k1, k2, k3];

            for i in 0..4 {
                round_keys[round][i] = round_keys[round - 1][i] ^ temp[i];
            }
            for col in 1..4 {
                for row in 0..4 {
                    round_keys[round][col * 4 + row] =
                        round_keys[round - 1][col * 4 + row] ^ round_keys[round][(col - 1) * 4 + row];
                }
            }
        }

        Self { round_keys }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;

        // Round 0: AddRoundKey
        for i in 0..16 {
            state[i] ^= self.round_keys[0][i];
        }

        // Rounds 1..9
        for round in 1..10 {
            // SubBytes
            for b in state.iter_mut() {
                *b = SBOX[*b as usize];
            }

            // ShiftRows
            let tmp = state;
            state[1] = tmp[5]; state[5] = tmp[9]; state[9] = tmp[13]; state[13] = tmp[1];
            state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
            state[3] = tmp[15]; state[7] = tmp[3]; state[11] = tmp[7]; state[15] = tmp[11];

            // MixColumns
            for col in 0..4 {
                let c = col * 4;
                let s0 = state[c];
                let s1 = state[c + 1];
                let s2 = state[c + 2];
                let s3 = state[c + 3];

                state[c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
                state[c + 1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
                state[c + 2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
                state[c + 3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
            }

            // AddRoundKey
            for i in 0..16 {
                state[i] ^= self.round_keys[round][i];
            }
        }

        // Round 10 (No MixColumns)
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
        let tmp = state;
        state[1] = tmp[5]; state[5] = tmp[9]; state[9] = tmp[13]; state[13] = tmp[1];
        state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
        state[3] = tmp[15]; state[7] = tmp[3]; state[11] = tmp[7]; state[15] = tmp[11];

        for i in 0..16 {
            state[i] ^= self.round_keys[10][i];
        }

        state
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;

        // Round 10 inverse
        for i in 0..16 {
            state[i] ^= self.round_keys[10][i];
        }

        let tmp = state;
        state[1] = tmp[13]; state[5] = tmp[1]; state[9] = tmp[5]; state[13] = tmp[9];
        state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
        state[3] = tmp[7]; state[7] = tmp[11]; state[11] = tmp[15]; state[15] = tmp[3];

        for b in state.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }

        // Rounds 9 down to 1
        for round in (1..10).rev() {
            for i in 0..16 {
                state[i] ^= self.round_keys[round][i];
            }

            // InvMixColumns
            for col in 0..4 {
                let c = col * 4;
                let s0 = state[c];
                let s1 = state[c + 1];
                let s2 = state[c + 2];
                let s3 = state[c + 3];

                let x2 = |b| xtime(b);
                let x4 = |b| xtime(x2(b));
                let x8 = |b| xtime(x4(b));

                let m9 = |b| x8(b) ^ b;
                let mb = |b| x8(b) ^ x2(b) ^ b;
                let md = |b| x8(b) ^ x4(b) ^ b;
                let me = |b| x8(b) ^ x4(b) ^ x2(b);

                state[c] = me(s0) ^ mb(s1) ^ md(s2) ^ m9(s3);
                state[c + 1] = m9(s0) ^ me(s1) ^ mb(s2) ^ md(s3);
                state[c + 2] = md(s0) ^ m9(s1) ^ me(s2) ^ mb(s3);
                state[c + 3] = mb(s0) ^ md(s1) ^ m9(s2) ^ me(s3);
            }

            let tmp = state;
            state[1] = tmp[13]; state[5] = tmp[1]; state[9] = tmp[5]; state[13] = tmp[9];
            state[2] = tmp[10]; state[6] = tmp[14]; state[10] = tmp[2]; state[14] = tmp[6];
            state[3] = tmp[7]; state[7] = tmp[11]; state[11] = tmp[15]; state[15] = tmp[3];

            for b in state.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
        }

        // Round 0: AddRoundKey
        for i in 0..16 {
            state[i] ^= self.round_keys[0][i];
        }

        state
    }
}

/// Tweak multiplication in GF(2^128) by alpha = x with polynomial x^128 + x^7 + x^2 + x + 1 (IEEE 1619).
pub fn gf128_mul_x(tweak: &mut [u8; 16]) {
    let mut carry = 0u8;
    for b in tweak.iter_mut() {
        let next_carry = *b >> 7;
        *b = (*b << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

/// XTS Mode Engine implementing IEEE 1619.
#[derive(Debug, Clone)]
pub struct XtsEngine {
    cipher_k1: Aes128Cipher,
    cipher_k2: Aes128Cipher,
}

impl XtsEngine {
    /// Creates an XTS engine from a 256-bit key (two 128-bit keys: K1 for data, K2 for tweak).
    pub fn new(key256: &[u8; 32]) -> Self {
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k1.copy_from_slice(&key256[0..16]);
        k2.copy_from_slice(&key256[16..32]);

        Self {
            cipher_k1: Aes128Cipher::new(&k1),
            cipher_k2: Aes128Cipher::new(&k2),
        }
    }

    /// Computes the initial sector tweak T0 by encrypting the 64-bit sector number with K2.
    pub fn compute_initial_tweak(&self, sector: u64) -> [u8; 16] {
        let mut sector_block = [0u8; 16];
        sector_block[0..8].copy_from_slice(&sector.to_le_bytes());
        self.cipher_k2.encrypt_block(&sector_block)
    }

    /// Encrypts an entire 512-byte sector using XTS-AES.
    pub fn encrypt_sector(&self, sector: u64, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), CryptError> {
        if plaintext.len() != SECTOR_SIZE || ciphertext.len() != SECTOR_SIZE {
            return Err(CryptError::BufferLengthMismatch);
        }

        let mut tweak = self.compute_initial_tweak(sector);

        for block_idx in 0..(SECTOR_SIZE / AES_BLOCK_SIZE) {
            let offset = block_idx * AES_BLOCK_SIZE;
            let mut pt_block = [0u8; 16];
            pt_block.copy_from_slice(&plaintext[offset..offset + 16]);

            // P ^ T
            for i in 0..16 {
                pt_block[i] ^= tweak[i];
            }

            // Cipher_K1(P ^ T)
            let mut ct_block = self.cipher_k1.encrypt_block(&pt_block);

            // C = Cipher_K1(P ^ T) ^ T
            for i in 0..16 {
                ct_block[i] ^= tweak[i];
            }

            ciphertext[offset..offset + 16].copy_from_slice(&ct_block);
            gf128_mul_x(&mut tweak);
        }

        Ok(())
    }

    /// Decrypts an entire 512-byte sector using XTS-AES.
    pub fn decrypt_sector(&self, sector: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), CryptError> {
        if plaintext.len() != SECTOR_SIZE || ciphertext.len() != SECTOR_SIZE {
            return Err(CryptError::BufferLengthMismatch);
        }

        let mut tweak = self.compute_initial_tweak(sector);

        for block_idx in 0..(SECTOR_SIZE / AES_BLOCK_SIZE) {
            let offset = block_idx * AES_BLOCK_SIZE;
            let mut ct_block = [0u8; 16];
            ct_block.copy_from_slice(&ciphertext[offset..offset + 16]);

            // C ^ T
            for i in 0..16 {
                ct_block[i] ^= tweak[i];
            }

            // InvCipher_K1(C ^ T)
            let mut pt_block = self.cipher_k1.decrypt_block(&ct_block);

            // P = InvCipher_K1(C ^ T) ^ T
            for i in 0..16 {
                pt_block[i] ^= tweak[i];
            }

            plaintext[offset..offset + 16].copy_from_slice(&pt_block);
            gf128_mul_x(&mut tweak);
        }

        Ok(())
    }
}

/// LUKS2 Primary Header structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks2Header {
    pub magic: [u8; 6],
    pub version: u16,
    pub hdr_size: u64,
    pub seq_id: u64,
    pub sector_size: u32,
    pub label: [u8; 48],
    pub uuid: [u8; 40],
}

impl Luks2Header {
    pub fn new(sector_size: u32, uuid_str: &str) -> Self {
        let mut uuid_bytes = [0u8; 40];
        let bytes = uuid_str.as_bytes();
        let len = bytes.len().min(40);
        uuid_bytes[..len].copy_from_slice(&bytes[..len]);

        Self {
            magic: *LUKS2_MAGIC,
            version: 2,
            hdr_size: 16384,
            seq_id: 1,
            sector_size,
            label: [0u8; 48],
            uuid: uuid_bytes,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptError> {
        if bytes.len() < 128 {
            return Err(CryptError::BufferLengthMismatch);
        }

        if &bytes[0..6] != LUKS2_MAGIC {
            return Err(CryptError::InvalidMagic);
        }

        let version = u16::from_be_bytes([bytes[6], bytes[7]]);
        if version != 2 {
            return Err(CryptError::UnsupportedVersion(version));
        }

        let hdr_size = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let seq_id = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let sector_size = u32::from_be_bytes(bytes[24..28].try_into().unwrap());

        if sector_size != 512 && sector_size != 4096 {
            return Err(CryptError::InvalidSectorSize(sector_size));
        }

        let mut label = [0u8; 48];
        label.copy_from_slice(&bytes[28..76]);

        let mut uuid = [0u8; 40];
        uuid.copy_from_slice(&bytes[76..116]);

        Ok(Self {
            magic: *LUKS2_MAGIC,
            version,
            hdr_size,
            seq_id,
            sector_size,
            label,
            uuid,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; 512];
        out[0..6].copy_from_slice(&self.magic);
        out[6..8].copy_from_slice(&self.version.to_be_bytes());
        out[8..16].copy_from_slice(&self.hdr_size.to_be_bytes());
        out[16..24].copy_from_slice(&self.seq_id.to_be_bytes());
        out[24..28].copy_from_slice(&self.sector_size.to_be_bytes());
        out[28..76].copy_from_slice(&self.label);
        out[76..116].copy_from_slice(&self.uuid);
        out
    }
}

/// Transparent encrypted block device mapper target.
#[derive(Debug, Clone)]
pub struct DmCryptDevice {
    pub header: Luks2Header,
    pub xts: Option<XtsEngine>,
    pub storage: Vec<u8>,
    pub total_sectors: u64,
}

impl DmCryptDevice {
    pub fn new(header: Luks2Header, total_sectors: u64) -> Self {
        Self {
            header,
            xts: None,
            storage: vec![0u8; (total_sectors as usize) * SECTOR_SIZE],
            total_sectors,
        }
    }

    pub fn unlock(&mut self, master_key256: &[u8; 32]) {
        self.xts = Some(XtsEngine::new(master_key256));
    }

    pub fn lock(&mut self) {
        self.xts = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.xts.is_some()
    }

    pub fn write_sector(&mut self, sector: u64, plaintext: &[u8]) -> Result<(), CryptError> {
        let xts = self.xts.as_ref().ok_or(CryptError::KeyslotInactive)?;
        if sector >= self.total_sectors {
            return Err(CryptError::StorageError);
        }

        let mut ciphertext = [0u8; SECTOR_SIZE];
        xts.encrypt_sector(sector, plaintext, &mut ciphertext)?;

        let offset = (sector as usize) * SECTOR_SIZE;
        self.storage[offset..offset + SECTOR_SIZE].copy_from_slice(&ciphertext);
        Ok(())
    }

    pub fn read_sector(&self, sector: u64, plaintext: &mut [u8]) -> Result<(), CryptError> {
        let xts = self.xts.as_ref().ok_or(CryptError::KeyslotInactive)?;
        if sector >= self.total_sectors {
            return Err(CryptError::StorageError);
        }

        let offset = (sector as usize) * SECTOR_SIZE;
        let ciphertext = &self.storage[offset..offset + SECTOR_SIZE];
        xts.decrypt_sector(sector, ciphertext, plaintext)
    }
}
