//! RFC 8439 ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
//!
//! Bare-metal no_std pure Rust implementation of RFC 8439 AEAD cipher.
//! Used extensively in modern secure protocols (TLS 1.3, WireGuard, SSH, QUIC).

use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    InvalidKeyLength,
    InvalidNonceLength,
    AuthenticationFailed,
    BufferOverflow,
}

/// RFC 8439 ChaCha20-Poly1305 AEAD Engine
pub struct ChaCha20Poly1305 {
    key: [u8; KEY_SIZE],
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20Poly1305 cipher instance with 256-bit key
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Derive the 32-byte Poly1305 one-time key using ChaCha20 with counter = 0
    fn derive_poly1305_key(&self, nonce: &[u8; NONCE_SIZE]) -> [u8; 32] {
        let mut chacha = ChaCha20::new(&self.key, nonce, 0);
        let mut block = [0u8; 64];
        chacha.apply_keystream(&mut block);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block[..32]);
        poly_key
    }

    /// Pad buffer with zeros to 16-byte boundary and feed into Poly1305
    fn pad16(poly: &mut Poly1305, len: usize) {
        let remainder = len % 16;
        if remainder != 0 {
            let pad_len = 16 - remainder;
            let zeros = [0u8; 16];
            poly.update(&zeros[..pad_len]);
        }
    }

    /// Encrypt plaintext in-place and append 16-byte authentication tag
    ///
    /// Plaintext buffer must have at least `TAG_SIZE` extra capacity at the end,
    /// or `out` buffer must be `plaintext.len() + TAG_SIZE`.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, AeadError> {
        let out_len = plaintext.len() + TAG_SIZE;
        if ciphertext_and_tag.len() < out_len {
            return Err(AeadError::BufferOverflow);
        }

        // 1. Derive Poly1305 one-time subkey
        let poly_key = self.derive_poly1305_key(nonce);

        // 2. Encrypt plaintext with ChaCha20 counter = 1
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        ciphertext_and_tag[..plaintext.len()].copy_from_slice(plaintext);
        chacha.apply_keystream(&mut ciphertext_and_tag[..plaintext.len()]);

        // 3. Compute Poly1305 MAC over (AAD || pad || Ciphertext || pad || len(AAD) || len(Ciphertext))
        let mut poly = Poly1305::new(&poly_key);

        // Feed AAD
        if !aad.is_empty() {
            poly.update(aad);
            Self::pad16(&mut poly, aad.len());
        }

        // Feed Ciphertext
        poly.update(&ciphertext_and_tag[..plaintext.len()]);
        Self::pad16(&mut poly, plaintext.len());

        // Feed lengths as 64-bit little endian
        let aad_len_bytes = (aad.len() as u64).to_le_bytes();
        let ct_len_bytes = (plaintext.len() as u64).to_le_bytes();
        poly.update(&aad_len_bytes);
        poly.update(&ct_len_bytes);

        // 4. Append tag
        let tag = poly.finalize();
        ciphertext_and_tag[plaintext.len()..out_len].copy_from_slice(&tag);

        Ok(out_len)
    }

    /// Decrypt ciphertext and verify 16-byte authentication tag in constant time
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<usize, AeadError> {
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err(AeadError::AuthenticationFailed);
        }

        let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
        if plaintext_out.len() < ct_len {
            return Err(AeadError::BufferOverflow);
        }

        let (ciphertext, received_tag) = ciphertext_and_tag.split_at(ct_len);

        // 1. Derive Poly1305 key
        let poly_key = self.derive_poly1305_key(nonce);

        // 2. Compute Poly1305 MAC over (AAD || pad || Ciphertext || pad || len(AAD) || len(Ciphertext))
        let mut poly = Poly1305::new(&poly_key);

        if !aad.is_empty() {
            poly.update(aad);
            Self::pad16(&mut poly, aad.len());
        }

        poly.update(ciphertext);
        Self::pad16(&mut poly, ciphertext.len());

        let aad_len_bytes = (aad.len() as u64).to_le_bytes();
        let ct_len_bytes = (ciphertext.len() as u64).to_le_bytes();
        poly.update(&aad_len_bytes);
        poly.update(&ct_len_bytes);

        let computed_tag = poly.finalize();

        // 3. Constant-time tag comparison
        let mut diff = 0u8;
        for i in 0..TAG_SIZE {
            diff |= computed_tag[i] ^ received_tag[i];
        }

        if diff != 0 {
            return Err(AeadError::AuthenticationFailed);
        }

        // 4. Decrypt ciphertext into plaintext_out
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        plaintext_out[..ct_len].copy_from_slice(ciphertext);
        chacha.apply_keystream(&mut plaintext_out[..ct_len]);

        Ok(ct_len)
    }
}
