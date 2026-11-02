//! CorOS Cryptographic Engine (Kernel Crypto Subsystem)
//!
//! Provides bare-metal implementations of cryptographic primitives:
//! - SHA-256 / HMAC-SHA256 (FIPS 180-4)
//! - SHA-512 / SHA-384 / HMAC-SHA512 (FIPS 180-4)
//! - AES-128 / AES-256 (FIPS 197) with ECB, CBC, CTR modes
//! - ChaCha20 Stream Cipher & Poly1305 Authenticator (RFC 8439)
//! - RSA PKCS#1 v1.5 Signature Verification & Multi-precision BigUint Arithmetic
//! - Ed25519 Twisted Edwards Curve Digital Signatures (RFC 8032)
//! - Hardware RDRAND / RDSEED Entropy Gathering & CSPRNG

pub mod sha256;
pub mod sha512;
pub mod aes;
pub mod chacha20;
pub mod poly1305;
pub mod rsa;
pub mod ed25519;
pub mod random;
pub mod aes_gcm;
pub mod xts_aes;
pub mod argon2;
pub mod chacha20poly1305;
pub mod kyber;

pub use sha256::{sha256_hash, HmacSha256};
pub use sha512::{sha512_hash, hmac_sha512, Sha512};
pub use aes::{Aes128, Aes256, CipherMode};
pub use chacha20::ChaCha20;
pub use poly1305::{Poly1305, poly1305_mac};
pub use rsa::{BigUint, RsaPublicKey};
pub use ed25519::{Ed25519PublicKey, EdwardsPoint, FieldElement};
pub use random::Csprng;
pub use aes_gcm::{AesGcm, GHash, Gf128};
pub use xts_aes::{XtsAes256, EncryptedVolume};
pub use argon2::{argon2id_derive_key, Argon2Params, Argon2Type, Argon2Block};
pub use chacha20poly1305::{ChaCha20Poly1305, AeadError};
pub use kyber::{Kyber768, KyberPublicKey, KyberSecretKey, Poly, PolyVec};


