#![no_std]
//! `corcrypto` — CorOS Pure-Rust Cryptographic Suite & Hardware Entropy Engine.
//!
//! Provides constant-time primitives, FIPS 180-4 SHA-256 and SHA-512, RFC 7693 BLAKE2b,
//! RFC 8439 ChaCha20-Poly1305 AEAD, FIPS 197 AES-256-GCM AEAD, RFC 8032 Ed25519 finite
//! field & signature primitives, RFC 7748 X25519 Montgomery ladder key exchange,
//! hardware RDRAND/RDSEED + ChaCha20 CSPRNG, RFC 5869 HKDF & RFC 8018 PBKDF2,
//! NIST/RFC Known Answer Tests, and UEFI PE32+ Secure Boot manifest verification.

extern crate alloc;

pub mod aes_gcm;
pub mod blake2b_simd;
pub mod chacha20_poly1305;
pub mod constant_time;
pub mod csprng_entropy;
pub mod ed25519_sign;
pub mod hkdf_pbkdf2;
pub mod nist_kat_vectors;
pub mod secure_boot_verify;
pub mod sha256_engine;
pub mod sha512_engine;
pub mod x25519_kex;

/// Runs real NIST/RFC Known Answer Tests (KATs) and algorithm self-tests across all 12 modules.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += constant_time::run_constant_time_self_test();
    passed += sha256_engine::run_sha256_self_test();
    passed += sha512_engine::run_sha512_self_test();
    passed += blake2b_simd::run_blake2b_self_test();
    passed += chacha20_poly1305::run_chacha20_poly1305_self_test();
    passed += aes_gcm::run_aes_gcm_self_test();
    passed += ed25519_sign::run_ed25519_self_test();
    passed += x25519_kex::run_x25519_self_test();
    passed += csprng_entropy::run_csprng_self_test();
    passed += hkdf_pbkdf2::run_kdf_self_test();
    passed += nist_kat_vectors::run_all_kat_verifications();
    passed += secure_boot_verify::run_secure_boot_self_test();
    passed
}
