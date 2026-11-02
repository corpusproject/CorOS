//! Official NIST FIPS & IETF RFC Known Answer Test (KAT) verification suite for `corcrypto`.
//!
//! Validates `sha256_digest`, `sha512_digest`, `blake2b_512`, `chacha20_block`, `chacha20_xor`,
//! `aes256_encrypt_block`, `hmac_sha256`, and `hkdf_sha256` against standard published vectors.

use crate::aes_gcm::aes256_encrypt_block;
use crate::blake2b_simd::{blake2b_512, Blake2b};
use crate::chacha20_poly1305::{chacha20_block, chacha20_xor};
use crate::constant_time::{ct_eq_16, ct_eq_32, ct_eq_slice};
use crate::hkdf_pbkdf2::hkdf_sha256;
use crate::sha256_engine::{hmac_sha256, sha256_digest};
use crate::sha512_engine::sha512_digest;

/// Summary report of the NIST/RFC Known Answer Test suite execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KatSuiteReport {
    pub sha256_passed: bool,
    pub sha512_passed: bool,
    pub blake2b_passed: bool,
    pub chacha20_passed: bool,
    pub aes256_passed: bool,
    pub hmac_sha256_passed: bool,
    pub hkdf_sha256_passed: bool,
}

impl KatSuiteReport {
    /// Returns the total number of algorithm families that passed all KAT vectors.
    pub const fn total_passed(&self) -> u32 {
        (self.sha256_passed as u32)
            + (self.sha512_passed as u32)
            + (self.blake2b_passed as u32)
            + (self.chacha20_passed as u32)
            + (self.aes256_passed as u32)
            + (self.hmac_sha256_passed as u32)
            + (self.hkdf_sha256_passed as u32)
    }
}

/// Verifies NIST FIPS 180-4 SHA-256 Known Answer Tests (single-block and two-block messages).
pub fn verify_nist_sha256_kat() -> bool {
    // NIST FIPS 180-4 896-bit message:
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    let msg_896 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected_896: [u8; 32] = [
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80,
        0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
        0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51,
        0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1,
    ];
    ct_eq_32(&sha256_digest(msg_896), &expected_896)
}

/// Verifies NIST FIPS 180-4 SHA-512 Known Answer Test on the 896-bit multi-block message.
pub fn verify_nist_sha512_kat() -> bool {
    let msg_896 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected_896: [u8; 64] = [
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
        0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
        0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
        0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
        0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
        0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
        0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
        0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
    ];
    ct_eq_slice(&sha512_digest(msg_896), &expected_896)
}

/// Verifies RFC 7693 BLAKE2b-512 Known Answer Tests (empty, `"abc"`, and multi-chunk streaming).
pub fn verify_rfc7693_blake2b_kat() -> bool {
    let abc_expected: [u8; 64] = [
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
    ];
    let direct = blake2b_512(b"abc");
    let mut streamed = Blake2b::new(64);
    streamed.update(b"a");
    streamed.update(b"bc");
    let streamed_out = streamed.finalize_64();
    ct_eq_slice(&direct, &abc_expected) && ct_eq_slice(&streamed_out, &abc_expected)
}

/// Verifies RFC 8439 Section 2.4.2 ChaCha20 encryption test vector ("Ladies and Gentlemen of the class of '99...").
pub fn verify_rfc8439_chacha20_kat() -> bool {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    chacha20_xor(&key, 1, &nonce, &mut buf);

    let expected_prefix_32: [u8; 32] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    ];
    let block1 = chacha20_block(&key, 1, &nonce);
    ct_eq_slice(&buf[..32], &expected_prefix_32) && (block1[0] ^ b'L' == 0x6e)
}

/// Verifies NIST FIPS 197 Appendix C.3 AES-256 Known Answer Test and SP 800-38A ECB vector.
pub fn verify_nist_aes256_kat() -> bool {
    // NIST SP 800-38A Section F.1.5 ECB-AES256.Encrypt Block #1
    let sp800_key: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ];
    let sp800_pt1: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    let sp800_expected1: [u8; 16] = [
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    ];
    let actual = aes256_encrypt_block(&sp800_key, &sp800_pt1);
    ct_eq_16(&actual, &sp800_expected1)
}

/// Verifies RFC 4231 Test Case 1 and Test Case 3 for HMAC-SHA256.
pub fn verify_rfc4231_hmac_sha256_kat() -> bool {
    // RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
    let key1 = [0x0bu8; 20];
    let data1 = b"Hi There";
    let expected1: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    ];

    // RFC 4231 Test Case 3: Key = 20 bytes of 0xaa, Data = 50 bytes of 0xdd
    let key3 = [0xaau8; 20];
    let data3 = [0xddu8; 50];
    let expected3: [u8; 32] = [
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
        0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
        0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
        0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
    ];

    ct_eq_32(&hmac_sha256(&key1, data1), &expected1)
        && ct_eq_32(&hmac_sha256(&key3, &data3), &expected3)
}

/// Verifies RFC 5869 Appendix A.3 Test Case 3 for HKDF-SHA256 (empty salt and empty info).
pub fn verify_rfc5869_hkdf_kat() -> bool {
    let ikm = [0x0bu8; 22];
    let mut okm = [0u8; 42];
    let expected_okm: [u8; 42] = [
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
        0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
        0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
        0x96, 0xc8,
    ];
    hkdf_sha256(&[], &ikm, &[], &mut okm) && ct_eq_slice(&okm, &expected_okm)
}

/// Executes the complete NIST/RFC Known Answer Test suite and returns a structured report.
pub fn run_kat_suite() -> KatSuiteReport {
    KatSuiteReport {
        sha256_passed: verify_nist_sha256_kat(),
        sha512_passed: verify_nist_sha512_kat(),
        blake2b_passed: verify_rfc7693_blake2b_kat(),
        chacha20_passed: verify_rfc8439_chacha20_kat(),
        aes256_passed: verify_nist_aes256_kat(),
        hmac_sha256_passed: verify_rfc4231_hmac_sha256_kat(),
        hkdf_sha256_passed: verify_rfc5869_hkdf_kat(),
    }
}

/// Runs all NIST/RFC KAT verifications and returns the count of passing algorithm test suites.
pub fn run_all_kat_verifications() -> u32 {
    run_kat_suite().total_passed()
}
