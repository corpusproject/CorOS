//! RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256)
//! and RFC 8018 Password-Based Key Derivation Function 2 (PBKDF2-HMAC-SHA256).

use crate::constant_time::{ct_eq_32, ct_eq_slice, zeroize_slice};
use crate::sha256_engine::{hmac_sha256, HmacSha256};

/// RFC 5869 Section 2.2 `HKDF-Extract(salt, IKM) -> PRK`.
/// Extracts a fixed-length 32-byte pseudorandom key (`PRK`) from input keying material `ikm`.
/// If `salt` is empty, a 32-byte all-zero salt is used per RFC 5869.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    if salt.is_empty() {
        let zero_salt = [0u8; 32];
        hmac_sha256(&zero_salt, ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

/// RFC 5869 Section 2.3 `HKDF-Expand(PRK, info, L) -> OKM`.
/// Expands a 32-byte pseudorandom key `prk` with context `info` into `okm` (up to `255 * 32 = 8160` bytes).
/// Returns `true` on success, or `false` if `okm.len() > 255 * 32`.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> bool {
    if okm.len() > 255 * 32 {
        return false;
    }

    let mut t_prev = [0u8; 32];
    let mut offset = 0usize;
    let mut counter = 1u8;

    while offset < okm.len() {
        let mut mac = HmacSha256::new(prk);
        if counter > 1 {
            mac.update(&t_prev);
        }
        mac.update(info);
        mac.update(&[counter]);
        let t_curr = mac.finalize();

        let copy_len = (okm.len() - offset).min(32);
        okm[offset..offset + copy_len].copy_from_slice(&t_curr[..copy_len]);
        t_prev = t_curr;

        offset += copy_len;
        counter = counter.wrapping_add(1);
    }

    zeroize_slice(&mut t_prev);
    true
}

/// Combined RFC 5869 `HKDF-SHA256(salt, ikm, info, okm)`.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    let mut prk = hkdf_extract(salt, ikm);
    let ok = hkdf_expand(&prk, info, okm);
    zeroize_slice(&mut prk);
    ok
}

/// RFC 8018 Section 5.2 `PBKDF2-HMAC-SHA256(P, S, c, dkLen)`.
/// Derives a cryptographic key into `out` using `iterations` rounds of iterated `HMAC-SHA256`.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let rounds = iterations.max(1);
    let mut block_index = 1u32;
    let mut offset = 0usize;

    while offset < out.len() {
        // U_1 = PRF(P, S || INT_32_BE(i))
        let mut mac = HmacSha256::new(password);
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize();
        let mut t = u;

        let mut iter = 1u32;
        while iter < rounds {
            u = hmac_sha256(password, &u);
            let mut j = 0;
            while j < 32 {
                t[j] ^= u[j];
                j += 1;
            }
            iter += 1;
        }

        let take = (out.len() - offset).min(32);
        out[offset..offset + take].copy_from_slice(&t[..take]);

        zeroize_slice(&mut u);
        zeroize_slice(&mut t);

        offset += take;
        block_index = block_index.wrapping_add(1);
    }
}

/// Runs RFC 5869 HKDF-SHA256 and RFC 6070 / RFC 8018 PBKDF2-HMAC-SHA256 Known Answer Tests.
pub fn run_kdf_self_test() -> u32 {
    let mut passed = 0u32;

    // 1. RFC 5869 Appendix A.1 Test Case 1 for HKDF-SHA256
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ];
    let expected_prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    ];
    let expected_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    ];

    let prk = hkdf_extract(&salt, &ikm);
    if ct_eq_32(&prk, &expected_prk) {
        passed += 1;
    }

    let mut okm = [0u8; 42];
    if hkdf_expand(&prk, &info, &mut okm) && ct_eq_slice(&okm, &expected_okm) {
        passed += 1;
    }

    // 2. PBKDF2-HMAC-SHA256 Test Vector (Password = "password", Salt = "salt", c = 2)
    let mut dk_c2 = [0u8; 32];
    pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut dk_c2);
    let expected_pbkdf2_c2: [u8; 32] = [
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf,
        0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
    ];
    if ct_eq_32(&dk_c2, &expected_pbkdf2_c2) {
        passed += 1;
    }

    passed
}
