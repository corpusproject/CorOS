//! RFC 7748 X25519 Elliptic Curve Diffie-Hellman key exchange using the Curve25519 Montgomery ladder.

use crate::constant_time::{ct_eq_32, zeroize_slice};
use crate::ed25519_sign::Fe25519;

/// Standard Curve25519 base point $u = 9$ in little-endian bytes.
pub const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Clamps a 32-byte X25519 private scalar according to RFC 7748 Section 5:
/// clears the 3 lowest bits, clears bit 255, and sets bit 254.
#[inline]
pub fn clamp_scalar(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Constant-time conditional swap of two Montgomery projective coordinate pairs `(x2, z2)` and `(x3, z3)`.
#[inline]
pub fn cswap_projective(swap: u64, x2: &mut Fe25519, x3: &mut Fe25519, z2: &mut Fe25519, z3: &mut Fe25519) {
    Fe25519::cswap(swap, x2, x3);
    Fe25519::cswap(swap, z2, z3);
}

/// RFC 7748 Section 5 Curve25519 Montgomery ladder scalar multiplication `X25519(scalar, point)`.
/// Computes the shared $u$-coordinate on $v^2 = u^3 + 486662 u^2 + u$ over $GF(2^{255}-19)$.
pub fn x25519(scalar: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    let mut k = clamp_scalar(scalar);
    let x_1 = Fe25519::from_bytes(&point);

    let mut x_2 = Fe25519::ONE;
    let mut z_2 = Fe25519::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe25519::ONE;
    let mut swap = 0u64;

    let mut t = 255usize;
    while t > 0 {
        t -= 1;
        let k_t = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= k_t;
        cswap_projective(swap, &mut x_2, &mut x_3, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x_3 = da.add(&cb).square();
        z_3 = x_1.mul(&da.sub(&cb).square());
        x_2 = aa.mul(&bb);
        z_2 = e.mul(&aa.add(&Fe25519::MONTGOMERY_A24.mul(&e)));
    }

    cswap_projective(swap, &mut x_2, &mut x_3, &mut z_2, &mut z_3);
    zeroize_slice(&mut k);

    let z_inv = z_2.invert();
    let result = x_2.mul(&z_inv);
    result.to_bytes()
}

/// Derives an X25519 public key from a 32-byte private key by multiplying the base point $u = 9$.
pub fn x25519_public_key(private_key: [u8; 32]) -> [u8; 32] {
    x25519(private_key, X25519_BASEPOINT)
}

/// Runs RFC 7748 Section 6.1 Known Answer Tests and Diffie-Hellman key agreement verification.
pub fn run_x25519_self_test() -> u32 {
    let mut passed = 0u32;

    // 1. RFC 7748 Section 6.1 Test Vector #1
    let scalar_1: [u8; 32] = [
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
        0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
        0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
        0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
    ];
    let u_coord_1: [u8; 32] = [
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
        0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
        0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
        0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
    ];
    let expected_1: [u8; 32] = [
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
        0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
        0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
        0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
    ];
    let out_1 = x25519(scalar_1, u_coord_1);
    if ct_eq_32(&out_1, &expected_1) {
        passed += 1;
    }

    // 2. RFC 7748 Section 6.1 Alice-Bob Diffie-Hellman Key Exchange Test Vector
    let alice_priv: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];
    let alice_expected_pub: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ];
    let bob_priv: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ];
    let bob_expected_pub: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ];
    let expected_shared: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    ];

    let alice_pub = x25519_public_key(alice_priv);
    let bob_pub = x25519_public_key(bob_priv);
    if ct_eq_32(&alice_pub, &alice_expected_pub) && ct_eq_32(&bob_pub, &bob_expected_pub) {
        passed += 1;
    }

    let shared_ab = x25519(alice_priv, bob_pub);
    let shared_ba = x25519(bob_priv, alice_pub);
    if ct_eq_32(&shared_ab, &expected_shared) && ct_eq_32(&shared_ba, &expected_shared) {
        passed += 1;
    }

    passed
}
