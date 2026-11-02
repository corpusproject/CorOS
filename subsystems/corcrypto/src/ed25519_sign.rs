//! Prime field $GF(2^{255}-19)$ limb arithmetic (`Fe25519`), scalar reduction modulo
//! $\ell = 2^{252} + 27742317777372353535851937790883648493$, and Ed25519 verification primitives.

use crate::constant_time::{ct_eq_32, ct_select_u64};
use crate::sha512_engine::Sha512;

const MASK51: u64 = (1u64 << 51) - 1;

/// Element of the prime field $GF(2^{255}-19)$ represented in radix-$2^{51}$ across five 64-bit limbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe25519(pub [u64; 5]);

impl Fe25519 {
    /// Additive identity $0 \in GF(2^{255}-19)$.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0]);

    /// Multiplicative identity $1 \in GF(2^{255}-19)$.
    pub const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Edwards curve constant $d = -121665 / 121666 \bmod (2^{255}-19)$.
    pub const EDWARDS_D: Self = Self([
        0x0003_4dca_1359_78a3,
        0x0001_a828_3b15_6ebd,
        0x0005_e7a2_6001_c029,
        0x0007_39c6_63a0_3cbb,
        0x0005_2036_cee2_b6ff,
    ]);

    /// Montgomery ladder constant $a_{24} = (486662 - 2) / 4 = 121665$.
    pub const MONTGOMERY_A24: Self = Self([121665, 0, 0, 0, 0]);

    /// Constructs a field element from a small `u64` integer.
    #[inline(always)]
    pub const fn from_u64(v: u64) -> Self {
        Self([v & MASK51, v >> 51, 0, 0, 0])
    }

    /// Decodes a 32-byte little-endian array into $GF(2^{255}-19)$, masking bit 255 per RFC 7748 / RFC 8032.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ])
        };

        let l0 = load8(0) & MASK51;
        let l1 = (load8(6) >> 3) & MASK51;
        let l2 = (load8(12) >> 6) & MASK51;
        let l3 = (load8(19) >> 1) & MASK51;
        let l4 = (load8(24) >> 12) & MASK51;

        Self([l0, l1, l2, l3, l4])
    }

    /// Canonicalizes the field element modulo $2^{255}-19$ and serializes it into 32 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut l0 = self.0[0];
        let mut l1 = self.0[1];
        let mut l2 = self.0[2];
        let mut l3 = self.0[3];
        let mut l4 = self.0[4];

        // First carry pass
        let mut c = l0 >> 51;
        l0 &= MASK51;
        l1 += c;
        c = l1 >> 51;
        l1 &= MASK51;
        l2 += c;
        c = l2 >> 51;
        l2 &= MASK51;
        l3 += c;
        c = l3 >> 51;
        l3 &= MASK51;
        l4 += c;
        c = l4 >> 51;
        l4 &= MASK51;
        l0 += c * 19;

        // Second carry pass
        c = l0 >> 51;
        l0 &= MASK51;
        l1 += c;
        c = l1 >> 51;
        l1 &= MASK51;
        l2 += c;
        c = l2 >> 51;
        l2 &= MASK51;
        l3 += c;
        c = l3 >> 51;
        l3 &= MASK51;
        l4 += c;
        l4 &= MASK51;

        // Constant-time conditional subtraction of p = 2^255 - 19:
        // q = 1 iff l + 19 >= 2^255
        let mut q = (l0 + 19) >> 51;
        q = (l1 + q) >> 51;
        q = (l2 + q) >> 51;
        q = (l3 + q) >> 51;
        q = (l4 + q) >> 51;

        l0 += 19 * q;
        c = l0 >> 51;
        l0 &= MASK51;
        l1 += c;
        c = l1 >> 51;
        l1 &= MASK51;
        l2 += c;
        c = l2 >> 51;
        l2 &= MASK51;
        l3 += c;
        c = l3 >> 51;
        l3 &= MASK51;
        l4 = (l4 + c) & MASK51;

        let w0 = l0 | (l1 << 51);
        let w1 = (l1 >> 13) | (l2 << 38);
        let w2 = (l2 >> 26) | (l3 << 25);
        let w3 = (l3 >> 39) | (l4 << 12);

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    /// Computes $(a + b) \bmod (2^{255}-19)$.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut l0 = self.0[0] + rhs.0[0];
        let mut l1 = self.0[1] + rhs.0[1];
        let mut l2 = self.0[2] + rhs.0[2];
        let mut l3 = self.0[3] + rhs.0[3];
        let mut l4 = self.0[4] + rhs.0[4];

        let mut c = l0 >> 51;
        l0 &= MASK51;
        l1 += c;
        c = l1 >> 51;
        l1 &= MASK51;
        l2 += c;
        c = l2 >> 51;
        l2 &= MASK51;
        l3 += c;
        c = l3 >> 51;
        l3 &= MASK51;
        l4 += c;
        c = l4 >> 51;
        l4 &= MASK51;
        l0 += c * 19;

        Self([l0, l1, l2, l3, l4])
    }

    /// Computes $(a - b) \bmod (2^{255}-19)$ by adding $2p$ before subtracting to avoid underflow.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        // 2p in radix 2^51: limb 0 is 2*(2^51 - 19) = 0x000f_ffff_ffff_ffda, limbs 1..4 are 2*(2^51 - 1) = 0x000f_ffff_ffff_fffe
        const TWO_P0: u64 = 0x000f_ffff_ffff_ffda;
        const TWO_PN: u64 = 0x000f_ffff_ffff_fffe;

        let mut l0 = (self.0[0] + TWO_P0) - rhs.0[0];
        let mut l1 = (self.0[1] + TWO_PN) - rhs.0[1];
        let mut l2 = (self.0[2] + TWO_PN) - rhs.0[2];
        let mut l3 = (self.0[3] + TWO_PN) - rhs.0[3];
        let mut l4 = (self.0[4] + TWO_PN) - rhs.0[4];

        let mut c = l0 >> 51;
        l0 &= MASK51;
        l1 += c;
        c = l1 >> 51;
        l1 &= MASK51;
        l2 += c;
        c = l2 >> 51;
        l2 &= MASK51;
        l3 += c;
        c = l3 >> 51;
        l3 &= MASK51;
        l4 += c;
        c = l4 >> 51;
        l4 &= MASK51;
        l0 += c * 19;

        Self([l0, l1, l2, l3, l4])
    }

    /// Computes $(a \cdot b) \bmod (2^{255}-19)$ using 128-bit accumulator products.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let a0 = self.0[0] as u128;
        let a1 = self.0[1] as u128;
        let a2 = self.0[2] as u128;
        let a3 = self.0[3] as u128;
        let a4 = self.0[4] as u128;

        let r0 = rhs.0[0] as u128;
        let r1 = rhs.0[1] as u128;
        let r2 = rhs.0[2] as u128;
        let r3 = rhs.0[3] as u128;
        let r4 = rhs.0[4] as u128;

        let r1_19 = r1 * 19;
        let r2_19 = r2 * 19;
        let r3_19 = r3 * 19;
        let r4_19 = r4 * 19;

        let t0 = a0 * r0 + a1 * r4_19 + a2 * r3_19 + a3 * r2_19 + a4 * r1_19;
        let mut t1 = a0 * r1 + a1 * r0 + a2 * r4_19 + a3 * r3_19 + a4 * r2_19;
        let mut t2 = a0 * r2 + a1 * r1 + a2 * r0 + a3 * r4_19 + a4 * r3_19;
        let mut t3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * r4_19;
        let mut t4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;

        let mask = MASK51 as u128;

        let mut c = t0 >> 51;
        let mut l0 = (t0 & mask) as u64;
        t1 += c;
        c = t1 >> 51;
        let mut l1 = (t1 & mask) as u64;
        t2 += c;
        c = t2 >> 51;
        let l2 = (t2 & mask) as u64;
        t3 += c;
        c = t3 >> 51;
        let l3 = (t3 & mask) as u64;
        t4 += c;
        c = t4 >> 51;
        let l4 = (t4 & mask) as u64;

        l0 = l0.wrapping_add((c as u64) * 19);
        let c0 = l0 >> 51;
        l0 &= MASK51;
        l1 += c0;

        Self([l0, l1, l2, l3, l4])
    }

    /// Computes $a^2 \bmod (2^{255}-19)$.
    #[inline]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Repeatedly squares `self` `count` times: $a^{2^{\text{count}}} \bmod (2^{255}-19)$.
    #[inline]
    pub fn pow2k(&self, count: usize) -> Self {
        let mut acc = *self;
        let mut i = 0;
        while i < count {
            acc = acc.square();
            i += 1;
        }
        acc
    }

    /// Computes the multiplicative inverse $z^{-1} = z^{p-2} = z^{2^{255}-21} \bmod (2^{255}-19)$
    /// in constant time using an addition chain of 254 squarings and 11 multiplications.
    pub fn invert(&self) -> Self {
        let z2 = self.square();                                // 2^1
        let z9 = z2.pow2k(2).mul(self);                        // 2^3 + 1 = 9
        let z11 = z9.mul(&z2);                                 // 2^3 + 2 + 1 = 11
        let z_5_0 = z11.square().mul(&z9);                     // 22 + 9 = 31 = 2^5 - 1
        let z_10_0 = z_5_0.pow2k(5).mul(&z_5_0);               // 2^10 - 1
        let z_20_0 = z_10_0.pow2k(10).mul(&z_10_0);            // 2^20 - 1
        let z_40_0 = z_20_0.pow2k(20).mul(&z_20_0);            // 2^40 - 1
        let z_50_0 = z_40_0.pow2k(10).mul(&z_10_0);            // 2^50 - 1
        let z_100_0 = z_50_0.pow2k(50).mul(&z_50_0);           // 2^100 - 1
        let z_200_0 = z_100_0.pow2k(100).mul(&z_100_0);        // 2^200 - 1
        let z_250_0 = z_200_0.pow2k(50).mul(&z_50_0);          // 2^250 - 1
        z_250_0.pow2k(5).mul(&z11)                             // 2^255 - 32 + 11 = 2^255 - 21
    }

    /// Constant-time conditional swap of two field elements `a` and `b` when `swap != 0`.
    #[inline]
    pub fn cswap(swap: u64, a: &mut Self, b: &mut Self) {
        let mut i = 0;
        while i < 5 {
            let ai = a.0[i];
            let bi = b.0[i];
            a.0[i] = ct_select_u64(swap, bi, ai);
            b.0[i] = ct_select_u64(swap, ai, bi);
            i += 1;
        }
    }
}

/// Group order $\ell = 2^{252} + 27742317777372353535851937790883648493$ in little-endian bytes.
pub const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Checks whether a 32-byte little-endian scalar `s` is strictly canonical ($0 \le s < \ell$).
pub fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    let mut borrow = 0i32;
    let mut i = 0;
    while i < 32 {
        let diff = (s[i] as i32) - (ED25519_L[i] as i32) - borrow;
        borrow = if diff < 0 { 1 } else { 0 };
        i += 1;
    }
    borrow == 1
}

/// Reduces a 64-byte little-endian integer modulo the Ed25519 group order
/// $\ell = 2^{252} + 27742317777372353535851937790883648493$ per RFC 8032 Section 5.1.
pub fn sc_reduce_64(input: &[u8; 64]) -> [u8; 32] {
    // Low 128 bits of (2^252 - l) = -27742317777372353535851937790883648493
    // Explicitly, l = 2^252 + C where C = 0x14def9dea2f79cd6_5812631a5cf5d3ed (125 bits).
    // We process bit-by-bit from the top byte down, reducing modulo l.
    let mut rem = [0u8; 33];

    let mut byte_idx = 64usize;
    while byte_idx > 0 {
        byte_idx -= 1;
        let in_byte = input[byte_idx];
        let mut bit = 8usize;
        while bit > 0 {
            bit -= 1;
            // Shift rem left by 1 bit and insert the next input bit
            let mut carry = (in_byte >> bit) & 1;
            let mut j = 0;
            while j < 33 {
                let next_carry = (rem[j] >> 7) & 1;
                rem[j] = (rem[j] << 1) | carry;
                carry = next_carry;
                j += 1;
            }

            // Subtract l if rem >= l
            let mut sub = [0u8; 33];
            let mut borrow = 0i32;
            let mut k = 0;
            while k < 32 {
                let d = (rem[k] as i32) - (ED25519_L[k] as i32) - borrow;
                sub[k] = (d & 0xFF) as u8;
                borrow = if d < 0 { 1 } else { 0 };
                k += 1;
            }
            let d32 = (rem[32] as i32) - borrow;
            sub[32] = (d32 & 0xFF) as u8;
            let ge_l = d32 >= 0;

            let mask = if ge_l { 0xFFu8 } else { 0x00u8 };
            let mut m = 0;
            while m < 33 {
                rem[m] = (sub[m] & mask) | (rem[m] & !mask);
                m += 1;
            }
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&rem[..32]);
    out
}

/// Computes the RFC 8032 Ed25519 challenge scalar $k = \text{SHA-512}(R \parallel A \parallel M) \bmod \ell$.
pub fn ed25519_challenge_scalar(r_bytes: &[u8; 32], pub_key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(pub_key);
    hasher.update(msg);
    let digest = hasher.finalize();
    sc_reduce_64(&digest)
}

/// Runs self-tests for $GF(2^{255}-19)$ field arithmetic, Fermat inversion, and RFC 8032 scalar reduction.
pub fn run_ed25519_self_test() -> u32 {
    let mut passed = 0u32;

    // 1. Field addition and subtraction identity: (a + b) - b == a
    let a = Fe25519::EDWARDS_D;
    let b = Fe25519::from_u64(486662);
    let sum = a.add(&b);
    let diff = sum.sub(&b);
    if ct_eq_32(&diff.to_bytes(), &a.to_bytes()) {
        passed += 1;
    }

    // 2. Multiplicative inverse via Fermat's Little Theorem: a * a^(-1) == 1 mod (2^255 - 19)
    let inv_a = a.invert();
    let prod = a.mul(&inv_a);
    if ct_eq_32(&prod.to_bytes(), &Fe25519::ONE.to_bytes()) {
        passed += 1;
    }

    // 3. Modular wrap-around check: (2^255 - 19) + 19 == 19 mod (2^255 - 19)
    let mut p_bytes = [0xFFu8; 32];
    p_bytes[0] = 0xED; // 255 - 18 = 237 = 0xED
    p_bytes[31] = 0x7F;
    let p_fe = Fe25519::from_bytes(&p_bytes);
    if ct_eq_32(&p_fe.to_bytes(), &Fe25519::ZERO.to_bytes()) {
        passed += 1;
    }

    // 4. Scalar reduction mod l check: l reduced mod l == 0
    let mut l_64 = [0u8; 64];
    l_64[..32].copy_from_slice(&ED25519_L);
    let reduced_l = sc_reduce_64(&l_64);
    if ct_eq_32(&reduced_l, &[0u8; 32]) && !is_canonical_scalar(&ED25519_L) && is_canonical_scalar(&reduced_l) {
        passed += 1;
    }

    passed
}
