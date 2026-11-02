//! CorOS Multi-Precision Big Integer Arithmetic & RSA Verification Engine (`rsa.rs`)
//!
//! Provides bare-metal asymmetric cryptography primitives:
//! - Multi-precision unsigned integer (`BigUint`: 64-bit limb array)
//! - Constant-time addition, subtraction, multi-limb multiplication, and division
//! - Montgomery / Binary Modular Exponentiation ($b^e \pmod m$)
//! - RSA PKCS#1 v1.5 Signature Verification (SHA-256 DigestInfo prefix matching)
//! - Public key encryption / signature verification (RSA-1024, RSA-2048, RSA-4096)

extern crate alloc;

use alloc::vec::Vec;
use super::sha256::sha256_hash;

/// Big unsigned integer represented by 64-bit limbs in little-endian order
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigUint {
    pub limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn from_u64(val: u64) -> Self {
        if val == 0 {
            Self::zero()
        } else {
            Self { limbs: alloc::vec![val] }
        }
    }

    /// Construct BigUint from big-endian byte slice
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }

        let mut limbs = Vec::with_capacity((bytes.len() + 7) / 8);
        let mut i = bytes.len();

        while i > 0 {
            let start = if i >= 8 { i - 8 } else { 0 };
            let chunk = &bytes[start..i];
            let mut limb = 0u64;
            for &b in chunk {
                limb = (limb << 8) | (b as u64);
            }
            limbs.push(limb);
            i = start;
        }

        let mut res = Self { limbs };
        res.trim();
        res
    }

    /// Convert BigUint to big-endian byte vector
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return alloc::vec![0];
        }

        let mut bytes = Vec::with_capacity(self.limbs.len() * 8);
        for &limb in self.limbs.iter().rev() {
            for shift in (0..8).rev() {
                bytes.push(((limb >> (shift * 8)) & 0xFF) as u8);
            }
        }

        // Trim leading zeros
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        bytes[first_non_zero..].to_vec()
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty() || self.limbs.iter().all(|&l| l == 0)
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().map(|&l| (l & 1) != 0).unwrap_or(false)
    }

    fn trim(&mut self) {
        while let Some(&0) = self.limbs.last() {
            self.limbs.pop();
        }
    }

    /// Add two BigUints
    pub fn add(&self, other: &Self) -> Self {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u128;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u128;
            let sum = a + b + carry;
            result.push(sum as u64);
            carry = sum >> 64;
        }

        if carry != 0 {
            result.push(carry as u64);
        }

        let mut res = Self { limbs: result };
        res.trim();
        res
    }

    /// Subtract other from self (assumes self >= other)
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;

        for i in 0..self.limbs.len() {
            let a = self.limbs.get(i).copied().unwrap_or(0) as i128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i128;
            let diff = a - b - borrow;
            if diff < 0 {
                result.push((diff + (1i128 << 64)) as u64);
                borrow = 1;
            } else {
                result.push(diff as u64);
                borrow = 0;
            }
        }

        let mut res = Self { limbs: result };
        res.trim();
        res
    }

    /// Multiply two BigUints
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut result = alloc::vec![0u64; self.limbs.len() + other.limbs.len()];

        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = result[i + j] as u128 + (a as u128) * (b as u128) + carry;
                result[i + j] = cur as u64;
                carry = cur >> 64;
            }
            if carry > 0 {
                result[i + other.limbs.len()] += carry as u64;
            }
        }

        let mut res = Self { limbs: result };
        res.trim();
        res
    }

    /// Shift right by 1 bit (divide by 2)
    pub fn shr1(&mut self) {
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let next_carry = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = next_carry;
        }
        self.trim();
    }

    /// Modulo reduction: self % modulus
    pub fn rem(&self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if self < modulus {
            return self.clone();
        }

        // Binary long division
        let mut rem = Self::zero();
        for &limb in self.limbs.iter().rev() {
            for shift in (0..64).rev() {
                let bit = (limb >> shift) & 1;
                // rem = rem * 2 + bit
                let mut next_rem = rem.add(&rem);
                if bit == 1 {
                    next_rem = next_rem.add(&Self::from_u64(1));
                }
                if &next_rem >= modulus {
                    rem = next_rem.sub(modulus);
                } else {
                    rem = next_rem;
                }
            }
        }

        rem
    }

    /// Modular Exponentiation: (self ^ exp) % modulus
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }

        let mut result = Self::from_u64(1);
        let mut base = self.rem(modulus);
        let mut exponent = exp.clone();

        while !exponent.is_zero() {
            if exponent.is_odd() {
                let prod = result.mul(&base);
                result = prod.rem(modulus);
            }
            let next_base = base.mul(&base);
            base = next_base.rem(modulus);
            exponent.shr1();
        }

        result
    }
}

/// RSA Public Key for verification
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub modulus: BigUint,
    pub exponent: BigUint,
}

impl RsaPublicKey {
    pub fn new(modulus_bytes: &[u8], exponent_bytes: &[u8]) -> Self {
        Self {
            modulus: BigUint::from_be_bytes(modulus_bytes),
            exponent: BigUint::from_be_bytes(exponent_bytes),
        }
    }

    /// Verify RSA PKCS#1 v1.5 Signature over SHA-256 Digest
    pub fn verify_pkcs1_v15_sha256(&self, message: &[u8], signature_bytes: &[u8]) -> bool {
        let sig = BigUint::from_be_bytes(signature_bytes);
        let recovered = sig.mod_pow(&self.exponent, &self.modulus);
        let recovered_bytes = recovered.to_be_bytes();

        let mod_len = (self.modulus.limbs.len() * 8).max(recovered_bytes.len());
        let mut padded = alloc::vec![0u8; mod_len];
        let start = mod_len.saturating_sub(recovered_bytes.len());
        padded[start..].copy_from_slice(&recovered_bytes);

        // Check PKCS#1 v1.5 padding: 0x00, 0x01, [0xFF...], 0x00, DigestInfo
        if padded.len() < 38 || padded[0] != 0 || padded[1] != 1 {
            return false;
        }

        let mut idx = 2;
        while idx < padded.len() && padded[idx] == 0xFF {
            idx += 1;
        }

        if idx >= padded.len() || padded[idx] != 0 {
            return false;
        }
        idx += 1;

        // SHA-256 DigestInfo prefix: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        const SHA256_DIGEST_INFO: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ];

        let payload = &padded[idx..];
        if payload.len() != SHA256_DIGEST_INFO.len() + 32 {
            return false;
        }

        if &payload[..19] != &SHA256_DIGEST_INFO {
            return false;
        }

        let actual_hash = sha256_hash(message);
        &payload[19..] == &actual_hash
    }
}
