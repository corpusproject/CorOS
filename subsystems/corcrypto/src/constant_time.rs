//! Side-channel resistant constant-time comparison, selection, and volatile zeroization primitives.

use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};

/// Returns `0xFF` if `x == 0`, otherwise `0x00`, in constant time without branching.
#[inline(always)]
pub fn ct_is_zero_u8(x: u8) -> u8 {
    let v = x as u16;
    let neg = v.wrapping_sub(1);
    ((neg >> 8) & 0xFF) as u8
}

/// Returns `0xFFFF_FFFF` if `x == 0`, otherwise `0`, in constant time without branching.
#[inline(always)]
pub fn ct_is_zero_u32(x: u32) -> u32 {
    let v = x as u64;
    let neg = v.wrapping_sub(1);
    ((neg >> 32) & 0xFFFF_FFFF) as u32
}

/// Returns `0xFFFF_FFFF_FFFF_FFFF` if `x == 0`, otherwise `0`, in constant time.
#[inline(always)]
pub fn ct_is_zero_u64(x: u64) -> u64 {
    let non_zero = (x | x.wrapping_neg()) >> 63;
    non_zero.wrapping_sub(1)
}

/// Constant-time equality comparison of two byte slices.
/// Returns `true` if `a` and `b` have identical length and identical byte contents.
#[inline]
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
    ct_is_zero_u8(diff) == 0xFF
}

/// Constant-time equality comparison of two 32-byte arrays.
#[inline]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_eq_slice(a, b)
}

/// Constant-time equality comparison of two 16-byte authentication tags.
#[inline]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    ct_eq_slice(a, b)
}

/// Constant-time byte selection: returns `a` if `choice != 0`, or `b` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u8(choice: u8, a: u8, b: u8) -> u8 {
    let is_zero = ct_is_zero_u8(choice);
    let mask = !is_zero;
    (a & mask) | (b & !mask)
}

/// Constant-time 32-bit integer selection: returns `a` if `choice != 0`, or `b` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u32(choice: u32, a: u32, b: u32) -> u32 {
    let is_zero = ct_is_zero_u32(choice);
    let mask = !is_zero;
    (a & mask) | (b & !mask)
}

/// Constant-time 64-bit integer selection: returns `a` if `choice != 0`, or `b` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u64(choice: u64, a: u64, b: u64) -> u64 {
    let is_zero = ct_is_zero_u64(choice);
    let mask = !is_zero;
    (a & mask) | (b & !mask)
}

/// Constant-time conditional swap of two mutable byte slices of equal length.
/// Swaps `a` and `b` in-place when `swap != 0`, leaves them unchanged when `swap == 0`.
#[inline]
pub fn ct_swap_slice(swap: u8, a: &mut [u8], b: &mut [u8]) {
    let len = if a.len() < b.len() { a.len() } else { b.len() };
    let mask = !ct_is_zero_u8(swap);
    let mut i = 0;
    while i < len {
        let diff = (a[i] ^ b[i]) & mask;
        a[i] ^= diff;
        b[i] ^= diff;
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time conditional copy: copies `src` into `dst` if `copy != 0`.
#[inline]
pub fn ct_copy_slice(copy: u8, dst: &mut [u8], src: &[u8]) {
    let len = if dst.len() < src.len() { dst.len() } else { src.len() };
    let mask = !ct_is_zero_u8(copy);
    let mut i = 0;
    while i < len {
        dst[i] ^= (dst[i] ^ src[i]) & mask;
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely overwrites a mutable byte slice with zeros using volatile writes and a compiler barrier.
#[inline]
pub fn zeroize_slice(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: `buf[i]` is a valid aligned mutable reference within the slice bounds.
        unsafe {
            write_volatile(&mut buf[i], 0u8);
        }
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely overwrites a mutable slice of 32-bit words with zeros.
#[inline]
pub fn zeroize_words32(buf: &mut [u32]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: `buf[i]` is a valid aligned mutable reference within the slice bounds.
        unsafe {
            write_volatile(&mut buf[i], 0u32);
        }
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely overwrites a mutable slice of 64-bit words with zeros.
#[inline]
pub fn zeroize_words64(buf: &mut [u64]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: `buf[i]` is a valid aligned mutable reference within the slice bounds.
        unsafe {
            write_volatile(&mut buf[i], 0u64);
        }
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Runs self-tests for constant-time selection, equality, conditional swap, and zeroization.
pub fn run_constant_time_self_test() -> u32 {
    let mut passed = 0u32;

    if ct_is_zero_u32(0) == 0xFFFF_FFFF && ct_is_zero_u32(1) == 0 && ct_is_zero_u32(u32::MAX) == 0 {
        passed += 1;
    }
    if ct_select_u8(1, 0xAA, 0x55) == 0xAA && ct_select_u8(0, 0xAA, 0x55) == 0x55 {
        passed += 1;
    }
    if ct_select_u64(42, 0xDEAD_BEEF_CAFE_BABE, 0x0102_0304_0506_0708) == 0xDEAD_BEEF_CAFE_BABE
        && ct_select_u64(0, 0xDEAD_BEEF_CAFE_BABE, 0x0102_0304_0506_0708) == 0x0102_0304_0506_0708
    {
        passed += 1;
    }

    let tag_a = [0x41u8; 16];
    let mut tag_b = [0x41u8; 16];
    if ct_eq_16(&tag_a, &tag_b) {
        passed += 1;
    }
    tag_b[15] ^= 0x01;
    if !ct_eq_16(&tag_a, &tag_b) {
        passed += 1;
    }

    let mut left = [1u8, 2, 3, 4];
    let mut right = [9u8, 8, 7, 6];
    ct_swap_slice(0, &mut left, &mut right);
    if left == [1, 2, 3, 4] && right == [9, 8, 7, 6] {
        passed += 1;
    }
    ct_swap_slice(1, &mut left, &mut right);
    if left == [9, 8, 7, 6] && right == [1, 2, 3, 4] {
        passed += 1;
    }

    let mut secret = [0x7Fu8; 32];
    zeroize_slice(&mut secret);
    if ct_eq_32(&secret, &[0u8; 32]) {
        passed += 1;
    }

    passed
}
