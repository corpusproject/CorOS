//! x86_64 Page Table Entry (PTE) Swap Entry Encoding & Decoding.
//!
//! When a 4 KiB virtual page is swapped out to a block device or compressed zram,
//! its corresponding PTE is marked non-present (`Present = 0`, bit 0 = 0).
//! To differentiate a swapped-out page from an unmapped/uncommitted page,
//! bit 1 is set to 1.
//!
//! Layout:
//! - Bit 0 (Present): 0
//! - Bit 1: 1 (indicates swap entry)
//! - Bits 2..=6 (5 bits): `swap_type` (0..=31 swap spaces)
//! - Bits 7..=56 (50 bits): `slot_offset` (slot/page index within swap space)
//! - Bits 57..=63: 0 (or reserved)

pub const SWAP_PRESENT_BIT: u64 = 0x1;
pub const SWAP_MARKER_BIT: u64 = 0x2;
pub const SWAP_TYPE_SHIFT: u32 = 2;
pub const SWAP_TYPE_MASK: u64 = 0x1F;
pub const SWAP_OFFSET_SHIFT: u32 = 7;
pub const SWAP_OFFSET_MASK: u64 = 0x0003_FFFF_FFFF_FFFF;

/// Encodes `swap_type` and `slot_offset` into an x86_64 non-present swap PTE.
#[inline]
pub fn encode_swap_entry(swap_type: u8, slot_offset: u64) -> u64 {
    let t = (swap_type as u64 & SWAP_TYPE_MASK) << SWAP_TYPE_SHIFT;
    let off = (slot_offset & SWAP_OFFSET_MASK) << SWAP_OFFSET_SHIFT;
    t | off | SWAP_MARKER_BIT
}

/// Checks whether a 64-bit PTE value represents a valid swap entry (`Present == 0` and bit 1 == 1).
#[inline]
pub fn is_swap_entry(pte: u64) -> bool {
    (pte & (SWAP_PRESENT_BIT | SWAP_MARKER_BIT)) == SWAP_MARKER_BIT
}

/// Decodes an x86_64 PTE swap entry into `Some((swap_type, slot_offset))` or `None` if not a swap entry.
#[inline]
pub fn decode_swap_entry(pte: u64) -> Option<(u8, u64)> {
    if !is_swap_entry(pte) {
        return None;
    }
    let swap_type = ((pte >> SWAP_TYPE_SHIFT) & SWAP_TYPE_MASK) as u8;
    let slot_offset = (pte >> SWAP_OFFSET_SHIFT) & SWAP_OFFSET_MASK;
    Some((swap_type, slot_offset))
}

/// Verification self-tests for swap entry encoding, decoding, and edge conditions.
pub fn verify_swap_entries() -> u32 {
    let mut passed = 0u32;

    // 1. Basic round-trip encoding and decoding
    let entry = encode_swap_entry(3, 0x12345);
    if is_swap_entry(entry) {
        passed += 1;
    }
    if decode_swap_entry(entry) == Some((3, 0x12345)) {
        passed += 1;
    }

    // 2. Present bit set must NOT be recognized as swap entry
    let present_pte = entry | SWAP_PRESENT_BIT;
    if !is_swap_entry(present_pte) && decode_swap_entry(present_pte).is_none() {
        passed += 1;
    }

    // 3. Unmapped zero PTE must NOT be recognized as swap entry
    if !is_swap_entry(0) && decode_swap_entry(0).is_none() {
        passed += 1;
    }

    // 4. Maximum boundaries: swap_type = 31, maximum 50-bit slot_offset
    let max_entry = encode_swap_entry(31, SWAP_OFFSET_MASK);
    if decode_swap_entry(max_entry) == Some((31, SWAP_OFFSET_MASK)) {
        passed += 1;
    }

    passed
}
