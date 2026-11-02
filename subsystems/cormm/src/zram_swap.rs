//! In-RAM Compressed Swap Block Device (`ZramDevice`).
//!
//! Provides fast 4 KiB page compression/decompression using a lossless hybrid
//! Run-Length Encoding (RLE) + LZ77 sliding-window back-reference codec,
//! zero-page fastpath detection (`SAME_ELEMENT`), and compression telemetry.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Standard uncompressed swap page size (4096 bytes).
pub const ZRAM_PAGE_SIZE: usize = 4096;

/// Token tags used in the lossless `zram` byte stream format.
const TOKEN_LITERAL_RUN: u8 = 0xA0;
const TOKEN_REPEAT_BYTE: u8 = 0xB1;
const TOKEN_LZ77_MATCH: u8 = 0xC2;

/// Storage representation of a swapped-out page inside `ZramDevice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapPayload {
    /// Entire 4 KiB page consists of a single repeated byte (e.g., `0x00` zero page).
    UniformByte(u8),
    /// Losslessly compressed RLE + LZ77 byte payload.
    Compressed(Vec<u8>),
    /// Incompressible page stored verbatim (`4096` bytes).
    RawIncompressible(Vec<u8>),
}

/// Metadata entry for an occupied swap slot in `ZramDevice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapSlotEntry {
    pub slot_index: u32,
    pub original_size: usize,
    pub stored_size: usize,
    pub payload: SwapPayload,
}

/// Telemetry counters for a `ZramDevice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZramTelemetry {
    pub total_slots_used: usize,
    pub zero_pages_stored: usize,
    pub original_bytes: usize,
    pub compressed_bytes: usize,
    /// Compression ratio scaled by 100 (e.g., `450` = `4.50x` compression).
    pub compression_ratio_x100: usize,
}

/// Checks if a 4 KiB page consists entirely of a single uniform byte value.
pub fn detect_uniform_byte(page: &[u8]) -> Option<u8> {
    let first = *page.first()?;
    if page.iter().all(|&b| b == first) {
        Some(first)
    } else {
        None
    }
}

/// Compresses a byte slice using a lossless RLE + LZ77 byte-match encoder.
pub fn compress_rle_lz77(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut pos = 0usize;

    while pos < input.len() {
        // 1. Check for a single-byte RLE run of length >= 4
        let current_byte = input[pos];
        let mut rle_len = 1usize;
        while pos + rle_len < input.len()
            && input[pos + rle_len] == current_byte
            && rle_len < 255
        {
            rle_len += 1;
        }
        if rle_len >= 4 {
            out.push(TOKEN_REPEAT_BYTE);
            out.push(rle_len as u8);
            out.push(current_byte);
            pos += rle_len;
            continue;
        }

        // 2. Check for an LZ77 backward match in the preceding 255-byte window
        let window_start = pos.saturating_sub(255);
        let mut best_offset = 0usize;
        let mut best_length = 0usize;

        for cand in window_start..pos {
            let mut match_len = 0usize;
            while pos + match_len < input.len()
                && input[cand + match_len] == input[pos + match_len]
                && match_len < 255
                && (cand + match_len) < pos
            {
                match_len += 1;
            }
            if match_len >= 5 && match_len > best_length {
                best_length = match_len;
                best_offset = pos - cand;
            }
        }

        if best_length >= 5 {
            out.push(TOKEN_LZ77_MATCH);
            out.push(best_offset as u8);
            out.push(best_length as u8);
            pos += best_length;
            continue;
        }

        // 3. Emit a literal run up to the next RLE or LZ77 opportunity (max 127 bytes)
        let lit_start = pos;
        let mut lit_len = 0usize;
        while pos < input.len() && lit_len < 127 {
            let b = input[pos];
            if pos + 4 <= input.len()
                && input[pos + 1] == b
                && input[pos + 2] == b
                && input[pos + 3] == b
            {
                break;
            }
            pos += 1;
            lit_len += 1;
        }
        out.push(TOKEN_LITERAL_RUN);
        out.push(lit_len as u8);
        out.extend_from_slice(&input[lit_start..lit_start + lit_len]);
    }

    out
}

/// Decompresses a byte stream produced by `compress_rle_lz77`.
pub fn decompress_rle_lz77(compressed: &[u8], expected_len: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(expected_len);
    let mut idx = 0usize;

    while idx < compressed.len() {
        let token = compressed[idx];
        idx += 1;
        match token {
            TOKEN_REPEAT_BYTE => {
                if idx + 2 > compressed.len() {
                    return Err("Truncated RLE token");
                }
                let count = compressed[idx] as usize;
                let value = compressed[idx + 1];
                idx += 2;
                out.resize(out.len() + count, value);
            }
            TOKEN_LZ77_MATCH => {
                if idx + 2 > compressed.len() {
                    return Err("Truncated LZ77 token");
                }
                let offset = compressed[idx] as usize;
                let length = compressed[idx + 1] as usize;
                idx += 2;
                if offset == 0 || offset > out.len() {
                    return Err("Invalid LZ77 back-reference offset");
                }
                let start = out.len() - offset;
                for i in 0..length {
                    let byte = out[start + i];
                    out.push(byte);
                }
            }
            TOKEN_LITERAL_RUN => {
                if idx >= compressed.len() {
                    return Err("Truncated literal token");
                }
                let lit_len = compressed[idx] as usize;
                idx += 1;
                if idx + lit_len > compressed.len() {
                    return Err("Truncated literal payload");
                }
                out.extend_from_slice(&compressed[idx..idx + lit_len]);
                idx += lit_len;
            }
            _ => return Err("Corrupted zram stream token"),
        }
    }

    if out.len() != expected_len {
        return Err("Decompressed byte count mismatch");
    }
    Ok(out)
}

/// In-RAM Compressed Swap Block Device (`zram`).
#[derive(Debug, Clone)]
pub struct ZramDevice {
    max_slots: u32,
    slots: BTreeMap<u32, SwapSlotEntry>,
}

impl ZramDevice {
    /// Creates a new `ZramDevice` with capacity for `max_slots` 4 KiB swap pages.
    pub fn new(max_slots: u32) -> Self {
        Self {
            max_slots,
            slots: BTreeMap::new(),
        }
    }

    /// Compresses and stores a 4 KiB page at `slot_index`.
    pub fn store_page(&mut self, slot_index: u32, page_data: &[u8]) -> Result<usize, &'static str> {
        if slot_index >= self.max_slots {
            return Err("Swap slot index out of range");
        }
        if page_data.len() != ZRAM_PAGE_SIZE {
            return Err("Page slice must be exactly 4096 bytes");
        }

        let (payload, stored_size) = if let Some(uniform) = detect_uniform_byte(page_data) {
            (SwapPayload::UniformByte(uniform), 0usize)
        } else {
            let compressed = compress_rle_lz77(page_data);
            if compressed.len() < ZRAM_PAGE_SIZE {
                let len = compressed.len();
                (SwapPayload::Compressed(compressed), len)
            } else {
                (SwapPayload::RawIncompressible(page_data.to_vec()), ZRAM_PAGE_SIZE)
            }
        };

        self.slots.insert(
            slot_index,
            SwapSlotEntry {
                slot_index,
                original_size: ZRAM_PAGE_SIZE,
                stored_size,
                payload,
            },
        );
        Ok(stored_size)
    }

    /// Decompresses and retrieves the 4 KiB page stored at `slot_index`.
    pub fn load_page(&self, slot_index: u32) -> Result<Vec<u8>, &'static str> {
        let entry = self
            .slots
            .get(&slot_index)
            .ok_or("Swap slot is not populated")?;
        match &entry.payload {
            SwapPayload::UniformByte(byte) => Ok(alloc::vec![*byte; ZRAM_PAGE_SIZE]),
            SwapPayload::Compressed(stream) => decompress_rle_lz77(stream, ZRAM_PAGE_SIZE),
            SwapPayload::RawIncompressible(raw) => Ok(raw.clone()),
        }
    }

    /// Frees a swap slot when a page is faulted back in or process exits.
    pub fn free_slot(&mut self, slot_index: u32) -> bool {
        self.slots.remove(&slot_index).is_some()
    }

    /// Computes compression ratio and memory savings telemetry.
    pub fn telemetry(&self) -> ZramTelemetry {
        let total_slots_used = self.slots.len();
        let mut zero_pages_stored = 0usize;
        let mut original_bytes = 0usize;
        let mut compressed_bytes = 0usize;

        for entry in self.slots.values() {
            original_bytes += entry.original_size;
            compressed_bytes += entry.stored_size;
            if entry.payload == SwapPayload::UniformByte(0) {
                zero_pages_stored += 1;
            }
        }

        let effective_denom = compressed_bytes.max(1);
        let compression_ratio_x100 = (original_bytes * 100) / effective_denom;

        ZramTelemetry {
            total_slots_used,
            zero_pages_stored,
            original_bytes,
            compressed_bytes,
            compression_ratio_x100,
        }
    }
}
