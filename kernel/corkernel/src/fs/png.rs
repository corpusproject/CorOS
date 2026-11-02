//! Pure in-house no_std PNG encoder for CorOS.
//! Encodes 32-bit ARGB/RGB raw pixel buffers into valid standard PNG files
//! using uncompressed Deflate blocks and authentic PNG chunk headers (IHDR, IDAT, IEND)
//! with Adler-32 and CRC-32 integrity checksums.

use alloc::vec::Vec;

/// Generates a standard CRC32 table at compile time
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Computes CRC32 checksum for a slice of bytes
pub fn crc32(buf: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in buf {
        let idx = ((c ^ (b as u32)) & 0xFF) as usize;
        c = CRC_TABLE[idx] ^ (c >> 8);
    }
    !c
}

/// Computes Adler32 checksum required by zlib wrapper in PNG IDAT
pub fn adler32(buf: &[u8]) -> u32 {
    let mut s1 = 1u32;
    let mut s2 = 0u32;
    for &b in buf {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    (s2 << 16) | s1
}

/// Appends a standard PNG chunk (Length + Type + Data + CRC32) to `out`
fn append_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    // 1. Length (4 bytes, big endian)
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());

    // 2. Type & Data for CRC32 computation
    let start = out.len();
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..]);

    // 3. CRC32 (4 bytes, big endian)
    out.extend_from_slice(&crc.to_be_bytes());
}

/// Encodes a 32-bit pixel slice (width x height) into standard valid PNG format bytes.
/// Format: 24-bit TrueColor (RGB 8:8:8), Filter Type 0 (None)
pub fn encode_rgba_to_png(pixels: &[u32], width: u32, height: u32) -> Vec<u8> {
    let mut png = Vec::with_capacity(32 + (width * height * 3) as usize);

    // 1. Standard PNG Signature (8 bytes)
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // 2. IHDR Chunk (Image Header: 13 bytes)
    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8;  // Bit depth: 8 bits per channel
    ihdr[9] = 2;  // Color type: 2 (RGB TrueColor)
    ihdr[10] = 0; // Compression method: 0 (Deflate)
    ihdr[11] = 0; // Filter method: 0 (Standard adaptive)
    ihdr[12] = 0; // Interlace: 0 (None)
    append_chunk(&mut png, b"IHDR", &ihdr);

    // 3. Prepare Raw Filtered Image Scanlines
    // Each scanline begins with a filter byte (0 = None), followed by RGB triplets
    let row_bytes = 1 + (width as usize) * 3;
    let mut raw_data = Vec::with_capacity(row_bytes * (height as usize));

    for y in 0..(height as usize) {
        raw_data.push(0); // Filter byte: 0 (None)
        for x in 0..(width as usize) {
            let px = pixels[y * (width as usize) + x];
            let r = ((px >> 16) & 0xFF) as u8;
            let g = ((px >> 8) & 0xFF) as u8;
            let b = (px & 0xFF) as u8;
            raw_data.push(r);
            raw_data.push(g);
            raw_data.push(b);
        }
    }

    // 4. IDAT Chunk with Zlib Compression Wrapper (Non-compressed Deflate blocks)
    let adler = adler32(&raw_data);
    let mut zlib_stream = Vec::with_capacity(raw_data.len() + 64);
    // Zlib Header: CMF=0x78 (Deflate, 32K window), FLG=0x01 (No preset dict, check bit)
    zlib_stream.extend_from_slice(&[0x78, 0x01]);

    // Split raw_data into Deflate uncompressed blocks (max 65,535 bytes per block)
    let block_size = 65530usize;
    let num_blocks = (raw_data.len() + block_size - 1) / block_size;
    let total_blocks = if num_blocks == 0 { 1 } else { num_blocks };

    for b in 0..total_blocks {
        let is_last = b + 1 == total_blocks;
        let start = b * block_size;
        let end = (start + block_size).min(raw_data.len());
        let chunk = if start < raw_data.len() { &raw_data[start..end] } else { &[] };
        let len = chunk.len() as u16;
        let nlen = !len;

        // BFINAL + BTYPE (00 = no compression)
        let header = if is_last { 0x01u8 } else { 0x00u8 };
        zlib_stream.push(header);
        zlib_stream.extend_from_slice(&len.to_le_bytes());
        zlib_stream.extend_from_slice(&nlen.to_le_bytes());
        zlib_stream.extend_from_slice(chunk);
    }

    // Zlib Adler-32 Checksum (4 bytes, big endian)
    zlib_stream.extend_from_slice(&adler.to_be_bytes());

    append_chunk(&mut png, b"IDAT", &zlib_stream);

    // 5. IEND Chunk (Empty payload)
    append_chunk(&mut png, b"IEND", &[]);

    png
}

/// Decodes standard uncompressed Deflate TrueColor PNG into a raw `Vec<u32>` pixel buffer.
/// Returns `Some((pixels, width, height))` on success.
pub fn decode_png_to_rgba(png: &[u8]) -> Option<(Vec<u32>, u32, u32)> {
    if png.len() < 8 || &png[0..8] != &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return None;
    }

    let mut offset = 8;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut raw_decompressed = Vec::new();

    while offset + 8 <= png.len() {
        let length = u32::from_be_bytes([png[offset], png[offset + 1], png[offset + 2], png[offset + 3]]) as usize;
        let chunk_type = &png[offset + 4..offset + 8];
        let data_start = offset + 8;
        let data_end = data_start + length;

        if data_end > png.len() {
            break;
        }

        let chunk_data = &png[data_start..data_end];

        if chunk_type == b"IHDR" && length >= 8 {
            width = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
            height = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
        } else if chunk_type == b"IDAT" {
            // Unpack zlib stream
            if chunk_data.len() > 6 {
                // Skip 2 bytes zlib header (0x78, 0x01) and parse Deflate blocks
                let mut p = 2;
                while p + 5 <= chunk_data.len() - 4 { // leave 4 bytes adler
                    let _bheader = chunk_data[p];
                    let blen = u16::from_le_bytes([chunk_data[p + 1], chunk_data[p + 2]]) as usize;
                    p += 5;
                    if p + blen <= chunk_data.len() - 4 {
                        raw_decompressed.extend_from_slice(&chunk_data[p..p + blen]);
                        p += blen;
                    } else {
                        break;
                    }
                }
            }
        } else if chunk_type == b"IEND" {
            break;
        }

        offset = data_end + 4; // skip CRC
    }

    if width == 0 || height == 0 || raw_decompressed.is_empty() {
        return None;
    }

    let row_bytes = 1 + (width as usize) * 3;
    let mut pixels = Vec::with_capacity((width * height) as usize);

    for y in 0..(height as usize) {
        let row_start = y * row_bytes;
        if row_start + row_bytes <= raw_decompressed.len() {
            let row = &raw_decompressed[row_start..row_start + row_bytes];
            // byte 0 is filter byte (0)
            for x in 0..(width as usize) {
                let px_idx = 1 + x * 3;
                let r = row[px_idx] as u32;
                let g = row[px_idx + 1] as u32;
                let b = row[px_idx + 2] as u32;
                pixels.push((r << 16) | (g << 8) | b);
            }
        }
    }

    if pixels.len() == (width * height) as usize {
        Some((pixels, width, height))
    } else {
        None
    }
}
