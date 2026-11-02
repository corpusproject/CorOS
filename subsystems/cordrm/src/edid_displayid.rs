//! VESA E-EDID 1.4 & CTA-861 Extension Parser, Detailed Timing Descriptors & HDR metadata.

use alloc::vec::Vec;

/// Parsed 18-byte Detailed Timing Descriptor (DTD).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DetailedTimingDescriptor {
    pub pixel_clock_khz: u32,
    pub h_active: u16,
    pub h_blank: u16,
    pub h_sync_offset: u16,
    pub h_sync_width: u16,
    pub v_active: u16,
    pub v_blank: u16,
    pub v_sync_offset: u16,
    pub v_sync_width: u16,
    pub h_size_mm: u16,
    pub v_size_mm: u16,
    pub interlaced: bool,
}

impl DetailedTimingDescriptor {
    pub fn parse_18_bytes(raw: &[u8; 18]) -> Option<Self> {
        let pixel_clock_10khz = u16::from_le_bytes([raw[0], raw[1]]);
        if pixel_clock_10khz == 0 {
            return None; // Display descriptor, not a timing descriptor
        }
        let pixel_clock_khz = (pixel_clock_10khz as u32) * 10;

        let h_active = (raw[2] as u16) | (((raw[4] >> 4) as u16) << 8);
        let h_blank = (raw[3] as u16) | (((raw[4] & 0x0F) as u16) << 8);

        let v_active = (raw[5] as u16) | (((raw[7] >> 4) as u16) << 8);
        let v_blank = (raw[6] as u16) | (((raw[7] & 0x0F) as u16) << 8);

        let h_sync_offset = (raw[8] as u16) | ((((raw[11] >> 6) & 0x03) as u16) << 8);
        let h_sync_width = (raw[9] as u16) | ((((raw[11] >> 4) & 0x03) as u16) << 8);

        let v_sync_offset = ((raw[10] >> 4) as u16) | ((((raw[11] >> 2) & 0x03) as u16) << 4);
        let v_sync_width = ((raw[10] & 0x0F) as u16) | (((raw[11] & 0x03) as u16) << 4);

        let h_size_mm = (raw[12] as u16) | (((raw[14] >> 4) as u16) << 8);
        let v_size_mm = (raw[13] as u16) | (((raw[14] & 0x0F) as u16) << 8);

        let flags = raw[17];
        let interlaced = (flags & (1 << 7)) != 0;

        Some(Self {
            pixel_clock_khz,
            h_active,
            h_blank,
            h_sync_offset,
            h_sync_width,
            v_active,
            v_blank,
            v_sync_offset,
            v_sync_width,
            h_size_mm,
            v_size_mm,
            interlaced,
        })
    }
}

/// Parsed E-EDID structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedEdid {
    pub manufacturer_id: [char; 3],
    pub product_code: u16,
    pub serial_number: u32,
    pub edid_version: u8,
    pub edid_revision: u8,
    pub timings: Vec<DetailedTimingDescriptor>,
    pub monitor_name: [u8; 13],
}

impl ParsedEdid {
    pub const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

    /// Verifies standard EDID checksum (sum of all 128 bytes modulo 256 must be 0).
    pub fn verify_checksum(block: &[u8; 128]) -> bool {
        let mut sum = 0u8;
        for &b in block {
            sum = sum.wrapping_add(b);
        }
        sum == 0
    }

    /// Parses a standard 128-byte VESA EDID 1.4 block.
    pub fn parse(block: &[u8; 128]) -> Result<Self, &'static str> {
        if block[0..8] != Self::HEADER {
            return Err("Invalid EDID header");
        }
        if !Self::verify_checksum(block) {
            return Err("EDID checksum mismatch");
        }

        // Manufacturer ID (compressed 5-bit characters)
        let mfg_raw = u16::from_be_bytes([block[8], block[9]]);
        let c1 = (((mfg_raw >> 10) & 0x1F) as u8 + b'@') as char;
        let c2 = (((mfg_raw >> 5) & 0x1F) as u8 + b'@') as char;
        let c3 = ((mfg_raw & 0x1F) as u8 + b'@') as char;

        let product_code = u16::from_le_bytes([block[10], block[11]]);
        let serial_number = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        let edid_version = block[18];
        let edid_revision = block[19];

        let mut timings = Vec::new();
        let mut monitor_name = [0u8; 13];

        // 4 x 18-byte detailed timing / descriptor blocks at offsets 54, 72, 90, 108
        for block_idx in 0..4 {
            let offset = 54 + block_idx * 18;
            let mut slice = [0u8; 18];
            slice.copy_from_slice(&block[offset..offset + 18]);
            if let Some(dtd) = DetailedTimingDescriptor::parse_18_bytes(&slice) {
                timings.push(dtd);
            } else if slice[0] == 0 && slice[1] == 0 && slice[2] == 0 && slice[3] == 0xFC {
                // Monitor Name descriptor
                monitor_name.copy_from_slice(&slice[5..18]);
            }
        }

        Ok(Self {
            manufacturer_id: [c1, c2, c3],
            product_code,
            serial_number,
            edid_version,
            edid_revision,
            timings,
            monitor_name,
        })
    }
}
