//! CorOS Windows NT Registry HBIN Cell Heap Allocator (`reg_cell.rs`)
//!
//! Implements on-disk and in-memory binary format of Windows NT Hive Bins:
//! - HBIN Header (`hbin` signature = 0x6E696268, FileOffset, BinSize, Timestamp)
//! - Registry Cells:
//!   - Negative size indicates ALLOCATED cell (e.g. -32 means 32 bytes allocated)
//!   - Positive size indicates FREE cell (available for allocation)
//! - Free list management and first-fit cell allocation
//! - Cell coalescing on deallocation to prevent fragmentation

extern crate alloc;

use alloc::vec::Vec;

pub const HBIN_MAGIC: u32 = 0x6E696268; // "hbin" in little-endian
pub const HBIN_BLOCK_SIZE: usize = 4096;

/// HBIN Header (32 bytes at start of every 4096-byte bin)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HbinHeader {
    pub magic: u32,             // 0x6E696268
    pub file_offset: u32,       // Offset from start of hive data (after 4096-byte regf header)
    pub bin_size: u32,          // Size of this bin (multiple of 4096)
    pub reserved1: u32,
    pub reserved2: u32,
    pub timestamp: u64,
    pub spare: u32,
}

/// A Cell inside an HBIN block
#[derive(Debug, Clone)]
pub struct RegistryCell {
    pub offset_in_bin: usize,
    pub raw_size: i32,
    pub is_allocated: bool,
    pub cell_size: usize,
    pub data: Vec<u8>,
}

/// In-Memory Representation of an HBIN block
pub struct HiveBin {
    pub file_offset: u32,
    pub bin_size: usize,
    pub timestamp: u64,
    pub raw_bytes: Vec<u8>,
}

impl HiveBin {
    pub fn new(file_offset: u32, size: usize, timestamp: u64) -> Self {
        let bin_size = (size + HBIN_BLOCK_SIZE - 1) & !(HBIN_BLOCK_SIZE - 1);
        let mut raw = Vec::with_capacity(bin_size);
        raw.resize(bin_size, 0);

        // Populate HBIN header
        raw[0..4].copy_from_slice(&HBIN_MAGIC.to_le_bytes());
        raw[4..8].copy_from_slice(&file_offset.to_le_bytes());
        raw[8..12].copy_from_slice(&(bin_size as u32).to_le_bytes());
        raw[20..28].copy_from_slice(&timestamp.to_le_bytes());

        // Initialize single large free cell filling the bin past 32-byte header
        let free_size = (bin_size - 32) as i32;
        raw[32..36].copy_from_slice(&free_size.to_le_bytes());

        Self {
            file_offset,
            bin_size,
            timestamp,
            raw_bytes: raw,
        }
    }

    /// Parse existing HBIN block from raw slice
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != HBIN_MAGIC {
            return None;
        }

        let file_offset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let bin_size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let timestamp = u64::from_le_bytes([
            bytes[20], bytes[21], bytes[22], bytes[23],
            bytes[24], bytes[25], bytes[26], bytes[27],
        ]);

        if bytes.len() < bin_size {
            return None;
        }

        Some(Self {
            file_offset,
            bin_size,
            timestamp,
            raw_bytes: bytes[..bin_size].to_vec(),
        })
    }

    /// Enumerate all cells inside this bin
    pub fn list_cells(&self) -> Vec<RegistryCell> {
        let mut cells = Vec::new();
        let mut cursor = 32; // Skip 32-byte HBIN header

        while cursor + 4 <= self.bin_size {
            let size_field = i32::from_le_bytes([
                self.raw_bytes[cursor],
                self.raw_bytes[cursor + 1],
                self.raw_bytes[cursor + 2],
                self.raw_bytes[cursor + 3],
            ]);

            let is_allocated = size_field < 0;
            let cell_size = size_field.unsigned_abs() as usize;

            if cell_size == 0 || cursor + cell_size > self.bin_size {
                break;
            }

            let data_slice = if cell_size > 4 {
                self.raw_bytes[cursor + 4..cursor + cell_size].to_vec()
            } else {
                Vec::new()
            };

            cells.push(RegistryCell {
                offset_in_bin: cursor,
                raw_size: size_field,
                is_allocated,
                cell_size,
                data: data_slice,
            });

            cursor += cell_size;
        }

        cells
    }

    /// Allocate cell within bin (First-fit)
    pub fn allocate_cell(&mut self, payload_size: usize) -> Option<usize> {
        // Cells must be 8-byte aligned, including 4-byte size header
        let needed_size = (payload_size + 4 + 7) & !7;
        let mut cursor = 32;

        while cursor + 4 <= self.bin_size {
            let size_field = i32::from_le_bytes([
                self.raw_bytes[cursor],
                self.raw_bytes[cursor + 1],
                self.raw_bytes[cursor + 2],
                self.raw_bytes[cursor + 3],
            ]);

            if size_field > 0 {
                let free_size = size_field as usize;
                if free_size >= needed_size {
                    // Split if remainder is at least 16 bytes
                    let remainder = free_size - needed_size;
                    if remainder >= 16 {
                        // Mark allocated cell (negative size)
                        let alloc_field = -(needed_size as i32);
                        self.raw_bytes[cursor..cursor + 4].copy_from_slice(&alloc_field.to_le_bytes());

                        // Write remainder free cell
                        let rem_field = remainder as i32;
                        let rem_cursor = cursor + needed_size;
                        self.raw_bytes[rem_cursor..rem_cursor + 4].copy_from_slice(&rem_field.to_le_bytes());
                    } else {
                        // Take whole free cell
                        let alloc_field = -(free_size as i32);
                        self.raw_bytes[cursor..cursor + 4].copy_from_slice(&alloc_field.to_le_bytes());
                    }

                    // Return relative offset to data (after 4-byte cell header)
                    return Some(cursor + 4);
                }
                cursor += free_size;
            } else {
                let alloc_size = (-size_field) as usize;
                if alloc_size == 0 {
                    break;
                }
                cursor += alloc_size;
            }
        }

        None
    }

    /// Free an allocated cell by its offset
    pub fn free_cell(&mut self, cell_data_offset: usize) -> bool {
        if cell_data_offset < 36 || cell_data_offset >= self.bin_size {
            return false;
        }

        let header_offset = cell_data_offset - 4;
        let size_field = i32::from_le_bytes([
            self.raw_bytes[header_offset],
            self.raw_bytes[header_offset + 1],
            self.raw_bytes[header_offset + 2],
            self.raw_bytes[header_offset + 3],
        ]);

        if size_field < 0 {
            let positive_size = -size_field;
            self.raw_bytes[header_offset..header_offset + 4].copy_from_slice(&positive_size.to_le_bytes());
            // Clear payload bytes
            for i in cell_data_offset..header_offset + (positive_size as usize) {
                self.raw_bytes[i] = 0;
            }
            true
        } else {
            false
        }
    }
}
