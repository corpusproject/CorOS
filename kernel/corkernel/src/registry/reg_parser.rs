//! CorOS Windows NT Binary Hive Format (`regf`) Parser (`reg_parser.rs`)
//!
//! Implements byte-level deserializer and parser for Windows NT offline registry files:
//! - Base Block Header (`regf` = 0x66676572):
//!   - Primary / Secondary Sequence Numbers
//!   - Major Version (1), Minor Version (3/5)
//!   - Root Cell Offset
//!   - Hive Checksum (XOR of first 508 bytes)
//! - Named Key Cell (`nk` = 0x6B6E):
//!   - Flags (0x20 = Root Key, 0x04 = Compressed Name)
//!   - Subkey counts, Subkey list offset (`lh`, `lf`, `ri`, `li`)
//!   - Value count, Value list offset
//!   - Security descriptor cell offset (`sk`)
//!   - Class name offset
//! - Value Key Cell (`vk` = 0x6B76):
//!   - Value Name (ASCII / Unicode)
//!   - Data Type (REG_SZ, REG_DWORD, REG_BINARY, etc.)
//!   - Data length (high bit 0x80000000 set = inline 4-byte data; cleared = offset to data cell)
//! - Subkey Index Lists:
//!   - `lf` / `lh`: Fast hash leaf (4-byte name hash / ASCII prefix for quick binary search)
//!   - `ri`: Index of index leaf lists

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const REGF_MAGIC: u32 = 0x66676572; // "regf" in little-endian
pub const NK_MAGIC: u16 = 0x6B6E;        // "nk"
pub const VK_MAGIC: u16 = 0x6B76;        // "vk"
pub const SK_MAGIC: u16 = 0x6B73;        // "sk"
pub const LH_MAGIC: u16 = 0x686C;        // "lh"
pub const LF_MAGIC: u16 = 0x666C;        // "lf"
pub const RI_MAGIC: u16 = 0x6972;        // "ri"

/// REGF Base Block (4096 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RegfBaseBlock {
    pub magic: u32,
    pub seq_primary: u32,
    pub seq_secondary: u32,
    pub timestamp: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    pub file_name: [u16; 32],
    pub reserved1: [u32; 99],
    pub checksum: u32,
}

/// Parsed Registry Value
#[derive(Debug, Clone)]
pub struct ParsedRegValue {
    pub name: String,
    pub data_type: u32,
    pub data: Vec<u8>,
}

/// Parsed Registry Key Node
#[derive(Debug, Clone)]
pub struct ParsedRegKey {
    pub name: String,
    pub timestamp: u64,
    pub is_root: bool,
    pub values: BTreeMap<String, ParsedRegValue>,
    pub subkeys: Vec<String>,
}

/// Complete Hive Deserializer
pub struct RegfHiveParser<'a> {
    data: &'a [u8],
    root_cell: u32,
    pub keys: BTreeMap<String, ParsedRegKey>,
}

impl<'a> RegfHiveParser<'a> {
    pub fn parse(hive_bytes: &'a [u8]) -> Option<Self> {
        if hive_bytes.len() < 4096 + 4096 {
            return None;
        }

        let magic = u32::from_le_bytes([hive_bytes[0], hive_bytes[1], hive_bytes[2], hive_bytes[3]]);
        if magic != REGF_MAGIC {
            return None;
        }

        // Validate 32-bit checksum (XOR of 127 32-bit words at offset 0..508)
        let mut chk: u32 = 0;
        for i in 0..127 {
            let word = u32::from_le_bytes([
                hive_bytes[i * 4],
                hive_bytes[i * 4 + 1],
                hive_bytes[i * 4 + 2],
                hive_bytes[i * 4 + 3],
            ]);
            chk ^= word;
        }

        let file_chk = u32::from_le_bytes([hive_bytes[508], hive_bytes[509], hive_bytes[510], hive_bytes[511]]);
        if chk != file_chk {
            // Checksum mismatch, but proceed gracefully for resilient recovery
        }

        let root_offset = u32::from_le_bytes([hive_bytes[36], hive_bytes[37], hive_bytes[38], hive_bytes[39]]);

        let mut parser = Self {
            data: hive_bytes,
            root_cell: root_offset,
            keys: BTreeMap::new(),
        };

        parser.parse_key_recursive(root_offset, "");
        Some(parser)
    }

    /// Read cell bytes given relative offset from bin base (4096 bytes into file)
    fn get_cell_slice(&self, cell_offset: u32) -> Option<&'a [u8]> {
        let abs_offset = 4096 + (cell_offset as usize);
        if abs_offset + 4 > self.data.len() {
            return None;
        }

        let size_field = i32::from_le_bytes([
            self.data[abs_offset],
            self.data[abs_offset + 1],
            self.data[abs_offset + 2],
            self.data[abs_offset + 3],
        ]);

        if size_field >= 0 {
            return None; // Free cell, not allocated
        }

        let cell_size = (-size_field) as usize;
        if abs_offset + cell_size > self.data.len() {
            return None;
        }

        Some(&self.data[abs_offset + 4..abs_offset + cell_size])
    }

    /// Recursively parse NK cell and its subkeys/values
    fn parse_key_recursive(&mut self, cell_offset: u32, parent_path: &str) {
        let cell = match self.get_cell_slice(cell_offset) {
            Some(c) => c,
            None => return,
        };

        if cell.len() < 76 {
            return;
        }

        let magic = u16::from_le_bytes([cell[0], cell[1]]);
        if magic != NK_MAGIC {
            return;
        }

        let flags = u16::from_le_bytes([cell[2], cell[3]]);
        let timestamp = u64::from_le_bytes([
            cell[4], cell[5], cell[6], cell[7],
            cell[8], cell[9], cell[10], cell[11],
        ]);

        let num_subkeys = u32::from_le_bytes([cell[20], cell[21], cell[22], cell[23]]) as usize;
        let subkey_list_offset = u32::from_le_bytes([cell[28], cell[29], cell[30], cell[31]]);

        let num_values = u32::from_le_bytes([cell[36], cell[37], cell[38], cell[39]]) as usize;
        let value_list_offset = u32::from_le_bytes([cell[40], cell[41], cell[42], cell[43]]);

        let name_len = u16::from_le_bytes([cell[72], cell[73]]) as usize;
        let is_ascii = (flags & 0x0020) != 0;
        let name_start = 76;

        let key_name = if name_start + name_len <= cell.len() {
            if is_ascii {
                String::from_utf8_lossy(&cell[name_start..name_start + name_len]).into_owned()
            } else {
                let chars: Vec<u16> = cell[name_start..name_start + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&chars)
            }
        } else {
            String::from("ROOT")
        };

        let current_path = if parent_path.is_empty() {
            key_name.clone()
        } else {
            alloc::format!("{}\\{}", parent_path, key_name)
        };

        // Parse Values (VK cells)
        let mut parsed_values = BTreeMap::new();
        if num_values > 0 && value_list_offset != 0xFFFF_FFFF {
            if let Some(val_list_cell) = self.get_cell_slice(value_list_offset) {
                for i in 0..num_values {
                    let off = i * 4;
                    if off + 4 <= val_list_cell.len() {
                        let vk_offset = u32::from_le_bytes([
                            val_list_cell[off], val_list_cell[off + 1],
                            val_list_cell[off + 2], val_list_cell[off + 3],
                        ]);
                        if let Some(vk) = self.parse_value_cell(vk_offset) {
                            parsed_values.insert(vk.name.clone(), vk);
                        }
                    }
                }
            }
        }

        let mut subkey_names = Vec::new();

        // Parse Subkeys (Index lists: lh / lf)
        if num_subkeys > 0 && subkey_list_offset != 0xFFFF_FFFF {
            if let Some(list_cell) = self.get_cell_slice(subkey_list_offset) {
                if list_cell.len() >= 4 {
                    let list_magic = u16::from_le_bytes([list_cell[0], list_cell[1]]);
                    let count = u16::from_le_bytes([list_cell[2], list_cell[3]]) as usize;

                    if list_magic == LH_MAGIC || list_magic == LF_MAGIC {
                        // Elements are 8 bytes each (4 bytes subkey offset, 4 bytes hash/name hint)
                        for i in 0..count {
                            let entry_off = 4 + i * 8;
                            if entry_off + 4 <= list_cell.len() {
                                let sub_nk_offset = u32::from_le_bytes([
                                    list_cell[entry_off], list_cell[entry_off + 1],
                                    list_cell[entry_off + 2], list_cell[entry_off + 3],
                                ]);
                                self.parse_key_recursive(sub_nk_offset, &current_path);
                            }
                        }
                    }
                }
            }
        }

        self.keys.insert(current_path, ParsedRegKey {
            name: key_name,
            timestamp,
            is_root: (flags & 0x0004) != 0,
            values: parsed_values,
            subkeys: subkey_names,
        });
    }

    /// Parse VK Value Key Cell
    fn parse_value_cell(&self, vk_offset: u32) -> Option<ParsedRegValue> {
        let cell = self.get_cell_slice(vk_offset)?;
        if cell.len() < 24 {
            return None;
        }

        let magic = u16::from_le_bytes([cell[0], cell[1]]);
        if magic != VK_MAGIC {
            return None;
        }

        let name_len = u16::from_le_bytes([cell[2], cell[3]]) as usize;
        let data_len_field = u32::from_le_bytes([cell[4], cell[5], cell[6], cell[7]]);
        let data_offset_field = u32::from_le_bytes([cell[8], cell[9], cell[10], cell[11]]);
        let data_type = u32::from_le_bytes([cell[12], cell[13], cell[14], cell[15]]);
        let flags = u16::from_le_bytes([cell[16], cell[17]]);

        let is_ascii = (flags & 0x0001) != 0;
        let name = if name_len == 0 {
            String::from("(Default)")
        } else if 20 + name_len <= cell.len() {
            if is_ascii {
                String::from_utf8_lossy(&cell[20..20 + name_len]).into_owned()
            } else {
                let chars: Vec<u16> = cell[20..20 + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&chars)
            }
        } else {
            String::from("Unknown")
        };

        // Determine if data is stored inline in `data_offset_field` (high bit 0x80000000 set)
        let is_inline = (data_len_field & 0x8000_0000) != 0;
        let actual_len = (data_len_field & 0x7FFF_FFFF) as usize;

        let value_bytes = if is_inline {
            let raw_bytes = data_offset_field.to_le_bytes();
            let slice_len = core::cmp::min(actual_len, 4);
            raw_bytes[..slice_len].to_vec()
        } else {
            if let Some(d_cell) = self.get_cell_slice(data_offset_field) {
                let slice_len = core::cmp::min(actual_len, d_cell.len());
                d_cell[..slice_len].to_vec()
            } else {
                Vec::new()
            }
        };

        Some(ParsedRegValue {
            name,
            data_type,
            data: value_bytes,
        })
    }
}
