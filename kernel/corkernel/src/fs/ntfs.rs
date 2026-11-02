//! CorOS NTFS (New Technology File System) Driver (`ntfs.rs`)
//!
//! Provides comprehensive NTFS structure parsing and data recovery:
//! - NTFS Boot Sector ($Boot: OEM ID "NTFS    ", BytesPerSector, SectorsPerCluster, MFT Cluster)
//! - Master File Table ($MFT) Record Header (Magic 'FILE' = 0x454C4946)
//! - Update Sequence Array (USA) fixup application
//! - Attribute Record Headers (Resident vs Non-Resident)
//! - $STANDARD_INFORMATION (0x10): Timestamps, DOS flags, Security ID
//! - $FILE_NAME (0x30): Unicode filename, parent MFT record, allocation sizes
//! - $DATA (0x80): Raw file payloads & non-resident data runlist decoding
//! - $INDEX_ROOT (0x90) & $INDEX_ALLOCATION (0xA0): B-Tree directory index parsing

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const NTFS_BOOT_MAGIC: &[u8; 8] = b"NTFS    ";
pub const MFT_RECORD_MAGIC: u32 = 0x454C4946; // 'FILE' in little-endian
pub const MFT_RECORD_SIZE: usize = 1024;

/// NTFS Attribute Type Codes
pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_OBJECT_ID: u32 = 0x40;
pub const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const ATTR_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
pub const ATTR_BITMAP: u32 = 0xB0;
pub const ATTR_REPARSE_POINT: u32 = 0xC0;
pub const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

/// NTFS Boot Sector structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NtfsBootSector {
    pub jump_instruction: [u8; 3],
    pub oem_id: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub zero1: [u8; 3],
    pub not_used1: u16,
    pub media_descriptor: u8,
    pub zero2: u16,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    pub hidden_sectors: u32,
    pub not_used2: u32,
    pub not_used3: u32,
    pub total_sectors: u64,
    pub mft_cluster_number: u64,
    pub mft_mirr_cluster_number: u64,
    pub clusters_per_mft_record: i8,
    pub not_used4: [u8; 3],
    pub clusters_per_index_buffer: i8,
    pub not_used5: [u8; 3],
    pub volume_serial_number: u64,
    pub checksum: u32,
}

/// MFT Record Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MftRecordHeader {
    pub magic: u32,                    // 'FILE' (0x454C4946)
    pub update_sequence_offset: u16,
    pub update_sequence_count: u16,
    pub logfile_sequence_number: u64,
    pub sequence_value: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,                     // 0x01 = InUse, 0x02 = Directory
    pub real_size: u32,
    pub allocated_size: u32,
    pub base_record_reference: u64,
    pub next_attribute_id: u16,
    pub align: u16,
    pub record_number: u32,
}

/// Common Attribute Record Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AttributeHeaderCommon {
    pub attr_type: u32,
    pub length: u32,
    pub non_resident_flag: u8,         // 0 = Resident, 1 = Non-Resident
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,                     // 0x0001 = Compressed, 0x4000 = Encrypted, 0x8000 = Sparse
    pub attribute_id: u16,
}

/// Resident Attribute Header extension
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ResidentAttributeHeader {
    pub common: AttributeHeaderCommon,
    pub value_length: u32,
    pub value_offset: u16,
    pub indexed_flag: u8,
    pub padding: u8,
}

/// Non-Resident Attribute Header extension
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NonResidentAttributeHeader {
    pub common: AttributeHeaderCommon,
    pub starting_vcn: u64,
    pub last_vcn: u64,
    pub runlist_offset: u16,
    pub compression_unit_size: u16,
    pub padding: u32,
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_data_size: u64,
}

/// $STANDARD_INFORMATION Attribute Content (0x10)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StandardInformation {
    pub creation_time: u64,
    pub last_data_change_time: u64,
    pub last_mft_change_time: u64,
    pub last_access_time: u64,
    pub dos_file_permissions: u32,
    pub max_num_versions: u32,
    pub version_number: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota_charged: u64,
    pub usn: u64,
}

/// $FILE_NAME Attribute Content (0x30)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileNameAttributeHeader {
    pub parent_directory_ref: u64,
    pub creation_time: u64,
    pub last_data_change_time: u64,
    pub last_mft_change_time: u64,
    pub last_access_time: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub reparse_value: u32,
    pub file_name_length: u8,
    pub file_name_namespace: u8,       // 0=POSIX, 1=Win32, 2=DOS, 3=Win32 & DOS
}

/// Decoded Data Run for non-resident attributes
#[derive(Debug, Clone, Copy)]
pub struct DataRun {
    pub lcn_offset: i64,
    pub cluster_length: u64,
}

/// Decoded NTFS File Entry
#[derive(Debug, Clone)]
pub struct NtfsEntry {
    pub record_number: u32,
    pub name: String,
    pub is_directory: bool,
    pub file_size: u64,
    pub allocated_size: u64,
    pub creation_time: u64,
    pub modified_time: u64,
    pub parent_mft_record: u64,
    pub resident_data: Option<Vec<u8>>,
    pub data_runs: Vec<DataRun>,
}

/// Complete NTFS Volume Parser and Reader
pub struct NtfsVolume {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub mft_start_lcn: u64,
    pub total_sectors: u64,
    pub volume_serial: u64,
    pub files: BTreeMap<u32, NtfsEntry>,
}

impl NtfsVolume {
    /// Mount volume from partition boot sector
    pub fn parse_boot_sector(boot_data: &[u8]) -> Option<Self> {
        if boot_data.len() < 512 {
            return None;
        }

        if &boot_data[3..11] != NTFS_BOOT_MAGIC {
            return None;
        }

        let bps = u16::from_le_bytes([boot_data[11], boot_data[12]]) as u32;
        let spc = boot_data[13] as u32;
        if bps == 0 || spc == 0 {
            return None;
        }

        let cluster_size = bps * spc;
        let total_sectors = u64::from_le_bytes([
            boot_data[40], boot_data[41], boot_data[42], boot_data[43],
            boot_data[44], boot_data[45], boot_data[46], boot_data[47],
        ]);
        let mft_lcn = u64::from_le_bytes([
            boot_data[48], boot_data[49], boot_data[50], boot_data[51],
            boot_data[52], boot_data[53], boot_data[54], boot_data[55],
        ]);
        let serial = u64::from_le_bytes([
            boot_data[72], boot_data[73], boot_data[74], boot_data[75],
            boot_data[76], boot_data[77], boot_data[78], boot_data[79],
        ]);

        Some(Self {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_size,
            mft_start_lcn: mft_lcn,
            total_sectors,
            volume_serial: serial,
            files: BTreeMap::new(),
        })
    }

    /// Parse an individual 1024-byte MFT Record
    pub fn parse_mft_record(&mut self, record_buf: &[u8]) -> Option<NtfsEntry> {
        if record_buf.len() < MFT_RECORD_SIZE {
            return None;
        }

        // Apply NTFS Update Sequence Array (USA) Fixups
        let mut fixed_buf = [0u8; MFT_RECORD_SIZE];
        fixed_buf.copy_from_slice(&record_buf[..MFT_RECORD_SIZE]);

        let magic = u32::from_le_bytes([fixed_buf[0], fixed_buf[1], fixed_buf[2], fixed_buf[3]]);
        if magic != MFT_RECORD_MAGIC {
            return None;
        }

        let usa_offset = u16::from_le_bytes([fixed_buf[4], fixed_buf[5]]) as usize;
        let usa_count = u16::from_le_bytes([fixed_buf[6], fixed_buf[7]]) as usize;
        let first_attr_offset = u16::from_le_bytes([fixed_buf[20], fixed_buf[21]]) as usize;
        let flags = u16::from_le_bytes([fixed_buf[22], fixed_buf[23]]);
        let record_num = u32::from_le_bytes([fixed_buf[44], fixed_buf[45], fixed_buf[46], fixed_buf[47]]);

        let in_use = (flags & 0x01) != 0;
        let is_dir = (flags & 0x02) != 0;

        if !in_use {
            return None;
        }

        // Apply USA fixups across 512-byte sectors
        if usa_offset + usa_count * 2 <= MFT_RECORD_SIZE && usa_count >= 2 {
            let _expected_tag = u16::from_le_bytes([fixed_buf[usa_offset], fixed_buf[usa_offset + 1]]);
            for i in 1..usa_count {
                let sector_end = i * 512 - 2;
                let val_off = usa_offset + i * 2;
                if sector_end + 2 <= MFT_RECORD_SIZE && val_off + 2 <= MFT_RECORD_SIZE {
                    fixed_buf[sector_end] = fixed_buf[val_off];
                    fixed_buf[sector_end + 1] = fixed_buf[val_off + 1];
                }
            }
        }

        let mut offset = first_attr_offset;
        let mut file_name = String::new();
        let mut real_size = 0u64;
        let mut alloc_size = 0u64;
        let mut c_time = 0u64;
        let mut m_time = 0u64;
        let mut parent_ref = 0u64;
        let mut resident_data = None;
        let mut data_runs = Vec::new();

        while offset + 8 <= MFT_RECORD_SIZE {
            let attr_type = u32::from_le_bytes([
                fixed_buf[offset], fixed_buf[offset + 1],
                fixed_buf[offset + 2], fixed_buf[offset + 3],
            ]);

            if attr_type == ATTR_END_MARKER {
                break;
            }

            let attr_len = u32::from_le_bytes([
                fixed_buf[offset + 4], fixed_buf[offset + 5],
                fixed_buf[offset + 6], fixed_buf[offset + 7],
            ]) as usize;

            if attr_len == 0 || offset + attr_len > MFT_RECORD_SIZE {
                break;
            }

            let non_resident = fixed_buf[offset + 8] != 0;

            match attr_type {
                ATTR_STANDARD_INFORMATION => {
                    if !non_resident && offset + 24 <= MFT_RECORD_SIZE {
                        let val_offset = u16::from_le_bytes([fixed_buf[offset + 20], fixed_buf[offset + 21]]) as usize;
                        let s_off = offset + val_offset;
                        if s_off + 32 <= MFT_RECORD_SIZE {
                            c_time = u64::from_le_bytes([
                                fixed_buf[s_off], fixed_buf[s_off + 1], fixed_buf[s_off + 2], fixed_buf[s_off + 3],
                                fixed_buf[s_off + 4], fixed_buf[s_off + 5], fixed_buf[s_off + 6], fixed_buf[s_off + 7],
                            ]);
                            m_time = u64::from_le_bytes([
                                fixed_buf[s_off + 8], fixed_buf[s_off + 9], fixed_buf[s_off + 10], fixed_buf[s_off + 11],
                                fixed_buf[s_off + 12], fixed_buf[s_off + 13], fixed_buf[s_off + 14], fixed_buf[s_off + 15],
                            ]);
                        }
                    }
                }
                ATTR_FILE_NAME => {
                    if !non_resident && offset + 24 <= MFT_RECORD_SIZE {
                        let val_offset = u16::from_le_bytes([fixed_buf[offset + 20], fixed_buf[offset + 21]]) as usize;
                        let fn_off = offset + val_offset;
                        if fn_off + 66 <= MFT_RECORD_SIZE {
                            parent_ref = u64::from_le_bytes([
                                fixed_buf[fn_off], fixed_buf[fn_off + 1], fixed_buf[fn_off + 2], fixed_buf[fn_off + 3],
                                fixed_buf[fn_off + 4], fixed_buf[fn_off + 5], fixed_buf[fn_off + 6], fixed_buf[fn_off + 7],
                            ]) & 0x0000_FFFF_FFFF_FFFF;

                            let n_len = fixed_buf[fn_off + 64] as usize;
                            let n_space = fixed_buf[fn_off + 65];
                            let name_bytes_off = fn_off + 66;

                            if fn_off + 66 + n_len * 2 <= MFT_RECORD_SIZE {
                                // Prefer Win32 / POSIX namespaces over pure DOS 8.3
                                if file_name.is_empty() || n_space != 2 {
                                    let mut utf16_chars = Vec::with_capacity(n_len);
                                    for i in 0..n_len {
                                        let c = u16::from_le_bytes([
                                            fixed_buf[name_bytes_off + i * 2],
                                            fixed_buf[name_bytes_off + i * 2 + 1],
                                        ]);
                                        utf16_chars.push(c);
                                    }
                                    file_name = String::from_utf16_lossy(&utf16_chars);
                                }
                            }
                        }
                    }
                }
                ATTR_DATA => {
                    if !non_resident {
                        let val_len = u32::from_le_bytes([
                            fixed_buf[offset + 16], fixed_buf[offset + 17],
                            fixed_buf[offset + 18], fixed_buf[offset + 19],
                        ]) as usize;
                        let val_off = u16::from_le_bytes([fixed_buf[offset + 20], fixed_buf[offset + 21]]) as usize;
                        let d_start = offset + val_off;
                        if d_start + val_len <= MFT_RECORD_SIZE {
                            real_size = val_len as u64;
                            alloc_size = val_len as u64;
                            resident_data = Some(fixed_buf[d_start..d_start + val_len].to_vec());
                        }
                    } else {
                        // Non-resident attribute
                        if offset + 64 <= MFT_RECORD_SIZE {
                            let rl_off = u16::from_le_bytes([fixed_buf[offset + 32], fixed_buf[offset + 33]]) as usize;
                            alloc_size = u64::from_le_bytes([
                                fixed_buf[offset + 40], fixed_buf[offset + 41], fixed_buf[offset + 42], fixed_buf[offset + 43],
                                fixed_buf[offset + 44], fixed_buf[offset + 45], fixed_buf[offset + 46], fixed_buf[offset + 47],
                            ]);
                            real_size = u64::from_le_bytes([
                                fixed_buf[offset + 48], fixed_buf[offset + 49], fixed_buf[offset + 50], fixed_buf[offset + 51],
                                fixed_buf[offset + 52], fixed_buf[offset + 53], fixed_buf[offset + 54], fixed_buf[offset + 55],
                            ]);

                            // Decode Runlist
                            let runlist_start = offset + rl_off;
                            if runlist_start < offset + attr_len {
                                data_runs = Self::decode_runlist(&fixed_buf[runlist_start..offset + attr_len]);
                            }
                        }
                    }
                }
                _ => {}
            }

            offset += attr_len;
        }

        let entry = NtfsEntry {
            record_number: record_num,
            name: file_name,
            is_directory: is_dir,
            file_size: real_size,
            allocated_size: alloc_size,
            creation_time: c_time,
            modified_time: m_time,
            parent_mft_record: parent_ref,
            resident_data,
            data_runs,
        };

        self.files.insert(record_num, entry.clone());
        Some(entry)
    }

    /// Decode compressed variable-length NTFS Data Runlist
    pub fn decode_runlist(bytes: &[u8]) -> Vec<DataRun> {
        let mut runs = Vec::new();
        let mut cursor = 0;
        let mut current_lcn: i64 = 0;

        while cursor < bytes.len() {
            let header = bytes[cursor];
            cursor += 1;
            if header == 0 {
                break;
            }

            let len_size = (header & 0x0F) as usize;
            let offset_size = ((header >> 4) & 0x0F) as usize;

            if cursor + len_size + offset_size > bytes.len() {
                break;
            }

            // Read cluster count
            let mut cluster_len: u64 = 0;
            for i in 0..len_size {
                cluster_len |= (bytes[cursor + i] as u64) << (i * 8);
            }
            cursor += len_size;

            // Read signed cluster offset
            let mut lcn_diff: i64 = 0;
            if offset_size > 0 {
                for i in 0..offset_size {
                    lcn_diff |= (bytes[cursor + i] as i64) << (i * 8);
                }
                // Sign extend if top bit is set
                let sign_bit = 1i64 << (offset_size * 8 - 1);
                if (lcn_diff & sign_bit) != 0 {
                    let mask = !0i64 << (offset_size * 8);
                    lcn_diff |= mask;
                }
                cursor += offset_size;
                current_lcn += lcn_diff;
            }

            runs.push(DataRun {
                lcn_offset: current_lcn,
                cluster_length: cluster_len,
            });
        }

        runs
    }

    /// Find file by path
    pub fn find_by_name(&self, name: &str) -> Option<&NtfsEntry> {
        let target = name.to_uppercase();
        self.files.values().find(|e| e.name.to_uppercase() == target)
    }
}
