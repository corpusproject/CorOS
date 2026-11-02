//! Universal Disc Formats: ISO 9660 Volume Descriptor & UDF (ECMA-167) Anchors.
//! Pure `#![no_std]` Rust filesystem format registry without numbered repetition.

pub const ISO9660_STANDARD_ID: [u8; 5] = *b"CD001";
pub const ISO9660_PVD_SECTOR_OFFSET: u64 = 16; // Sector 16 (0x8000 for 2048-byte sectors)
pub const ISO9660_SECTOR_SIZE: usize = 2048;

pub const UDF_BEA01_ID: [u8; 5] = *b"BEA01";
pub const UDF_NSR02_ID: [u8; 5] = *b"NSR02";
pub const UDF_NSR03_ID: [u8; 5] = *b"NSR03";
pub const UDF_TEA01_ID: [u8; 5] = *b"TEA01";

/// ISO 9660 Primary Volume Descriptor (PVD).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iso9660PrimaryVolumeDescriptor {
    pub type_code: u8, // 1 for Primary Volume Descriptor
    pub standard_id: [u8; 5], // "CD001"
    pub version: u8, // 1
    pub unused0: u8,
    pub system_id: [u8; 32],
    pub volume_id: [u8; 32],
    pub unused1: [u8; 8],
    pub volume_space_size_le: u32,
    pub volume_space_size_be: u32,
    pub unused2: [u8; 32],
    pub volume_set_size_le: u16,
    pub volume_set_size_be: u16,
    pub volume_sequence_number_le: u16,
    pub volume_sequence_number_be: u16,
    pub logical_block_size_le: u16,
    pub logical_block_size_be: u16,
    pub path_table_size_le: u32,
    pub path_table_size_be: u32,
    pub type_l_path_table_loc: u32,
    pub opt_type_l_path_table_loc: u32,
    pub type_m_path_table_loc: u32,
    pub opt_type_m_path_table_loc: u32,
    pub root_directory_record: [u8; 34],
    pub volume_set_id: [u8; 128],
    pub publisher_id: [u8; 128],
    pub data_preparer_id: [u8; 128],
    pub application_id: [u8; 128],
}

impl Iso9660PrimaryVolumeDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.type_code == 1 && self.standard_id == ISO9660_STANDARD_ID && self.version == 1
    }

    #[inline]
    pub fn block_size(&self) -> u16 {
        self.logical_block_size_le
    }
}

/// SUSP 4-byte generic header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspHeader {
    pub signature: [u8; 2],
    pub length: u8,
    pub version: u8,
}
