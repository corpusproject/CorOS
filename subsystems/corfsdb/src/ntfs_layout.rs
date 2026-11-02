//! Microsoft NTFS (New Technology File System) Boot Sector, BPB & MFT Record Architectures.
//! Pure `#![no_std]` Rust filesystem format registry without numbered repetition.

pub const NTFS_OEM_ID: [u8; 8] = *b"NTFS    ";
pub const NTFS_FILE_MAGIC: [u8; 4] = *b"FILE";
pub const NTFS_BAAD_MAGIC: [u8; 4] = *b"BAAD";

/// NTFS Volume Boot Record / BIOS Parameter Block (Sector 0).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtfsBootSector {
    pub jump_instruction: [u8; 3],
    pub oem_id: [u8; 8], // "NTFS    "
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub unused_zero0: [u8; 3],
    pub unused_zero1: u16,
    pub media_descriptor: u8,
    pub unused_zero2: u16,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    pub hidden_sectors: u32,
    pub unused_zero3: u32,
    pub total_sectors: u64,
    pub mft_cluster_lcn: u64,
    pub mft_mirror_cluster_lcn: u64,
    pub clusters_per_mft_record: i8,
    pub unused_zero4: [u8; 3],
    pub clusters_per_index_buffer: i8,
    pub unused_zero5: [u8; 3],
    pub volume_serial_number: u64,
    pub checksum: u32,
}

impl NtfsBootSector {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.oem_id == NTFS_OEM_ID && self.bytes_per_sector >= 512
    }

    #[inline]
    pub fn cluster_size_bytes(&self) -> u32 {
        (self.bytes_per_sector as u32) * (self.sectors_per_cluster as u32)
    }

    /// Computes Master File Table (MFT) Record byte length (usually 1024 bytes).
    pub fn mft_record_size_bytes(&self) -> u32 {
        if self.clusters_per_mft_record > 0 {
            (self.clusters_per_mft_record as u32) * self.cluster_size_bytes()
        } else {
            1 << (-self.clusters_per_mft_record as u32)
        }
    }
}

/// Standard 1024-byte NTFS MFT File Record Header.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtfsMftRecordHeader {
    pub magic: [u8; 4], // "FILE"
    pub update_sequence_offset: u16,
    pub update_sequence_size: u16,
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16, // 0x0001 = InUse, 0x0002 = Directory
    pub used_size_bytes: u32,
    pub allocated_size_bytes: u32,
    pub base_record_file_reference: u64,
    pub next_attribute_instance: u16,
}

impl NtfsMftRecordHeader {
    #[inline]
    pub fn is_file_record(&self) -> bool {
        self.magic == NTFS_FILE_MAGIC
    }

    #[inline]
    pub fn is_directory(&self) -> bool {
        (self.flags & 0x0002) != 0
    }

    #[inline]
    pub fn is_in_use(&self) -> bool {
        (self.flags & 0x0001) != 0
    }
}
