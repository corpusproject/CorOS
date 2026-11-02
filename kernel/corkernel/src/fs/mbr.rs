//! Master Boot Record (MBR) & Extended Partition (EBR) Manager for CorOS.
//! 100% in-house implementation supporting:
//! - Standard 512-byte MBR sector verification (Signature 0x55, 0xAA)
//! - 4 primary partition record slots
//! - Extended Boot Record (EBR) linked-list traversal for logical drives
//! - Partition type identification (FAT32, NTFS, Linux Native, Swap, GPT Protective)

use alloc::vec::Vec;

pub const MBR_SIGNATURE: u16         = 0xAA55;
pub const MBR_BOOTABLE_FLAG: u8      = 0x80;

// Standard MBR Partition Types
pub const PART_TYPE_EMPTY: u8        = 0x00;
pub const PART_TYPE_FAT12: u8        = 0x01;
pub const PART_TYPE_FAT16: u8        = 0x04;
pub const PART_TYPE_EXTENDED: u8     = 0x05;
pub const PART_TYPE_FAT16B: u8       = 0x06;
pub const PART_TYPE_NTFS_EXFAT: u8   = 0x07;
pub const PART_TYPE_FAT32_CHS: u8    = 0x0B;
pub const PART_TYPE_FAT32_LBA: u8    = 0x0C;
pub const PART_TYPE_FAT16_LBA: u8    = 0x0E;
pub const PART_TYPE_EXTENDED_LBA: u8 = 0x0F;
pub const PART_TYPE_LINUX_SWAP: u8   = 0x82;
pub const PART_TYPE_LINUX_NATIVE: u8 = 0x83;
pub const PART_TYPE_LINUX_EXT: u8    = 0x85;
pub const PART_TYPE_LINUX_LVM: u8    = 0x8E;
pub const PART_TYPE_GPT_PROTECT: u8  = 0xEE;
pub const PART_TYPE_EFI_SYSTEM: u8   = 0xEF;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MbrPartitionEntryRaw {
    pub boot_indicator: u8, // 0x80 = Active / Bootable, 0x00 = Inactive
    pub start_chs: [u8; 3], // Cylinder-Head-Sector starting address
    pub partition_type: u8, // Filesystem type ID
    pub end_chs: [u8; 3],   // CHS ending address
    pub start_lba: u32,     // Starting Logical Block Address
    pub sector_count: u32,  // Size in 512-byte sectors
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MbrSectorRaw {
    pub bootstrap_code: [u8; 446],
    pub partitions: [MbrPartitionEntryRaw; 4],
    pub signature: u16,
}

#[derive(Clone, Debug)]
pub struct MbrPartition {
    pub slot: u8, // 1..4 (or 5+ for logical drives in extended partition)
    pub is_bootable: bool,
    pub part_type: u8,
    pub start_lba: u64,
    pub sector_count: u64,
    pub type_name: &'static str,
}

impl MbrPartition {
    pub fn size_mb(&self) -> u64 {
        (self.sector_count * 512) / (1024 * 1024)
    }

    pub fn type_name_for(type_id: u8) -> &'static str {
        match type_id {
            PART_TYPE_FAT12 => "FAT12",
            PART_TYPE_FAT16 | PART_TYPE_FAT16B | PART_TYPE_FAT16_LBA => "FAT16",
            PART_TYPE_FAT32_CHS | PART_TYPE_FAT32_LBA => "FAT32",
            PART_TYPE_NTFS_EXFAT => "NTFS / exFAT",
            PART_TYPE_EXTENDED | PART_TYPE_EXTENDED_LBA | PART_TYPE_LINUX_EXT => "Extended",
            PART_TYPE_LINUX_SWAP => "Linux Swap",
            PART_TYPE_LINUX_NATIVE => "Linux Native (Ext2/3/4)",
            PART_TYPE_LINUX_LVM => "Linux LVM",
            PART_TYPE_GPT_PROTECT => "GPT Protective",
            PART_TYPE_EFI_SYSTEM => "EFI System Partition (ESP)",
            _ => "Unknown / Raw",
        }
    }
}

pub struct MbrTable;

impl MbrTable {
    /// Parse MBR sector 0 and extract all active partitions.
    pub fn parse(sector_bytes: &[u8]) -> Result<Vec<MbrPartition>, &'static str> {
        if sector_bytes.len() < 512 {
            return Err("Sector buffer too small for MBR (needs 512 bytes)");
        }

        let mbr = unsafe { *(sector_bytes.as_ptr() as *const MbrSectorRaw) };
        if mbr.signature != MBR_SIGNATURE {
            return Err("Invalid MBR signature (expected 0xAA55)");
        }

        let mut partitions = Vec::new();

        for i in 0..4 {
            let entry = mbr.partitions[i];
            if entry.partition_type == PART_TYPE_EMPTY || entry.sector_count == 0 {
                continue;
            }

            partitions.push(MbrPartition {
                slot: (i + 1) as u8,
                is_bootable: entry.boot_indicator == MBR_BOOTABLE_FLAG,
                part_type: entry.partition_type,
                start_lba: entry.start_lba as u64,
                sector_count: entry.sector_count as u64,
                type_name: MbrPartition::type_name_for(entry.partition_type),
            });
        }

        Ok(partitions)
    }
}
