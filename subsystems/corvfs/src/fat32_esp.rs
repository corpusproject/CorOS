//! CorOS VFS Module: `fat32_esp`
//!
//! Real FAT32 EFI System Partition driver: BIOS Parameter Block (`BiosParameterBlock`),
//! 32-byte standard directory entry (`FatDirEntry`), Long File Name (`LfnEntry`) UCS-2
//! assembler & 8.3 short-name checksum verifier, cluster-to-LBA translator, FAT cluster
//! chain follower, and free cluster allocator.

use alloc::string::String;
use alloc::vec::Vec;

/// FAT32 special cluster markers.
pub const FAT32_CLUSTER_FREE: u32 = 0x0000_0000;
pub const FAT32_CLUSTER_BAD: u32 = 0x0FFF_FFF7;
pub const FAT32_CLUSTER_EOC_MIN: u32 = 0x0FFF_FFF8;
pub const FAT32_CLUSTER_EOC: u32 = 0x0FFF_FFFF;
pub const FAT32_ENTRY_MASK: u32 = 0x0FFF_FFFF;

/// FAT directory attribute flags.
pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// Parsed FAT32 BIOS Parameter Block (BPB) from volume boot sector (sector 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BiosParameterBlock {
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub total_sectors_32: u32,
    pub sectors_per_fat_32: u32,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub volume_id: u32,
}

impl BiosParameterBlock {
    /// Parses and validates a 512-byte FAT32 boot sector.
    pub fn parse_boot_sector(sector: &[u8]) -> Option<Self> {
        if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
            return None;
        }

        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        let sectors_per_cluster = sector[13];
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let sectors_per_fat_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]) & FAT32_ENTRY_MASK;
        let fs_info_sector = u16::from_le_bytes([sector[48], sector[49]]);
        let backup_boot_sector = u16::from_le_bytes([sector[50], sector[51]]);
        let volume_id = u32::from_le_bytes([sector[67], sector[68], sector[69], sector[70]]);

        if !bytes_per_sector.is_power_of_two()
            || bytes_per_sector < 512
            || !sectors_per_cluster.is_power_of_two()
            || reserved_sectors == 0
            || num_fats == 0
            || sectors_per_fat_32 == 0
            || root_cluster < 2
        {
            return None;
        }

        let mut oem_name = [0u8; 8];
        oem_name.copy_from_slice(&sector[3..11]);

        let total_sectors = if total_sectors_32 != 0 {
            total_sectors_32
        } else {
            total_sectors_16 as u32
        };

        Some(Self {
            oem_name,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors_32: total_sectors,
            sectors_per_fat_32,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
            volume_id,
        })
    }

    /// Returns the first sector (LBA offset from partition start) of the data region (cluster 2).
    #[inline]
    pub const fn first_data_sector(&self) -> u64 {
        (self.reserved_sectors as u64) + (self.num_fats as u64) * (self.sectors_per_fat_32 as u64)
    }

    /// Converts a cluster number (`>= 2`) to its starting sector LBA within the partition.
    #[inline]
    pub const fn cluster_to_lba(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }
        Some(self.first_data_sector() + ((cluster - 2) as u64) * (self.sectors_per_cluster as u64))
    }

    /// Returns the byte size of one cluster.
    #[inline]
    pub const fn cluster_size_bytes(&self) -> usize {
        (self.bytes_per_sector as usize) * (self.sectors_per_cluster as usize)
    }
}

/// Standard 32-byte FAT 8.3 Short Directory Entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct FatDirEntry {
    pub short_name: [u8; 11],
    pub attr: u8,
    pub nt_res: u8,
    pub crt_time_tenth: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub lst_acc_date: u16,
    pub fst_clus_hi: u16,
    pub wrt_time: u16,
    pub wrt_date: u16,
    pub fst_clus_lo: u16,
    pub file_size: u32,
}

impl FatDirEntry {
    /// Extracts the 28-bit starting cluster number.
    #[inline]
    pub const fn first_cluster(&self) -> u32 {
        (((self.fst_clus_hi as u32) << 16) | (self.fst_clus_lo as u32)) & FAT32_ENTRY_MASK
    }

    /// Formats the 11-byte 8.3 `short_name` into a clean ASCII string (e.g., `"BOOTX64.EFI"`).
    pub fn format_short_name(&self) -> String {
        let base = &self.short_name[0..8];
        let ext = &self.short_name[8..11];
        let mut out = String::new();

        for &b in base {
            if b == b' ' {
                break;
            }
            out.push(b as char);
        }

        let ext_trimmed: Vec<u8> = ext.iter().copied().take_while(|&b| b != b' ').collect();
        if !ext_trimmed.is_empty() {
            out.push('.');
            for b in ext_trimmed {
                out.push(b as char);
            }
        }
        out
    }
}

/// 32-byte VFAT Long File Name (LFN) Directory Entry storing 13 UCS-2 code units.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct LfnEntry {
    pub ord: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub lfn_type: u8,
    pub chksum: u8,
    pub name2: [u16; 6],
    pub fst_clus_lo: u16,
    pub name3: [u16; 2],
}

impl LfnEntry {
    /// Extracts up to 13 UTF-16LE / UCS-2 code units from this LFN entry (stopping at NUL `0x0000` or pad `0xFFFF`).
    pub fn decode_ucs2_chars(&self) -> Vec<u16> {
        let mut units = Vec::with_capacity(13);
        let n1 = self.name1;
        let n2 = self.name2;
        let n3 = self.name3;
        for u in n1.into_iter().chain(n2).chain(n3) {
            let ch = u16::from_le(u);
            if ch == 0x0000 || ch == 0xFFFF {
                break;
            }
            units.push(ch);
        }
        units
    }
}

/// Computes the Microsoft FAT 8.3 short-name checksum used to validate preceding LFN entries.
pub fn compute_lfn_checksum(short_name_11: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short_name_11 {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// High-level resolved directory entry produced by scanning a FAT32 directory cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedFatEntry {
    pub name: String,
    pub is_dir: bool,
    pub first_cluster: u32,
    pub size_bytes: u32,
}

/// Parses a raw directory buffer (multiple of 32 bytes), assembling LFN sequences and verifying checksums.
pub fn parse_fat32_directory(raw_dir_bytes: &[u8]) -> Vec<ResolvedFatEntry> {
    let mut results = Vec::new();
    let mut lfn_fragments: Vec<(u8, Vec<u16>)> = Vec::new();
    let mut expected_chksum: Option<u8> = None;

    for chunk in raw_dir_bytes.chunks_exact(32) {
        let first_byte = chunk[0];
        if first_byte == 0x00 {
            break; // End of directory
        }
        if first_byte == 0xE5 {
            lfn_fragments.clear();
            expected_chksum = None;
            continue; // Deleted entry
        }

        let attr = chunk[11];
        if attr == ATTR_LONG_NAME {
            let ord = chunk[0];
            let chksum = chunk[13];
            if (ord & 0x40) != 0 {
                lfn_fragments.clear();
                expected_chksum = Some(chksum);
            }
            if expected_chksum == Some(chksum) {
                let mut chars = Vec::with_capacity(13);
                // name1: bytes 1..11, name2: bytes 14..26, name3: bytes 28..32
                for pair in chunk[1..11]
                    .chunks_exact(2)
                    .chain(chunk[14..26].chunks_exact(2))
                    .chain(chunk[28..32].chunks_exact(2))
                {
                    let ch = u16::from_le_bytes([pair[0], pair[1]]);
                    if ch == 0x0000 || ch == 0xFFFF {
                        break;
                    }
                    chars.push(ch);
                }
                lfn_fragments.push((ord & 0x1F, chars));
            } else {
                lfn_fragments.clear();
                expected_chksum = None;
            }
            continue;
        }

        if (attr & ATTR_VOLUME_ID) != 0 {
            lfn_fragments.clear();
            expected_chksum = None;
            continue;
        }

        let mut short_name = [0u8; 11];
        short_name.copy_from_slice(&chunk[0..11]);
        let fst_clus_hi = u16::from_le_bytes([chunk[20], chunk[21]]);
        let fst_clus_lo = u16::from_le_bytes([chunk[26], chunk[27]]);
        let file_size = u32::from_le_bytes([chunk[28], chunk[29], chunk[30], chunk[31]]);

        let entry = FatDirEntry {
            short_name,
            attr,
            nt_res: chunk[12],
            crt_time_tenth: chunk[13],
            crt_time: u16::from_le_bytes([chunk[14], chunk[15]]),
            crt_date: u16::from_le_bytes([chunk[16], chunk[17]]),
            lst_acc_date: u16::from_le_bytes([chunk[18], chunk[19]]),
            fst_clus_hi,
            wrt_time: u16::from_le_bytes([chunk[22], chunk[23]]),
            wrt_date: u16::from_le_bytes([chunk[24], chunk[25]]),
            fst_clus_lo,
            file_size,
        };

        let calc_chksum = compute_lfn_checksum(&short_name);
        let final_name = if !lfn_fragments.is_empty() && expected_chksum == Some(calc_chksum) {
            lfn_fragments.sort_by_key(|(seq, _)| *seq);
            let ucs2: Vec<u16> = lfn_fragments.iter().flat_map(|(_, v)| v.iter().copied()).collect();
            String::from_utf16_lossy(&ucs2)
        } else {
            entry.format_short_name()
        };

        lfn_fragments.clear();
        expected_chksum = None;

        results.push(ResolvedFatEntry {
            name: final_name,
            is_dir: (attr & ATTR_DIRECTORY) != 0,
            first_cluster: entry.first_cluster(),
            size_bytes: file_size,
        });
    }

    results
}

/// In-memory FAT32 File Allocation Table manager supporting cluster chain traversal and allocation.
pub struct Fat32Table {
    entries: Vec<u32>,
    next_free_hint: u32,
}

impl Fat32Table {
    pub fn new(total_clusters: usize) -> Self {
        let mut entries = Vec::with_capacity(total_clusters.max(3));
        for _ in 0..total_clusters.max(3) {
            entries.push(FAT32_CLUSTER_FREE);
        }
        // Clusters 0 and 1 are reserved by the FAT specification; cluster 2 is root directory EOC
        entries[0] = 0x0FFF_FFF8;
        entries[1] = FAT32_CLUSTER_EOC;
        entries[2] = FAT32_CLUSTER_EOC;
        Self {
            entries,
            next_free_hint: 3,
        }
    }

    /// Follows a cluster chain starting at `start_cluster`, guarding against cyclic corruption.
    pub fn follow_chain(&self, start_cluster: u32) -> Result<Vec<u32>, &'static str> {
        if start_cluster < 2 || (start_cluster as usize) >= self.entries.len() {
            return Err("Start cluster out of bounds");
        }

        let mut chain = Vec::new();
        let mut curr = start_cluster & FAT32_ENTRY_MASK;
        let max_steps = self.entries.len();

        while curr >= 2 && (curr as usize) < self.entries.len() {
            if chain.len() >= max_steps {
                return Err("Cyclic FAT32 cluster chain detected");
            }
            chain.push(curr);
            let next = self.entries[curr as usize] & FAT32_ENTRY_MASK;
            if next >= FAT32_CLUSTER_EOC_MIN {
                return Ok(chain);
            }
            if next == FAT32_CLUSTER_FREE || next == FAT32_CLUSTER_BAD {
                return Err("Broken or bad cluster in FAT32 chain");
            }
            curr = next;
        }
        Err("Invalid cluster pointer in chain")
    }

    /// Allocates a chain of `count` free clusters and links them together terminated by `FAT32_CLUSTER_EOC`.
    pub fn allocate_chain(&mut self, count: usize) -> Option<u32> {
        if count == 0 {
            return None;
        }

        let mut allocated = Vec::with_capacity(count);
        let total = self.entries.len() as u32;
        let start_search = self.next_free_hint.max(2);

        for offset in 0..total {
            let candidate = 2 + ((start_search - 2 + offset) % (total - 2));
            if (self.entries[candidate as usize] & FAT32_ENTRY_MASK) == FAT32_CLUSTER_FREE {
                allocated.push(candidate);
                if allocated.len() == count {
                    break;
                }
            }
        }

        if allocated.len() < count {
            return None;
        }

        for idx in 0..allocated.len() {
            let clus = allocated[idx] as usize;
            if idx + 1 < allocated.len() {
                self.entries[clus] = allocated[idx + 1] & FAT32_ENTRY_MASK;
            } else {
                self.entries[clus] = FAT32_CLUSTER_EOC;
                self.next_free_hint = allocated[idx] + 1;
            }
        }

        Some(allocated[0])
    }
}

/// Self-test suite for `fat32_esp`.
pub fn verify_vfs_fat32_esp() -> u32 {
    let mut passed = 0u32;

    // Construct a valid 512-byte FAT32 boot sector
    let mut boot = [0u8; 512];
    boot[3..11].copy_from_slice(b"COROSFAT");
    boot[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector = 512
    boot[13] = 8; // sectors_per_cluster = 8 (4 KiB clusters)
    boot[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved_sectors = 32
    boot[16] = 2; // num_fats = 2
    boot[32..36].copy_from_slice(&65536u32.to_le_bytes()); // total_sectors_32
    boot[36..40].copy_from_slice(&512u32.to_le_bytes()); // sectors_per_fat_32 = 512
    boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // root_cluster = 2
    boot[48..50].copy_from_slice(&1u16.to_le_bytes()); // fs_info_sector = 1
    boot[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup_boot_sector = 6
    boot[510] = 0x55;
    boot[511] = 0xAA;

    if let Some(bpb) = BiosParameterBlock::parse_boot_sector(&boot) {
        // first_data_sector = 32 + 2 * 512 = 1056; cluster 3 LBA = 1056 + 8 = 1064
        if bpb.first_data_sector() == 1056 && bpb.cluster_to_lba(3) == Some(1064) && bpb.cluster_size_bytes() == 4096 {
            passed += 1;
        }
    }

    // Verify 8.3 short-name checksum & directory parsing with LFN entry
    let short: [u8; 11] = *b"BOOTX64 EFI";
    let chksum = compute_lfn_checksum(&short);

    let mut dir_buf = [0u8; 64];
    // Entry 0: LFN entry for "bootx64.efi" (11 chars)
    dir_buf[0] = 0x41; // last LFN entry, seq 1
    dir_buf[11] = ATTR_LONG_NAME;
    dir_buf[13] = chksum;
    let lfn_utf16: [u16; 11] = [
        b'b' as u16, b'o' as u16, b'o' as u16, b't' as u16, b'x' as u16,
        b'6' as u16, b'4' as u16, b'.' as u16, b'e' as u16, b'f' as u16, b'i' as u16,
    ];
    for i in 0..5 {
        dir_buf[1 + i * 2..3 + i * 2].copy_from_slice(&lfn_utf16[i].to_le_bytes());
    }
    for i in 0..6 {
        dir_buf[14 + i * 2..16 + i * 2].copy_from_slice(&lfn_utf16[5 + i].to_le_bytes());
    }
    dir_buf[28..30].copy_from_slice(&0x0000u16.to_le_bytes());
    dir_buf[30..32].copy_from_slice(&0xFFFFu16.to_le_bytes());

    // Entry 1: 8.3 Short entry
    dir_buf[32..43].copy_from_slice(&short);
    dir_buf[32 + 11] = ATTR_ARCHIVE;
    dir_buf[32 + 26..32 + 28].copy_from_slice(&5u16.to_le_bytes()); // first cluster = 5
    dir_buf[32 + 28..32 + 32].copy_from_slice(&131072u32.to_le_bytes()); // 128 KiB

    let parsed = parse_fat32_directory(&dir_buf);
    if parsed.len() == 1 && parsed[0].name == "bootx64.efi" && parsed[0].first_cluster == 5 {
        passed += 1;
    }

    // Verify FAT32 cluster chain allocator and follower
    let mut fat = Fat32Table::new(64);
    if let Some(head) = fat.allocate_chain(4) {
        if let Ok(chain) = fat.follow_chain(head) {
            if chain.len() == 4 && chain[0] == 3 && chain[3] == 6 {
                passed += 1;
            }
        }
    }

    passed
}
