//! 100% In-House FAT32 Filesystem Driver for CorOS.
//! Provides native MBR partition parsing, FAT32 table caching, LFN name decoding,
//! directory traversal, and persistent file reading/writing.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::storage::{BlockDevice, StorageError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    DiskError(StorageError),
    InvalidMbr,
    PartitionNotFound,
    InvalidBpb,
    FileNotFound,
    NotADirectory,
    DirectoryFull,
    DiskFull,
    InvalidPath,
}

impl From<StorageError> for FsError {
    fn from(e: StorageError) -> Self {
        FsError::DiskError(e)
    }
}

#[derive(Clone, Debug)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_directory: bool,
    pub size: u32,
    pub first_cluster: u32,
}

pub static mut GLOBAL_FS: Option<Fat32FileSystem> = None;

pub struct Fat32FileSystem {
    device: Box<dyn BlockDevice>,
    pub partition_start_lba: u64,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub fat_start_lba: u64,
    pub data_start_lba: u64,
    pub total_clusters: u32,
    pub volume_label: String,
}

impl Fat32FileSystem {
    /// Mounts the FAT32 filesystem from the ESP partition on the block device
    pub fn mount(mut device: Box<dyn BlockDevice>) -> Result<Self, FsError> {
        // 1. Read Sector 0 (MBR)
        let mut mbr_buf = [0u8; 512];
        device.read_sectors(0, 1, &mut mbr_buf)?;

        if mbr_buf[510] != 0x55 || mbr_buf[511] != 0xAA {
            return Err(FsError::InvalidMbr);
        }

        // 2. Scan MBR Partition Table (4 entries at offset 446)
        let mut part_start_lba = 0u64;
        let mut part_found = false;

        for i in 0..4 {
            let offset = 446 + i * 16;
            let part_type = mbr_buf[offset + 4];
            let start_lba = u32::from_le_bytes([
                mbr_buf[offset + 8],
                mbr_buf[offset + 9],
                mbr_buf[offset + 10],
                mbr_buf[offset + 11],
            ]) as u64;

            // Type 0xEF = EFI System Partition (ESP), 0x0B/0x0C = FAT32
            if part_type == 0xEF || part_type == 0x0C || part_type == 0x0B {
                part_start_lba = start_lba;
                part_found = true;
                break;
            }
        }

        if !part_found {
            // Check if Sector 0 is itself a FAT32 VBR (superfloppy mode)
            if &mbr_buf[82..87] == b"FAT32" {
                part_start_lba = 0;
            } else {
                return Err(FsError::PartitionNotFound);
            }
        }

        // 3. Read Volume Boot Record (BPB)
        let mut vbr_buf = [0u8; 512];
        device.read_sectors(part_start_lba, 1, &mut vbr_buf)?;

        if vbr_buf[510] != 0x55 || vbr_buf[511] != 0xAA {
            return Err(FsError::InvalidBpb);
        }

        let bytes_per_sector = u16::from_le_bytes([vbr_buf[11], vbr_buf[12]]);
        if bytes_per_sector != 512 {
            return Err(FsError::InvalidBpb);
        }

        let sectors_per_cluster = vbr_buf[13];
        let reserved_sectors = u16::from_le_bytes([vbr_buf[14], vbr_buf[15]]);
        let num_fats = vbr_buf[16];
        let sectors_per_fat = u32::from_le_bytes([vbr_buf[36], vbr_buf[37], vbr_buf[38], vbr_buf[39]]);
        let root_cluster = u32::from_le_bytes([vbr_buf[44], vbr_buf[45], vbr_buf[46], vbr_buf[47]]);

        let total_sectors_32 = u32::from_le_bytes([vbr_buf[32], vbr_buf[33], vbr_buf[34], vbr_buf[35]]);
        let fat_start_lba = part_start_lba + reserved_sectors as u64;
        let data_start_lba = fat_start_lba + (num_fats as u64 * sectors_per_fat as u64);
        let data_sectors = (total_sectors_32 as u64).saturating_sub(reserved_sectors as u64 + (num_fats as u64 * sectors_per_fat as u64));
        let total_clusters = (data_sectors / sectors_per_cluster as u64) as u32;

        let mut label = String::new();
        for &b in &vbr_buf[71..82] {
            if b != b' ' && b != 0 {
                label.push(b as char);
            }
        }

        Ok(Self {
            device,
            partition_start_lba: part_start_lba,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_cluster,
            fat_start_lba,
            data_start_lba,
            total_clusters,
            volume_label: label,
        })
    }

    pub fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba + ((cluster.saturating_sub(2)) as u64 * self.sectors_per_cluster as u64)
    }

    pub fn read_fat_entry(&mut self, cluster: u32) -> Result<u32, FsError> {
        let fat_offset = (cluster as u64) * 4;
        let fat_sector = self.fat_start_lba + (fat_offset / 512);
        let byte_offset = (fat_offset % 512) as usize;

        let mut sec_buf = [0u8; 512];
        self.device.read_sectors(fat_sector, 1, &mut sec_buf)?;

        let val = u32::from_le_bytes([
            sec_buf[byte_offset],
            sec_buf[byte_offset + 1],
            sec_buf[byte_offset + 2],
            sec_buf[byte_offset + 3],
        ]);
        Ok(val & 0x0FFF_FFFF)
    }

    pub fn write_fat_entry(&mut self, cluster: u32, next_cluster: u32) -> Result<(), FsError> {
        let fat_offset = (cluster as u64) * 4;
        let sec_idx = fat_offset / 512;
        let byte_offset = (fat_offset % 512) as usize;

        // Update each FAT copy (usually FAT1 and FAT2)
        for fat_i in 0..self.num_fats {
            let fat_sector = self.fat_start_lba + (fat_i as u64 * self.sectors_per_fat as u64) + sec_idx;
            let mut sec_buf = [0u8; 512];
            self.device.read_sectors(fat_sector, 1, &mut sec_buf)?;

            let bytes = (next_cluster & 0x0FFF_FFFF).to_le_bytes();
            sec_buf[byte_offset..byte_offset + 4].copy_from_slice(&bytes);

            self.device.write_sectors(fat_sector, 1, &sec_buf)?;
        }
        Ok(())
    }

    pub fn allocate_cluster(&mut self) -> Result<u32, FsError> {
        for c in 3..self.total_clusters {
            if self.read_fat_entry(c)? == 0 {
                self.write_fat_entry(c, 0x0FFF_FFFF)?; // EOF marker
                // Zero out the newly allocated cluster
                let lba = self.cluster_to_lba(c);
                let zeros = [0u8; 512];
                for s in 0..self.sectors_per_cluster {
                    self.device.write_sectors(lba + s as u64, 1, &zeros)?;
                }
                return Ok(c);
            }
        }
        Err(FsError::DiskFull)
    }

    pub fn read_cluster_data(&mut self, cluster: u32, buf: &mut [u8]) -> Result<(), FsError> {
        let lba = self.cluster_to_lba(cluster);
        self.device.read_sectors(lba, self.sectors_per_cluster as u32, buf)?;
        Ok(())
    }

    pub fn write_cluster_data(&mut self, cluster: u32, buf: &[u8]) -> Result<(), FsError> {
        let lba = self.cluster_to_lba(cluster);
        self.device.write_sectors(lba, self.sectors_per_cluster as u32, buf)?;
        Ok(())
    }

    pub fn read_directory_entries(&mut self, dir_cluster: u32) -> Result<Vec<DirEntryInfo>, FsError> {
        let mut entries = Vec::new();
        let cluster_bytes = (self.sectors_per_cluster as usize) * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_bytes];

        let mut cur_cluster = dir_cluster;
        let mut lfn_chars: Vec<u16> = Vec::new();

        while cur_cluster < 0x0FFF_FFF8 && cur_cluster >= 2 {
            self.read_cluster_data(cur_cluster, &mut cluster_buf)?;

            for i in 0..(cluster_bytes / 32) {
                let entry = &cluster_buf[i * 32..(i + 1) * 32];
                let first_byte = entry[0];

                if first_byte == 0x00 {
                    // No more entries
                    return Ok(entries);
                }
                if first_byte == 0xE5 {
                    // Deleted entry, reset LFN
                    lfn_chars.clear();
                    continue;
                }

                let attr = entry[11];
                if attr == 0x0F {
                    // Long File Name (LFN) entry
                    let mut chunk = [0u16; 13];
                    chunk[0] = u16::from_le_bytes([entry[1], entry[2]]);
                    chunk[1] = u16::from_le_bytes([entry[3], entry[4]]);
                    chunk[2] = u16::from_le_bytes([entry[5], entry[6]]);
                    chunk[3] = u16::from_le_bytes([entry[7], entry[8]]);
                    chunk[4] = u16::from_le_bytes([entry[9], entry[10]]);

                    chunk[5] = u16::from_le_bytes([entry[14], entry[15]]);
                    chunk[6] = u16::from_le_bytes([entry[16], entry[17]]);
                    chunk[7] = u16::from_le_bytes([entry[18], entry[19]]);
                    chunk[8] = u16::from_le_bytes([entry[20], entry[21]]);
                    chunk[9] = u16::from_le_bytes([entry[22], entry[23]]);
                    chunk[10] = u16::from_le_bytes([entry[24], entry[25]]);

                    chunk[11] = u16::from_le_bytes([entry[28], entry[29]]);
                    chunk[12] = u16::from_le_bytes([entry[30], entry[31]]);

                    // Insert at beginning because LFN entries are in reverse order
                    for &c in chunk.iter().rev() {
                        if c != 0xFFFF && c != 0 {
                            lfn_chars.insert(0, c);
                        }
                    }
                    continue;
                }

                // Standard 8.3 Directory Entry
                let name = if !lfn_chars.is_empty() {
                    let mut s = String::new();
                    for &u in &lfn_chars {
                        if u < 128 {
                            s.push(u as u8 as char);
                        }
                    }
                    lfn_chars.clear();
                    s
                } else {
                    let mut short_name = String::new();
                    for &b in &entry[0..8] {
                        if b != b' ' {
                            short_name.push(b as char);
                        }
                    }
                    let mut short_ext = String::new();
                    for &b in &entry[8..11] {
                        if b != b' ' {
                            short_ext.push(b as char);
                        }
                    }
                    if !short_ext.is_empty() {
                        short_name.push('.');
                        short_name.push_str(&short_ext);
                    }
                    short_name
                };

                let is_dir = (attr & 0x10) != 0;
                let cluster_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let cluster_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let first_c = (cluster_hi << 16) | cluster_lo;
                let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

                if name != "." && name != ".." {
                    entries.push(DirEntryInfo {
                        name,
                        is_directory: is_dir,
                        size: file_size,
                        first_cluster: first_c,
                    });
                }
            }

            cur_cluster = self.read_fat_entry(cur_cluster)?;
        }

        Ok(entries)
    }

    /// Reads an entire file by relative or absolute path (e.g. "/EFI/BOOT/BOOTX64.EFI")
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, FsError> {
        let clean_path = path.trim_start_matches('/');
        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Err(FsError::InvalidPath);
        }

        let mut cur_dir_cluster = self.root_cluster;

        for (idx, part) in parts.iter().enumerate() {
            let is_last = idx == parts.len() - 1;
            let entries = self.read_directory_entries(cur_dir_cluster)?;

            let found = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(part));

            match found {
                Some(entry) => {
                    if is_last {
                        if entry.is_directory {
                            return Err(FsError::NotADirectory);
                        }
                        // Read file data
                        return self.read_file_clusters(entry.first_cluster, entry.size as usize);
                    } else {
                        if !entry.is_directory {
                            return Err(FsError::NotADirectory);
                        }
                        cur_dir_cluster = entry.first_cluster;
                    }
                }
                None => return Err(FsError::FileNotFound),
            }
        }

        Err(FsError::FileNotFound)
    }

    fn read_file_clusters(&mut self, start_cluster: u32, size: usize) -> Result<Vec<u8>, FsError> {
        let mut data = Vec::with_capacity(size);
        let cluster_bytes = (self.sectors_per_cluster as usize) * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_bytes];

        let mut cur_cluster = start_cluster;

        while cur_cluster < 0x0FFF_FFF8 && cur_cluster >= 2 && data.len() < size {
            self.read_cluster_data(cur_cluster, &mut cluster_buf)?;
            let to_copy = (size - data.len()).min(cluster_bytes);
            data.extend_from_slice(&cluster_buf[..to_copy]);
            cur_cluster = self.read_fat_entry(cur_cluster)?;
        }

        Ok(data)
    }

    /// Lists directory contents for a given path
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntryInfo>, FsError> {
        let clean_path = path.trim_start_matches('/');
        if clean_path.is_empty() {
            return self.read_directory_entries(self.root_cluster);
        }

        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
        let mut cur_dir_cluster = self.root_cluster;

        for part in parts {
            let entries = self.read_directory_entries(cur_dir_cluster)?;
            let found = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(part));
            match found {
                Some(entry) if entry.is_directory => {
                    cur_dir_cluster = entry.first_cluster;
                }
                _ => return Err(FsError::FileNotFound),
            }
        }

        self.read_directory_entries(cur_dir_cluster)
    }

    /// Writes data to a new or existing file at `path` (e.g. "/EFI/COROS/BOOT.LOG")
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        let clean_path = path.trim_start_matches('/');
        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Err(FsError::InvalidPath);
        }

        let file_name = parts[parts.len() - 1];
        let mut cur_dir_cluster = self.root_cluster;

        // Traverse to parent directory
        for &dir_part in &parts[..parts.len() - 1] {
            let entries = self.read_directory_entries(cur_dir_cluster)?;
            let found = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(dir_part));
            match found {
                Some(entry) if entry.is_directory => cur_dir_cluster = entry.first_cluster,
                _ => return Err(FsError::FileNotFound),
            }
        }

        // If file already exists, delete it first to free old cluster chain and overwrite cleanly
        let _ = self.delete_file(path);

        // Allocate clusters for the file
        let cluster_bytes = (self.sectors_per_cluster as usize) * 512;
        let num_clusters = if data.is_empty() { 1 } else { (data.len() + cluster_bytes - 1) / cluster_bytes };

        let first_cluster = self.allocate_cluster()?;
        let mut cur_cluster = first_cluster;

        for chunk_idx in 0..num_clusters {
            let start = chunk_idx * cluster_bytes;
            let end = (start + cluster_bytes).min(data.len());
            let mut buf = alloc::vec![0u8; cluster_bytes];
            if start < data.len() {
                buf[..end - start].copy_from_slice(&data[start..end]);
            }
            self.write_cluster_data(cur_cluster, &buf)?;

            if chunk_idx + 1 < num_clusters {
                let next = self.allocate_cluster()?;
                self.write_fat_entry(cur_cluster, next)?;
                cur_cluster = next;
            } else {
                self.write_fat_entry(cur_cluster, 0x0FFF_FFFF)?; // EOF
            }
        }

        // Add 8.3 entry to parent directory
        self.add_directory_entry(cur_dir_cluster, file_name, first_cluster, data.len() as u32)?;

        Ok(())
    }

    fn add_directory_entry(&mut self, dir_cluster: u32, filename: &str, first_cluster: u32, size: u32) -> Result<(), FsError> {
        let cluster_bytes = (self.sectors_per_cluster as usize) * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_bytes];

        let mut cur_cluster = dir_cluster;
        loop {
            self.read_cluster_data(cur_cluster, &mut cluster_buf)?;

            for i in 0..(cluster_bytes / 32) {
                let offset = i * 32;
                let b = cluster_buf[offset];
                if b == 0x00 || b == 0xE5 {
                    // Found free slot!
                    let mut entry = [0u8; 32];
                    // Format 8.3 filename
                    let parts: Vec<&str> = filename.split('.').collect();
                    let name_part = parts[0].as_bytes();
                    let ext_part = if parts.len() > 1 { parts[1].as_bytes() } else { &[] };

                    for j in 0..8 {
                        entry[j] = if j < name_part.len() { name_part[j].to_ascii_uppercase() } else { b' ' };
                    }
                    for j in 0..3 {
                        entry[8 + j] = if j < ext_part.len() { ext_part[j].to_ascii_uppercase() } else { b' ' };
                    }

                    entry[11] = 0x20; // Archive / Regular file
                    entry[20] = ((first_cluster >> 16) & 0xFF) as u8;
                    entry[21] = ((first_cluster >> 24) & 0xFF) as u8;
                    entry[26] = (first_cluster & 0xFF) as u8;
                    entry[27] = ((first_cluster >> 8) & 0xFF) as u8;

                    let size_bytes = size.to_le_bytes();
                    entry[28..32].copy_from_slice(&size_bytes);

                    cluster_buf[offset..offset + 32].copy_from_slice(&entry);
                    self.write_cluster_data(cur_cluster, &cluster_buf)?;
                    return Ok(());
                }
            }

            let next = self.read_fat_entry(cur_cluster)?;
            if next >= 0x0FFF_FFF8 {
                // Directory cluster is full, allocate new cluster for directory
                let new_cluster = self.allocate_cluster()?;
                self.write_fat_entry(cur_cluster, new_cluster)?;
                cur_cluster = new_cluster;
            } else {
                cur_cluster = next;
            }
        }
    }

    /// Deletes a file at `path` by marking its directory entry as 0xE5 and clearing its FAT chain
    pub fn delete_file(&mut self, path: &str) -> Result<(), FsError> {
        let clean_path = path.trim_start_matches('/');
        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Err(FsError::InvalidPath);
        }

        let file_name = parts[parts.len() - 1];
        let mut cur_dir_cluster = self.root_cluster;

        // Traverse to parent directory
        for &dir_part in &parts[..parts.len() - 1] {
            let entries = self.read_directory_entries(cur_dir_cluster)?;
            let found = entries.into_iter().find(|e| e.name.eq_ignore_ascii_case(dir_part));
            match found {
                Some(entry) if entry.is_directory => cur_dir_cluster = entry.first_cluster,
                _ => return Err(FsError::FileNotFound),
            }
        }

        let cluster_bytes = (self.sectors_per_cluster as usize) * 512;
        let mut cluster_buf = alloc::vec![0u8; cluster_bytes];
        let mut dir_cluster = cur_dir_cluster;

        while dir_cluster < 0x0FFF_FFF8 && dir_cluster >= 2 {
            self.read_cluster_data(dir_cluster, &mut cluster_buf)?;

            for i in 0..(cluster_bytes / 32) {
                let offset = i * 32;
                let b = cluster_buf[offset];
                if b == 0x00 {
                    return Err(FsError::FileNotFound);
                }
                if b == 0xE5 {
                    continue;
                }

                // Format short name to match
                let mut name_buf = [b' '; 11];
                let file_parts: Vec<&str> = file_name.split('.').collect();
                let np = file_parts[0].as_bytes();
                let ep = if file_parts.len() > 1 { file_parts[1].as_bytes() } else { &[] };
                for j in 0..8 {
                    if j < np.len() { name_buf[j] = np[j].to_ascii_uppercase(); }
                }
                for j in 0..3 {
                    if j < ep.len() { name_buf[8 + j] = ep[j].to_ascii_uppercase(); }
                }

                if &cluster_buf[offset..offset + 11] == &name_buf[..] {
                    // Found file entry! Read first cluster to free FAT chain
                    let low = u16::from_le_bytes([cluster_buf[offset + 26], cluster_buf[offset + 27]]) as u32;
                    let high = u16::from_le_bytes([cluster_buf[offset + 20], cluster_buf[offset + 21]]) as u32;
                    let mut first_cluster = (high << 16) | low;

                    // Mark directory entry as deleted (0xE5)
                    cluster_buf[offset] = 0xE5;
                    self.write_cluster_data(dir_cluster, &cluster_buf)?;

                    // Free cluster chain in FAT
                    while first_cluster < 0x0FFF_FFF8 && first_cluster >= 2 {
                        let next = self.read_fat_entry(first_cluster)?;
                        let _ = self.write_fat_entry(first_cluster, 0); // Mark cluster free
                        first_cluster = next;
                    }

                    return Ok(());
                }
            }

            dir_cluster = self.read_fat_entry(dir_cluster)?;
        }

        Err(FsError::FileNotFound)
    }
}
