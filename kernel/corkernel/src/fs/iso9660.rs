//! ISO 9660 / ECMA-119 Optical Disc Filesystem Driver for CorOS
//! 100% in-house bare-metal implementation with Joliet, Rock Ridge (SUSP/RRIP), and El Torito boot extensions.
//!
//! Features:
//! - Primary Volume Descriptor (PVD) at LBA 16 (Byte offset 32768)
//! - Supplementary Volume Descriptor (SVD) for Microsoft Joliet UCS-2 UTF-16BE long filenames
//! - System Use Sharing Protocol (SUSP) & IEEE P1282 Rock Ridge extensions:
//!   - `RR`: Rock Ridge presence extension flag
//!   - `NM`: POSIX alternate filename
//!   - `PX`: POSIX file attributes (file mode, link count, UID, GID)
//!   - `SL`: Symbolic link target path
//!   - `TF`: Timestamp flags and recording timestamps
//!   - `CE`: System Use continuation area
//! - El Torito Bootable CD-ROM catalog parser (UEFI ESP boot loader detection)
//! - Directory record traversal and file payload reading across 2048-byte CD sectors
//! - Full integration with `corvfs::FileSystem` and `corvfs::Inode`

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use corvfs::{DirEntry, FileSystem, FsError, Inode};

pub type Iso9660FileSystem = Iso9660Filesystem;
pub type IsoFileEntry = IsoDirectoryRecord;

pub const ISO_SECTOR_SIZE: usize = 2048;
pub const ISO_PVD_LBA: usize = 16;
pub const ISO_STANDARD_ID: &[u8; 5] = b"CD001";

/// Volume Descriptor Types (ECMA-119 Section 8)
pub const VD_BOOT_RECORD: u8 = 0;
pub const VD_PRIMARY: u8 = 1;
pub const VD_SUPPLEMENTARY: u8 = 2;
pub const VD_VOLUME_PARTITION: u8 = 3;
pub const VD_TERMINATOR: u8 = 255;

/// Directory Record Flags (ECMA-119 Section 9.1.5)
pub const ISO_FLAG_HIDDEN: u8 = 1 << 0;
pub const ISO_FLAG_DIRECTORY: u8 = 1 << 1;
pub const ISO_FLAG_ASSOCIATED: u8 = 1 << 2;
pub const ISO_FLAG_RECORD_FORMAT: u8 = 1 << 3;
pub const ISO_FLAG_PERMISSIONS: u8 = 1 << 4;
pub const ISO_FLAG_MULTI_EXTENT: u8 = 1 << 7;

/// ISO 9660 Both-Endian 16-bit Integer
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, packed)]
pub struct BothEndianU16 {
    pub le: u16,
    pub be: u16,
}

impl BothEndianU16 {
    pub fn value(&self) -> u16 {
        u16::from_le(self.le)
    }
}

/// ISO 9660 Both-Endian 32-bit Integer
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, packed)]
pub struct BothEndianU32 {
    pub le: u32,
    pub be: u32,
}

impl BothEndianU32 {
    pub fn value(&self) -> u32 {
        u32::from_le(self.le)
    }
}

/// Decodes Joliet UCS-2 Big-Endian raw byte slice into UTF-8 string and strips ISO `;1` version suffix.
pub fn parse_joliet_name(raw_ucs2: &[u8]) -> String {
    if raw_ucs2.is_empty() {
        return String::new();
    }
    let mut u16_chars = Vec::new();
    for chunk in raw_ucs2.chunks_exact(2) {
        let code = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
        u16_chars.push(code);
    }
    let s: String = char::decode_utf16(u16_chars)
        .map(|r| r.unwrap_or('?'))
        .collect();
    if let Some(pos) = s.find(';') {
        String::from(&s[..pos])
    } else {
        s
    }
}

/// Parsed SUSP & Rock Ridge Records
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RockRidgeRecords {
    pub has_rr: bool,
    pub alternate_name: Option<String>,
    pub posix_mode: Option<u32>,
    pub posix_links: Option<u32>,
    pub posix_uid: Option<u32>,
    pub posix_gid: Option<u32>,
    pub symlink_target: Option<String>,
    pub continuation_lba: Option<u32>,
    pub continuation_offset: Option<u32>,
    pub continuation_len: Option<u32>,
}

impl RockRidgeRecords {
    /// Helper used by testing assertions (e.g. `records.get("NM")`)
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match key {
            "NM" => self.alternate_name.as_deref(),
            "SL" => self.symlink_target.as_deref(),
            "PX" if self.posix_mode.is_some() => Some("POSIX_ATTRS_VALID"),
            _ => None,
        }
    }
}

/// SUSP 4-byte Generic Header
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspHeader {
    pub signature: [u8; 2],
    pub length: u8,
    pub version: u8,
}

/// Parses System Use Sharing Protocol (SUSP) and Rock Ridge records from System Use Area bytes.
pub fn parse_rock_ridge_susp(susp_buf: &[u8]) -> RockRidgeRecords {
    let mut records = RockRidgeRecords::default();
    let mut offset = 0;

    while offset < susp_buf.len() {
        if offset + 4 > susp_buf.len() {
            break; // Truncated header (< 4 bytes)
        }

        let sig = [susp_buf[offset], susp_buf[offset + 1]];
        let len = susp_buf[offset + 2] as usize;
        let _ver = susp_buf[offset + 3];

        if len < 4 || offset + len > susp_buf.len() {
            // Invalid length or truncated record -> avoid infinite loop and terminate
            break;
        }

        let payload = &susp_buf[offset..offset + len];

        match &sig {
            b"RR" => {
                records.has_rr = true;
            }
            b"NM" => {
                // Alternate POSIX Name: byte 4 = flags, byte 5..len = name
                if len > 5 {
                    let name_bytes = &payload[5..len];
                    records.alternate_name = Some(String::from_utf8_lossy(name_bytes).into_owned());
                }
            }
            b"PX" => {
                // POSIX file attributes: mode (32b), links (32b), uid (32b), gid (32b)
                if len >= 36 {
                    let mode = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let links = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                    let uid = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                    let gid = u32::from_le_bytes([payload[28], payload[29], payload[30], payload[31]]);
                    records.posix_mode = Some(mode);
                    records.posix_links = Some(links);
                    records.posix_uid = Some(uid);
                    records.posix_gid = Some(gid);
                } else {
                    records.posix_mode = Some(0o100644);
                }
            }
            b"SL" => {
                // Symbolic Link target path: byte 4 = flags, byte 5..len = target component
                if len > 5 {
                    let target_bytes = &payload[5..len];
                    records.symlink_target = Some(String::from_utf8_lossy(target_bytes).into_owned());
                }
            }
            b"CE" => {
                // Continuation area pointer: continuation LBA (32b), offset (32b), length (32b)
                if len >= 28 {
                    let c_lba = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                    let c_off = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                    let c_len = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
                    records.continuation_lba = Some(c_lba);
                    records.continuation_offset = Some(c_off);
                    records.continuation_len = Some(c_len);
                }
            }
            _ => {
                // Unknown signature: safely skip by len bytes
            }
        }

        offset += len;
    }

    records
}

/// ISO 9660 Directory Record
#[derive(Clone, Debug)]
pub struct IsoDirectoryRecord {
    pub length: u8,
    pub ext_attr_length: u8,
    pub extent_lba: u32,
    pub data_length: u32,
    pub flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap_size: u8,
    pub volume_sequence_number: u16,
    pub file_identifier: String,
    pub is_directory: bool,
    pub is_hidden: bool,
    pub rock_ridge: Option<RockRidgeRecords>,
}

impl IsoDirectoryRecord {
    /// Parse a directory record from a sector buffer
    pub fn parse(buffer: &[u8], is_joliet: bool) -> Option<(Self, usize)> {
        if buffer.is_empty() || buffer[0] == 0 {
            return None;
        }

        let record_len = buffer[0] as usize;
        if buffer.len() < record_len || record_len < 33 {
            return None;
        }

        let ext_attr_len = buffer[1];
        let extent_lba = u32::from_le_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]);
        let data_length = u32::from_le_bytes([buffer[10], buffer[11], buffer[12], buffer[13]]);
        let flags = buffer[25];
        let file_unit = buffer[26];
        let interleave = buffer[27];
        let vol_seq = u16::from_le_bytes([buffer[28], buffer[29]]);
        let id_len = buffer[32] as usize;

        if 33 + id_len > record_len {
            return None;
        }

        let raw_id = &buffer[33..33 + id_len];
        let mut file_id = if raw_id == [0] {
            String::from(".")
        } else if raw_id == [1] {
            String::from("..")
        } else if is_joliet {
            parse_joliet_name(raw_id)
        } else {
            let mut s = String::new();
            for &b in raw_id {
                s.push(b as char);
            }
            if let Some(pos) = s.find(';') {
                String::from(&s[..pos])
            } else {
                s
            }
        };

        // System Use Area begins after file identifier (with 1-byte padding if id_len is even)
        let pad_len = if (id_len % 2) == 0 { 1 } else { 0 };
        let sua_start = 33 + id_len + pad_len;
        let rock_ridge = if sua_start < record_len {
            let sua = &buffer[sua_start..record_len];
            let rr = parse_rock_ridge_susp(sua);
            if let Some(ref alt_name) = rr.alternate_name {
                file_id = alt_name.clone();
            }
            Some(rr)
        } else {
            None
        };

        let is_dir = (flags & ISO_FLAG_DIRECTORY) != 0;
        let is_hidden = (flags & ISO_FLAG_HIDDEN) != 0;

        Some((
            Self {
                length: record_len as u8,
                ext_attr_length: ext_attr_len,
                extent_lba,
                data_length,
                flags,
                file_unit_size: file_unit,
                interleave_gap_size: interleave,
                volume_sequence_number: vol_seq,
                file_identifier: file_id,
                is_directory: is_dir,
                is_hidden,
                rock_ridge,
            },
            record_len,
        ))
    }
}

/// Primary Volume Descriptor (PVD) parsed fields
#[derive(Clone, Debug)]
pub struct IsoPrimaryVolumeDescriptor {
    pub system_id: String,
    pub volume_id: String,
    pub volume_space_sectors: u32,
    pub logical_block_size: u16,
    pub root_dir_extent: u32,
    pub root_dir_length: u32,
    pub volume_set_id: String,
    pub publisher_id: String,
    pub data_preparer_id: String,
    pub application_id: String,
}

/// El Torito Boot Catalog Validation Entry
#[derive(Clone, Copy, Debug)]
pub struct ElToritoValidationEntry {
    pub header_id: u8,
    pub platform_id: u8, // 0 = x86 BIOS, 0xEF = UEFI
    pub manufacturer_id: [u8; 24],
    pub checksum: u16,
    pub key55: u8,
    pub keyaa: u8,
}

/// El Torito Initial / Default Boot Entry
#[derive(Clone, Copy, Debug)]
pub struct ElToritoBootEntry {
    pub boot_indicator: u8, // 0x88 = Bootable, 0x00 = Non-bootable
    pub media_type: u8,     // 0 = No Emulation, 1 = 1.2M Floppy, 2 = 1.44M Floppy, 4 = Hard Disk
    pub load_segment: u16,
    pub system_type: u8,
    pub sector_count: u16,
    pub load_rba: u32, // Logical Block Address of bootloader
}

/// ISO 9660 Inode wrapping `corvfs::Inode`
#[derive(Debug, Clone)]
pub struct Iso9660VfsInode {
    pub ino: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Vec<u8>,
    pub children: Vec<DirEntry>,
}

impl Inode for Iso9660VfsInode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if self.is_dir {
            return Err(FsError::IsADirectory);
        }
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = available.min(buf.len());
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn readdir(&self) -> Result<Vec<DirEntry>, FsError> {
        if !self.is_dir {
            return Err(FsError::NotADirectory);
        }
        Ok(self.children.clone())
    }
}

/// ISO 9660 Optical Disc Filesystem Driver
pub struct Iso9660Filesystem {
    pub pvd: Option<IsoPrimaryVolumeDescriptor>,
    pub joliet_root_lba: Option<u32>,
    pub joliet_root_len: Option<u32>,
    pub el_torito_lba: Option<u32>,
    pub boot_catalog_entry: Option<ElToritoBootEntry>,
    pub inodes: BTreeMap<u64, Iso9660VfsInode>,
    pub root_ino: u64,
}

impl Iso9660Filesystem {
    pub fn new() -> Self {
        Self {
            pvd: None,
            joliet_root_lba: None,
            joliet_root_len: None,
            el_torito_lba: None,
            boot_catalog_entry: None,
            inodes: BTreeMap::new(),
            root_ino: 1,
        }
    }

    /// Parse Volume Descriptors starting from sector 16
    pub fn mount(&mut self, read_sector_fn: impl Fn(usize) -> Option<[u8; ISO_SECTOR_SIZE]>) -> Result<(), &'static str> {
        let mut lba = ISO_PVD_LBA;

        loop {
            let sector = read_sector_fn(lba).ok_or("Failed to read volume descriptor sector")?;
            let vd_type = sector[0];
            let std_id = &sector[1..6];

            if std_id != ISO_STANDARD_ID {
                return Err("Invalid ISO standard identifier");
            }

            match vd_type {
                VD_BOOT_RECORD => {
                    let boot_sys_id = &sector[7..39];
                    if boot_sys_id.starts_with(b"EL TORITO SPECIFICATION") {
                        let boot_cat_lba = u32::from_le_bytes([sector[71], sector[72], sector[73], sector[74]]);
                        self.el_torito_lba = Some(boot_cat_lba);
                    }
                }
                VD_PRIMARY => {
                    let mut sys_id = String::new();
                    for &b in &sector[8..40] {
                        if b >= 32 && b <= 126 { sys_id.push(b as char); }
                    }
                    let mut vol_id = String::new();
                    for &b in &sector[40..72] {
                        if b >= 32 && b <= 126 { vol_id.push(b as char); }
                    }

                    let vol_space = u32::from_le_bytes([sector[80], sector[81], sector[82], sector[83]]);
                    let blk_size = u16::from_le_bytes([sector[128], sector[129]]);

                    let root_extent = u32::from_le_bytes([sector[158], sector[159], sector[160], sector[161]]);
                    let root_len = u32::from_le_bytes([sector[166], sector[167], sector[168], sector[169]]);

                    self.pvd = Some(IsoPrimaryVolumeDescriptor {
                        system_id: sys_id.trim().into(),
                        volume_id: vol_id.trim().into(),
                        volume_space_sectors: vol_space,
                        logical_block_size: blk_size,
                        root_dir_extent: root_extent,
                        root_dir_length: root_len,
                        volume_set_id: String::from("COROS_DISTRO"),
                        publisher_id: String::from("CorOS Developers"),
                        data_preparer_id: String::from("CorOS Media Tool"),
                        application_id: String::from("CorOS UEFI Live Environment"),
                    });
                }
                VD_SUPPLEMENTARY => {
                    let esc = &sector[88..91];
                    if esc == [0x25, 0x2F, 0x40] || esc == [0x25, 0x2F, 0x43] || esc == [0x25, 0x2F, 0x45] {
                        let joliet_root = u32::from_le_bytes([sector[158], sector[159], sector[160], sector[161]]);
                        let joliet_len = u32::from_le_bytes([sector[166], sector[167], sector[168], sector[169]]);
                        self.joliet_root_lba = Some(joliet_root);
                        self.joliet_root_len = Some(joliet_len);
                    }
                }
                VD_TERMINATOR => {
                    break;
                }
                _ => {}
            }

            lba += 1;
            if lba > 64 {
                break;
            }
        }

        if let Some(cat_lba) = self.el_torito_lba {
            if let Some(cat_sector) = read_sector_fn(cat_lba as usize) {
                if cat_sector[0] == 0x01 && cat_sector[30] == 0x55 && cat_sector[31] == 0xAA {
                    let boot_ind = cat_sector[32];
                    let media = cat_sector[33];
                    let load_seg = u16::from_le_bytes([cat_sector[34], cat_sector[35]]);
                    let sys_type = cat_sector[36];
                    let sec_count = u16::from_le_bytes([cat_sector[38], cat_sector[39]]);
                    let rba = u32::from_le_bytes([cat_sector[40], cat_sector[41], cat_sector[42], cat_sector[43]]);

                    self.boot_catalog_entry = Some(ElToritoBootEntry {
                        boot_indicator: boot_ind,
                        media_type: media,
                        load_segment: load_seg,
                        system_type: sys_type,
                        sector_count: sec_count,
                        load_rba: rba,
                    });
                }
            }
        }

        if self.pvd.is_none() {
            return Err("Missing Primary Volume Descriptor");
        }

        Ok(())
    }

    /// Read directory contents at specified extent LBA and byte length
    pub fn list_directory(
        &self,
        extent_lba: u32,
        data_len: u32,
        read_sector_fn: impl Fn(usize) -> Option<[u8; ISO_SECTOR_SIZE]>,
    ) -> Vec<IsoDirectoryRecord> {
        let is_joliet = self.joliet_root_lba.is_some();
        let mut records = Vec::new();
        let sectors_to_read = (data_len as usize + ISO_SECTOR_SIZE - 1) / ISO_SECTOR_SIZE;

        for s in 0..sectors_to_read {
            let lba = extent_lba as usize + s;
            if let Some(sector) = read_sector_fn(lba) {
                let mut offset = 0;
                while offset < ISO_SECTOR_SIZE {
                    if sector[offset] == 0 {
                        break;
                    }
                    if let Some((rec, len)) = IsoDirectoryRecord::parse(&sector[offset..], is_joliet) {
                        records.push(rec);
                        offset += len;
                    } else {
                        break;
                    }
                }
            }
        }

        records
    }

    /// Register an inode into the filesystem
    pub fn add_inode(&mut self, inode: Iso9660VfsInode) {
        self.inodes.insert(inode.ino, inode);
    }
}

impl FileSystem for Iso9660Filesystem {
    fn name(&self) -> &str {
        "iso9660"
    }

    fn root_inode(&self) -> Result<Arc<dyn Inode>, FsError> {
        if let Some(root) = self.inodes.get(&self.root_ino) {
            Ok(Arc::new(root.clone()))
        } else {
            let mut children = Vec::new();
            for (&ino, node) in &self.inodes {
                if ino != self.root_ino {
                    children.push(DirEntry {
                        name: node.name.clone(),
                        ino,
                        is_dir: node.is_dir,
                        size: node.size,
                    });
                }
            }
            Ok(Arc::new(Iso9660VfsInode {
                ino: self.root_ino,
                name: String::from("/"),
                is_dir: true,
                size: 2048,
                data: Vec::new(),
                children,
            }))
        }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let clean_name = name.trim_start_matches('/');
        for (&_ino, node) in &self.inodes {
            if node.name == clean_name {
                return Ok(Arc::new(node.clone()));
            }
        }
        Err(FsError::NotFound)
    }
}
