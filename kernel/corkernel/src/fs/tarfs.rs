//! POSIX UStar (Unix Standard TAR) Archive Filesystem for CorOS.
//! 100% in-house implementation supporting:
//! - 512-byte standard UStar header parsing
//! - Octal header number conversion (file size, permissions, uid, gid)
//! - Header checksum verification (RFC standard unsigned byte sum with blanks)
//! - In-memory archive mounting, directory mapping, and direct file extraction.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const TAR_BLOCK_SIZE: usize = 512;
pub const TAR_MAGIC_USTAR: [u8; 6] = *b"ustar\0";

// File Type Flags
pub const TAR_TYPE_REGULAR: u8     = b'0';
pub const TAR_TYPE_REGULAR_ALT: u8 = 0;
pub const TAR_TYPE_HARDLINK: u8    = b'1';
pub const TAR_TYPE_SYMLINK: u8     = b'2';
pub const TAR_TYPE_CHARDEV: u8     = b'3';
pub const TAR_TYPE_BLOCKDEV: u8    = b'4';
pub const TAR_TYPE_DIRECTORY: u8   = b'5';
pub const TAR_TYPE_FIFO: u8        = b'6';
pub const TAR_TYPE_CONTIGUOUS: u8  = b'7';

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TarHeaderRaw {
    pub name: [u8; 100],
    pub mode: [u8; 8],
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    pub size: [u8; 12],
    pub mtime: [u8; 12],
    pub chksum: [u8; 8],
    pub typeflag: u8,
    pub linkname: [u8; 100],
    pub magic: [u8; 6],
    pub version: [u8; 2],
    pub uname: [u8; 32],
    pub gname: [u8; 32],
    pub devmajor: [u8; 8],
    pub devminor: [u8; 8],
    pub prefix: [u8; 155],
    pub pad: [u8; 12],
}

#[derive(Clone, Debug)]
pub struct TarEntry {
    pub path: String,
    pub size: usize,
    pub mode: u32,
    pub is_dir: bool,
    pub data_offset: usize, // Offset in the archive bytes
}

pub struct TarArchive<'a> {
    archive_data: &'a [u8],
    pub entries: BTreeMap<String, TarEntry>,
}

impl<'a> TarArchive<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut entries = BTreeMap::new();
        let mut offset = 0;

        while offset + TAR_BLOCK_SIZE <= data.len() {
            let block = &data[offset..offset + TAR_BLOCK_SIZE];

            // Check for end-of-archive marker (two consecutive blocks of zeroes)
            let is_zero_block = block.iter().all(|&b| b == 0);
            if is_zero_block {
                break;
            }

            let raw = unsafe { *(block.as_ptr() as *const TarHeaderRaw) };

            // Verify checksum
            let expected_chksum = Self::parse_octal(&raw.chksum);
            let calculated_chksum = Self::calculate_checksum(block);
            if expected_chksum != calculated_chksum {
                return Err("TAR header checksum mismatch");
            }

            let file_size = Self::parse_octal(&raw.size) as usize;
            let mode = Self::parse_octal(&raw.mode) as u32;
            let is_dir = raw.typeflag == TAR_TYPE_DIRECTORY || raw.name.ends_with(b"/");

            // Build full path (prefix + name)
            let mut full_path = String::new();
            if raw.prefix[0] != 0 {
                let p_len = raw.prefix.iter().position(|&b| b == 0).unwrap_or(raw.prefix.len());
                full_path.push_str(&String::from_utf8_lossy(&raw.prefix[..p_len]));
                if !full_path.ends_with('/') {
                    full_path.push('/');
                }
            }
            let n_len = raw.name.iter().position(|&b| b == 0).unwrap_or(raw.name.len());
            full_path.push_str(&String::from_utf8_lossy(&raw.name[..n_len]));

            let clean_path = String::from(full_path.trim_end_matches('/'));

            entries.insert(clean_path.clone(), TarEntry {
                path: clean_path,
                size: file_size,
                mode,
                is_dir,
                data_offset: offset + TAR_BLOCK_SIZE,
            });

            // Advance offset past header and data blocks (each file rounded up to 512 bytes)
            let data_blocks = (file_size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE;
            offset += (1 + data_blocks) * TAR_BLOCK_SIZE;
        }

        Ok(Self {
            archive_data: data,
            entries,
        })
    }

    /// Read raw file bytes from archive by path.
    pub fn read_file(&self, path: &str) -> Option<&'a [u8]> {
        let clean = path.trim_start_matches('/').trim_end_matches('/');
        let entry = self.entries.get(clean)?;
        if entry.is_dir {
            return None;
        }
        let end = entry.data_offset + entry.size;
        if end <= self.archive_data.len() {
            Some(&self.archive_data[entry.data_offset..end])
        } else {
            None
        }
    }

    fn parse_octal(bytes: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for &b in bytes {
            if b >= b'0' && b <= b'7' {
                val = (val << 3) | (b - b'0') as u64;
            } else if b == 0 || b == b' ' {
                // Terminator
                break;
            }
        }
        val
    }

    fn calculate_checksum(block: &[u8]) -> u64 {
        let mut sum: u64 = 0;
        for (i, &b) in block.iter().enumerate() {
            // Bytes 148..156 are the checksum field itself: treated as ASCII spaces (0x20)
            if i >= 148 && i < 156 {
                sum += 0x20;
            } else {
                sum += b as u64;
            }
        }
        sum
    }
}
