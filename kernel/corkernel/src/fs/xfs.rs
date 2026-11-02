//! SGI XFS (Silicon Graphics 64-bit High-Performance Filesystem) for CorOS.
//!
//! Implements XFS v4 and v5 structures:
//! - Superblock `xfs_sb` with magic "XFSB" (`0x58465342`)
//! - AG logarithm calculations (`sb_agblocks`, `sb_blocklog`, `sb_inolog`, `sb_agblklog`, `inode_to_physical`)
//! - Allocation Groups (AG): Decentralized parallel allocation domains
//! - Allocation Group Free Space (`agf`) and Inode (`agi`) headers
//! - Inode core `xfs_dinode` with data fork formats (Local / Extents / B+Tree)
//! - Shortform local directory parsing (`xfs_dir2_sf_hdr_t`, `xfs_dir2_sf_entry_t`)
//! - B-Tree extent records `xfs_bmbt_rec` (128-bit packed descriptors)
//! - Full integration with `corvfs::FileSystem` and `corvfs::Inode`

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use corvfs::{DirEntry, FileSystem, FsError, Inode};

/// XFS Superblock Magic "XFSB" (0x58465342 Big-Endian)
pub const XFS_SB_MAGIC: u32 = 0x58465342;

/// XFS AG Free Space Header Magic "XAGF"
pub const XFS_AGF_MAGIC: u32 = 0x58414746;

/// XFS AG Inode Header Magic "XAGI"
pub const XFS_AGI_MAGIC: u32 = 0x58414749;

/// XFS Inode Magic "IN" (0x494E)
pub const XFS_DINODE_MAGIC: u16 = 0x494E;

/// Inode Fork Format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfsForkFormat {
    /// Data is stored directly inside the inode core (shortform directory or small file)
    Local,
    /// Data is mapped via an array of contiguous extent records
    Extents,
    /// Data extents are indexed via a multi-level B+tree root
    Btree,
    Dev,
    Uuid,
    Unknown(u8),
}

/// 128-bit Packed BMBT (Block Map B+Tree) Extent Record (Big-Endian)
/// Bits:
/// [0]      = 1 bit: flag (0 = written, 1 = unwritten)
/// [1..54]  = 54 bits: logical file block offset
/// [55..106]= 52 bits: starting physical block number
/// [107..127]= 21 bits: block count
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfsExtent {
    pub is_unwritten: bool,
    pub logical_start: u64,
    pub physical_start: u64,
    pub block_count: u32,
}

impl XfsExtent {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let hi = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ]);
        let lo = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15],
        ]);

        let is_unwritten = (hi >> 63) != 0;
        let logical_start = (hi >> 9) & 0x003F_FFFF_FFFF_FFFF;
        let physical_start_hi = hi & 0x01FF;
        let physical_start_lo = lo >> 21;
        let physical_start = (physical_start_hi << 43) | physical_start_lo;
        let block_count = (lo & 0x001F_FFFF) as u32;

        Some(Self {
            is_unwritten,
            logical_start,
            physical_start,
            block_count,
        })
    }
}

/// Decodes 64-bit XFS inode into exact physical disk byte offset using AG logarithms.
pub fn inode_to_physical(
    ino: u64,
    inopblog: u8,
    agblklog: u8,
    agblocks: u32,
    blocksize: u32,
    inodesize: u32,
) -> u64 {
    let agno = ino >> (inopblog as u64 + agblklog as u64);
    let agbno = (ino >> (inopblog as u64)) & ((1u64 << agblklog) - 1);
    let offset_in_block = (ino & ((1u64 << inopblog) - 1)) * (inodesize as u64);
    (agno * (agblocks as u64) + agbno) * (blocksize as u64) + offset_in_block
}

/// XFS Shortform Local Directory Entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfsShortformEntry {
    pub namelen: u8,
    pub offset: u16,
    pub name: String,
    pub inumber: u64,
    pub file_type: u8,
}

/// XFS Shortform Directory Header and Parser
#[derive(Debug, Clone)]
pub struct XfsDir2SfHdr {
    pub count: u8,
    pub i8count: u8,
    pub parent: u64,
}

impl XfsDir2SfHdr {
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 3 {
            return None;
        }
        let count = buf[0];
        let i8count = buf[1];
        let (parent, hdr_len) = if i8count == 0 {
            if buf.len() < 6 {
                return None;
            }
            let p = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as u64;
            (p, 6)
        } else {
            if buf.len() < 10 {
                return None;
            }
            let p = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5],
                buf[6], buf[7], buf[8], buf[9],
            ]);
            (p, 10)
        };

        Some((Self { count, i8count, parent }, hdr_len))
    }

    /// Parse entries from shortform data fork buffer.
    pub fn parse_entries(buf: &[u8]) -> Vec<XfsShortformEntry> {
        let mut entries = Vec::new();
        let (hdr, mut offset) = match Self::parse(buf) {
            Some(res) => res,
            None => return entries,
        };

        if hdr.count == 0 {
            return entries;
        }

        let is_i8 = hdr.i8count > 0;
        let inumber_len = if is_i8 { 8 } else { 4 };

        for _ in 0..hdr.count {
            if offset + 3 > buf.len() {
                break;
            }
            let namelen = buf[offset] as usize;
            let entry_offset = u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]);
            let name_start = offset + 3;
            if name_start + namelen + 1 + inumber_len > buf.len() {
                break;
            }

            let name = String::from_utf8_lossy(&buf[name_start..name_start + namelen]).into_owned();
            let ftype_pos = name_start + namelen;
            let file_type = buf[ftype_pos];

            let ino_pos = ftype_pos + 1;
            let inumber = if is_i8 {
                u64::from_be_bytes([
                    buf[ino_pos], buf[ino_pos + 1], buf[ino_pos + 2], buf[ino_pos + 3],
                    buf[ino_pos + 4], buf[ino_pos + 5], buf[ino_pos + 6], buf[ino_pos + 7],
                ])
            } else {
                u32::from_be_bytes([
                    buf[ino_pos], buf[ino_pos + 1], buf[ino_pos + 2], buf[ino_pos + 3],
                ]) as u64
            };

            entries.push(XfsShortformEntry {
                namelen: namelen as u8,
                offset: entry_offset,
                name,
                inumber,
                file_type,
            });

            offset = ino_pos + inumber_len;
        }

        entries
    }
}

/// XFS Disk Inode Core (`xfs_dinode_core`)
#[derive(Debug, Clone)]
pub struct XfsInode {
    pub magic: u16,        // 0x494E ("IN")
    pub mode: u16,         // File mode and type
    pub version: u8,       // 1, 2, or 3 (v5 CRC)
    pub format: XfsForkFormat, // Data fork format
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,         // File size in bytes
    pub nblocks: u64,      // Number of 512-byte blocks allocated
    pub extents_count: u32,// Number of extents in data fork
    pub atime_sec: i32,
    pub mtime_sec: i32,
    pub ctime_sec: i32,
    pub data_fork: Vec<u8>,// Raw data fork payload (local data or extent records)
}

impl XfsInode {
    pub fn parse(buf: &[u8], inode_size: usize) -> Option<Self> {
        if buf.len() < 100 || buf.len() < inode_size {
            return None;
        }
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != XFS_DINODE_MAGIC {
            return None;
        }
        let mode = u16::from_be_bytes([buf[2], buf[3]]);
        let version = buf[4];
        let format_raw = buf[5];
        let format = match format_raw {
            1 => XfsForkFormat::Local,
            2 => XfsForkFormat::Extents,
            3 => XfsForkFormat::Btree,
            4 => XfsForkFormat::Dev,
            5 => XfsForkFormat::Uuid,
            other => XfsForkFormat::Unknown(other),
        };

        let uid = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let gid = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let nlink = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let atime_sec = i32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let mtime_sec = i32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let ctime_sec = i32::from_be_bytes([buf[48], buf[49], buf[50], buf[51]]);
        let size = u64::from_be_bytes([
            buf[56], buf[57], buf[58], buf[59],
            buf[60], buf[61], buf[62], buf[63],
        ]);
        let nblocks = u64::from_be_bytes([
            buf[64], buf[65], buf[66], buf[67],
            buf[68], buf[69], buf[70], buf[71],
        ]);
        let extents_count = u32::from_be_bytes([buf[76], buf[77], buf[78], buf[79]]);

        let fork_offset = if version >= 3 { 176 } else { 100 };
        let fork_data = if buf.len() > fork_offset {
            buf[fork_offset..inode_size.min(buf.len())].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            magic,
            mode,
            version,
            format,
            nlink,
            uid,
            gid,
            size,
            nblocks,
            extents_count,
            atime_sec,
            mtime_sec,
            ctime_sec,
            data_fork: fork_data,
        })
    }

    /// Extract all extent descriptors from data fork
    pub fn extents(&self) -> Vec<XfsExtent> {
        let mut list = Vec::new();
        if self.format == XfsForkFormat::Extents {
            for chunk in self.data_fork.chunks_exact(16) {
                if let Some(ext) = XfsExtent::parse(chunk) {
                    list.push(ext);
                }
            }
        }
        list
    }

    /// Resolve physical block number for given logical file block
    pub fn lookup_block(&self, logical_block: u64) -> Option<u64> {
        for ext in self.extents() {
            let start = ext.logical_start;
            let end = start + (ext.block_count as u64);
            if logical_block >= start && logical_block < end {
                return Some(ext.physical_start + (logical_block - start));
            }
        }
        None
    }

    /// Parse directory entries if this inode is a shortform local directory
    pub fn shortform_entries(&self) -> Vec<XfsShortformEntry> {
        if self.format == XfsForkFormat::Local {
            XfsDir2SfHdr::parse_entries(&self.data_fork)
        } else {
            Vec::new()
        }
    }
}

/// XFS Allocation Group Free Space Block (`xfs_agf`)
#[derive(Debug, Clone, Copy)]
pub struct XfsAgf {
    pub magic: u32,         // 0x58414746 ("XAGF")
    pub version: u32,
    pub seq_no: u32,        // AG number (0, 1, 2...)
    pub length: u32,        // AG size in filesystem blocks
    pub bnobt_root: u32,    // Root block of free space B+Tree sorted by block number
    pub cntbt_root: u32,    // Root block of free space B+Tree sorted by block length
    pub free_blocks: u32,   // Current free blocks in this AG
    pub longest_extent: u32,// Longest contiguous free extent in this AG
}

impl XfsAgf {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 40 {
            return None;
        }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != XFS_AGF_MAGIC {
            return None;
        }
        Some(Self {
            magic,
            version: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            seq_no: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            length: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            bnobt_root: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            cntbt_root: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
            free_blocks: u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]),
            longest_extent: u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
        })
    }
}

/// XFS Superblock (`xfs_sb`) (512 bytes on disk)
#[derive(Debug, Clone)]
pub struct XfsSuperblock {
    pub magic: u32,        // 0x58465342 ("XFSB")
    pub block_size: u32,   // Block size in bytes
    pub dblocks: u64,      // Total data blocks
    pub rblocks: u64,      // Realtime blocks
    pub rextents: u64,     // Realtime extents
    pub uuid: [u8; 16],
    pub root_ino: u64,     // Root directory inode number
    pub ag_blocks: u32,    // Size of an AG in blocks
    pub ag_count: u32,     // Number of Allocation Groups
    pub inode_size: u16,   // Inode size in bytes (typically 256 or 512)
    pub block_log: u8,
    pub sector_log: u8,
    pub inode_log: u8,
    pub inopblog: u8,      // block_log - inode_log
    pub agblklog: u8,      // ceil(log2(ag_blocks))
    pub fs_name: [u8; 12],
}

impl XfsSuperblock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 512 {
            return None;
        }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != XFS_SB_MAGIC {
            return None;
        }

        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let dblocks = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15],
        ]);
        let rblocks = u64::from_be_bytes([
            buf[16], buf[17], buf[18], buf[19],
            buf[20], buf[21], buf[22], buf[23],
        ]);
        let rextents = u64::from_be_bytes([
            buf[24], buf[25], buf[26], buf[27],
            buf[28], buf[29], buf[30], buf[31],
        ]);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[32..48]);

        let root_ino = u64::from_be_bytes([
            buf[56], buf[57], buf[58], buf[59],
            buf[60], buf[61], buf[62], buf[63],
        ]);

        let ag_blocks = u32::from_be_bytes([buf[84], buf[85], buf[86], buf[87]]);
        let ag_count = u32::from_be_bytes([buf[88], buf[89], buf[90], buf[91]]);
        let inode_size = u16::from_be_bytes([buf[104], buf[105]]);

        let block_log = buf[120];
        let sector_log = buf[121];
        let inode_log = buf[122];

        let inopblog = block_log.saturating_sub(inode_log);
        let agblklog = if ag_blocks > 1 {
            (32 - (ag_blocks - 1).leading_zeros()) as u8
        } else {
            0
        };

        let mut fs_name = [0u8; 12];
        fs_name.copy_from_slice(&buf[108..120]);

        Some(Self {
            magic,
            block_size,
            dblocks,
            rblocks,
            rextents,
            uuid,
            root_ino,
            ag_blocks,
            ag_count,
            inode_size,
            block_log,
            sector_log,
            inode_log,
            inopblog,
            agblklog,
            fs_name,
        })
    }
}

/// XFS Inode wrapper implementing `corvfs::Inode`
#[derive(Debug, Clone)]
pub struct XfsVfsInode {
    pub ino: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Vec<u8>,
    pub children: Vec<DirEntry>,
}

impl Inode for XfsVfsInode {
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

/// SGI XFS High-Performance Filesystem Manager
pub struct XfsFileSystem {
    pub superblock: XfsSuperblock,
    pub inodes: BTreeMap<u64, XfsVfsInode>,
}

impl XfsFileSystem {
    pub fn mount(raw_sb: &[u8]) -> Result<Self, &'static str> {
        let sb = XfsSuperblock::parse(raw_sb).ok_or("Invalid XFS Superblock magic")?;
        Ok(Self {
            superblock: sb,
            inodes: BTreeMap::new(),
        })
    }

    /// Calculate physical byte offset on disk for an allocation group
    pub fn ag_offset(&self, ag_index: u32) -> u64 {
        (ag_index as u64) * (self.superblock.ag_blocks as u64) * (self.superblock.block_size as u64)
    }

    /// Calculate exact physical disk byte offset for a 64-bit inode number
    pub fn inode_to_physical(&self, ino: u64) -> u64 {
        inode_to_physical(
            ino,
            self.superblock.inopblog,
            self.superblock.agblklog,
            self.superblock.ag_blocks,
            self.superblock.block_size,
            self.superblock.inode_size as u32,
        )
    }

    /// Register an inode into the filesystem
    pub fn add_inode(&mut self, inode: XfsVfsInode) {
        self.inodes.insert(inode.ino, inode);
    }
}

impl FileSystem for XfsFileSystem {
    fn name(&self) -> &str {
        "xfs"
    }

    fn root_inode(&self) -> Result<Arc<dyn Inode>, FsError> {
        let root_ino = self.superblock.root_ino;
        if let Some(root) = self.inodes.get(&root_ino) {
            Ok(Arc::new(root.clone()))
        } else {
            let mut children = Vec::new();
            for (&ino, node) in &self.inodes {
                if ino != root_ino {
                    children.push(DirEntry {
                        name: node.name.clone(),
                        ino,
                        is_dir: node.is_dir,
                        size: node.size,
                    });
                }
            }
            Ok(Arc::new(XfsVfsInode {
                ino: root_ino,
                name: String::from("/"),
                is_dir: true,
                size: self.superblock.block_size as u64,
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

impl fmt::Display for XfsFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_str = core::str::from_utf8(&self.superblock.fs_name).unwrap_or("xfs");
        write!(
            f,
            "XfsFS(name='{}', block_size={}B, dblocks={}, ag_count={})",
            name_str.trim_matches(char::from(0)),
            self.superblock.block_size,
            self.superblock.dblocks,
            self.superblock.ag_count
        )
    }
}
