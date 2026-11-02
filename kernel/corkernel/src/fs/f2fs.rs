//! Samsung F2FS (Flash-Friendly File System) for SSDs, NVMe & eMMC on CorOS.
//!
//! Implements Flash Log-Structured File System architecture:
//! - Superblock `f2fs_super_block` with magic `0xF2F52010` (at offset 1024 and 0)
//! - Dual checkpoint selection comparing `checkpoint_ver` between CP 1 and CP 2 packs
//! - Node Address Table (NAT) page translation (455 entries per 4 KiB block)
//! - Inode direct data addressing (923 block pointers), direct & indirect node blocks
//! - 214-entry dentry block parser (`F2fsDentryBlock`, 27-byte bitmap, 11-byte `F2fsDirEntry`, 8-byte filename slots)
//! - Full integration with `corvfs::FileSystem` and `corvfs::Inode`

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use corvfs::{DirEntry, FileSystem, FsError, Inode};

/// F2FS Superblock Magic (`0xF2F52010`)
pub const F2FS_SUPER_MAGIC: u32 = 0xF2F5_2010;

/// Standard F2FS Block Size (4096 bytes)
pub const F2FS_BLKSIZE: usize = 4096;

/// Standard F2FS Segment Size in Blocks (512 * 4KB = 2 MB)
pub const F2FS_BLOCKS_PER_SEGMENT: usize = 512;

/// Number of direct data block addresses packed in an inode body
pub const ADDRS_PER_INODE: usize = 923;

/// Number of 9-byte NAT entries per 4096-byte NAT block (4096 / 9 = 455)
pub const F2FS_NAT_ENTRIES_PER_BLOCK: usize = 455;

/// Number of directory entries per 4096-byte dentry block
pub const F2FS_DENTRIES_PER_BLOCK: usize = 214;

/// F2FS Active Log Types (6-stream log architecture)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F2fsCurlogType {
    HotData,    // Directory entries, small files
    WarmData,   // General user file data
    ColdData,   // Multimedia, compressed files, garbage collection migrated data
    HotNode,    // Direct node blocks of directories
    WarmNode,   // Direct node blocks of regular files
    ColdNode,   // Indirect node blocks
}

/// F2FS Superblock Structure (located at offset 1024 and mirrored at 0x00 / 0x1000)
#[derive(Debug, Clone)]
pub struct F2fsSuperblock {
    pub magic: u32,
    pub major_ver: u16,
    pub minor_ver: u16,
    pub log_sectorsize: u32,
    pub log_sectors_per_block: u32,
    pub log_blocksize: u32,
    pub log_blocks_per_seg: u32,
    pub segs_per_sec: u32,
    pub secs_per_zone: u32,
    pub total_section_count: u32,
    pub segment_count: u32,
    pub segment_count_ckpt: u32,
    pub segment_count_sit: u32,
    pub segment_count_nat: u32,
    pub segment_count_ssa: u32,
    pub segment_count_main: u32,
    pub cp_blkaddr: u32,
    pub sit_blkaddr: u32,
    pub nat_blkaddr: u32,
    pub ssa_blkaddr: u32,
    pub main_blkaddr: u32,
    pub root_ino: u32,
    pub volume_name: [u8; 16],
}

impl F2fsSuperblock {
    pub fn parse(raw_disk: &[u8]) -> Option<Self> {
        if raw_disk.len() < 1024 {
            return None;
        }

        // Try standard offset 1024 (0x400) first, then fallback to 0
        let buf = if raw_disk.len() >= 1024 + 128 {
            let magic_at_1024 = u32::from_le_bytes([
                raw_disk[1024], raw_disk[1025], raw_disk[1026], raw_disk[1027],
            ]);
            if magic_at_1024 == F2FS_SUPER_MAGIC {
                &raw_disk[1024..]
            } else {
                raw_disk
            }
        } else {
            raw_disk
        };

        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != F2FS_SUPER_MAGIC {
            return None;
        }

        let major_ver = u16::from_le_bytes([buf[4], buf[5]]);
        let minor_ver = u16::from_le_bytes([buf[6], buf[7]]);
        let log_sectorsize = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let log_sectors_per_block = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let log_blocksize = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let log_blocks_per_seg = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let segs_per_sec = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let secs_per_zone = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let total_section_count = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let segment_count = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);

        let segment_count_ckpt = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let segment_count_sit = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        let segment_count_nat = u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]);
        let segment_count_ssa = u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]);
        let segment_count_main = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);

        let cp_blkaddr = u32::from_le_bytes([buf[64], buf[65], buf[66], buf[67]]);
        let sit_blkaddr = u32::from_le_bytes([buf[68], buf[69], buf[70], buf[71]]);
        let nat_blkaddr = u32::from_le_bytes([buf[72], buf[73], buf[74], buf[75]]);
        let ssa_blkaddr = u32::from_le_bytes([buf[76], buf[77], buf[78], buf[79]]);
        let main_blkaddr = u32::from_le_bytes([buf[80], buf[81], buf[82], buf[83]]);

        let root_ino = u32::from_le_bytes([buf[84], buf[85], buf[86], buf[87]]);

        let mut volume_name = [0u8; 16];
        if buf.len() >= 124 {
            volume_name.copy_from_slice(&buf[108..124]);
        }

        Some(Self {
            magic,
            major_ver,
            minor_ver,
            log_sectorsize,
            log_sectors_per_block,
            log_blocksize,
            log_blocks_per_seg,
            segs_per_sec,
            secs_per_zone,
            total_section_count,
            segment_count,
            segment_count_ckpt,
            segment_count_sit,
            segment_count_nat,
            segment_count_ssa,
            segment_count_main,
            cp_blkaddr,
            sit_blkaddr,
            nat_blkaddr,
            ssa_blkaddr,
            main_blkaddr,
            root_ino,
            volume_name,
        })
    }
}

/// F2FS Checkpoint Header (`f2fs_checkpoint`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsCheckpoint {
    pub checkpoint_ver: u64,
    pub user_block_count: u64,
    pub valid_block_count: u64,
    pub rsvd_segment_count: u32,
    pub overprov_segment_count: u32,
    pub free_segment_count: u32,
    pub cur_node_segno: [u32; 3], // Hot, Warm, Cold
    pub cur_data_segno: [u32; 3], // Hot, Warm, Cold
    pub ckpt_flags: u32,
    pub checksum_offset: u32,
}

impl F2fsCheckpoint {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 68 {
            return None;
        }
        let checkpoint_ver = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ]);
        let user_block_count = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11],
            buf[12], buf[13], buf[14], buf[15],
        ]);
        let valid_block_count = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19],
            buf[20], buf[21], buf[22], buf[23],
        ]);
        let rsvd_segment_count = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let overprov_segment_count = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let free_segment_count = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);

        let cur_node_segno = [
            u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
            u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
            u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
        ];

        let cur_data_segno = [
            u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
            u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]),
            u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]),
        ];

        let ckpt_flags = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]);
        let checksum_offset = u32::from_le_bytes([buf[64], buf[65], buf[66], buf[67]]);

        Some(Self {
            checkpoint_ver,
            user_block_count,
            valid_block_count,
            rsvd_segment_count,
            overprov_segment_count,
            free_segment_count,
            cur_node_segno,
            cur_data_segno,
            ckpt_flags,
            checksum_offset,
        })
    }

    /// Select active checkpoint from CP 1 and CP 2 buffers by highest valid checkpoint_ver.
    pub fn select_active(cp1_buf: &[u8], cp2_buf: &[u8]) -> Option<Self> {
        let cp1 = Self::parse(cp1_buf);
        let cp2 = Self::parse(cp2_buf);

        match (cp1, cp2) {
            (Some(c1), Some(c2)) => {
                if c2.checkpoint_ver > c1.checkpoint_ver {
                    Some(c2)
                } else {
                    Some(c1)
                }
            }
            (Some(c1), None) => Some(c1),
            (None, Some(c2)) => Some(c2),
            (None, None) => None,
        }
    }
}

/// NAT Entry: Maps Node ID to Physical Block Address on Flash (9 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsNatEntry {
    pub version: u8,
    pub ino: u32,
    pub block_addr: u32,
}

impl F2fsNatEntry {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 9 {
            return None;
        }
        Some(Self {
            version: buf[0],
            ino: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            block_addr: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
        })
    }
}

/// Translates Node ID (NID) to physical block address using 455-entry NAT pages.
pub fn translate_nat_blocks(nat_blkaddr: u32, nid: u32, blocks: &BTreeMap<u32, Vec<u8>>) -> Option<u32> {
    let block_idx = nat_blkaddr + (nid / (F2FS_NAT_ENTRIES_PER_BLOCK as u32));
    let entry_idx = ((nid % (F2FS_NAT_ENTRIES_PER_BLOCK as u32)) as usize) * 9;

    let page = blocks.get(&block_idx)?;
    if page.len() < entry_idx + 9 {
        return None;
    }

    let blk_addr = u32::from_le_bytes([
        page[entry_idx + 5],
        page[entry_idx + 6],
        page[entry_idx + 7],
        page[entry_idx + 8],
    ]);

    Some(blk_addr)
}

/// F2FS 24-byte Node Footer (at offset 4072 in 4096-byte node page)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsNodeFooter {
    pub nid: u32,
    pub ino: u32,
    pub cp_ver: u64,
    pub next_blkaddr: u32,
}

impl F2fsNodeFooter {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        Some(Self {
            nid: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            ino: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            cp_ver: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11],
                buf[12], buf[13], buf[14], buf[15],
            ]),
            next_blkaddr: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }
}

/// F2FS Inode Structure (4096-byte node page)
#[derive(Debug, Clone)]
pub struct F2fsInode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub direct_node_ptrs: [u32; 2],
    pub indirect_node_ptrs: [u32; 2],
    pub double_indirect_ptr: u32,
    pub inline_data: bool,
    pub direct_data_ptrs: Vec<u32>,
    pub footer: Option<F2fsNodeFooter>,
}

impl F2fsInode {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 1024 {
            return None;
        }
        let mode = u16::from_le_bytes([buf[0], buf[1]]);
        let uid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let gid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let links = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let size = u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19],
            buf[20], buf[21], buf[22], buf[23],
        ]);
        let blocks = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27],
            buf[28], buf[29], buf[30], buf[31],
        ]);
        let atime = u64::from_le_bytes([
            buf[32], buf[33], buf[34], buf[35],
            buf[36], buf[37], buf[38], buf[39],
        ]);
        let mtime = u64::from_le_bytes([
            buf[40], buf[41], buf[42], buf[43],
            buf[44], buf[45], buf[46], buf[47],
        ]);
        let ctime = u64::from_le_bytes([
            buf[48], buf[49], buf[50], buf[51],
            buf[52], buf[53], buf[54], buf[55],
        ]);

        let inline_flags = buf[64];
        let inline_data = (inline_flags & 0x02) != 0;

        let mut data_ptrs = Vec::new();
        let ptrs_offset = 200;
        let max_ptrs = ADDRS_PER_INODE;
        for i in 0..max_ptrs {
            let off = ptrs_offset + (i * 4);
            if off + 4 <= buf.len() {
                let ptr = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                if ptr != 0 {
                    data_ptrs.push(ptr);
                }
            }
        }

        // Parse node pointers at offset 200 + 923*4 = 3892
        let node_ptrs_offset = ptrs_offset + max_ptrs * 4;
        let mut direct_nodes = [0u32; 2];
        let mut indirect_nodes = [0u32; 2];
        let mut double_indirect = 0u32;

        if node_ptrs_offset + 20 <= buf.len() {
            direct_nodes[0] = u32::from_le_bytes([buf[node_ptrs_offset], buf[node_ptrs_offset + 1], buf[node_ptrs_offset + 2], buf[node_ptrs_offset + 3]]);
            direct_nodes[1] = u32::from_le_bytes([buf[node_ptrs_offset + 4], buf[node_ptrs_offset + 5], buf[node_ptrs_offset + 6], buf[node_ptrs_offset + 7]]);
            indirect_nodes[0] = u32::from_le_bytes([buf[node_ptrs_offset + 8], buf[node_ptrs_offset + 9], buf[node_ptrs_offset + 10], buf[node_ptrs_offset + 11]]);
            indirect_nodes[1] = u32::from_le_bytes([buf[node_ptrs_offset + 12], buf[node_ptrs_offset + 13], buf[node_ptrs_offset + 14], buf[node_ptrs_offset + 15]]);
            double_indirect = u32::from_le_bytes([buf[node_ptrs_offset + 16], buf[node_ptrs_offset + 17], buf[node_ptrs_offset + 18], buf[node_ptrs_offset + 19]]);
        }

        // Node footer at end of 4096-byte page
        let footer = if buf.len() >= 4096 {
            F2fsNodeFooter::parse(&buf[4096 - 24..4096])
        } else {
            None
        };

        let ino = footer.map(|f| f.ino).unwrap_or(0);

        Some(Self {
            ino,
            mode,
            uid,
            gid,
            links,
            size,
            blocks,
            atime,
            mtime,
            ctime,
            direct_node_ptrs: direct_nodes,
            indirect_node_ptrs: indirect_nodes,
            double_indirect_ptr: double_indirect,
            inline_data,
            direct_data_ptrs: data_ptrs,
            footer,
        })
    }
}

/// F2FS 11-byte Directory Entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsDirEntry {
    pub hash_code: u32,
    pub ino: u32,
    pub name_len: u16,
    pub file_type: u8,
}

impl F2fsDirEntry {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 11 {
            return None;
        }
        Some(Self {
            hash_code: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            ino: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            name_len: u16::from_le_bytes([buf[8], buf[9]]),
            file_type: buf[10],
        })
    }
}

/// Parsed F2FS Directory Entry with decoded name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct F2fsDecodedDentry {
    pub name: String,
    pub ino: u32,
    pub file_type: u8,
}

/// F2FS 4096-byte Dentry Block Parser
pub struct F2fsDentryBlock;

impl F2fsDentryBlock {
    /// Parse all active directory entries from a 4096-byte dentry block.
    /// Layout:
    /// - 27 bytes: dentry_bitmap (214 bits)
    /// - 3 bytes: reserved padding
    /// - 2354 bytes: 214 * 11-byte F2fsDirEntry
    /// - 1712 bytes: 214 * 8-byte filename slots
    /// Total = 4096 bytes.
    pub fn parse(buf: &[u8]) -> Option<Vec<F2fsDecodedDentry>> {
        if buf.len() < F2FS_BLKSIZE {
            return None;
        }

        let bitmap = &buf[0..27];
        let dentry_base = 30; // 27 + 3
        let filename_base = 30 + F2FS_DENTRIES_PER_BLOCK * 11; // 30 + 2354 = 2384

        let mut entries = Vec::new();
        let mut slot = 0;

        while slot < F2FS_DENTRIES_PER_BLOCK {
            let byte_idx = slot / 8;
            let bit_idx = slot % 8;
            let is_set = (bitmap[byte_idx] & (1 << bit_idx)) != 0;

            if is_set {
                let d_off = dentry_base + slot * 11;
                if let Some(de) = F2fsDirEntry::parse(&buf[d_off..d_off + 11]) {
                    let name_len = de.name_len as usize;
                    let slots_needed = (name_len + 7) / 8;

                    let fn_off = filename_base + slot * 8;
                    if fn_off + name_len <= buf.len() {
                        let name_bytes = &buf[fn_off..fn_off + name_len];
                        let name = String::from_utf8_lossy(name_bytes).into_owned();
                        entries.push(F2fsDecodedDentry {
                            name,
                            ino: de.ino,
                            file_type: de.file_type,
                        });
                    }

                    slot += slots_needed.max(1);
                    continue;
                }
            }
            slot += 1;
        }

        Some(entries)
    }
}

/// F2FS Inode wrapper implementing `corvfs::Inode`
#[derive(Debug, Clone)]
pub struct F2fsVfsInode {
    pub ino: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub data: Vec<u8>,
    pub children: Vec<DirEntry>,
}

impl Inode for F2fsVfsInode {
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

/// Samsung F2FS Filesystem Engine
pub struct F2fsFileSystem {
    pub superblock: F2fsSuperblock,
    pub checkpoint: Option<F2fsCheckpoint>,
    pub nat_cache: BTreeMap<u32, Vec<u8>>,
    pub inodes: BTreeMap<u64, F2fsVfsInode>,
    pub root_ino: u64,
}

impl F2fsFileSystem {
    pub fn mount(raw_sb: &[u8]) -> Result<Self, &'static str> {
        let sb = F2fsSuperblock::parse(raw_sb).ok_or("Invalid F2FS Superblock")?;
        let root_ino = sb.root_ino as u64;
        Ok(Self {
            superblock: sb,
            checkpoint: None,
            nat_cache: BTreeMap::new(),
            inodes: BTreeMap::new(),
            root_ino,
        })
    }

    /// Select active checkpoint from CP 1 and CP 2 blocks.
    pub fn load_active_checkpoint(&mut self, cp1_buf: &[u8], cp2_buf: &[u8]) -> Option<F2fsCheckpoint> {
        let active = F2fsCheckpoint::select_active(cp1_buf, cp2_buf);
        self.checkpoint = active;
        active
    }

    /// Store a NAT block into the in-memory block cache.
    pub fn insert_nat_block(&mut self, blkaddr: u32, data: Vec<u8>) {
        self.nat_cache.insert(blkaddr, data);
    }

    /// Translate Node ID (NID) to physical flash block address via NAT pages.
    pub fn translate_nat(&self, nid: u32) -> Option<u32> {
        translate_nat_blocks(self.superblock.nat_blkaddr, nid, &self.nat_cache)
    }

    /// Calculate byte address of a block number
    pub fn block_to_bytes(&self, blkaddr: u32) -> u64 {
        (blkaddr as u64) * (F2FS_BLKSIZE as u64)
    }

    /// Calculate byte address of Segment Info Table (SIT)
    pub fn sit_byte_offset(&self) -> u64 {
        self.block_to_bytes(self.superblock.sit_blkaddr)
    }

    /// Calculate byte address of Node Address Table (NAT)
    pub fn nat_byte_offset(&self) -> u64 {
        self.block_to_bytes(self.superblock.nat_blkaddr)
    }

    /// Register a file or directory inode.
    pub fn add_inode(&mut self, inode: F2fsVfsInode) {
        self.inodes.insert(inode.ino, inode);
    }
}

impl FileSystem for F2fsFileSystem {
    fn name(&self) -> &str {
        "f2fs"
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
            Ok(Arc::new(F2fsVfsInode {
                ino: self.root_ino,
                name: String::from("/"),
                is_dir: true,
                size: 4096,
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

impl fmt::Display for F2fsFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vol_str = core::str::from_utf8(&self.superblock.volume_name).unwrap_or("f2fs");
        write!(
            f,
            "F2FS(vol='{}', total_secs={}, main_blks={})",
            vol_str.trim_matches(char::from(0)),
            self.superblock.total_section_count,
            self.superblock.segment_count_main * 512
        )
    }
}
