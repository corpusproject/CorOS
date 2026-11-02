//! Pure Bare-Metal Ext2 (Second Extended) Filesystem Driver for CorOS.
//! 100% in-house implementation supporting Superblock parsing, Block Group
//! Descriptors, Inode Tables, Direct/Single-Indirect/Double-Indirect block indexing,
//! directory entry walking, and byte stream file reading.

use alloc::string::String;
use alloc::vec::Vec;

pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

// Inode File Types (i_mode & 0xF000)
pub const EXT2_S_IFSOCK: u16 = 0xC000;
pub const EXT2_S_IFLNK:  u16 = 0xA000;
pub const EXT2_S_IFREG:  u16 = 0x8000;
pub const EXT2_S_IFBLK:  u16 = 0x6000;
pub const EXT2_S_IFDIR:  u16 = 0x4000;
pub const EXT2_S_IFCHR:  u16 = 0x2000;
pub const EXT2_S_IFIFO:  u16 = 0x1000;

// Directory Entry File Types
pub const EXT2_FT_UNKNOWN:  u8 = 0;
pub const EXT2_FT_REG_FILE: u8 = 1;
pub const EXT2_FT_DIR:      u8 = 2;
pub const EXT2_FT_CHRDEV:   u8 = 3;
pub const EXT2_FT_BLKDEV:   u8 = 4;
pub const EXT2_FT_FIFO:     u8 = 5;
pub const EXT2_FT_SOCK:     u8 = 6;
pub const EXT2_FT_SYMLINK:  u8 = 7;

// Root Directory Inode Number in standard Ext2
pub const EXT2_ROOT_INO: u32 = 2;

// -----------------------------------------------------------------------------
// Superblock Structure (Offset 1024 bytes)
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2Superblock {
    pub s_inodes_count: u32,
    pub s_blocks_count: u32,
    pub s_r_blocks_count: u32,
    pub s_free_blocks_count: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_frag_size: u32,
    pub s_blocks_per_group: u32,
    pub s_frags_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // Extended fields (Revision >= 1)
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algo_bitmap: u32,
}

// -----------------------------------------------------------------------------
// Block Group Descriptor (32 bytes)
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Ext2BlockGroupDesc {
    pub bg_block_bitmap: u32,
    pub bg_inode_bitmap: u32,
    pub bg_inode_table: u32,
    pub bg_free_blocks_count: u16,
    pub bg_free_inodes_count: u16,
    pub bg_used_dirs_count: u16,
    pub bg_pad: u16,
    pub bg_reserved: [u8; 12],
}

// -----------------------------------------------------------------------------
// Inode Structure (128 bytes)
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Ext2Inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks: u32, // 512-byte blocks count
    pub i_flags: u32,
    pub i_osd1: u32,
    pub i_block: [u32; 15], // 0-11: direct, 12: indirect, 13: double indirect, 14: triple indirect
    pub i_generation: u32,
    pub i_file_acl: u32,
    pub i_dir_acl: u32,
    pub i_faddr: u32,
    pub i_osd2: [u8; 12],
}

// -----------------------------------------------------------------------------
// Directory Entry
// -----------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Ext2DirEntryRaw {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

#[derive(Clone, Debug)]
pub struct Ext2DirEntry {
    pub inode: u32,
    pub file_type: u8,
    pub name: String,
}

// -----------------------------------------------------------------------------
// Ext2 Filesystem Driver
// -----------------------------------------------------------------------------
pub struct Ext2FileSystem<D> {
    device: D,
    pub superblock: Ext2Superblock,
    pub block_size: usize,
    pub block_groups_count: usize,
    pub group_descriptors: Vec<Ext2BlockGroupDesc>,
    pub inode_size: usize,
}

pub trait BlockDevice {
    fn read_block(&mut self, block_idx: u64, buf: &mut [u8]) -> Result<(), &'static str>;
}

impl<D: BlockDevice> Ext2FileSystem<D> {
    pub fn mount(mut device: D) -> Result<Self, &'static str> {
        // Read Superblock at offset 1024
        let mut sb_buf = [0u8; 1024];
        // For standard 1024-byte block 1 or from byte 1024
        device.read_block(1, &mut sb_buf)?;

        let sb = unsafe { *(sb_buf.as_ptr() as *const Ext2Superblock) };
        if sb.s_magic != EXT2_SUPER_MAGIC {
            return Err("Ext2 magic number mismatch (not 0xEF53)");
        }

        let block_size = 1024 << sb.s_log_block_size;
        let inode_size = if sb.s_rev_level >= 1 && sb.s_inode_size > 0 {
            sb.s_inode_size as usize
        } else {
            128
        };

        let blocks_per_group = sb.s_blocks_per_group as usize;
        let block_groups_count = ((sb.s_blocks_count as usize) + blocks_per_group - 1) / blocks_per_group;

        // Block group descriptor table starts at block 2 (if block_size=1024) or block 1 (if block_size > 1024)
        let bgd_start_block = if block_size == 1024 { 2 } else { 1 };
        let mut group_descriptors = Vec::with_capacity(block_groups_count);

        let bgds_per_block = block_size / core::mem::size_of::<Ext2BlockGroupDesc>();
        let num_bgd_blocks = (block_groups_count + bgds_per_block - 1) / bgds_per_block;

        let mut bgd_buf = Vec::with_capacity(block_size);
        bgd_buf.resize(block_size, 0);

        let mut read_bgds = 0;
        for i in 0..num_bgd_blocks {
            device.read_block((bgd_start_block + i) as u64, &mut bgd_buf)?;
            let desc_array = bgd_buf.as_ptr() as *const Ext2BlockGroupDesc;

            for j in 0..bgds_per_block {
                if read_bgds >= block_groups_count {
                    break;
                }
                unsafe {
                    group_descriptors.push(*desc_array.add(j));
                }
                read_bgds += 1;
            }
        }

        Ok(Self {
            device,
            superblock: sb,
            block_size,
            block_groups_count,
            group_descriptors,
            inode_size,
        })
    }

    /// Read an Inode by its 1-based index.
    pub fn read_inode(&mut self, ino: u32) -> Result<Ext2Inode, &'static str> {
        if ino == 0 || ino > self.superblock.s_inodes_count {
            return Err("Ext2 inode number out of range");
        }

        let group = ((ino - 1) / self.superblock.s_inodes_per_group) as usize;
        let index = ((ino - 1) % self.superblock.s_inodes_per_group) as usize;

        if group >= self.group_descriptors.len() {
            return Err("Block group index out of bounds");
        }

        let inode_table_block = self.group_descriptors[group].bg_inode_table as u64;
        let inodes_per_block = self.block_size / self.inode_size;
        let block_offset = (index / inodes_per_block) as u64;
        let index_in_block = index % inodes_per_block;

        let mut block_buf = Vec::with_capacity(self.block_size);
        block_buf.resize(self.block_size, 0);

        self.device.read_block(inode_table_block + block_offset, &mut block_buf)?;

        let inode_ptr = (block_buf.as_ptr() as usize + index_in_block * self.inode_size) as *const Ext2Inode;
        let inode = unsafe { *inode_ptr };
        Ok(inode)
    }

    /// Resolve logical block index of an inode to physical filesystem block.
    pub fn get_block_address(&mut self, inode: &Ext2Inode, logical_block: u32) -> Result<u32, &'static str> {
        let ptrs_per_block = (self.block_size / 4) as u32;

        // 1. Direct blocks (0..11)
        if logical_block < 12 {
            return Ok(inode.i_block[logical_block as usize]);
        }

        // 2. Single indirect (12 .. 12 + ptrs_per_block - 1)
        let mut idx = logical_block - 12;
        if idx < ptrs_per_block {
            let indirect_block = inode.i_block[12];
            if indirect_block == 0 {
                return Ok(0);
            }
            let mut buf = Vec::with_capacity(self.block_size);
            buf.resize(self.block_size, 0);
            self.device.read_block(indirect_block as u64, &mut buf)?;
            let array = buf.as_ptr() as *const u32;
            let phys_block = unsafe { *array.add(idx as usize) };
            return Ok(phys_block);
        }

        // 3. Double indirect
        idx -= ptrs_per_block;
        let double_indirect_limit = ptrs_per_block * ptrs_per_block;
        if idx < double_indirect_limit {
            let d_indirect_block = inode.i_block[13];
            if d_indirect_block == 0 {
                return Ok(0);
            }

            let mut d_buf = Vec::with_capacity(self.block_size);
            d_buf.resize(self.block_size, 0);
            self.device.read_block(d_indirect_block as u64, &mut d_buf)?;

            let first_idx = (idx / ptrs_per_block) as usize;
            let second_idx = (idx % ptrs_per_block) as usize;

            let first_array = d_buf.as_ptr() as *const u32;
            let indirect_block = unsafe { *first_array.add(first_idx) };
            if indirect_block == 0 {
                return Ok(0);
            }

            let mut s_buf = Vec::with_capacity(self.block_size);
            s_buf.resize(self.block_size, 0);
            self.device.read_block(indirect_block as u64, &mut s_buf)?;

            let second_array = s_buf.as_ptr() as *const u32;
            let phys_block = unsafe { *second_array.add(second_idx) };
            return Ok(phys_block);
        }

        Err("Triple indirect block not implemented or file exceeds limit")
    }

    /// Read all entries in a directory inode.
    pub fn read_dir(&mut self, inode: &Ext2Inode) -> Result<Vec<Ext2DirEntry>, &'static str> {
        if (inode.i_mode & EXT2_S_IFDIR) == 0 {
            return Err("Inode is not a directory");
        }

        let mut entries = Vec::new();
        let total_size = inode.i_size as usize;
        let num_blocks = (total_size + self.block_size - 1) / self.block_size;

        let mut buf = Vec::with_capacity(self.block_size);
        buf.resize(self.block_size, 0);

        for b in 0..num_blocks {
            let phys_block = self.get_block_address(inode, b as u32)?;
            if phys_block == 0 {
                continue;
            }

            self.device.read_block(phys_block as u64, &mut buf)?;

            let mut offset = 0;
            while offset < self.block_size {
                let raw_ptr = (buf.as_ptr() as usize + offset) as *const Ext2DirEntryRaw;
                let raw = unsafe { *raw_ptr };

                if raw.rec_len == 0 {
                    break;
                }

                if raw.inode != 0 && raw.name_len > 0 {
                    let name_ptr = (buf.as_ptr() as usize + offset + 8) as *const u8;
                    let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, raw.name_len as usize) };
                    let name = String::from_utf8_lossy(name_slice).into_owned();

                    entries.push(Ext2DirEntry {
                        inode: raw.inode,
                        file_type: raw.file_type,
                        name,
                    });
                }

                offset += raw.rec_len as usize;
            }
        }

        Ok(entries)
    }

    /// Read the complete byte contents of a file inode.
    pub fn read_file_data(&mut self, inode: &Ext2Inode) -> Result<Vec<u8>, &'static str> {
        let size = inode.i_size as usize;
        let mut data = Vec::with_capacity(size);
        let num_blocks = (size + self.block_size - 1) / self.block_size;

        let mut buf = Vec::with_capacity(self.block_size);
        buf.resize(self.block_size, 0);

        let mut bytes_left = size;
        for b in 0..num_blocks {
            let phys_block = self.get_block_address(inode, b as u32)?;
            if phys_block == 0 {
                let to_zero = bytes_left.min(self.block_size);
                for _ in 0..to_zero {
                    data.push(0);
                }
                bytes_left -= to_zero;
                continue;
            }

            self.device.read_block(phys_block as u64, &mut buf)?;
            let to_copy = bytes_left.min(self.block_size);
            data.extend_from_slice(&buf[..to_copy]);
            bytes_left -= to_copy;
        }

        Ok(data)
    }

    /// Resolve an absolute pathname e.g. `/etc/passwd` to its Inode.
    pub fn resolve_path(&mut self, path: &str) -> Result<Ext2Inode, &'static str> {
        let mut cur_inode = self.read_inode(EXT2_ROOT_INO)?;

        for component in path.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }

            let entries = self.read_dir(&cur_inode)?;
            let mut found_ino = None;
            for entry in entries {
                if entry.name == component {
                    found_ino = Some(entry.inode);
                    break;
                }
            }

            match found_ino {
                Some(ino) => {
                    cur_inode = self.read_inode(ino)?;
                }
                None => return Err("Path not found"),
            }
        }

        Ok(cur_inode)
    }
}
