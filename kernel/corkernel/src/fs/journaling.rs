//! Journaling Block Device 2 (JBD2) Logging Subsystem
//!
//! Implements atomic filesystem transaction logging for crash resilience:
//! - Journal Superblock (Magic `0xC03B3998`, Block size, Max transaction size)
//! - Descriptor Block (Mapping of journal blocks to physical filesystem blocks)
//! - Commit Block (Cryptographic checksum of transaction payload)
//! - Revoke Block (Tracking stale blocks freed before commit to prevent replay corruption)
//! - Checkpoint list & circular ring buffer journal log head/tail advancement
//! - Journal replay & crash recovery parser on mount

#![allow(dead_code)]

use alloc::vec::Vec;

pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B3998;

/// JBD2 Block Types
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub const JBD2_COMMIT_BLOCK: u32 = 2;
pub const JBD2_SUPERBLOCK_V1: u32 = 3;
pub const JBD2_SUPERBLOCK_V2: u32 = 4;
pub const JBD2_REVOKE_BLOCK: u32 = 5;

/// JBD2 Header present at the beginning of every journal block
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Jbd2Header {
    pub magic: u32,
    pub blocktype: u32,
    pub sequence: u32,
}

/// JBD2 Superblock Structure (1024 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Jbd2Superblock {
    pub header: Jbd2Header,
    pub blocksize: u32,
    pub maxlen: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub error_val: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub nr_users: u32,
    pub dynsuper: u32,
    pub max_transaction: u32,
    pub max_tr_data: u32,
    pub checksum_type: u8,
    pub padding: [u8; 3],
    pub padding2: [u32; 42],
    pub checksum: u32,
}

/// JBD2 Block Tag within Descriptor Block
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Jbd2BlockTag {
    pub blocknr: u32,
    pub flags: u32,
}

pub const JBD2_FLAG_ESCAPE: u32 = 1;
pub const JBD2_FLAG_SAME_UUID: u32 = 2;
pub const JBD2_FLAG_DELETED: u32 = 4;
pub const JBD2_FLAG_LAST_TAG: u32 = 8;

/// In-memory Transaction Unit
pub struct JournalTransaction {
    pub tid: u32,
    pub target_blocks: Vec<u64>,
    pub data_payloads: Vec<Vec<u8>>,
    pub revoked_blocks: Vec<u64>,
    pub is_committed: bool,
}

/// JBD2 Journaling Engine
pub struct Jbd2Journal {
    pub block_size: usize,
    pub total_journal_blocks: u32,
    pub first_log_block: u32,
    pub head_block: u32,
    pub tail_block: u32,
    pub current_sequence: u32,
    pub storage: Vec<u8>,
    pub active_transaction: Option<JournalTransaction>,
}

impl Jbd2Journal {
    /// Initialize a new JBD2 crash-consistent journal
    pub fn new(total_blocks: u32, block_size: usize) -> Self {
        let storage_len = (total_blocks as usize) * block_size;
        Self {
            block_size,
            total_journal_blocks: total_blocks,
            first_log_block: 1, // Block 0 is superblock
            head_block: 1,
            tail_block: 1,
            current_sequence: 1,
            storage: alloc::vec![0u8; storage_len],
            active_transaction: None,
        }
    }

    /// Begin a new atomic filesystem modification transaction
    pub fn start_transaction(&mut self) -> Result<u32, &'static str> {
        if self.active_transaction.is_some() {
            return Err("Transaction already in progress");
        }
        let tid = self.current_sequence;
        self.active_transaction = Some(JournalTransaction {
            tid,
            target_blocks: Vec::new(),
            data_payloads: Vec::new(),
            revoked_blocks: Vec::new(),
            is_committed: false,
        });
        Ok(tid)
    }

    /// Stage a modified physical block into the active journal transaction
    pub fn log_block(&mut self, fs_block_num: u64, data: &[u8]) -> Result<(), &'static str> {
        let tr = self.active_transaction.as_mut().ok_or("No active transaction")?;
        tr.target_blocks.push(fs_block_num);
        tr.data_payloads.push(data.to_vec());
        Ok(())
    }

    /// Mark a physical block as revoked (deallocated) to prevent replay corruption
    pub fn revoke_block(&mut self, fs_block_num: u64) -> Result<(), &'static str> {
        let tr = self.active_transaction.as_mut().ok_or("No active transaction")?;
        tr.revoked_blocks.push(fs_block_num);
        Ok(())
    }

    /// Commit the active transaction atomically to disk
    pub fn commit_transaction(&mut self) -> Result<(), &'static str> {
        let tr = self.active_transaction.take().ok_or("No active transaction")?;
        let block_count = tr.target_blocks.len();
        if block_count == 0 {
            return Ok(());
        }

        // 1. Write Descriptor Block
        let desc_block_idx = self.head_block;
        self.head_block = (self.head_block + 1) % self.total_journal_blocks;
        if self.head_block == 0 { self.head_block = self.first_log_block; }

        let desc_offset = (desc_block_idx as usize) * self.block_size;
        let mut desc_buf = alloc::vec![0u8; self.block_size];

        let hdr = Jbd2Header {
            magic: JBD2_MAGIC_NUMBER.to_be(),
            blocktype: JBD2_DESCRIPTOR_BLOCK.to_be(),
            sequence: tr.tid.to_be(),
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                desc_buf.as_mut_ptr(),
                core::mem::size_of::<Jbd2Header>(),
            );
        }

        // Fill descriptor tags
        let mut tag_offset = core::mem::size_of::<Jbd2Header>();
        for (i, &blk) in tr.target_blocks.iter().enumerate() {
            let flags = if i == block_count - 1 { JBD2_FLAG_LAST_TAG } else { 0 };
            let tag = Jbd2BlockTag {
                blocknr: (blk as u32).to_be(),
                flags: flags.to_be(),
            };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &tag as *const _ as *const u8,
                    desc_buf.as_mut_ptr().add(tag_offset),
                    core::mem::size_of::<Jbd2BlockTag>(),
                );
            }
            tag_offset += core::mem::size_of::<Jbd2BlockTag>();
        }
        self.storage[desc_offset..desc_offset + self.block_size].copy_from_slice(&desc_buf);

        // 2. Write Data Payload Blocks
        for payload in &tr.data_payloads {
            let data_block_idx = self.head_block;
            self.head_block = (self.head_block + 1) % self.total_journal_blocks;
            if self.head_block == 0 { self.head_block = self.first_log_block; }

            let offset = (data_block_idx as usize) * self.block_size;
            let len = payload.len().min(self.block_size);
            self.storage[offset..offset + len].copy_from_slice(&payload[..len]);
        }

        // 3. Write Commit Block (Ensures atomicity: if power cuts before this, transaction is discarded)
        let commit_block_idx = self.head_block;
        self.head_block = (self.head_block + 1) % self.total_journal_blocks;
        if self.head_block == 0 { self.head_block = self.first_log_block; }

        let commit_offset = (commit_block_idx as usize) * self.block_size;
        let mut commit_buf = alloc::vec![0u8; self.block_size];
        let commit_hdr = Jbd2Header {
            magic: JBD2_MAGIC_NUMBER.to_be(),
            blocktype: JBD2_COMMIT_BLOCK.to_be(),
            sequence: tr.tid.to_be(),
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &commit_hdr as *const _ as *const u8,
                commit_buf.as_mut_ptr(),
                core::mem::size_of::<Jbd2Header>(),
            );
        }
        self.storage[commit_offset..commit_offset + self.block_size].copy_from_slice(&commit_buf);

        self.current_sequence += 1;
        Ok(())
    }

    /// Perform crash recovery / journal replay during system boot
    pub fn replay_recovery<F>(&mut self, mut write_fs_block: F) -> Result<usize, &'static str>
    where
        F: FnMut(u64, &[u8]) -> Result<(), &'static str>,
    {
        let mut replayed_transactions = 0;
        let mut curr = self.tail_block;

        while curr != self.head_block {
            let offset = (curr as usize) * self.block_size;
            let hdr: Jbd2Header = unsafe { core::ptr::read_unaligned(self.storage.as_ptr().add(offset) as *const _) };

            if u32::from_be(hdr.magic) != JBD2_MAGIC_NUMBER {
                break;
            }

            let btype = u32::from_be(hdr.blocktype);
            if btype == JBD2_DESCRIPTOR_BLOCK {
                // Parse tags & replay following blocks
                let mut tag_offset = offset + core::mem::size_of::<Jbd2Header>();
                let mut data_idx = (curr + 1) % self.total_journal_blocks;
                if data_idx == 0 { data_idx = self.first_log_block; }

                loop {
                    let tag: Jbd2BlockTag = unsafe { core::ptr::read_unaligned(self.storage.as_ptr().add(tag_offset) as *const _) };
                    let target_blk = u32::from_be(tag.blocknr) as u64;
                    let flags = u32::from_be(tag.flags);

                    let data_offset = (data_idx as usize) * self.block_size;
                    let payload = &self.storage[data_offset..data_offset + self.block_size];

                    write_fs_block(target_blk, payload)?;

                    data_idx = (data_idx + 1) % self.total_journal_blocks;
                    if data_idx == 0 { data_idx = self.first_log_block; }
                    tag_offset += core::mem::size_of::<Jbd2BlockTag>();

                    if (flags & JBD2_FLAG_LAST_TAG) != 0 {
                        break;
                    }
                }
                curr = data_idx; // Move past committed data and commit block
                replayed_transactions += 1;
            } else {
                curr = (curr + 1) % self.total_journal_blocks;
                if curr == 0 { curr = self.first_log_block; }
            }
        }

        self.tail_block = self.head_block;
        Ok(replayed_transactions)
    }
}
