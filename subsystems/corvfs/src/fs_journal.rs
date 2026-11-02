//! CorOS VFS Module: `fs_journal`
//!
//! Write-Ahead Logging (WAL) atomic transaction journal (`JournalHeader`,
//! `JournalTransaction`, `JournalDescriptorBlock`, `JournalCommitBlock`,
//! IEEE 802.3 CRC32 checksum engine, and post-crash replay recovery engine).

use alloc::vec::Vec;

/// Magic signature for CorFS WAL journal blocks (`"CWAL"` = `0x4C41_5743`).
pub const JOURNAL_MAGIC: u32 = 0x4C41_5743;

/// Block types stored inside the circular on-disk journal ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum JournalBlockKind {
    Descriptor = 1,
    Commit = 2,
    Revoke = 3,
    SuperblockV1 = 4,
}

/// 16-byte header placed at the start of every journal metadata block.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub magic: u32,
    pub block_kind: u32,
    pub sequence_id: u64,
}

/// Descriptor entry mapping a journal log slot to its final home filesystem LBA.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalBlockTag {
    pub target_fs_lba: u64,
    pub flags: u32,
    pub payload_crc32: u32,
}

/// Descriptor block listing all metadata blocks modified in `sequence_id`.
#[derive(Clone, Debug)]
pub struct JournalDescriptorBlock {
    pub header: JournalHeader,
    pub tags: Vec<JournalBlockTag>,
}

/// Commit block sealing a transaction once all descriptor and data blocks have reached disk.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalCommitBlock {
    pub header: JournalHeader,
    pub total_blocks: u32,
    pub transaction_crc32: u32,
    pub commit_timestamp_ns: u64,
}

/// Lifecycle state of an in-memory `JournalTransaction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Running,
    LockedForFlush,
    CommittedToLog,
    CheckpointedToFs,
    Aborted,
}

/// Staged metadata block buffer inside an active transaction.
#[derive(Clone, Debug)]
pub struct StagedMetadataWrite {
    pub target_fs_lba: u64,
    pub data: Vec<u8>,
    pub crc32: u32,
}

/// Atomic Write-Ahead Log transaction.
#[derive(Clone, Debug)]
pub struct JournalTransaction {
    pub sequence_id: u64,
    pub state: TransactionState,
    pub staged_writes: Vec<StagedMetadataWrite>,
    pub commit_block: Option<JournalCommitBlock>,
}

/// Computes standard IEEE 802.3 CRC32 checksum bit-by-bit (zero table overhead in `#![no_std]`).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Computes the combined transaction checksum over the sequence ID and all staged block CRCs.
pub fn compute_transaction_crc(sequence_id: u64, writes: &[StagedMetadataWrite]) -> u32 {
    let mut buf = Vec::with_capacity(8 + writes.len() * 12);
    buf.extend_from_slice(&sequence_id.to_le_bytes());
    for w in writes {
        buf.extend_from_slice(&w.target_fs_lba.to_le_bytes());
        buf.extend_from_slice(&w.crc32.to_le_bytes());
    }
    crc32_ieee(&buf)
}

/// Write-Ahead Logging (WAL) Journal Manager & Crash Recovery Engine.
pub struct FsJournalManager {
    next_sequence_id: u64,
    pub committed_log: Vec<JournalTransaction>,
    pub replayed_blocks: u64,
}

impl FsJournalManager {
    pub const fn new(initial_seq: u64) -> Self {
        Self {
            next_sequence_id: initial_seq,
            committed_log: Vec::new(),
            replayed_blocks: 0,
        }
    }

    /// Starts a new running WAL transaction.
    pub fn begin_transaction(&mut self) -> JournalTransaction {
        let seq = self.next_sequence_id;
        self.next_sequence_id += 1;
        JournalTransaction {
            sequence_id: seq,
            state: TransactionState::Running,
            staged_writes: Vec::new(),
            commit_block: None,
        }
    }

    /// Attaches a modified metadata block to an active transaction, deduplicating earlier writes to the same LBA.
    pub fn stage_block(tx: &mut JournalTransaction, target_fs_lba: u64, data: &[u8]) -> Result<(), &'static str> {
        if tx.state != TransactionState::Running {
            return Err("Cannot stage blocks into a non-running transaction");
        }
        let checksum = crc32_ieee(data);
        if let Some(existing) = tx.staged_writes.iter_mut().find(|w| w.target_fs_lba == target_fs_lba) {
            existing.data.clear();
            existing.data.extend_from_slice(data);
            existing.crc32 = checksum;
            return Ok(());
        }

        let mut copy = Vec::with_capacity(data.len());
        copy.extend_from_slice(data);
        tx.staged_writes.push(StagedMetadataWrite {
            target_fs_lba,
            data: copy,
            crc32: checksum,
        });
        Ok(())
    }

    /// Builds the `JournalDescriptorBlock` for a transaction.
    pub fn build_descriptor(tx: &JournalTransaction) -> JournalDescriptorBlock {
        let tags = tx
            .staged_writes
            .iter()
            .map(|w| JournalBlockTag {
                target_fs_lba: w.target_fs_lba,
                flags: 0,
                payload_crc32: w.crc32,
            })
            .collect();

        JournalDescriptorBlock {
            header: JournalHeader {
                magic: JOURNAL_MAGIC,
                block_kind: JournalBlockKind::Descriptor as u32,
                sequence_id: tx.sequence_id,
            },
            tags,
        }
    }

    /// Seals and commits `tx` to the write-ahead log, generating its `JournalCommitBlock`.
    pub fn commit_transaction(&mut self, mut tx: JournalTransaction, timestamp_ns: u64) -> Result<u32, &'static str> {
        if tx.state != TransactionState::Running {
            return Err("Transaction is not in Running state");
        }
        tx.state = TransactionState::LockedForFlush;
        let tx_crc = compute_transaction_crc(tx.sequence_id, &tx.staged_writes);

        let commit = JournalCommitBlock {
            header: JournalHeader {
                magic: JOURNAL_MAGIC,
                block_kind: JournalBlockKind::Commit as u32,
                sequence_id: tx.sequence_id,
            },
            total_blocks: tx.staged_writes.len() as u32,
            transaction_crc32: tx_crc,
            commit_timestamp_ns: timestamp_ns,
        };

        tx.commit_block = Some(commit);
        tx.state = TransactionState::CommittedToLog;
        self.committed_log.push(tx);
        Ok(tx_crc)
    }

    /// Replays all valid committed transactions after a crash, verifying both block and commit CRC32s.
    /// Returns a list of `(target_fs_lba, verified_block_bytes)` to be written to their home locations.
    pub fn replay_recovery(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut recovered = Vec::new();

        for tx in &mut self.committed_log {
            if tx.state != TransactionState::CommittedToLog {
                continue;
            }
            let Some(commit) = tx.commit_block else {
                continue; // Uncommitted / torn transaction: skip!
            };
            if commit.header.magic != JOURNAL_MAGIC
                || commit.header.sequence_id != tx.sequence_id
                || commit.total_blocks as usize != tx.staged_writes.len()
            {
                continue;
            }

            // Verify every staged block's CRC32 and overall transaction CRC32
            let all_blocks_valid = tx
                .staged_writes
                .iter()
                .all(|w| crc32_ieee(&w.data) == w.crc32);
            let calc_tx_crc = compute_transaction_crc(tx.sequence_id, &tx.staged_writes);

            if all_blocks_valid && calc_tx_crc == commit.transaction_crc32 {
                for w in &tx.staged_writes {
                    recovered.push((w.target_fs_lba, w.data.clone()));
                    self.replayed_blocks += 1;
                }
                tx.state = TransactionState::CheckpointedToFs;
            }
        }

        recovered
    }
}

/// Self-test suite for `fs_journal`.
pub fn verify_vfs_fs_journal() -> u32 {
    let mut passed = 0u32;

    // IEEE 802.3 CRC32 standard check: "123456789" -> 0xCBF43926
    if crc32_ieee(b"123456789") == 0xCBF4_3926 {
        passed += 1;
    }

    let mut jmgr = FsJournalManager::new(100);
    let mut tx1 = jmgr.begin_transaction();
    let _ = FsJournalManager::stage_block(&mut tx1, 42, b"INODE_BITMAP_UPDATE_V1");
    let _ = FsJournalManager::stage_block(&mut tx1, 99, b"DIR_BLOCK_ENTRY_INSERT");

    let desc = FsJournalManager::build_descriptor(&tx1);
    if desc.header.magic == JOURNAL_MAGIC && desc.tags.len() == 2 {
        passed += 1;
    }

    if jmgr.commit_transaction(tx1, 1_000_000).is_ok() {
        passed += 1;
    }

    // Add a corrupted transaction to the log and ensure replay_recovery skips it while replaying tx1
    let mut tx_bad = jmgr.begin_transaction();
    let _ = FsJournalManager::stage_block(&mut tx_bad, 200, b"GOOD_DATA");
    let _ = jmgr.commit_transaction(tx_bad, 2_000_000);
    // Corrupt the payload of the second transaction in the log
    jmgr.committed_log[1].staged_writes[0].data[0] ^= 0xFF;

    let replayed = jmgr.replay_recovery();
    if replayed.len() == 2 && replayed[0].0 == 42 && replayed[1].0 == 99 {
        passed += 1;
    }

    passed
}
