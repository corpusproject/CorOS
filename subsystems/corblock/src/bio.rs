//! `bio.rs` — Block I/O request (`Bio`), scatter-gather vector (`BioVec`),
//! splitting, merging, and completion handling for the CorOS block layer.

use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;

/// Primary block I/O operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    Read,
    Write,
    Flush,
    Discard,
    WriteSame,
    SecureErase,
}

/// Flags modifying execution semantics of a block I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BioFlags(pub u32);

impl BioFlags {
    pub const NONE: Self = Self(0);
    pub const SYNC: Self = Self(1 << 0);
    pub const FAILFAST_DEV: Self = Self(1 << 1);
    pub const FAILFAST_TRANSPORT: Self = Self(1 << 2);
    pub const QUIET: Self = Self(1 << 3);
    pub const PREFLUSH: Self = Self(1 << 4);
    pub const FUA: Self = Self(1 << 5);

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    pub const fn union(&self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Completion status of a block I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioStatus {
    NotCompleted,
    Success,
    NotSupported,
    IoError,
    DeviceBusy,
    MediumError,
    Cancelled,
    Timeout,
}

/// Block layer error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BioError {
    InvalidSplitSize,
    UnmergeableBios,
    BufferTooSmall,
    AlignmentError,
    IoFailed(BioStatus),
}

/// A contiguous memory buffer segment within a scatter-gather block I/O request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BioVec {
    pub page_offset: usize,
    pub length: usize,
    pub data: Vec<u8>,
}

impl BioVec {
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            page_offset: 0,
            length: len,
            data,
        }
    }

    pub fn with_offset_len(data: Vec<u8>, offset: usize, len: usize) -> Result<Self, BioError> {
        if offset + len > data.len() {
            return Err(BioError::BufferTooSmall);
        }
        Ok(Self {
            page_offset: offset,
            length: len,
            data,
        })
    }

    pub fn slice(&self) -> &[u8] {
        &self.data[self.page_offset..self.page_offset + self.length]
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.page_offset..self.page_offset + self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Iterator tracking progress across scatter-gather segments during device transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BioIter {
    pub bvec_idx: usize,
    pub bvec_done: usize,
    pub bytes_remaining: usize,
}

/// Block I/O request representing an atomic block transfer command.
#[derive(Debug, Clone)]
pub struct Bio {
    pub bi_sector: u64,
    pub bi_size: usize,
    pub bi_op: BioOp,
    pub bi_flags: BioFlags,
    pub bi_status: BioStatus,
    pub bi_io_vec: Vec<BioVec>,
    pub bi_iter: BioIter,
    pub bi_private: u64,
}

impl Bio {
    pub fn new(op: BioOp, sector: u64) -> Self {
        Self {
            bi_sector: sector,
            bi_size: 0,
            bi_op: op,
            bi_flags: BioFlags::NONE,
            bi_status: BioStatus::NotCompleted,
            bi_io_vec: Vec::new(),
            bi_iter: BioIter::default(),
            bi_private: 0,
        }
    }

    pub fn with_flags(op: BioOp, sector: u64, flags: BioFlags) -> Self {
        let mut bio = Self::new(op, sector);
        bio.bi_flags = flags;
        bio
    }

    pub fn add_vec(&mut self, bvec: BioVec) {
        self.bi_size += bvec.length;
        self.bi_iter.bytes_remaining = self.bi_size;
        self.bi_io_vec.push(bvec);
    }

    pub fn add_buffer(&mut self, buf: &[u8]) {
        let bvec = BioVec::new(buf.to_vec());
        self.add_vec(bvec);
    }

    pub fn sector_count(&self) -> u64 {
        ((self.bi_size + SECTOR_SIZE - 1) / SECTOR_SIZE) as u64
    }

    pub fn is_read(&self) -> bool {
        self.bi_op == BioOp::Read
    }

    pub fn is_write(&self) -> bool {
        self.bi_op == BioOp::Write
    }

    pub fn is_flush(&self) -> bool {
        self.bi_op == BioOp::Flush
    }

    pub fn is_complete(&self) -> bool {
        self.bi_status != BioStatus::NotCompleted
    }

    pub fn complete(&mut self, status: BioStatus) {
        self.bi_status = status;
    }

    pub fn flatten_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bi_size);
        for bvec in &self.bi_io_vec {
            out.extend_from_slice(bvec.slice());
        }
        out
    }

    /// Advances the internal bio iterator by `bytes` transferred.
    pub fn advance(&mut self, mut bytes: usize) -> bool {
        if bytes > self.bi_iter.bytes_remaining {
            bytes = self.bi_iter.bytes_remaining;
        }

        self.bi_iter.bytes_remaining -= bytes;

        while bytes > 0 && self.bi_iter.bvec_idx < self.bi_io_vec.len() {
            let cur_bvec = &self.bi_io_vec[self.bi_iter.bvec_idx];
            let remaining_in_cur = cur_bvec.length - self.bi_iter.bvec_done;

            if bytes >= remaining_in_cur {
                bytes -= remaining_in_cur;
                self.bi_iter.bvec_idx += 1;
                self.bi_iter.bvec_done = 0;
            } else {
                self.bi_iter.bvec_done += bytes;
                bytes = 0;
            }
        }

        self.bi_iter.bytes_remaining == 0
    }

    /// Splits a large Bio into two sub-requests at `split_bytes`.
    /// The first Bio covers `[0..split_bytes]`, and the second Bio covers `[split_bytes..bi_size]`.
    pub fn split(&self, split_bytes: usize) -> Result<(Bio, Bio), BioError> {
        if split_bytes == 0 || split_bytes >= self.bi_size {
            return Err(BioError::InvalidSplitSize);
        }

        let mut first = Bio::with_flags(self.bi_op, self.bi_sector, self.bi_flags);
        first.bi_private = self.bi_private;

        let sectors_first = (split_bytes / SECTOR_SIZE) as u64;
        let second_sector = self.bi_sector + sectors_first;
        let mut second = Bio::with_flags(self.bi_op, second_sector, self.bi_flags);
        second.bi_private = self.bi_private;

        let mut accumulated = 0usize;

        for bvec in &self.bi_io_vec {
            let bvec_len = bvec.length;
            let bvec_slice = bvec.slice();

            if accumulated + bvec_len <= split_bytes {
                first.add_buffer(bvec_slice);
                accumulated += bvec_len;
            } else if accumulated < split_bytes {
                let part1_len = split_bytes - accumulated;

                first.add_buffer(&bvec_slice[..part1_len]);
                second.add_buffer(&bvec_slice[part1_len..]);

                accumulated = split_bytes;
            } else {
                second.add_buffer(bvec_slice);
            }
        }

        Ok((first, second))
    }

    /// Determines if `next` can be merged to the end of `self`.
    pub fn can_merge(&self, next: &Bio) -> bool {
        if self.bi_op != next.bi_op {
            return false;
        }
        if self.bi_flags.contains(BioFlags::FUA) != next.bi_flags.contains(BioFlags::FUA) {
            return false;
        }
        let expected_next_sector = self.bi_sector + (self.bi_size / SECTOR_SIZE) as u64;
        expected_next_sector == next.bi_sector
    }

    /// Merges `next` Bio into `self`.
    pub fn merge(&mut self, next: Bio) -> Result<(), BioError> {
        if !self.can_merge(&next) {
            return Err(BioError::UnmergeableBios);
        }

        for bvec in next.bi_io_vec {
            self.add_vec(bvec);
        }

        self.bi_flags.insert(next.bi_flags);
        Ok(())
    }
}
