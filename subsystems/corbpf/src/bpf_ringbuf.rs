//! `BPF_MAP_TYPE_RINGBUF` Variable-Length Lock-Free Ring Buffer.
//!
//! Implements the Linux kernel eBPF ring buffer protocol with an 8-byte record
//! header (`len_and_flags` + `page_offset`), `BPF_RINGBUF_BUSY_BIT` (bit 31),
//! `BPF_RINGBUF_DISCARD_BIT` (bit 30), `reserve`, `submit`, `discard`, and `consume_all`.

use alloc::vec;
use alloc::vec::Vec;

/// Record is currently reserved by a producer and not yet committed.
pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
/// Record was discarded by the producer and should be skipped by consumers.
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
/// Bitmask for extracting the payload length from the 32-bit record header word.
pub const BPF_RINGBUF_LEN_MASK: u32 = !(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
/// Size of the eBPF ringbuf record header in bytes.
pub const BPF_RINGBUF_HDR_SZ: usize = 8;

/// Error returned by `BpfRingBuf` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufError {
    CapacityNotPowerOfTwo,
    InsufficientSpace,
    InvalidReservationToken,
    RecordAlreadyFinalized,
}

/// Handle representing an active in-flight reservation in the `BpfRingBuf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingBufReservation {
    hdr_pos: u64,
    payload_len: usize,
}

/// Variable-length eBPF ring buffer (`BPF_MAP_TYPE_RINGBUF`).
pub struct BpfRingBuf {
    data: Vec<u8>,
    mask: usize,
    producer_pos: u64,
    consumer_pos: u64,
    submitted_records: u64,
    discarded_records: u64,
    dropped_reserves: u64,
}

impl BpfRingBuf {
    /// Create a ring buffer whose byte capacity is a power of two (`>= 64`).
    pub fn new(capacity: usize) -> Result<Self, RingBufError> {
        if capacity < 64 || !capacity.is_power_of_two() {
            return Err(RingBufError::CapacityNotPowerOfTwo);
        }
        Ok(Self {
            data: vec![0u8; capacity],
            mask: capacity - 1,
            producer_pos: 0,
            consumer_pos: 0,
            submitted_records: 0,
            discarded_records: 0,
            dropped_reserves: 0,
        })
    }

    #[inline]
    const fn align8(val: usize) -> usize {
        (val + 7) & !7
    }

    pub const fn capacity(&self) -> usize {
        self.mask + 1
    }

    pub const fn pending_bytes(&self) -> u64 {
        self.producer_pos.saturating_sub(self.consumer_pos)
    }

    pub const fn stats(&self) -> (u64, u64, u64) {
        (
            self.submitted_records,
            self.discarded_records,
            self.dropped_reserves,
        )
    }

    fn write_u32_at(&mut self, abs_pos: u64, val: u32) {
        let bytes = val.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            let idx = ((abs_pos as usize) + i) & self.mask;
            self.data[idx] = b;
        }
    }

    fn read_u32_at(&self, abs_pos: u64) -> u32 {
        let mut bytes = [0u8; 4];
        for (i, slot) in bytes.iter_mut().enumerate() {
            let idx = ((abs_pos as usize) + i) & self.mask;
            *slot = self.data[idx];
        }
        u32::from_le_bytes(bytes)
    }

    /// Reserve `size` payload bytes in the ring buffer, setting `BPF_RINGBUF_BUSY_BIT`.
    pub fn reserve(&mut self, size: usize) -> Result<RingBufReservation, RingBufError> {
        let aligned_payload = Self::align8(size);
        let total_rec_bytes = BPF_RINGBUF_HDR_SZ + aligned_payload;
        let used = (self.producer_pos - self.consumer_pos) as usize;
        if used + total_rec_bytes > self.capacity() {
            self.dropped_reserves += 1;
            return Err(RingBufError::InsufficientSpace);
        }

        let hdr_pos = self.producer_pos;
        self.producer_pos += total_rec_bytes as u64;

        let hdr_word = (size as u32 & BPF_RINGBUF_LEN_MASK) | BPF_RINGBUF_BUSY_BIT;
        self.write_u32_at(hdr_pos, hdr_word);
        self.write_u32_at(hdr_pos + 4, (hdr_pos & (self.mask as u64)) as u32);

        Ok(RingBufReservation {
            hdr_pos,
            payload_len: size,
        })
    }

    /// Write payload bytes into an active reservation before calling `submit` or `discard`.
    pub fn write_reservation(
        &mut self,
        res: RingBufReservation,
        payload: &[u8],
    ) -> Result<(), RingBufError> {
        if payload.len() > res.payload_len {
            return Err(RingBufError::InvalidReservationToken);
        }
        let hdr_word = self.read_u32_at(res.hdr_pos);
        if (hdr_word & BPF_RINGBUF_BUSY_BIT) == 0 {
            return Err(RingBufError::RecordAlreadyFinalized);
        }
        let data_start = res.hdr_pos + (BPF_RINGBUF_HDR_SZ as u64);
        for (i, &b) in payload.iter().enumerate() {
            let idx = ((data_start as usize) + i) & self.mask;
            self.data[idx] = b;
        }
        Ok(())
    }

    /// Commit a reserved record by clearing `BPF_RINGBUF_BUSY_BIT`.
    pub fn submit(&mut self, res: RingBufReservation) -> Result<(), RingBufError> {
        let hdr_word = self.read_u32_at(res.hdr_pos);
        if (hdr_word & BPF_RINGBUF_BUSY_BIT) == 0 {
            return Err(RingBufError::RecordAlreadyFinalized);
        }
        let committed_word = hdr_word & !BPF_RINGBUF_BUSY_BIT;
        self.write_u32_at(res.hdr_pos, committed_word);
        self.submitted_records += 1;
        Ok(())
    }

    /// Discard a reserved record by clearing `BPF_RINGBUF_BUSY_BIT` and setting `BPF_RINGBUF_DISCARD_BIT`.
    pub fn discard(&mut self, res: RingBufReservation) -> Result<(), RingBufError> {
        let hdr_word = self.read_u32_at(res.hdr_pos);
        if (hdr_word & BPF_RINGBUF_BUSY_BIT) == 0 {
            return Err(RingBufError::RecordAlreadyFinalized);
        }
        let discarded_word = (hdr_word & !BPF_RINGBUF_BUSY_BIT) | BPF_RINGBUF_DISCARD_BIT;
        self.write_u32_at(res.hdr_pos, discarded_word);
        self.discarded_records += 1;
        Ok(())
    }

    /// Drain all contiguous non-busy records in FIFO order, invoking `callback` for each submitted record.
    /// Returns the number of submitted records delivered to `callback`.
    pub fn consume_all<F: FnMut(&[u8])>(&mut self, mut callback: F) -> usize {
        let mut delivered = 0usize;
        let mut scratch = Vec::new();

        while self.consumer_pos < self.producer_pos {
            let hdr_word = self.read_u32_at(self.consumer_pos);
            if (hdr_word & BPF_RINGBUF_BUSY_BIT) != 0 {
                // Producer has not yet finalized this record; stop in-order consumption here.
                break;
            }

            let raw_len = (hdr_word & BPF_RINGBUF_LEN_MASK) as usize;
            let aligned_len = Self::align8(raw_len);
            let total_rec_bytes = BPF_RINGBUF_HDR_SZ + aligned_len;

            if (hdr_word & BPF_RINGBUF_DISCARD_BIT) == 0 {
                scratch.clear();
                scratch.reserve(raw_len);
                let data_start = self.consumer_pos + (BPF_RINGBUF_HDR_SZ as u64);
                for i in 0..raw_len {
                    let idx = ((data_start as usize) + i) & self.mask;
                    scratch.push(self.data[idx]);
                }
                callback(&scratch);
                delivered += 1;
            }

            self.consumer_pos += total_rec_bytes as u64;
        }

        delivered
    }
}
