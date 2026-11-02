//! Zero-copy SPSC/MPMC shared-memory IPC ring channel (`ShmRingHeader`, power-of-two
//! slot mask, variable-length message framing with wrap-around padding marker, and
//! `eventfd` wakeup counter).

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Record header tag indicating a valid variable-length payload frame.
pub const FRAME_TAG_DATA: u32 = 0x4441_5441; // "DATA"
/// Record header tag indicating a wrap-around padding skip to offset `0` of the ring buffer.
pub const FRAME_TAG_PADDING: u32 = 0x5041_4400; // "PAD\0"

/// Size in bytes of the frame header (`tag: u32` + `payload_len: u32`).
pub const FRAME_HEADER_BYTES: usize = 8;

/// Errors returned by `ShmRingChannel` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingChannelError {
    /// Capacity must be a power of two and at least 64 bytes.
    InvalidCapacity,
    /// Payload exceeds the maximum single-frame size supported by this ring.
    PayloadTooLarge,
    /// Insufficient free space in the ring buffer (`EAGAIN`).
    RingFull,
    /// No messages available to read (`EAGAIN`).
    RingEmpty,
    /// Corrupted frame header detected in shared memory.
    CorruptedFrame,
}

/// Shared-memory control block (`ShmRingHeader`) using atomic monotonic indices and `eventfd` wakeup state.
#[repr(C, align(64))]
pub struct ShmRingHeader {
    /// Power-of-two capacity in bytes.
    pub capacity: usize,
    /// Bitmask `capacity - 1` used for fast modulo indexing.
    pub mask: usize,
    /// Monotonically increasing write byte offset.
    pub write_pos: AtomicU64,
    /// Monotonically increasing read byte offset.
    pub read_pos: AtomicU64,
    /// `eventfd` counter incremented whenever a producer wakes a sleeping consumer.
    pub eventfd_counter: AtomicU64,
    /// Total frames successfully published.
    pub published_frames: AtomicU64,
}

impl ShmRingHeader {
    pub fn new(capacity: usize) -> Result<Self, RingChannelError> {
        if capacity < 64 || !capacity.is_power_of_two() {
            return Err(RingChannelError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            mask: capacity - 1,
            write_pos: AtomicU64::new(0),
            read_pos: AtomicU64::new(0),
            eventfd_counter: AtomicU64::new(0),
            published_frames: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn used_bytes(&self) -> usize {
        let w = self.write_pos.load(Ordering::Acquire);
        let r = self.read_pos.load(Ordering::Acquire);
        w.saturating_sub(r) as usize
    }

    #[inline]
    pub fn free_bytes(&self) -> usize {
        self.capacity.saturating_sub(self.used_bytes())
    }
}

#[inline]
const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Zero-copy-capable Shared-Memory IPC Ring Channel with wrap-around framing and `eventfd` signaling.
pub struct ShmRingChannel {
    pub header: ShmRingHeader,
    buffer: Vec<u8>,
}

impl ShmRingChannel {
    pub fn new(capacity: usize) -> Result<Self, RingChannelError> {
        let header = ShmRingHeader::new(capacity)?;
        Ok(Self {
            header,
            buffer: vec![0u8; capacity],
        })
    }

    fn write_frame_header(&mut self, offset: usize, tag: u32, len: u32) {
        self.buffer[offset..offset + 4].copy_from_slice(&tag.to_le_bytes());
        self.buffer[offset + 4..offset + 8].copy_from_slice(&len.to_le_bytes());
    }

    fn read_frame_header(&self, offset: usize) -> (u32, u32) {
        let tag = u32::from_le_bytes([
            self.buffer[offset],
            self.buffer[offset + 1],
            self.buffer[offset + 2],
            self.buffer[offset + 3],
        ]);
        let len = u32::from_le_bytes([
            self.buffer[offset + 4],
            self.buffer[offset + 5],
            self.buffer[offset + 6],
            self.buffer[offset + 7],
        ]);
        (tag, len)
    }

    /// Publish a variable-length frame into the ring buffer.
    /// If the frame does not fit contiguously before the end of the backing array, inserts a
    /// `FRAME_TAG_PADDING` wrap-around marker at the tail and writes the frame at offset `0`.
    pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), RingChannelError> {
        let aligned_payload = align8(payload.len());
        let record_bytes = FRAME_HEADER_BYTES + aligned_payload;
        if record_bytes > self.header.capacity / 2 {
            return Err(RingChannelError::PayloadTooLarge);
        }

        let w = self.header.write_pos.load(Ordering::Relaxed) as usize;
        let r = self.header.read_pos.load(Ordering::Acquire) as usize;
        let used = w.saturating_sub(r);
        let free = self.header.capacity.saturating_sub(used);

        let w_off = w & self.header.mask;
        let tail_room = self.header.capacity - w_off;

        if tail_room < record_bytes {
            // Need wrap-around padding of `tail_room` bytes plus `record_bytes` at offset 0.
            let total_needed = tail_room + record_bytes;
            if free < total_needed {
                return Err(RingChannelError::RingFull);
            }
            if tail_room >= FRAME_HEADER_BYTES {
                let pad_payload = (tail_room - FRAME_HEADER_BYTES) as u32;
                self.write_frame_header(w_off, FRAME_TAG_PADDING, pad_payload);
            }
            // Write actual data record starting at index 0.
            self.write_frame_header(0, FRAME_TAG_DATA, payload.len() as u32);
            self.buffer[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + payload.len()]
                .copy_from_slice(payload);
            self.header
                .write_pos
                .store((w + total_needed) as u64, Ordering::Release);
        } else {
            if free < record_bytes {
                return Err(RingChannelError::RingFull);
            }
            self.write_frame_header(w_off, FRAME_TAG_DATA, payload.len() as u32);
            let data_start = w_off + FRAME_HEADER_BYTES;
            self.buffer[data_start..data_start + payload.len()].copy_from_slice(payload);
            self.header
                .write_pos
                .store((w + record_bytes) as u64, Ordering::Release);
        }

        self.header.published_frames.fetch_add(1, Ordering::Relaxed);
        self.header.eventfd_counter.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Zero-copy inspect the next available frame slice in-place and advance `read_pos`,
    /// automatically skipping any `FRAME_TAG_PADDING` wrap-around marker.
    pub fn recv_frame_zero_copy<F, R>(&mut self, visit: F) -> Result<R, RingChannelError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        loop {
            let r = self.header.read_pos.load(Ordering::Relaxed) as usize;
            let w = self.header.write_pos.load(Ordering::Acquire) as usize;
            if r >= w {
                return Err(RingChannelError::RingEmpty);
            }

            let r_off = r & self.header.mask;
            let tail_room = self.header.capacity - r_off;
            if tail_room < FRAME_HEADER_BYTES {
                self.header
                    .read_pos
                    .store((r + tail_room) as u64, Ordering::Release);
                continue;
            }

            let (tag, len_u32) = self.read_frame_header(r_off);
            let len = len_u32 as usize;

            if tag == FRAME_TAG_PADDING {
                let skip = FRAME_HEADER_BYTES + len;
                self.header
                    .read_pos
                    .store((r + skip) as u64, Ordering::Release);
                continue;
            }

            if tag != FRAME_TAG_DATA {
                return Err(RingChannelError::CorruptedFrame);
            }

            let record_bytes = FRAME_HEADER_BYTES + align8(len);
            let data_start = r_off + FRAME_HEADER_BYTES;
            let result = visit(&self.buffer[data_start..data_start + len]);
            self.header
                .read_pos
                .store((r + record_bytes) as u64, Ordering::Release);
            return Ok(result);
        }
    }

    /// Consume and return the accumulated `eventfd` wakeup counter (`eventfd_read` semantics).
    pub fn consume_eventfd(&self) -> u64 {
        self.header.eventfd_counter.swap(0, Ordering::AcqRel)
    }
}

/// Self-test exercising `ShmRingChannel` power-of-two slot mask, wrap-around padding
/// marker insertion/skipping across the buffer boundary, and `eventfd` wakeup counter.
pub fn self_test() -> bool {
    let mut ring = match ShmRingChannel::new(64) {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Send 20-byte payload (8 header + 24 aligned = 32 bytes -> write_pos = 32).
    if ring.send_frame(&[0xAA; 20]).is_err() {
        return false;
    }
    // Pop it so read_pos = 32, write_pos = 32 (only 32 bytes remain before wrap-around at 64).
    let first_ok = match ring.recv_frame_zero_copy(|slice| slice.len() == 20 && slice[0] == 0xAA) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if !first_ok {
        return false;
    }

    // Now send a 26-byte payload (8 header + 32 aligned = 40 bytes > 32 tail_room).
    // This forces a 32-byte FRAME_TAG_PADDING at offset 32..64 and places the frame at offset 0..40!
    if ring.send_frame(b"WRAP_AROUND_ZERO_COPY_IPC!").is_err() {
        return false;
    }

    let wrapped_ok =
        match ring.recv_frame_zero_copy(|slice| slice == b"WRAP_AROUND_ZERO_COPY_IPC!") {
            Ok(b) => b,
            Err(_) => return false,
        };

    wrapped_ok && ring.consume_eventfd() == 2 && ring.header.used_bytes() == 0
}
