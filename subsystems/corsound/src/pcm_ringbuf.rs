//! ALSA-style circular PCM audio buffer with `hw_ptr` and `appl_ptr` boundary wrapping,
//! underrun/overrun (`XRUN`) detection and recovery, and sample format converters.

use alloc::vec;
use alloc::vec::Vec;

/// Supported linear PCM wire sample formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmSampleFormat {
    /// Unsigned 8-bit PCM (center bias at 128).
    U8,
    /// Signed 16-bit little-endian PCM.
    S16Le,
    /// Signed 24-bit packed little-endian PCM (3 bytes per sample).
    S24Le,
    /// Signed 32-bit little-endian PCM.
    S32Le,
}

impl PcmSampleFormat {
    /// Bytes occupied by a single mono sample in this format.
    #[inline]
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::S16Le => 2,
            Self::S24Le => 3,
            Self::S32Le => 4,
        }
    }

    /// Decode one raw little-endian sample starting at the beginning of `raw` into normalized `i32`
    /// full-scale (`i32::MIN ..= i32::MAX`).
    pub fn decode_to_s32(self, raw: &[u8]) -> Option<i32> {
        if raw.len() < self.bytes_per_sample() {
            return None;
        }
        Some(match self {
            Self::U8 => {
                let centered = (raw[0] as i32) - 128;
                centered << 24
            }
            Self::S16Le => {
                let val = i16::from_le_bytes([raw[0], raw[1]]) as i32;
                val << 16
            }
            Self::S24Le => {
                let low = raw[0] as u32;
                let mid = (raw[1] as u32) << 8;
                let high = (raw[2] as u32) << 16;
                let combined = (low | mid | high) << 8;
                combined as i32
            }
            Self::S32Le => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        })
    }

    /// Decode one raw little-endian sample into normalized `i16` full-scale.
    pub fn decode_to_s16(self, raw: &[u8]) -> Option<i16> {
        let s32_sample = self.decode_to_s32(raw)?;
        Some((s32_sample >> 16) as i16)
    }

    /// Encode a normalized signed 32-bit sample into `out` in this format.
    pub fn encode_from_s32(self, sample: i32, out: &mut [u8]) -> Option<usize> {
        let needed = self.bytes_per_sample();
        if out.len() < needed {
            return None;
        }
        match self {
            Self::U8 => {
                let shifted = (sample >> 24) + 128;
                out[0] = shifted.clamp(0, 255) as u8;
            }
            Self::S16Le => {
                let s16_val = (sample >> 16) as i16;
                let bytes = s16_val.to_le_bytes();
                out[0] = bytes[0];
                out[1] = bytes[1];
            }
            Self::S24Le => {
                let s24_val = (sample >> 8) as u32;
                out[0] = (s24_val & 0xFF) as u8;
                out[1] = ((s24_val >> 8) & 0xFF) as u8;
                out[2] = ((s24_val >> 16) & 0xFF) as u8;
            }
            Self::S32Le => {
                let bytes = sample.to_le_bytes();
                out[..4].copy_from_slice(&bytes);
            }
        }
        Some(needed)
    }
}

/// Convert an interleaved slice of raw PCM samples in `format` into normalized `i16` samples.
pub fn convert_raw_to_s16_vec(format: PcmSampleFormat, raw: &[u8]) -> Vec<i16> {
    let stride = format.bytes_per_sample();
    if stride == 0 {
        return Vec::new();
    }
    let count = raw.len() / stride;
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        let offset = idx * stride;
        if let Some(sample) = format.decode_to_s16(&raw[offset..offset + stride]) {
            out.push(sample);
        }
    }
    out
}

/// Convert an interleaved slice of raw PCM samples in `format` into normalized `i32` samples.
pub fn convert_raw_to_s32_vec(format: PcmSampleFormat, raw: &[u8]) -> Vec<i32> {
    let stride = format.bytes_per_sample();
    if stride == 0 {
        return Vec::new();
    }
    let count = raw.len() / stride;
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        let offset = idx * stride;
        if let Some(sample) = format.decode_to_s32(&raw[offset..offset + stride]) {
            out.push(sample);
        }
    }
    out
}

/// ALSA PCM stream operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmStreamState {
    /// Stream is allocated and configured, ready to start.
    Prepared,
    /// DMA and application transfers are active.
    Running,
    /// Underrun (playback) or overrun (capture) detected (`XRUN`).
    Xrun,
    /// Stream is draining remaining buffered frames before stopping.
    Draining,
    /// Stream is stopped.
    Stopped,
}

/// Error returned by ALSA-style PCM ring buffer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmError {
    /// Buffer underrun or overrun occurred (`-EPIPE` equivalent).
    XrunDetected,
    /// Invalid ring buffer configuration parameters.
    InvalidGeometry,
    /// Operation not permitted in current stream state.
    BadState,
}

/// ALSA-style circular PCM buffer with `hw_ptr` and `appl_ptr` wrapped at a high boundary
/// multiple of `buffer_frames` to disambiguate full versus empty conditions without wasting a slot.
#[derive(Debug, Clone)]
pub struct PcmRingBuffer {
    /// Interleaved signed 16-bit frame storage (`buffer_frames * channels`).
    storage: Vec<i16>,
    /// Number of audio channels per frame.
    channels: usize,
    /// Capacity in frames (`period_frames * period_count`).
    buffer_frames: usize,
    /// Frames per hardware interrupt period.
    period_frames: usize,
    /// High boundary multiple of `buffer_frames` used for pointer wrapping.
    boundary: usize,
    /// Hardware consumption/production pointer in frames (`0 .. boundary`).
    hw_ptr: usize,
    /// Application write/read pointer in frames (`0 .. boundary`).
    appl_ptr: usize,
    /// Current stream state.
    state: PcmStreamState,
    /// Total XRUN events encountered since creation.
    xrun_count: u32,
}

impl PcmRingBuffer {
    /// Construct a new circular PCM buffer with the specified channel count, period size, and period count.
    pub fn new(channels: usize, period_frames: usize, period_count: usize) -> Result<Self, PcmError> {
        if channels == 0 || period_frames == 0 || period_count < 2 {
            return Err(PcmError::InvalidGeometry);
        }
        let buffer_frames = period_frames
            .checked_mul(period_count)
            .ok_or(PcmError::InvalidGeometry)?;
        let total_samples = buffer_frames
            .checked_mul(channels)
            .ok_or(PcmError::InvalidGeometry)?;

        // Compute an ALSA-style boundary multiple of buffer_frames near usize::MAX / 2.
        let max_safe = (usize::MAX >> 2) / buffer_frames;
        let boundary = if max_safe > 1 {
            max_safe * buffer_frames
        } else {
            buffer_frames * 64
        };

        Ok(Self {
            storage: vec![0i16; total_samples],
            channels,
            buffer_frames,
            period_frames,
            boundary,
            hw_ptr: 0,
            appl_ptr: 0,
            state: PcmStreamState::Prepared,
            xrun_count: 0,
        })
    }

    /// Return the current stream state.
    #[inline]
    pub const fn state(&self) -> PcmStreamState {
        self.state
    }

    /// Return the hardware pointer (`hw_ptr`) in boundary space.
    #[inline]
    pub const fn hw_ptr(&self) -> usize {
        self.hw_ptr
    }

    /// Return the application pointer (`appl_ptr`) in boundary space.
    #[inline]
    pub const fn appl_ptr(&self) -> usize {
        self.appl_ptr
    }

    /// Return the wrapping boundary in frames.
    #[inline]
    pub const fn boundary(&self) -> usize {
        self.boundary
    }

    /// Return the ring capacity in frames.
    #[inline]
    pub const fn buffer_frames(&self) -> usize {
        self.buffer_frames
    }

    /// Return the period size in frames.
    #[inline]
    pub const fn period_frames(&self) -> usize {
        self.period_frames
    }

    /// Return total cumulative XRUN count.
    #[inline]
    pub const fn xrun_count(&self) -> u32 {
        self.xrun_count
    }

    /// Advance a pointer across the circular `boundary`.
    #[inline]
    fn wrap_boundary(&self, ptr: usize, delta: usize) -> usize {
        let sum = ptr.wrapping_add(delta);
        if sum >= self.boundary {
            sum % self.boundary
        } else {
            sum
        }
    }

    /// Number of queued playback frames currently waiting between `hw_ptr` and `appl_ptr`.
    #[inline]
    pub fn queued_frames(&self) -> usize {
        if self.appl_ptr >= self.hw_ptr {
            self.appl_ptr - self.hw_ptr
        } else {
            self.boundary - self.hw_ptr + self.appl_ptr
        }
    }

    /// Number of free frames available for the application to write before filling the buffer.
    #[inline]
    pub fn avail_playback_frames(&self) -> usize {
        let queued = self.queued_frames();
        self.buffer_frames.saturating_sub(queued)
    }

    /// Prepare or recover the stream from `Xrun` or `Stopped` back to `Prepared`, clearing pointers and silence-filling.
    pub fn prepare(&mut self) {
        self.hw_ptr = 0;
        self.appl_ptr = 0;
        for sample in self.storage.iter_mut() {
            *sample = 0;
        }
        self.state = PcmStreamState::Prepared;
    }

    /// Recover specifically from an `XRUN` condition (`snd_pcm_recover` equivalent).
    pub fn recover_from_xrun(&mut self) -> Result<(), PcmError> {
        if self.state != PcmStreamState::Xrun {
            return Err(PcmError::BadState);
        }
        self.prepare();
        Ok(())
    }

    /// Write interleaved `i16` frames from the application into the ring buffer, advancing `appl_ptr`.
    pub fn write_interleaved(&mut self, frames_data: &[i16]) -> Result<usize, PcmError> {
        if self.state == PcmStreamState::Xrun {
            return Err(PcmError::XrunDetected);
        }
        if self.state == PcmStreamState::Stopped {
            return Err(PcmError::BadState);
        }
        let incoming_frames = frames_data.len() / self.channels;
        let free_frames = self.avail_playback_frames();
        let to_write = incoming_frames.min(free_frames);

        for frame_idx in 0..to_write {
            let ring_frame = (self.appl_ptr + frame_idx) % self.buffer_frames;
            let dst_base = ring_frame * self.channels;
            let src_base = frame_idx * self.channels;
            self.storage[dst_base..dst_base + self.channels]
                .copy_from_slice(&frames_data[src_base..src_base + self.channels]);
        }

        self.appl_ptr = self.wrap_boundary(self.appl_ptr, to_write);
        if to_write > 0 && self.state == PcmStreamState::Prepared {
            self.state = PcmStreamState::Running;
        }
        Ok(to_write)
    }

    /// Consume `requested_frames` on behalf of the hardware DMA engine, advancing `hw_ptr`.
    /// If fewer frames are queued than requested, triggers `PcmStreamState::Xrun` and zero-fills the remainder.
    pub fn consume_hardware_period(&mut self, out_interleaved: &mut [i16]) -> Result<usize, PcmError> {
        if self.state == PcmStreamState::Xrun {
            return Err(PcmError::XrunDetected);
        }
        if self.state != PcmStreamState::Running && self.state != PcmStreamState::Draining {
            return Err(PcmError::BadState);
        }

        let requested_frames = out_interleaved.len() / self.channels;
        let available = self.queued_frames();

        if available < requested_frames {
            // Copy whatever valid frames remain, then silence-fill the tail and enter XRUN.
            for frame_idx in 0..available {
                let ring_frame = (self.hw_ptr + frame_idx) % self.buffer_frames;
                let src_base = ring_frame * self.channels;
                let dst_base = frame_idx * self.channels;
                out_interleaved[dst_base..dst_base + self.channels]
                    .copy_from_slice(&self.storage[src_base..src_base + self.channels]);
            }
            for sample in &mut out_interleaved[available * self.channels..] {
                *sample = 0;
            }
            self.hw_ptr = self.wrap_boundary(self.hw_ptr, available);
            self.state = PcmStreamState::Xrun;
            self.xrun_count = self.xrun_count.saturating_add(1);
            return Err(PcmError::XrunDetected);
        }

        for frame_idx in 0..requested_frames {
            let ring_frame = (self.hw_ptr + frame_idx) % self.buffer_frames;
            let src_base = ring_frame * self.channels;
            let dst_base = frame_idx * self.channels;
            out_interleaved[dst_base..dst_base + self.channels]
                .copy_from_slice(&self.storage[src_base..src_base + self.channels]);
        }

        self.hw_ptr = self.wrap_boundary(self.hw_ptr, requested_frames);
        Ok(requested_frames)
    }

    /// Force hardware and application pointers near the boundary to test boundary wrap-around behavior.
    pub fn set_pointers_for_wrap_test(&mut self, offset_before_boundary: usize) {
        let pos = self.boundary.saturating_sub(offset_before_boundary);
        self.hw_ptr = pos;
        self.appl_ptr = pos;
        self.state = PcmStreamState::Prepared;
    }
}
