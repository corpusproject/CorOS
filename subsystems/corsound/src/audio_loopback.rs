//! Virtual loopback audio device (`AloopSubstream`, full-duplex playback-to-capture ring bridge,
//! sample rate clock drift compensator via fractional phase-locked linear resampling, and
//! zero-fill silence injector when no producer is active).

use alloc::vec;
use alloc::vec::Vec;

/// Virtual loopback substream endpoint descriptor (`snd-aloop` equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AloopSubstream {
    /// Cable index (`0` or `1` in standard dual-cable loopback setups).
    pub cable_id: u8,
    /// Substream index (`0..8`).
    pub substream_id: u8,
    /// Configured sample rate in Hz on this endpoint.
    pub sample_rate: u32,
    /// Number of interleaved channels.
    pub channels: u8,
    /// Whether the endpoint is actively streaming (`TRIGGER_START`).
    pub active: bool,
}

impl AloopSubstream {
    /// Create a new loopback substream endpoint configuration.
    pub const fn new(cable_id: u8, substream_id: u8, sample_rate: u32, channels: u8) -> Self {
        Self {
            cable_id,
            substream_id,
            sample_rate,
            channels,
            active: false,
        }
    }
}

/// Full-duplex playback-to-capture virtual loopback cable with fractional clock-drift compensation
/// and automatic silence injection when no playback producer is running.
#[derive(Debug, Clone)]
pub struct AudioLoopbackBridge {
    /// Playback producer substream descriptor.
    pub playback: AloopSubstream,
    /// Capture consumer substream descriptor.
    pub capture: AloopSubstream,
    /// Circular FIFO storage of interleaved `i16` samples (`capacity_frames * channels`).
    fifo: Vec<i16>,
    /// Capacity of the FIFO in multi-channel frames.
    capacity_frames: usize,
    /// Read index in frames (`0..capacity_frames`).
    read_frame_pos: usize,
    /// Write index in frames (`0..capacity_frames`).
    write_frame_pos: usize,
    /// Number of valid frames currently buffered in the FIFO.
    queued_frames: usize,
    /// Fractional resampling phase in Q16 (`0..65536`) for clock-drift compensation.
    resample_phase_q16: u32,
    /// Nominal step ratio `(playback_rate / capture_rate)` in Q16.16 adjusted by clock drift ppm.
    step_ratio_q16: u32,
    /// Last frame read from the FIFO, used for click-free linear interpolation across block boundaries.
    last_frame: [i16; 2],
    /// Cumulative number of zero-filled silence frames injected when the producer was inactive or empty.
    pub silence_frames_injected: u64,
}

impl AudioLoopbackBridge {
    /// Construct a full-duplex loopback bridge linking a playback substream to a capture substream.
    pub fn new(
        cable_id: u8,
        substream_id: u8,
        sample_rate: u32,
        channels: u8,
        capacity_frames: usize,
    ) -> Self {
        let safe_channels = channels.clamp(1, 2);
        let safe_cap = capacity_frames.max(16);
        Self {
            playback: AloopSubstream::new(cable_id, substream_id, sample_rate, safe_channels),
            capture: AloopSubstream::new(cable_id, substream_id, sample_rate, safe_channels),
            fifo: vec![0i16; safe_cap * (safe_channels as usize)],
            capacity_frames: safe_cap,
            read_frame_pos: 0,
            write_frame_pos: 0,
            queued_frames: 0,
            resample_phase_q16: 0,
            step_ratio_q16: 1 << 16,
            last_frame: [0i16; 2],
            silence_frames_injected: 0,
        }
    }

    /// Start or stop the playback producer substream.
    pub fn set_producer_active(&mut self, active: bool) {
        self.playback.active = active;
    }

    /// Start or stop the capture consumer substream.
    pub fn set_consumer_active(&mut self, active: bool) {
        self.capture.active = active;
    }

    /// Configure the relative clock drift between the playback producer clock and capture consumer clock
    /// in parts-per-million (`drift_ppm`, e.g., `+500` ppm means producer runs 0.05% faster than consumer).
    pub fn set_clock_drift_ppm(&mut self, drift_ppm: i32) {
        let base_q16 = if self.capture.sample_rate == 0 {
            1u64 << 16
        } else {
            ((self.playback.sample_rate as u64) << 16) / (self.capture.sample_rate as u64)
        };
        let clamped_ppm = drift_ppm.clamp(-100_000, 100_000) as i64;
        let delta = ((base_q16 as i64) * clamped_ppm) / 1_000_000;
        self.step_ratio_q16 = ((base_q16 as i64) + delta).max(1024) as u32;
    }

    /// Number of unread frames currently queued in the loopback FIFO.
    #[inline]
    pub const fn queued_frames(&self) -> usize {
        self.queued_frames
    }

    /// Push interleaved playback frames from the producer into the loopback FIFO.
    /// Returns the number of frames accepted.
    pub fn push_playback_frames(&mut self, frames_in: &[i16]) -> usize {
        if !self.playback.active {
            self.playback.active = true;
        }
        let ch = self.playback.channels as usize;
        let incoming = frames_in.len() / ch;
        let free = self.capacity_frames.saturating_sub(self.queued_frames);
        let count = incoming.min(free);

        for idx in 0..count {
            let dst_base = self.write_frame_pos * ch;
            let src_base = idx * ch;
            self.fifo[dst_base..dst_base + ch].copy_from_slice(&frames_in[src_base..src_base + ch]);
            self.write_frame_pos = (self.write_frame_pos + 1) % self.capacity_frames;
        }
        self.queued_frames += count;
        count
    }

    /// Pop a single raw frame from the FIFO without resampling, or return `None` if empty.
    fn pop_raw_frame(&mut self) -> Option<[i16; 2]> {
        if self.queued_frames == 0 {
            return None;
        }
        let ch = self.playback.channels as usize;
        let base = self.read_frame_pos * ch;
        let left = self.fifo[base];
        let right = if ch > 1 { self.fifo[base + 1] } else { left };
        self.read_frame_pos = (self.read_frame_pos + 1) % self.capacity_frames;
        self.queued_frames -= 1;
        self.last_frame = [left, right];
        Some([left, right])
    }

    /// Peek at the next unread frame in the FIFO without advancing `read_frame_pos`.
    fn peek_next_frame(&self) -> Option<[i16; 2]> {
        if self.queued_frames == 0 {
            return None;
        }
        let ch = self.playback.channels as usize;
        let base = self.read_frame_pos * ch;
        let left = self.fifo[base];
        let right = if ch > 1 { self.fifo[base + 1] } else { left };
        Some([left, right])
    }

    /// Pull `out_capture.len() / channels` frames into `out_capture` on behalf of the capture consumer.
    ///
    /// - When the producer is inactive (`!playback.active`) or the ring buffer is empty,
    ///   automatically injects zero-filled silence frames so the capture clock never stalls.
    /// - When active, applies fractional Q16 linear interpolation to compensate for clock drift.
    pub fn pull_capture_frames(&mut self, out_capture: &mut [i16]) -> usize {
        let ch = self.capture.channels as usize;
        let requested_frames = out_capture.len() / ch;

        for frame_idx in 0..requested_frames {
            let dst_base = frame_idx * ch;

            if !self.playback.active || self.queued_frames == 0 {
                // Inject zero-fill silence when no producer is active or FIFO is dry.
                for c in 0..ch {
                    out_capture[dst_base + c] = 0;
                }
                self.silence_frames_injected = self.silence_frames_injected.saturating_add(1);
                continue;
            }

            // Advance integer frames according to the accumulated Q16 phase.
            while self.resample_phase_q16 >= (1 << 16) {
                self.resample_phase_q16 -= 1 << 16;
                if self.pop_raw_frame().is_none() {
                    break;
                }
            }

            let frac_q16 = (self.resample_phase_q16 & 0xFFFF) as i64;
            let next_frame = self.peek_next_frame().unwrap_or(self.last_frame);

            for c in 0..ch {
                let prev_val = self.last_frame[c] as i64;
                let next_val = next_frame[c] as i64;
                let interp = prev_val + (((next_val - prev_val) * frac_q16) >> 16);
                out_capture[dst_base + c] = interp.clamp(-32_767, 32_767) as i16;
            }

            self.resample_phase_q16 = self.resample_phase_q16.wrapping_add(self.step_ratio_q16);
        }

        requested_frames
    }
}
