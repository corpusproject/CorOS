//! CorOS Unified Sound & Audio Bridge (`sound_bridge.rs`)
//!
//! Bridges:
//! - `corsound::pcm_ringbuf::PcmRingBuffer` (ALSA/PipeWire circular PCM ring buffer)
//! - `corsound::multi_mixer::PolyphonicMixer` (16-channel polyphonic software mixer)
//! - `cordrivers::universal_device::Ac97AudioAdapter` (Bare-metal AC'97 hardware driver)

extern crate alloc;

use crate::sync::SpinLock;
use cordrivers::traits::AudioDeviceDriver;
use cordrivers::universal_device::Ac97AudioAdapter;
use corsound::multi_mixer::{PolyphonicMixer, MAX_MIXER_CHANNELS};
use corsound::pcm_ringbuf::{PcmError, PcmRingBuffer, PcmStreamState};

/// Diagnostic statistics from the unified sound subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SoundBridgeStats {
    pub is_initialized: bool,
    pub stream_state: Option<PcmStreamState>,
    pub master_gain_q8_8: u16,
    pub peak_left: u16,
    pub peak_right: u16,
    pub soft_clip_events: u32,
    pub queued_frames: usize,
    pub free_frames: usize,
}

pub struct SoundBridge {
    pcm_buffer: SpinLock<Option<PcmRingBuffer>>,
    mixer: SpinLock<PolyphonicMixer>,
    ac97_adapter: SpinLock<Option<Ac97AudioAdapter>>,
    is_active: SpinLock<bool>,
}

unsafe impl Send for SoundBridge {}
unsafe impl Sync for SoundBridge {}

impl SoundBridge {
    pub const fn uninit() -> Self {
        Self {
            pcm_buffer: SpinLock::new(None),
            mixer: SpinLock::new(PolyphonicMixer::new()),
            ac97_adapter: SpinLock::new(None),
            is_active: SpinLock::new(false),
        }
    }

    /// Initializes ALSA PCM ring buffer, 16-channel software mixer, and AC'97 driver adapter.
    pub fn initialize(&self) {
        let mut pcm = self.pcm_buffer.lock_irqsave();
        if pcm.is_none() {
            // Stereo, 512 frames per period, 4 periods = 2048 frames total buffer
            if let Ok(buf) = PcmRingBuffer::new(2, 512, 4) {
                *pcm = Some(buf);
            }
        }
        drop(pcm);

        let mut ac97 = self.ac97_adapter.lock_irqsave();
        if ac97.is_none() {
            let mut adapter = Ac97AudioAdapter::new("ac97-0");
            let _ = adapter.start_stream(2, 48000, 16);
            *ac97 = Some(adapter);
        }
        drop(ac97);

        let mut active = self.is_active.lock_irqsave();
        *active = true;
    }

    /// Writes interleaved signed 16-bit PCM frames into the ALSA ring buffer and AC'97 hardware buffer.
    pub fn write_pcm_samples(&self, samples: &[i16]) -> Result<usize, PcmError> {
        self.initialize();

        let mut pcm_guard = self.pcm_buffer.lock_irqsave();
        let written = if let Some(ref mut pcm) = *pcm_guard {
            pcm.write_interleaved(samples)?
        } else {
            return Err(PcmError::BadState);
        };
        drop(pcm_guard);

        // Forward to hardware adapter
        let mut ac97_guard = self.ac97_adapter.lock_irqsave();
        if let Some(ref mut ac97) = *ac97_guard {
            let _ = ac97.write_pcm_frames(samples);
        }

        Ok(written)
    }

    /// Consumes a hardware period of frames from the ALSA ring buffer for DMA output.
    pub fn read_hardware_period(&self, out: &mut [i16]) -> Result<usize, PcmError> {
        let mut pcm_guard = self.pcm_buffer.lock_irqsave();
        if let Some(ref mut pcm) = *pcm_guard {
            pcm.consume_hardware_period(out)
        } else {
            Err(PcmError::BadState)
        }
    }

    /// Mixes a single time-frame of up to 16 input mono channels into a stereo `(left, right)` pair.
    pub fn mix_channel_frame(&self, inputs: &[i16; MAX_MIXER_CHANNELS]) -> (i16, i16) {
        let mut mixer = self.mixer.lock_irqsave();
        mixer.mix_frame(inputs)
    }

    /// Mixes channel blocks into an interleaved stereo destination slice.
    pub fn mix_block(
        &self,
        channel_buffers: &[&[i16]; MAX_MIXER_CHANNELS],
        out_stereo_interleaved: &mut [i16],
    ) -> usize {
        let mut mixer = self.mixer.lock_irqsave();
        mixer.mix_block(channel_buffers, out_stereo_interleaved)
    }

    /// Sets linear gain (Q8.8) for an individual input channel strip (0..15).
    pub fn set_channel_gain(&self, channel: usize, gain_q8_8: u16) {
        if channel < MAX_MIXER_CHANNELS {
            let mut mixer = self.mixer.lock_irqsave();
            mixer.channels[channel].gain_q8_8 = gain_q8_8;
        }
    }

    /// Sets stereo pan position (-64 = Left, 0 = Center, +64 = Right) for a channel strip.
    pub fn set_channel_pan(&self, channel: usize, pan: i8) {
        if channel < MAX_MIXER_CHANNELS {
            let mut mixer = self.mixer.lock_irqsave();
            mixer.channels[channel].pan = pan;
        }
    }

    /// Sets master stereo bus gain (Q8.8, 256 = 1.0x unity gain) and updates AC'97 hardware volume.
    pub fn set_master_gain(&self, gain_q8_8: u16) {
        let mut mixer = self.mixer.lock_irqsave();
        mixer.master_gain_q8_8 = gain_q8_8;
        drop(mixer);

        // Convert Q8.8 gain to dB attenuation (0 to -128 dB)
        let gain_db = if gain_q8_8 >= 256 {
            0i8
        } else if gain_q8_8 == 0 {
            -128i8
        } else {
            // Rough log approximation: dB ~ 20 * log10(gain/256)
            let ratio = (gain_q8_8 as i32 * 100) / 256;
            let db = ((ratio - 100) * 60) / 100;
            db.clamp(-128, 0) as i8
        };

        let mut ac97_guard = self.ac97_adapter.lock_irqsave();
        if let Some(ref mut ac97) = *ac97_guard {
            ac97.set_master_volume(gain_db);
        }
    }

    /// Returns the current peak levels `(left, right)` from the master meter.
    pub fn peak_levels(&self) -> (u16, u16) {
        let mixer = self.mixer.lock_irqsave();
        (mixer.meter.peak_left, mixer.meter.peak_right)
    }

    /// Returns the current operational state of the PCM ring buffer.
    pub fn stream_state(&self) -> PcmStreamState {
        let pcm = self.pcm_buffer.lock_irqsave();
        if let Some(ref p) = *pcm {
            p.state()
        } else {
            PcmStreamState::Stopped
        }
    }

    /// Collects full diagnostic statistics of the sound bridge.
    pub fn stats(&self) -> SoundBridgeStats {
        let active = *self.is_active.lock_irqsave();
        let pcm = self.pcm_buffer.lock_irqsave();
        let mixer = self.mixer.lock_irqsave();

        let (stream_state, queued, free) = if let Some(ref p) = *pcm {
            (Some(p.state()), p.queued_frames(), p.avail_playback_frames())
        } else {
            (None, 0, 0)
        };

        SoundBridgeStats {
            is_initialized: active,
            stream_state,
            master_gain_q8_8: mixer.master_gain_q8_8,
            peak_left: mixer.meter.peak_left,
            peak_right: mixer.meter.peak_right,
            soft_clip_events: mixer.meter.soft_clip_events,
            queued_frames: queued,
            free_frames: free,
        }
    }
}

pub static GLOBAL_SOUND_BRIDGE: SoundBridge = SoundBridge::uninit();
