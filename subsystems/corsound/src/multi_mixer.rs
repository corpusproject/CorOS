//! 16-channel polyphonic software audio mixer with per-channel Q8.8 linear gain,
//! constant-power stereo panpot law, solo/mute group routing, master peak meter,
//! and soft-clipping cubic/rational saturator.

/// Total number of hardware/software input strips supported by the polyphonic mixer.
pub const MAX_MIXER_CHANNELS: usize = 16;

/// Quarter-circle sine lookup table (65 entries for pan positions `0..=64`, scaled in Q15 `0..=32767`)
/// used to evaluate constant-power stereo panning ($\cos(\theta)$ and $\sin(\theta)$).
const CONSTANT_POWER_PAN_LUT_Q15: [u16; 65] = [
    0, 804, 1608, 2411, 3212, 4011, 4808, 5602,
    6393, 7180, 7962, 8740, 9512, 10279, 11039, 11793,
    12540, 13279, 14010, 14733, 15447, 16151, 16846, 17531,
    18205, 18868, 19520, 20160, 20788, 21403, 22006, 22595,
    23170, 23732, 24279, 24812, 25330, 25833, 26320, 26791,
    27246, 27684, 28106, 28511, 28899, 29269, 29622, 29957,
    30274, 30572, 30853, 31114, 31357, 31581, 31786, 31972,
    32138, 32286, 32413, 32522, 32610, 32679, 32729, 32758,
    32767,
];

/// Compute constant-power stereo gain pair `(left_q15, right_q15)` for pan position `pan` in `-64..=64`.
/// At center (`pan == 0`), both left and right equal `23170 / 32767` ($\approx 0.7071$, i.e. -3 dB),
/// so $L^2 + R^2 \approx 1.0$ across the entire stereo field.
#[inline]
pub fn constant_power_pan_gains(pan: i8) -> (i32, i32) {
    let clamped = pan.clamp(-64, 64) as i32;
    // Map -64..=64 into index 0..=64 by shifting and halving with linear interpolation on odd steps.
    let shifted = (clamped + 64) as usize; // 0..=128
    let base_idx = shifted >> 1;
    let rem = shifted & 1;

    let right_q15 = if rem == 0 || base_idx >= 64 {
        CONSTANT_POWER_PAN_LUT_Q15[base_idx] as i32
    } else {
        let low = CONSTANT_POWER_PAN_LUT_Q15[base_idx] as i32;
        let high = CONSTANT_POWER_PAN_LUT_Q15[base_idx + 1] as i32;
        (low + high) >> 1
    };

    let rev_shifted = 128 - shifted;
    let rev_idx = rev_shifted >> 1;
    let rev_rem = rev_shifted & 1;
    let left_q15 = if rev_rem == 0 || rev_idx >= 64 {
        CONSTANT_POWER_PAN_LUT_Q15[rev_idx] as i32
    } else {
        let low = CONSTANT_POWER_PAN_LUT_Q15[rev_idx] as i32;
        let high = CONSTANT_POWER_PAN_LUT_Q15[rev_idx + 1] as i32;
        (low + high) >> 1
    };

    (left_q15, right_q15)
}

/// Soft-clipping saturator mapping an wide-dynamic-range accumulator sample (`i32`)
/// into signed 16-bit full-scale (`-32767 ..= 32767`) with smooth knee saturation
/// above $\pm 24576$ (75% full-scale) using a Padé-style rational curve.
#[inline]
pub fn soft_clip_saturate_s16(sample: i32) -> i16 {
    const KNEE: i64 = 24_576;
    const HEADROOM: i64 = 8_191; // 32767 - 24576
    let val = sample as i64;
    let abs_val = val.abs();
    if abs_val <= KNEE {
        return sample as i16;
    }
    let excess = abs_val - KNEE;
    // Rational saturation: KNEE + HEADROOM * excess / (excess + HEADROOM)
    let compressed = KNEE + (HEADROOM * excess) / (excess + HEADROOM);
    let clamped = compressed.min(32_767) as i16;
    if val < 0 {
        -clamped
    } else {
        clamped
    }
}

/// Individual strip in the 16-channel polyphonic mixer.
#[derive(Debug, Clone, Copy)]
pub struct MixerChannel {
    /// Linear gain in unsigned Q8.8 fixed-point (`256 == 1.0x` unity gain, `512 == 2.0x`).
    pub gain_q8_8: u16,
    /// Constant-power stereo panpot position (`-64` = hard left, `0` = center, `+64` = hard right).
    pub pan: i8,
    /// Channel mute switch.
    pub muted: bool,
    /// Channel solo switch.
    pub solo: bool,
    /// Routing group mask (bitfield for subgroup busses).
    pub group_mask: u8,
    /// Peak absolute level observed on this strip during the last mixed block.
    pub peak_level: u16,
}

impl MixerChannel {
    /// Construct a default unity-gain, center-panned unmuted mixer channel.
    pub const fn new() -> Self {
        Self {
            gain_q8_8: 256,
            pan: 0,
            muted: false,
            solo: false,
            group_mask: 0x01,
            peak_level: 0,
        }
    }

    /// Return whether this channel is audible given whether any channel in the console has `solo` enabled
    /// and the active group mute mask.
    #[inline]
    pub const fn is_audible(&self, any_solo_active: bool, muted_groups_mask: u8) -> bool {
        if (self.group_mask & muted_groups_mask) != 0 {
            return false;
        }
        if any_solo_active {
            self.solo && !self.muted
        } else {
            !self.muted
        }
    }
}

impl Default for MixerChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Stereo master peak meter tracking instantaneous peak and decaying hold values.
#[derive(Debug, Clone, Copy, Default)]
pub struct MasterPeakMeter {
    /// Left channel peak sample magnitude (`0..=32767`).
    pub peak_left: u16,
    /// Right channel peak sample magnitude (`0..=32767`).
    pub peak_right: u16,
    /// Count of samples that triggered the soft-clipping knee region.
    pub soft_clip_events: u32,
}

impl MasterPeakMeter {
    /// Reset peak hold readings to zero.
    pub fn reset(&mut self) {
        self.peak_left = 0;
        self.peak_right = 0;
        self.soft_clip_events = 0;
    }

    /// Apply linear ballistics decay to the peak hold registers between audio blocks.
    pub fn decay(&mut self, decay_step: u16) {
        self.peak_left = self.peak_left.saturating_sub(decay_step);
        self.peak_right = self.peak_right.saturating_sub(decay_step);
    }
}

/// 16-channel polyphonic software audio mixer.
#[derive(Debug, Clone)]
pub struct PolyphonicMixer {
    /// Input channel strips (`0..16`).
    pub channels: [MixerChannel; MAX_MIXER_CHANNELS],
    /// Master stereo bus gain in Q8.8 (`256 == 1.0x`).
    pub master_gain_q8_8: u16,
    /// Bitmask of muted routing groups.
    pub muted_groups_mask: u8,
    /// Master stereo peak meter.
    pub meter: MasterPeakMeter,
}

impl PolyphonicMixer {
    /// Create a 16-channel mixer with unity gain on all strips and master bus.
    pub const fn new() -> Self {
        Self {
            channels: [MixerChannel::new(); MAX_MIXER_CHANNELS],
            master_gain_q8_8: 256,
            muted_groups_mask: 0,
            meter: MasterPeakMeter {
                peak_left: 0,
                peak_right: 0,
                soft_clip_events: 0,
            },
        }
    }

    /// Check if at least one channel currently has `solo` enabled.
    pub fn any_solo_enabled(&self) -> bool {
        let mut idx = 0;
        while idx < MAX_MIXER_CHANNELS {
            if self.channels[idx].solo {
                return true;
            }
            idx += 1;
        }
        false
    }

    /// Mix a single time-frame of up to 16 mono `i16` channel inputs into a stereo `(left, right)` output pair.
    pub fn mix_frame(&mut self, inputs: &[i16; MAX_MIXER_CHANNELS]) -> (i16, i16) {
        let any_solo = self.any_solo_enabled();
        let mut accum_left: i64 = 0;
        let mut accum_right: i64 = 0;

        for ch_idx in 0..MAX_MIXER_CHANNELS {
            let strip = &mut self.channels[ch_idx];
            let raw_in = inputs[ch_idx] as i32;
            let abs_in = raw_in.unsigned_abs().min(32_767) as u16;
            if abs_in > strip.peak_level {
                strip.peak_level = abs_in;
            }

            if !strip.is_audible(any_solo, self.muted_groups_mask) || raw_in == 0 {
                continue;
            }

            // Apply per-channel Q8.8 gain.
            let gained = (raw_in as i64 * strip.gain_q8_8 as i64) >> 8;

            // Apply constant-power stereo panpot law (Q15).
            let (pan_left_q15, pan_right_q15) = constant_power_pan_gains(strip.pan);
            accum_left += (gained * pan_left_q15 as i64) >> 15;
            accum_right += (gained * pan_right_q15 as i64) >> 15;
        }

        // Apply master Q8.8 gain.
        let master_left = ((accum_left * self.master_gain_q8_8 as i64) >> 8) as i32;
        let master_right = ((accum_right * self.master_gain_q8_8 as i64) >> 8) as i32;

        if master_left.abs() > 24_576 || master_right.abs() > 24_576 {
            self.meter.soft_clip_events = self.meter.soft_clip_events.saturating_add(1);
        }

        let out_left = soft_clip_saturate_s16(master_left);
        let out_right = soft_clip_saturate_s16(master_right);

        let left_mag = (out_left as i32).unsigned_abs() as u16;
        let right_mag = (out_right as i32).unsigned_abs() as u16;
        if left_mag > self.meter.peak_left {
            self.meter.peak_left = left_mag;
        }
        if right_mag > self.meter.peak_right {
            self.meter.peak_right = right_mag;
        }

        (out_left, out_right)
    }

    /// Mix a block of mono channel buffers into an interleaved stereo output buffer (`[L, R, L, R, ...]`).
    pub fn mix_block(
        &mut self,
        channel_buffers: &[&[i16]; MAX_MIXER_CHANNELS],
        out_stereo_interleaved: &mut [i16],
    ) -> usize {
        let frames = out_stereo_interleaved.len() / 2;
        for frame_idx in 0..frames {
            let mut frame_inputs = [0i16; MAX_MIXER_CHANNELS];
            for ch_idx in 0..MAX_MIXER_CHANNELS {
                if let Some(&sample) = channel_buffers[ch_idx].get(frame_idx) {
                    frame_inputs[ch_idx] = sample;
                }
            }
            let (left, right) = self.mix_frame(&frame_inputs);
            out_stereo_interleaved[frame_idx * 2] = left;
            out_stereo_interleaved[frame_idx * 2 + 1] = right;
        }
        frames
    }
}

impl Default for PolyphonicMixer {
    fn default() -> Self {
        Self::new()
    }
}
