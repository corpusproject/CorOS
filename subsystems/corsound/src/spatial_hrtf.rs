//! 3D positional stereo audio processor implementing Woodworth-Schlosberg spherical-head
//! Interaural Time Difference (`ITD` fractional delay line per azimuth angle `-90..=+90` degrees),
//! Interaural Level Difference (`ILD` head-shadow attenuation), and distance inverse-square attenuation.

use crate::fm_synth::lookup_sine_interpolated;

/// Maximum delay line capacity in samples per ear (64 samples covers >1.3 ms at 48 kHz, well above the ~660 us human ITD limit).
pub const HRTF_DELAY_BUFFER_LEN: usize = 64;

/// Evaluate $\sin(|\theta|)$ in Q15 (`0..=32767`) for an azimuth magnitude `abs_azimuth_deg` in `0..=90`.
#[inline]
fn sin_azimuth_q15(abs_azimuth_deg: u8) -> i32 {
    let clamped = abs_azimuth_deg.min(90) as u64;
    // 90 degrees corresponds to 1/4 of a 32-bit phase circle (0x4000_0000).
    let phase = ((clamped * 0x4000_0000) / 90) as u32;
    lookup_sine_interpolated(phase) as i32
}

/// Compute the Woodworth-Schlosberg Interaural Time Difference (`ITD`) in Q8.8 fractional samples
/// for a sound source at `azimuth_deg` (`-90..=+90` degrees) and `sample_rate` Hz.
///
/// For a standard human head radius $a \approx 0.0875\text{ m}$ and speed of sound $c \approx 343\text{ m/s}$,
/// the maximum interaural delay at $\pm 90^\circ$ is $\tau_{\max} \approx 655\ \mu\text{s}$ ($\approx 31.4$ samples at 48 kHz).
pub fn compute_itd_fractional_samples_q8(azimuth_deg: i8, sample_rate: u32) -> (u16, u16) {
    let clamped = azimuth_deg.clamp(-90, 90);
    let abs_deg = clamped.unsigned_abs();
    let sin_q15 = sin_azimuth_q15(abs_deg) as u64;

    // Max delay in Q8.8 samples = (sample_rate * 655 * 256) / 1_000_000.
    let max_delay_q8 = ((sample_rate as u64) * 655 * 256) / 1_000_000;
    let delay_q8 = ((max_delay_q8 * sin_q15) >> 15).min(((HRTF_DELAY_BUFFER_LEN - 2) * 256) as u64) as u16;

    if clamped > 0 {
        // Source is to the right (+azimuth): right ear is ipsilateral (0 delay), left ear is contralateral (delayed).
        (delay_q8, 0)
    } else if clamped < 0 {
        // Source is to the left (-azimuth): left ear is ipsilateral (0 delay), right ear is contralateral (delayed).
        (0, delay_q8)
    } else {
        (0, 0)
    }
}

/// Compute Interaural Level Difference (`ILD`) head-shadow gains `(left_gain_q15, right_gain_q15)`
/// for a sound source at `azimuth_deg` (`-90..=+90` degrees).
/// The shadowed contralateral ear is attenuated up to -9.5 dB (`~0.33x` amplitude) at $\pm 90^\circ$.
pub fn compute_ild_gains_q15(azimuth_deg: i8) -> (i32, i32) {
    let clamped = azimuth_deg.clamp(-90, 90);
    let abs_deg = clamped.unsigned_abs();
    let sin_q15 = sin_azimuth_q15(abs_deg);

    // Shadowed ear attenuates smoothly from 32767 (0 deg) down to 32767 - 21845 = 10922 (90 deg).
    let shadow_attenuation = (sin_q15 * 21_845) >> 15;
    let contralateral_gain = 32_767 - shadow_attenuation;
    let ipsilateral_gain = 32_767;

    if clamped > 0 {
        // Right side source: left ear is shadowed, right ear is direct.
        (contralateral_gain, ipsilateral_gain)
    } else if clamped < 0 {
        // Left side source: left ear is direct, right ear is shadowed.
        (ipsilateral_gain, contralateral_gain)
    } else {
        (32_767, 32_767)
    }
}

/// Compute inverse-square distance attenuation gain in Q15 (`0..=32767`) relative to a reference
/// distance `ref_distance_cm` (clamped at 1.0x inside the reference sphere).
#[inline]
pub fn compute_distance_attenuation_q15(distance_cm: u32, ref_distance_cm: u32) -> i32 {
    let safe_ref = ref_distance_cm.max(1) as u64;
    let safe_dist = (distance_cm as u64).max(safe_ref);
    let ref_sq = safe_ref * safe_ref;
    let dist_sq = safe_dist * safe_dist;
    (((ref_sq << 15) / dist_sq).min(32_767)) as i32
}

/// Circular fractional delay line using 8-bit linear interpolation between adjacent samples.
#[derive(Debug, Clone)]
pub struct FractionalDelayLine {
    /// Circular sample buffer of length `HRTF_DELAY_BUFFER_LEN`.
    buffer: [i16; HRTF_DELAY_BUFFER_LEN],
    /// Current write cursor (`0..HRTF_DELAY_BUFFER_LEN`).
    write_pos: usize,
}

impl FractionalDelayLine {
    /// Create a zeroed fractional delay line.
    pub const fn new() -> Self {
        Self {
            buffer: [0i16; HRTF_DELAY_BUFFER_LEN],
            write_pos: 0,
        }
    }

    /// Push a new input sample and read back a delayed sample at `delay_q8` (`Q8.8` samples).
    pub fn push_and_read(&mut self, input: i16, delay_q8: u16) -> i16 {
        self.buffer[self.write_pos] = input;

        let int_delay = ((delay_q8 >> 8) as usize).min(HRTF_DELAY_BUFFER_LEN - 2);
        let frac = (delay_q8 & 0xFF) as i32;

        let idx_near = (self.write_pos + HRTF_DELAY_BUFFER_LEN - int_delay) % HRTF_DELAY_BUFFER_LEN;
        let idx_far = (idx_near + HRTF_DELAY_BUFFER_LEN - 1) % HRTF_DELAY_BUFFER_LEN;

        let sample_near = self.buffer[idx_near] as i32;
        let sample_far = self.buffer[idx_far] as i32;

        self.write_pos = (self.write_pos + 1) % HRTF_DELAY_BUFFER_LEN;

        let interpolated = sample_near + (((sample_far - sample_near) * frac) >> 8);
        interpolated.clamp(-32_767, 32_767) as i16
    }
}

impl Default for FractionalDelayLine {
    fn default() -> Self {
        Self::new()
    }
}

/// 3D Binaural Spatializer combining ITD fractional delay lines, ILD head-shadowing,
/// and inverse-square distance attenuation.
#[derive(Debug, Clone)]
pub struct SpatialHrtfProcessor {
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Source azimuth angle in degrees (`-90` = hard left, `0` = center ahead, `+90` = hard right).
    pub azimuth_deg: i8,
    /// Source distance from listener in centimeters.
    pub distance_cm: u32,
    /// Reference unity-gain distance in centimeters (typically `100` cm = 1 meter).
    pub ref_distance_cm: u32,
    /// Left ear fractional ITD delay line.
    left_delay: FractionalDelayLine,
    /// Right ear fractional ITD delay line.
    right_delay: FractionalDelayLine,
}

impl SpatialHrtfProcessor {
    /// Construct a 3D spatial audio processor for `sample_rate` Hz.
    pub const fn new(sample_rate: u32, azimuth_deg: i8, distance_cm: u32, ref_distance_cm: u32) -> Self {
        Self {
            sample_rate,
            azimuth_deg,
            distance_cm,
            ref_distance_cm,
            left_delay: FractionalDelayLine::new(),
            right_delay: FractionalDelayLine::new(),
        }
    }

    /// Spatialize a single mono `i16` sample into a binaural `(left, right)` stereo frame.
    pub fn process_mono_frame(&mut self, mono_input: i16) -> (i16, i16) {
        let dist_gain_q15 = compute_distance_attenuation_q15(self.distance_cm, self.ref_distance_cm);
        let dist_scaled = ((mono_input as i32 * dist_gain_q15) >> 15) as i16;

        let (left_delay_q8, right_delay_q8) =
            compute_itd_fractional_samples_q8(self.azimuth_deg, self.sample_rate);
        let delayed_left = self.left_delay.push_and_read(dist_scaled, left_delay_q8) as i32;
        let delayed_right = self.right_delay.push_and_read(dist_scaled, right_delay_q8) as i32;

        let (ild_left_q15, ild_right_q15) = compute_ild_gains_q15(self.azimuth_deg);
        let out_left = ((delayed_left * ild_left_q15) >> 15).clamp(-32_767, 32_767) as i16;
        let out_right = ((delayed_right * ild_right_q15) >> 15).clamp(-32_767, 32_767) as i16;

        (out_left, out_right)
    }

    /// Spatialize a block of mono samples into an interleaved stereo slice (`[L, R, L, R, ...]`).
    pub fn process_block(&mut self, mono_in: &[i16], stereo_out: &mut [i16]) -> usize {
        let count = mono_in.len().min(stereo_out.len() / 2);
        for idx in 0..count {
            let (left, right) = self.process_mono_frame(mono_in[idx]);
            stereo_out[idx * 2] = left;
            stereo_out[idx * 2 + 1] = right;
        }
        count
    }
}
