//! Fixed-point Q16.16 Direct-Form I Biquad IIR filter (`BiquadCoeffs`, `BiquadState`,
//! Low-Pass, High-Pass, Band-Pass, Notch, and Peaking EQ filter stages) and 5-band Master
//! Parametric Equalizer cascade.

use crate::fm_synth::lookup_sine_interpolated;

/// Unity scale factor for signed Q16.16 fixed-point arithmetic (`1.0 == 65_536`).
pub const Q16_ONE: i32 = 1 << 16;

/// Normalized Direct-Form I biquad transfer function coefficients in signed Q16.16 fixed-point:
///
/// $$y[n] = b_{\text{zero}} x[n] + b_{\text{one}} x[n-1] + b_{\text{two}} x[n-2]
///        - a_{\text{one}} y[n-1] - a_{\text{two}} y[n-2]$$
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiquadCoeffs {
    /// Feedforward tap for $x[n]$ in Q16.16.
    pub b_zero: i32,
    /// Feedforward tap for $x[n-1]$ in Q16.16.
    pub b_one: i32,
    /// Feedforward tap for $x[n-2]$ in Q16.16.
    pub b_two: i32,
    /// Feedback tap for $y[n-1]$ in Q16.16 (normalized by $a_{\text{zero}}$).
    pub a_one: i32,
    /// Feedback tap for $y[n-2]$ in Q16.16 (normalized by $a_{\text{zero}}$).
    pub a_two: i32,
}

/// Evaluate $(\sin \omega, \cos \omega)$ in Q16.16 for `cutoff_hz` at `sample_rate`.
fn trig_omega_q16(cutoff_hz: u32, sample_rate: u32) -> (i64, i64) {
    if sample_rate == 0 {
        return (0, Q16_ONE as i64);
    }
    let clamped_fc = cutoff_hz.min(sample_rate / 2);
    // Map [0 .. sample_rate] to 32-bit full circle phase.
    let phase = (((clamped_fc as u64) << 32) / (sample_rate as u64)) as u32;
    let quarter_turn: u32 = 0x4000_0000; // pi / 2
    let sin_q15 = lookup_sine_interpolated(phase) as i64;
    let cos_q15 = lookup_sine_interpolated(phase.wrapping_add(quarter_turn)) as i64;
    // Convert Q15 (-32767..32767) to Q16.16 (-65536..65536).
    (sin_q15 << 1, cos_q15 << 1)
}

/// Normalize raw unscaled Q16.16 coefficients by dividing by `a_zero_q16`.
fn normalize_biquad_q16(
    b_zero_q16: i64,
    b_one_q16: i64,
    b_two_q16: i64,
    a_zero_q16: i64,
    a_one_q16: i64,
    a_two_q16: i64,
) -> BiquadCoeffs {
    let denom = if a_zero_q16 == 0 { Q16_ONE as i64 } else { a_zero_q16 };
    BiquadCoeffs {
        b_zero: (((b_zero_q16 << 16) / denom) as i32),
        b_one: (((b_one_q16 << 16) / denom) as i32),
        b_two: (((b_two_q16 << 16) / denom) as i32),
        a_one: (((a_one_q16 << 16) / denom) as i32),
        a_two: (((a_two_q16 << 16) / denom) as i32),
    }
}

impl BiquadCoeffs {
    /// Unity bypass filter ($y[n] = x[n]$).
    pub const fn passthrough() -> Self {
        Self {
            b_zero: Q16_ONE,
            b_one: 0,
            b_two: 0,
            a_one: 0,
            a_two: 0,
        }
    }

    /// Design a 2nd-order Audio EQ Cookbook Low-Pass filter (`q_q8` is quality factor $Q$ in Q8.8, e.g. `181 == 0.707`).
    pub fn low_pass(cutoff_hz: u32, sample_rate: u32, q_q8: u16) -> Self {
        let (sin_w, cos_w) = trig_omega_q16(cutoff_hz, sample_rate);
        let safe_q = (q_q8.max(32)) as i64;
        // alpha = sin(w0) / (2 * Q)
        let alpha = (sin_w << 8) / (2 * safe_q);
        let one_minus_cos = (Q16_ONE as i64) - cos_w;

        let b_zero = one_minus_cos >> 1;
        let b_one = one_minus_cos;
        let b_two = one_minus_cos >> 1;
        let a_zero = (Q16_ONE as i64) + alpha;
        let a_one = -2 * cos_w;
        let a_two = (Q16_ONE as i64) - alpha;

        normalize_biquad_q16(b_zero, b_one, b_two, a_zero, a_one, a_two)
    }

    /// Design a 2nd-order Audio EQ Cookbook High-Pass filter (`q_q8` in Q8.8).
    pub fn high_pass(cutoff_hz: u32, sample_rate: u32, q_q8: u16) -> Self {
        let (sin_w, cos_w) = trig_omega_q16(cutoff_hz, sample_rate);
        let safe_q = (q_q8.max(32)) as i64;
        let alpha = (sin_w << 8) / (2 * safe_q);
        let one_plus_cos = (Q16_ONE as i64) + cos_w;

        let b_zero = one_plus_cos >> 1;
        let b_one = -one_plus_cos;
        let b_two = one_plus_cos >> 1;
        let a_zero = (Q16_ONE as i64) + alpha;
        let a_one = -2 * cos_w;
        let a_two = (Q16_ONE as i64) - alpha;

        normalize_biquad_q16(b_zero, b_one, b_two, a_zero, a_one, a_two)
    }

    /// Design a 2nd-order constant-0-dB-peak Band-Pass filter (`q_q8` in Q8.8).
    pub fn band_pass(center_hz: u32, sample_rate: u32, q_q8: u16) -> Self {
        let (sin_w, cos_w) = trig_omega_q16(center_hz, sample_rate);
        let safe_q = (q_q8.max(32)) as i64;
        let alpha = (sin_w << 8) / (2 * safe_q);

        let b_zero = alpha;
        let b_one = 0;
        let b_two = -alpha;
        let a_zero = (Q16_ONE as i64) + alpha;
        let a_one = -2 * cos_w;
        let a_two = (Q16_ONE as i64) - alpha;

        normalize_biquad_q16(b_zero, b_one, b_two, a_zero, a_one, a_two)
    }

    /// Design a 2nd-order band-reject Notch filter (`q_q8` in Q8.8).
    pub fn notch(center_hz: u32, sample_rate: u32, q_q8: u16) -> Self {
        let (sin_w, cos_w) = trig_omega_q16(center_hz, sample_rate);
        let safe_q = (q_q8.max(32)) as i64;
        let alpha = (sin_w << 8) / (2 * safe_q);

        let b_zero = Q16_ONE as i64;
        let b_one = -2 * cos_w;
        let b_two = Q16_ONE as i64;
        let a_zero = (Q16_ONE as i64) + alpha;
        let a_one = -2 * cos_w;
        let a_two = (Q16_ONE as i64) - alpha;

        normalize_biquad_q16(b_zero, b_one, b_two, a_zero, a_one, a_two)
    }

    /// Design a 2nd-order Peaking EQ bell filter (`amp_q8` is $\sqrt{10^{\text{dB}/20}}$ in Q8.8, where `256 == 0 dB`).
    pub fn peaking_eq(center_hz: u32, sample_rate: u32, q_q8: u16, amp_q8: u16) -> Self {
        let (sin_w, cos_w) = trig_omega_q16(center_hz, sample_rate);
        let safe_q = (q_q8.max(32)) as i64;
        let safe_amp = (amp_q8.max(32)) as i64;
        let alpha = (sin_w << 8) / (2 * safe_q);

        let alpha_times_a = (alpha * safe_amp) >> 8;
        let alpha_div_a = (alpha << 8) / safe_amp;

        let b_zero = (Q16_ONE as i64) + alpha_times_a;
        let b_one = -2 * cos_w;
        let b_two = (Q16_ONE as i64) - alpha_times_a;
        let a_zero = (Q16_ONE as i64) + alpha_div_a;
        let a_one = -2 * cos_w;
        let a_two = (Q16_ONE as i64) - alpha_div_a;

        normalize_biquad_q16(b_zero, b_one, b_two, a_zero, a_one, a_two)
    }
}

/// Delay-line state and coefficients for a single Direct-Form I Biquad IIR filter section.
#[derive(Debug, Clone, Copy)]
pub struct BiquadState {
    /// Active Q16.16 transfer function coefficients.
    pub coeffs: BiquadCoeffs,
    /// Previous input sample $x[n-1]$.
    prev_x_first: i32,
    /// Two-step delayed input sample $x[n-2]$.
    prev_x_second: i32,
    /// Previous output sample $y[n-1]$.
    prev_y_first: i32,
    /// Two-step delayed output sample $y[n-2]$.
    prev_y_second: i32,
}

impl BiquadState {
    /// Create a zero-state biquad filter section with the specified coefficients.
    pub const fn new(coeffs: BiquadCoeffs) -> Self {
        Self {
            coeffs,
            prev_x_first: 0,
            prev_x_second: 0,
            prev_y_first: 0,
            prev_y_second: 0,
        }
    }

    /// Clear unit-delay state registers without altering filter coefficients.
    pub fn reset(&mut self) {
        self.prev_x_first = 0;
        self.prev_x_second = 0;
        self.prev_y_first = 0;
        self.prev_y_second = 0;
    }

    /// Process a single signed 16-bit audio sample through the Direct-Form I difference equation.
    #[inline]
    pub fn process_sample(&mut self, input: i16) -> i16 {
        let x_now = input as i64;
        let acc = (self.coeffs.b_zero as i64) * x_now
            + (self.coeffs.b_one as i64) * (self.prev_x_first as i64)
            + (self.coeffs.b_two as i64) * (self.prev_x_second as i64)
            - (self.coeffs.a_one as i64) * (self.prev_y_first as i64)
            - (self.coeffs.a_two as i64) * (self.prev_y_second as i64);

        // Round to nearest Q16.16 integer and clamp to i16 range to prevent limit-cycle overflow.
        let y_now = ((acc + (1 << 15)) >> 16).clamp(-32_767, 32_767) as i32;

        self.prev_x_second = self.prev_x_first;
        self.prev_x_first = input as i32;
        self.prev_y_second = self.prev_y_first;
        self.prev_y_first = y_now;

        y_now as i16
    }

    /// Filter an entire mono buffer in place.
    pub fn process_block_in_place(&mut self, samples: &mut [i16]) {
        for sample in samples.iter_mut() {
            *sample = self.process_sample(*sample);
        }
    }
}

/// 5-Band Master Parametric Equalizer cascading five Direct-Form I Biquad sections in series.
#[derive(Debug, Clone)]
pub struct MasterParametricEq {
    /// Five cascaded biquad bands: Sub-Bass (60 Hz), Low-Mid (250 Hz), Presence (1000 Hz),
    /// Upper-Mid (4000 Hz), and Air/Brilliance (12000 Hz).
    pub bands: [BiquadState; 5],
    /// Master bypass switch.
    pub bypassed: bool,
}

impl MasterParametricEq {
    /// Construct a 5-band parametric EQ configured for `sample_rate` with flat initial response (`256 == 0 dB`).
    pub fn new(sample_rate: u32) -> Self {
        let default_q = 181; // Q ~= 0.707
        Self {
            bands: [
                BiquadState::new(BiquadCoeffs::peaking_eq(60, sample_rate, default_q, 256)),
                BiquadState::new(BiquadCoeffs::peaking_eq(250, sample_rate, default_q, 256)),
                BiquadState::new(BiquadCoeffs::peaking_eq(1_000, sample_rate, default_q, 256)),
                BiquadState::new(BiquadCoeffs::peaking_eq(4_000, sample_rate, default_q, 256)),
                BiquadState::new(BiquadCoeffs::peaking_eq(12_000, sample_rate, default_q, 256)),
            ],
            bypassed: false,
        }
    }

    /// Reconfigure a specific band (`0..5`) with custom `BiquadCoeffs`.
    pub fn set_band_coeffs(&mut self, band_idx: usize, coeffs: BiquadCoeffs) {
        if let Some(band) = self.bands.get_mut(band_idx) {
            band.coeffs = coeffs;
        }
    }

    /// Process a single mono `i16` sample through all 5 cascaded biquad sections.
    #[inline]
    pub fn process_sample(&mut self, input: i16) -> i16 {
        if self.bypassed {
            return input;
        }
        let mut stage_val = input;
        for band in self.bands.iter_mut() {
            stage_val = band.process_sample(stage_val);
        }
        stage_val
    }
}
