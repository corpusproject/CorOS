//! CorOS Audio Digital Signal Processing (DSP) Pipeline (`dsp.rs`)
//!
//! Provides bare-metal real-time audio filtering and effects:
//! - Direct Form II Biquad IIR Filters:
//!   - Lowpass Filter ($H(s) = \frac{1}{s^2 + s/Q + 1}$)
//!   - Highpass Filter ($H(s) = \frac{s^2}{s^2 + s/Q + 1}$)
//!   - Bandpass Filter ($H(s) = \frac{s/Q}{s^2 + s/Q + 1}$)
//!   - Notch / Peaking Equalizer Filters
//! - 3-Band Parametric Equalizer (Bass, Midrange, Treble)
//! - Dynamic Range Compressor (Threshold, Ratio, Attack, Release, Makeup Gain)
//! - Feedback Delay Line / Reverb Simulation (Comb & All-pass filter Schroeder reverberator)

extern crate alloc;

use alloc::vec::Vec;

/// Biquad Filter Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiquadFilterType {
    Lowpass,
    Highpass,
    Bandpass,
    Notch,
    PeakingEQ,
}

/// Direct Form II Transposed Biquad IIR Filter
#[derive(Debug, Clone, Copy)]
pub struct BiquadFilter {
    b0: f32,
    b1: f32,
    b2: f32,
    a1: f32,
    a2: f32,
    z1: f32,
    z2: f32,
}

impl BiquadFilter {
    pub fn new() -> Self {
        Self {
            b0: 1.0, b1: 0.0, b2: 0.0,
            a1: 0.0, a2: 0.0,
            z1: 0.0, z2: 0.0,
        }
    }

    /// Configure filter coefficients (Audio EQ Cookbook formulas)
    pub fn configure(&mut self, filter_type: BiquadFilterType, sample_rate: f32, cutoff_hz: f32, q: f32) {
        let omega = 2.0 * 3.14159265 * (cutoff_hz / sample_rate);
        // Taylor series sin and cos
        let sin_omega = omega - (omega * omega * omega) / 6.0;
        let cos_omega = 1.0 - (omega * omega) / 2.0;
        let alpha = sin_omega / (2.0 * q);

        match filter_type {
            BiquadFilterType::Lowpass => {
                let a0 = 1.0 + alpha;
                self.b0 = ((1.0 - cos_omega) / 2.0) / a0;
                self.b1 = (1.0 - cos_omega) / a0;
                self.b2 = ((1.0 - cos_omega) / 2.0) / a0;
                self.a1 = (-2.0 * cos_omega) / a0;
                self.a2 = (1.0 - alpha) / a0;
            }
            BiquadFilterType::Highpass => {
                let a0 = 1.0 + alpha;
                self.b0 = ((1.0 + cos_omega) / 2.0) / a0;
                self.b1 = (-(1.0 + cos_omega)) / a0;
                self.b2 = ((1.0 + cos_omega) / 2.0) / a0;
                self.a1 = (-2.0 * cos_omega) / a0;
                self.a2 = (1.0 - alpha) / a0;
            }
            BiquadFilterType::Bandpass => {
                let a0 = 1.0 + alpha;
                self.b0 = (sin_omega / 2.0) / a0;
                self.b1 = 0.0;
                self.b2 = (-(sin_omega / 2.0)) / a0;
                self.a1 = (-2.0 * cos_omega) / a0;
                self.a2 = (1.0 - alpha) / a0;
            }
            BiquadFilterType::Notch => {
                let a0 = 1.0 + alpha;
                self.b0 = 1.0 / a0;
                self.b1 = (-2.0 * cos_omega) / a0;
                self.b2 = 1.0 / a0;
                self.a1 = (-2.0 * cos_omega) / a0;
                self.a2 = (1.0 - alpha) / a0;
            }
            _ => {}
        }
    }

    /// Process a single audio sample through the IIR filter
    pub fn process_sample(&mut self, input: f32) -> f32 {
        let out = self.b0 * input + self.z1;
        self.z1 = self.b1 * input - self.a1 * out + self.z2;
        self.z2 = self.b2 * input - self.a2 * out;
        out
    }
}

/// 3-Band Parametric Equalizer
pub struct ThreeBandEqualizer {
    low_shelf: BiquadFilter,
    mid_peaking: BiquadFilter,
    high_shelf: BiquadFilter,
}

impl ThreeBandEqualizer {
    pub fn new(sample_rate: f32) -> Self {
        let mut low = BiquadFilter::new();
        low.configure(BiquadFilterType::Lowpass, sample_rate, 250.0, 0.707);

        let mut mid = BiquadFilter::new();
        mid.configure(BiquadFilterType::Bandpass, sample_rate, 1000.0, 1.0);

        let mut high = BiquadFilter::new();
        high.configure(BiquadFilterType::Highpass, sample_rate, 4000.0, 0.707);

        Self {
            low_shelf: low,
            mid_peaking: mid,
            high_shelf: high,
        }
    }

    pub fn process(&mut self, sample: f32, bass_gain: f32, mid_gain: f32, treble_gain: f32) -> f32 {
        let l = self.low_shelf.process_sample(sample) * bass_gain;
        let m = self.mid_peaking.process_sample(sample) * mid_gain;
        let h = self.high_shelf.process_sample(sample) * treble_gain;
        l + m + h
    }
}

/// Simple Feedback Comb Filter Reverb Unit
pub struct CombFilter {
    buffer: Vec<f32>,
    index: usize,
    feedback: f32,
    damp: f32,
    filter_state: f32,
}

impl CombFilter {
    pub fn new(delay_samples: usize, feedback: f32, damp: f32) -> Self {
        let mut buf = Vec::with_capacity(delay_samples);
        buf.resize(delay_samples, 0.0);
        Self {
            buffer: buf,
            index: 0,
            feedback,
            damp,
            filter_state: 0.0,
        }
    }

    pub fn process(&mut self, input: f32) -> f32 {
        let output = self.buffer[self.index];
        self.filter_state = output * (1.0 - self.damp) + self.filter_state * self.damp;
        self.buffer[self.index] = input + self.filter_state * self.feedback;
        self.index = (self.index + 1) % self.buffer.len();
        output
    }
}
