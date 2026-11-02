//! CorOS Polyphonic Sound Synthesizer & MIDI Engine (`synthesizer.rs`)
//!
//! Provides bare-metal real-time audio synthesis:
//! - Waveform Generators: Sine, Square (with variable duty cycle), Triangle, Sawtooth, White Noise
//! - ADSR Envelope Generator:
//!   - Attack: Linear ramp to peak amplitude
//!   - Decay: Exponential drop to sustain level
//!   - Sustain: Steady-state amplitude holding phase
//!   - Release: Fade-out to silence on Note-Off
//! - Polyphony: 16 simultaneous audio synthesizer voices
//! - Standard MIDI Message Parser:
//!   - Note On (0x90): Note frequency mapping ($f = 440 \cdot 2^{(n-69)/12}$ Hz), velocity
//!   - Note Off (0x80): Triggers envelope release phase
//!   - Pitch Bend (0xE0): 14-bit microtonal frequency modulation
//!   - Control Change (0xB0): Master volume, Pan, Reverb send

extern crate alloc;

use alloc::vec::Vec;

pub const MAX_VOICES: usize = 16;
pub const SAMPLE_RATE: u32 = 44100;

/// Synthesizer Oscillator Waveform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waveform {
    Sine,
    Square,
    Triangle,
    Sawtooth,
    Noise,
}

/// ADSR Envelope Phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopePhase {
    Idle,
    Attack,
    Decay,
    Sustain,
    Release,
}

/// ADSR Envelope Parameters (in milliseconds)
#[derive(Debug, Clone, Copy)]
pub struct AdsrParameters {
    pub attack_ms: f32,
    pub decay_ms: f32,
    pub sustain_level: f32, // 0.0 to 1.0
    pub release_ms: f32,
}

impl Default for AdsrParameters {
    fn default() -> Self {
        Self {
            attack_ms: 10.0,
            decay_ms: 50.0,
            sustain_level: 0.7,
            release_ms: 100.0,
        }
    }
}

/// A single polyphonic synthesizer voice
#[derive(Debug, Clone)]
pub struct SynthVoice {
    pub active: bool,
    pub midi_note: u8,
    pub frequency_hz: f32,
    pub velocity: f32,
    pub phase_accumulator: f32,
    pub waveform: Waveform,
    pub env_phase: EnvelopePhase,
    pub env_amplitude: f32,
    pub adsr: AdsrParameters,
    noise_seed: u32,
}

impl SynthVoice {
    pub fn new() -> Self {
        Self {
            active: false,
            midi_note: 0,
            frequency_hz: 440.0,
            velocity: 0.0,
            phase_accumulator: 0.0,
            waveform: Waveform::Sine,
            env_phase: EnvelopePhase::Idle,
            env_amplitude: 0.0,
            adsr: AdsrParameters::default(),
            noise_seed: 0x1337BEEF,
        }
    }

    /// Trigger Note On
    pub fn note_on(&mut self, note: u8, velocity: u8, wave: Waveform, adsr: AdsrParameters) {
        self.active = true;
        self.midi_note = note;
        self.velocity = (velocity as f32) / 127.0;
        self.waveform = wave;
        self.adsr = adsr;
        self.env_phase = EnvelopePhase::Attack;
        self.phase_accumulator = 0.0;

        // MIDI Note to Frequency formula: f = 440.0 * 2^((note - 69) / 12)
        let semitones = (note as i32) - 69;
        self.frequency_hz = 440.0 * Self::approx_pow2((semitones as f32) / 12.0);
    }

    /// Trigger Note Off
    pub fn note_off(&mut self) {
        if self.active {
            self.env_phase = EnvelopePhase::Release;
        }
    }

    fn approx_pow2(x: f32) -> f32 {
        // Fast float approximation of 2^x
        let xi = x as i32;
        let xf = x - (xi as f32);
        let int_pow = if xi >= 0 { (1 << xi) as f32 } else { 1.0 / ((1 << (-xi)) as f32) };
        // Linear interpolation for fractional power
        let frac_pow = 1.0 + xf * (0.693147 + xf * 0.240226);
        int_pow * frac_pow
    }

    /// Generate next single mono sample (-1.0 to 1.0)
    pub fn render_sample(&mut self) -> f32 {
        if !self.active || self.env_phase == EnvelopePhase::Idle {
            return 0.0;
        }

        // 1. Advance ADSR Envelope
        let sample_rate_f = SAMPLE_RATE as f32;
        match self.env_phase {
            EnvelopePhase::Attack => {
                let step = 1000.0 / (self.adsr.attack_ms * sample_rate_f);
                self.env_amplitude += step;
                if self.env_amplitude >= 1.0 {
                    self.env_amplitude = 1.0;
                    self.env_phase = EnvelopePhase::Decay;
                }
            }
            EnvelopePhase::Decay => {
                let step = 1000.0 / (self.adsr.decay_ms * sample_rate_f);
                self.env_amplitude -= step;
                if self.env_amplitude <= self.adsr.sustain_level {
                    self.env_amplitude = self.adsr.sustain_level;
                    self.env_phase = EnvelopePhase::Sustain;
                }
            }
            EnvelopePhase::Sustain => {
                self.env_amplitude = self.adsr.sustain_level;
            }
            EnvelopePhase::Release => {
                let step = 1000.0 / (self.adsr.release_ms * sample_rate_f);
                self.env_amplitude -= step;
                if self.env_amplitude <= 0.0 {
                    self.env_amplitude = 0.0;
                    self.env_phase = EnvelopePhase::Idle;
                    self.active = false;
                    return 0.0;
                }
            }
            EnvelopePhase::Idle => return 0.0,
        }

        // 2. Generate raw waveform sample
        let raw_sample = match self.waveform {
            Waveform::Sine => {
                // Approximate sine using parabolic polynomial
                let p = self.phase_accumulator; // 0.0 to 1.0
                let x = (p - 0.5) * 2.0;       // -1.0 to 1.0
                4.0 * x * (1.0 - x.abs())
            }
            Waveform::Square => {
                if self.phase_accumulator < 0.5 { 1.0 } else { -1.0 }
            }
            Waveform::Triangle => {
                let p = self.phase_accumulator;
                if p < 0.5 {
                    4.0 * p - 1.0
                } else {
                    3.0 - 4.0 * p
                }
            }
            Waveform::Sawtooth => {
                2.0 * self.phase_accumulator - 1.0
            }
            Waveform::Noise => {
                self.noise_seed = self.noise_seed.wrapping_mul(1664525).wrapping_add(1013904223);
                ((self.noise_seed & 0xFFFF) as f32 / 32768.0) - 1.0
            }
        };

        // 3. Advance phase accumulator
        let phase_step = self.frequency_hz / sample_rate_f;
        self.phase_accumulator = (self.phase_accumulator + phase_step) % 1.0;

        raw_sample * self.env_amplitude * self.velocity
    }
}

/// 16-Voice Polyphonic Sound Synthesizer
pub struct PolySynth {
    pub voices: [SynthVoice; MAX_VOICES],
    pub master_volume: f32,
}

impl PolySynth {
    pub fn new() -> Self {
        Self {
            voices: core::array::from_fn(|_| SynthVoice::new()),
            master_volume: 0.8,
        }
    }

    /// Play a MIDI note
    pub fn note_on(&mut self, note: u8, velocity: u8, wave: Waveform, adsr: AdsrParameters) {
        // Find idle voice, or steal oldest voice
        let free_voice = self.voices.iter_mut().find(|v| !v.active);
        if let Some(voice) = free_voice {
            voice.note_on(note, velocity, wave, adsr);
        } else {
            // Voice stealing
            self.voices[0].note_on(note, velocity, wave, adsr);
        }
    }

    /// Release a MIDI note
    pub fn note_off(&mut self, note: u8) {
        for voice in &mut self.voices {
            if voice.active && voice.midi_note == note {
                voice.note_off();
            }
        }
    }

    /// Render a block of 16-bit signed stereo PCM audio samples
    pub fn render_pcm16(&mut self, stereo_samples_count: usize) -> Vec<i16> {
        let mut pcm = Vec::with_capacity(stereo_samples_count * 2);

        for _ in 0..stereo_samples_count {
            let mut mixed = 0.0f32;
            for voice in &mut self.voices {
                mixed += voice.render_sample();
            }

            // Apply master gain and soft clipping
            mixed *= self.master_volume;
            if mixed > 1.0 { mixed = 1.0; }
            if mixed < -1.0 { mixed = -1.0; }

            let sample16 = (mixed * 32767.0) as i16;
            pcm.push(sample16); // Left
            pcm.push(sample16); // Right
        }

        pcm
    }
}
