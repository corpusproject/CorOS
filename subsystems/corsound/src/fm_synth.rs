//! 4-Operator FM (Frequency Modulation) phase-accumulator synthesizer featuring an
//! ADSR envelope generator, quarter-wave sine lookup table with linear interpolation,
//! 4 classic DX routing algorithms, and MIDI note-to-phase-increment conversion.

/// Quarter-wave sine lookup table (65 entries covering `[0 .. pi/2]`, scaled to Q15 `0..=32767`).
const QUARTER_SINE_Q15: [i16; 65] = [
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

/// Twelve-tone equal-temperament frequencies for MIDI octave 9 (notes `108..=119`, C8..=B8)
/// scaled in centi-Hertz (`Hz * 100`) for exact integer phase-increment derivation across all octaves.
const MIDI_TOP_OCTAVE_CENTI_HZ: [u32; 12] = [
    418_601, // C8  (4186.01 Hz)
    443_492, // C#8 (4434.92 Hz)
    469_864, // D8  (4698.64 Hz)
    497_803, // D#8 (4978.03 Hz)
    527_404, // E8  (5274.04 Hz)
    558_765, // F8  (5587.65 Hz)
    591_991, // F#8 (5919.91 Hz)
    627_193, // G8  (6271.93 Hz)
    664_488, // G#8 (6644.88 Hz)
    704_000, // A8  (7040.00 Hz, exact multiple of A4 = 440 Hz)
    745_862, // A#8 (7458.62 Hz)
    790_213, // B8  (7902.13 Hz)
];

/// Evaluate a full-period sine wave from a 32-bit unsigned phase angle (`0 ..= u32::MAX`)
/// using symmetry reflection and 8-bit fractional linear interpolation over `QUARTER_SINE_Q15`.
/// Returns a signed Q15 amplitude in `-32767 ..= +32767`.
#[inline]
pub fn lookup_sine_interpolated(phase: u32) -> i16 {
    // Top 2 bits select the quadrant (0..3).
    // Next 6 bits select the quarter-wave table index (0..63).
    // Next 8 bits provide the fractional interpolation weight (0..255).
    let quadrant = (phase >> 30) & 0x03;
    let raw_pos = (phase >> 16) & 0x3FFF; // 14-bit position within quadrant

    let mapped_pos = if (quadrant & 1) != 0 {
        0x4000 - raw_pos
    } else {
        raw_pos
    };

    let idx = (mapped_pos >> 8) as usize;
    let frac = (mapped_pos & 0xFF) as i32;

    let magnitude = if idx >= 64 {
        QUARTER_SINE_Q15[64] as i32
    } else {
        let low = QUARTER_SINE_Q15[idx] as i32;
        let high = QUARTER_SINE_Q15[idx + 1] as i32;
        low + (((high - low) * frac) >> 8)
    };

    if (quadrant & 2) != 0 {
        -(magnitude as i16)
    } else {
        magnitude as i16
    }
}

/// Convert a MIDI note number (`0..=127`, where `69 == A4 == 440 Hz`) and sample rate (Hz)
/// into a 32-bit phase accumulator increment per sample.
pub fn midi_note_to_phase_increment(midi_note: u8, sample_rate: u32) -> u32 {
    if sample_rate == 0 {
        return 0;
    }
    let clamped = midi_note.min(127);
    let semitone = (clamped % 12) as usize;
    let octave = (clamped / 12) as i32;

    let top_centi_hz = MIDI_TOP_OCTAVE_CENTI_HZ[semitone] as u64;
    // Note 108..=119 is octave == 9.
    let octave_shift = 9 - octave;
    let num = top_centi_hz << 32;
    let denom = (sample_rate as u64) * 100;
    let top_inc = num / denom;

    if octave_shift >= 0 {
        (top_inc >> (octave_shift as u32)) as u32
    } else {
        (top_inc << ((-octave_shift) as u32)) as u32
    }
}

/// Stage of an ADSR (Attack, Decay, Sustain, Release) envelope generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdsrStage {
    /// Voice is silent.
    Idle,
    /// Linearly ramping up toward full-scale (`0x7FFF_FFFF`).
    Attack,
    /// Ramping down from peak toward the sustain plateau.
    Decay,
    /// Holding at the sustain level while key remains depressed.
    Sustain,
    /// Ramping down toward zero after key-off.
    Release,
}

/// Fixed-point 31-bit ADSR envelope generator producing Q15 output (`0..=32767`).
#[derive(Debug, Clone, Copy)]
pub struct AdsrEnvelope {
    /// Current envelope stage.
    pub stage: AdsrStage,
    /// Internal envelope level in Q30 (`0 ..= 0x4000_0000`).
    level_q30: u32,
    /// Increment per sample during Attack stage (Q30).
    pub attack_step_q30: u32,
    /// Decrement per sample during Decay stage (Q30).
    pub decay_step_q30: u32,
    /// Sustain plateau level in Q30 (`0 ..= 0x4000_0000`).
    pub sustain_level_q30: u32,
    /// Decrement per sample during Release stage (Q30).
    pub release_step_q30: u32,
}

impl AdsrEnvelope {
    /// Maximum internal envelope value in Q30 (`1.0`).
    pub const MAX_LEVEL_Q30: u32 = 0x4000_0000;

    /// Construct an ADSR envelope from per-stage sample rates and a Q15 sustain level (`0..=32767`).
    pub const fn new(
        attack_samples: u32,
        decay_samples: u32,
        sustain_q15: u16,
        release_samples: u32,
    ) -> Self {
        let clamped_sustain = if sustain_q15 > 32767 {
            32767u32
        } else {
            sustain_q15 as u32
        };
        let sustain_level_q30 = clamped_sustain << 15;
        let attack_step_q30 = if attack_samples == 0 {
            Self::MAX_LEVEL_Q30
        } else {
            Self::MAX_LEVEL_Q30 / attack_samples
        };
        let decay_span = Self::MAX_LEVEL_Q30.saturating_sub(sustain_level_q30);
        let decay_step_q30 = if decay_samples == 0 {
            decay_span
        } else {
            decay_span / decay_samples
        };
        let release_step_q30 = if release_samples == 0 {
            Self::MAX_LEVEL_Q30
        } else {
            sustain_level_q30 / release_samples
        };

        Self {
            stage: AdsrStage::Idle,
            level_q30: 0,
            attack_step_q30: if attack_step_q30 == 0 { 1 } else { attack_step_q30 },
            decay_step_q30: if decay_step_q30 == 0 { 1 } else { decay_step_q30 },
            sustain_level_q30,
            release_step_q30: if release_step_q30 == 0 { 1 } else { release_step_q30 },
        }
    }

    /// Trigger key-on (starts the Attack phase).
    pub fn note_on(&mut self) {
        self.stage = AdsrStage::Attack;
    }

    /// Trigger key-off (transitions to the Release phase).
    pub fn note_off(&mut self) {
        if self.stage != AdsrStage::Idle {
            self.stage = AdsrStage::Release;
        }
    }

    /// Advance the envelope by one sample and return the current Q15 amplitude (`0..=32767`).
    pub fn next_sample_q15(&mut self) -> u16 {
        match self.stage {
            AdsrStage::Idle => {
                self.level_q30 = 0;
            }
            AdsrStage::Attack => {
                let next = self.level_q30.saturating_add(self.attack_step_q30);
                if next >= Self::MAX_LEVEL_Q30 {
                    self.level_q30 = Self::MAX_LEVEL_Q30;
                    self.stage = AdsrStage::Decay;
                } else {
                    self.level_q30 = next;
                }
            }
            AdsrStage::Decay => {
                if self.level_q30 <= self.sustain_level_q30 + self.decay_step_q30 {
                    self.level_q30 = self.sustain_level_q30;
                    self.stage = AdsrStage::Sustain;
                } else {
                    self.level_q30 -= self.decay_step_q30;
                }
            }
            AdsrStage::Sustain => {
                self.level_q30 = self.sustain_level_q30;
            }
            AdsrStage::Release => {
                if self.level_q30 <= self.release_step_q30 {
                    self.level_q30 = 0;
                    self.stage = AdsrStage::Idle;
                } else {
                    self.level_q30 -= self.release_step_q30;
                }
            }
        }
        (self.level_q30 >> 15).min(32_767) as u16
    }
}

/// Single FM oscillator operator with harmonic ratio, feedback, and ADSR envelope.
#[derive(Debug, Clone, Copy)]
pub struct FmOperator {
    /// 32-bit phase accumulator.
    pub phase: u32,
    /// Base phase increment before frequency ratio multiplication.
    pub base_phase_inc: u32,
    /// Frequency multiplier in Q8.8 (`256 == 1.0x` fundamental, `512 == 2.0x` second harmonic).
    pub freq_ratio_q8_8: u16,
    /// Operator output level / modulation index in Q15 (`0..=32767`).
    pub output_level_q15: u16,
    /// Self-feedback shift (`0` = disabled, `1..=7` = feedback depth).
    pub feedback_shift: u8,
    /// Previous output sample for self-feedback calculation.
    prev_out: i16,
    /// Dedicated ADSR envelope for this operator.
    pub envelope: AdsrEnvelope,
}

impl FmOperator {
    /// Construct a new FM operator with the given frequency ratio (Q8.8), output level (Q15), and envelope.
    pub const fn new(freq_ratio_q8_8: u16, output_level_q15: u16, envelope: AdsrEnvelope) -> Self {
        Self {
            phase: 0,
            base_phase_inc: 0,
            freq_ratio_q8_8,
            output_level_q15,
            feedback_shift: 0,
            prev_out: 0,
            envelope,
        }
    }

    /// Compute the next operator sample given an external phase modulation offset (`mod_input` in Q15).
    pub fn tick(&mut self, mod_input: i32) -> i16 {
        let env_q15 = self.envelope.next_sample_q15() as i32;
        if env_q15 == 0 {
            self.prev_out = 0;
            return 0;
        }

        let fb_offset = if self.feedback_shift > 0 && self.feedback_shift <= 12 {
            (self.prev_out as i32) << (16 - self.feedback_shift)
        } else {
            0
        };

        // External modulation shifts the 32-bit phase angle (full Q15 swing == +/- 2*pi radians).
        let phase_mod = (mod_input << 15) as u32;
        let effective_phase = self
            .phase
            .wrapping_add(phase_mod)
            .wrapping_add(fb_offset as u32);

        let raw_sine = lookup_sine_interpolated(effective_phase) as i32;
        let step_inc = ((self.base_phase_inc as u64 * self.freq_ratio_q8_8 as u64) >> 8) as u32;
        self.phase = self.phase.wrapping_add(step_inc);

        let env_scaled = (raw_sine * env_q15) >> 15;
        let out = ((env_scaled * self.output_level_q15 as i32) >> 15).clamp(-32_767, 32_767) as i16;
        self.prev_out = out;
        out
    }
}

/// Classic 4-operator DX FM routing topologies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxAlgorithm {
    /// Serial cascade: `Op4 -> Op3 -> Op2 -> Op1` (Brassy/reed lead).
    SerialCascade,
    /// Dual-modulator stack: `(Op4 + Op3) -> Op2 -> Op1` (Rich acoustic piano / warm strings).
    DualModStack,
    /// Two parallel 2-operator pairs: `(Op2 -> Op1) + (Op4 -> Op3)` (Chorus electric piano / bells).
    ParallelPairs,
    /// Pure additive 4 carriers: `Op1 + Op2 + Op3 + Op4` (Drawbar organ).
    FourCarriersAdditive,
}

/// 4-Operator FM Synthesizer voice.
#[derive(Debug, Clone)]
pub struct FmSynthVoice {
    /// Active DX routing algorithm.
    pub algorithm: DxAlgorithm,
    /// Four operators (`[Op1, Op2, Op3, Op4]`).
    pub operators: [FmOperator; 4],
    /// Output sample rate in Hz.
    pub sample_rate: u32,
}

impl FmSynthVoice {
    /// Construct a 4-operator FM voice with default harmonic ratios (`1x, 2x, 3x, 4x`).
    pub fn new(sample_rate: u32, algorithm: DxAlgorithm) -> Self {
        let default_env = AdsrEnvelope::new(64, 256, 24_576, 512);
        Self {
            algorithm,
            operators: [
                FmOperator::new(256, 32_767, default_env),
                FmOperator::new(512, 20_000, default_env),
                FmOperator::new(768, 16_000, default_env),
                FmOperator::new(1024, 12_000, default_env),
            ],
            sample_rate,
        }
    }

    /// Trigger a MIDI note on all 4 operators.
    pub fn note_on(&mut self, midi_note: u8) {
        let base_inc = midi_note_to_phase_increment(midi_note, self.sample_rate);
        for op in self.operators.iter_mut() {
            op.base_phase_inc = base_inc;
            op.phase = 0;
            op.envelope.note_on();
        }
    }

    /// Release the currently playing note on all 4 operators.
    pub fn note_off(&mut self) {
        for op in self.operators.iter_mut() {
            op.envelope.note_off();
        }
    }

    /// Synthesize the next mono `i16` sample according to the active `DxAlgorithm`.
    pub fn render_sample(&mut self) -> i16 {
        let [op_first, op_second, op_third, op_fourth] = &mut self.operators;
        match self.algorithm {
            DxAlgorithm::SerialCascade => {
                let out_fourth = op_fourth.tick(0) as i32;
                let out_third = op_third.tick(out_fourth) as i32;
                let out_second = op_second.tick(out_third) as i32;
                op_first.tick(out_second)
            }
            DxAlgorithm::DualModStack => {
                let out_fourth = op_fourth.tick(0) as i32;
                let out_third = op_third.tick(0) as i32;
                let out_second = op_second.tick((out_fourth + out_third) >> 1) as i32;
                op_first.tick(out_second)
            }
            DxAlgorithm::ParallelPairs => {
                let out_fourth = op_fourth.tick(0) as i32;
                let carrier_upper = op_third.tick(out_fourth) as i32;
                let out_second = op_second.tick(0) as i32;
                let carrier_lower = op_first.tick(out_second) as i32;
                ((carrier_upper + carrier_lower) >> 1).clamp(-32_767, 32_767) as i16
            }
            DxAlgorithm::FourCarriersAdditive => {
                let c_fourth = op_fourth.tick(0) as i32;
                let c_third = op_third.tick(0) as i32;
                let c_second = op_second.tick(0) as i32;
                let c_first = op_first.tick(0) as i32;
                ((c_first + c_second + c_third + c_fourth) >> 2).clamp(-32_767, 32_767) as i16
            }
        }
    }
}
