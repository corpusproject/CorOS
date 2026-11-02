//! CorOS Hardware Driver Module: `ac97_audio`
//!
//! Intel ICH AC'97 Rev 2.3 Native Audio Mixer (`NAM` BAR0 I/O ports) and
//! Native Audio Bus Master (`NABM` BAR1 I/O ports), 8-byte Buffer Descriptor List
//! entry (`Ac97BdlEntry`), Master/PCM dB attenuator encoder, Variable Rate Audio (`VRA`)
//! sample rate configuration, and linear 16-bit stereo sample rate interpolator.

/// AC'97 Native Audio Mixer (`NAM`, BAR0) 16-bit register offsets.
pub mod ac97_nam_regs {
    pub const RESET: u16 = 0x00;
    pub const MASTER_VOLUME: u16 = 0x02;
    pub const HEADPHONE_VOLUME: u16 = 0x04;
    pub const MASTER_VOLUME_MONO: u16 = 0x06;
    pub const PC_BEEP: u16 = 0x0A;
    pub const PCM_OUT_VOLUME: u16 = 0x18;
    pub const RECORD_SELECT: u16 = 0x1A;
    pub const RECORD_GAIN: u16 = 0x1C;
    pub const EXTENDED_AUDIO_ID: u16 = 0x28;
    pub const EXTENDED_AUDIO_CTRL_STAT: u16 = 0x2A;
    pub const PCM_FRONT_DAC_RATE: u16 = 0x2C;
    pub const PCM_SURROUND_DAC_RATE: u16 = 0x2E;
    pub const PCM_LFE_DAC_RATE: u16 = 0x30;
    pub const PCM_LR_ADC_RATE: u16 = 0x32;
    pub const VENDOR_ID1: u16 = 0x7C;
    pub const VENDOR_ID2: u16 = 0x7E;
}

/// AC'97 Native Audio Bus Master (`NABM`, BAR1) register offsets for PCM Out (`PO_`, base `0x10`).
pub mod ac97_nabm_regs {
    /// PCM Out Buffer Descriptor List Base Address (32-bit physical address).
    pub const PO_BDBAR: u16 = 0x10;
    /// PCM Out Current Index Value (8-bit, read-only `0..=31`).
    pub const PO_CIV: u16 = 0x14;
    /// PCM Out Last Valid Index (8-bit, read/write `0..=31`).
    pub const PO_LVI: u16 = 0x15;
    /// PCM Out Status Register (16-bit).
    pub const PO_SR: u16 = 0x16;
    /// PCM Out Position in Current Buffer (16-bit sample count).
    pub const PO_PICB: u16 = 0x18;
    /// PCM Out Prefetched Index Value (8-bit).
    pub const PO_PIV: u16 = 0x1A;
    /// PCM Out Control Register (8-bit).
    pub const PO_CR: u16 = 0x1B;
    /// Global Control Register (32-bit).
    pub const GLOB_CNT: u16 = 0x2C;
    /// Global Status Register (32-bit).
    pub const GLOB_STA: u16 = 0x30;
}

/// `PO_CR` (PCM Out Control Register) bitflags.
pub mod ac97_po_cr {
    /// Run/Pause Bus Master (`1 = Run`, `0 = Pause`).
    pub const RPBM: u8 = 1 << 0;
    /// Reset Registers (`RR`).
    pub const RR: u8 = 1 << 1;
    /// Last Valid Buffer Interrupt Enable (`LVBIE`).
    pub const LVBIE: u8 = 1 << 2;
    /// FIFO Error Interrupt Enable (`FEIE`).
    pub const FEIE: u8 = 1 << 3;
    /// Interrupt on Completion Enable (`IOCE`).
    pub const IOCE: u8 = 1 << 4;
}

/// 8-byte AC'97 Buffer Descriptor List (`BDL`) entry (32 entries per stream ring).
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ac97BdlEntry {
    /// Physical address of the 16-bit PCM sample buffer (must be 8-byte aligned).
    pub buffer_phys: u32,
    /// Bits `15:0`: Number of 16-bit PCM samples (`0..=65535`, NOT bytes);
    /// Bit 30: `BUP` (Buffer Underrun Policy: `1 = play last sample`);
    /// Bit 31: `IOC` (Interrupt On Completion).
    pub length_and_flags: u32,
}

impl Ac97BdlEntry {
    pub const FLAG_IOC: u32 = 1 << 31;
    pub const FLAG_BUP: u32 = 1 << 30;

    #[inline]
    pub const fn new(
        buffer_phys: u32,
        num_16bit_samples: u16,
        interrupt_on_completion: bool,
        underrun_silence: bool,
    ) -> Self {
        let ioc = if interrupt_on_completion {
            Self::FLAG_IOC
        } else {
            0
        };
        let bup = if !underrun_silence {
            Self::FLAG_BUP
        } else {
            0
        };
        Self {
            buffer_phys: buffer_phys & !0x07,
            length_and_flags: ioc | bup | (num_16bit_samples as u32),
        }
    }

    #[inline]
    pub const fn sample_count(&self) -> u16 {
        (self.length_and_flags & 0xFFFF) as u16
    }

    #[inline]
    pub const fn byte_count(&self) -> u32 {
        (self.sample_count() as u32) * 2
    }
}

/// Encodes a 16-bit AC'97 Mixer Volume register (`MASTER_VOLUME` `0x02` or `PCM_OUT_VOLUME` `0x18`)
/// from a percentage (`0..=100`) and mute flag.
///
/// AC'97 attenuation uses 6-bit (or 5-bit) steps of 1.5 dB where `0x00` = 0 dB (max volume)
/// and `0x1F` = -46.5 dB (minimum volume), plus Bit 15 = Mute.
#[inline]
pub const fn encode_ac97_mixer_volume(left_percent: u8, right_percent: u8, mute: bool) -> u16 {
    if mute {
        return 0x8000;
    }
    let l_clamped = if left_percent > 100 { 100 } else { left_percent };
    let r_clamped = if right_percent > 100 { 100 } else { right_percent };
    let l_atten = ((100 - l_clamped) as u16 * 31) / 100;
    let r_atten = ((100 - r_clamped) as u16 * 31) / 100;
    ((l_atten & 0x1F) << 8) | (r_atten & 0x1F)
}

/// Resamples a 16-bit signed mono/stereo PCM frame stream from `src_rate_hz` (e.g. `44100`)
/// to native AC'97 `48000` Hz using fixed-point linear interpolation (`16.16`).
pub fn resample_pcm16_to_48khz(src_samples: &[i16], src_rate_hz: u32, dst_out: &mut [i16]) -> usize {
    if src_samples.is_empty() || src_rate_hz == 0 {
        return 0;
    }
    let step_fp16 = ((src_rate_hz as u64) << 16) / 48_000u64;
    let mut pos_fp16 = 0u64;
    let mut written = 0usize;

    while written < dst_out.len() {
        let idx = (pos_fp16 >> 16) as usize;
        if idx >= src_samples.len() {
            break;
        }
        let frac = (pos_fp16 & 0xFFFF) as i32;
        let s0 = src_samples[idx] as i32;
        let s1 = if idx + 1 < src_samples.len() {
            src_samples[idx + 1] as i32
        } else {
            s0
        };
        let interpolated = s0 + (((s1 - s0) * frac) >> 16);
        dst_out[written] = interpolated as i16;
        written += 1;
        pos_fp16 += step_fp16;
    }

    written
}

/// Self-test for `ac97_audio` 8-byte BDL entries, mixer dB volume attenuation, and 44.1kHz -> 48kHz resampling.
pub fn verify_driver_module_ac97_audio() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Ac97BdlEntry is 8 bytes and calculates sample/byte count accurately
    let bdl = Ac97BdlEntry::new(0x0040_0000, 4096, true, true);
    if core::mem::size_of::<Ac97BdlEntry>() == 8
        && bdl.sample_count() == 4096
        && bdl.byte_count() == 8192
        && (bdl.length_and_flags & Ac97BdlEntry::FLAG_IOC) != 0
    {
        passed += 1;
    }

    // 2. Verify AC'97 volume attenuator encoding (100% -> 0x0000, 0% -> 0x1F1F, Mute -> 0x8000)
    if encode_ac97_mixer_volume(100, 100, false) == 0x0000
        && encode_ac97_mixer_volume(0, 0, false) == 0x1F1F
        && encode_ac97_mixer_volume(80, 80, true) == 0x8000
    {
        passed += 1;
    }

    // 3. Verify 44.1 kHz -> 48 kHz fixed-point linear PCM resampler
    let mut src = [0i16; 441];
    let mut i = 0;
    while i < src.len() {
        src[i] = (i as i16) * 50;
        i += 1;
    }
    let mut dst = [0i16; 512];
    let produced = resample_pcm16_to_48khz(&src, 44_100, &mut dst);
    if produced == 480 && dst[0] == 0 && dst[479] > dst[0] {
        passed += 1;
    }

    passed
}
