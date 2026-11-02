//! Native 100% in-house AC'97 (Audio Codec '97) Bare-Metal Audio Driver for CorOS.
//! Provides audio buffer playback via Bus Mastering DMA (NAMBAR & NABMBAR I/O ports),
//! volume attenuation control, and procedural synthesis for Windows startup chime and sound effects.

use crate::arch::x86_64::cpu;
use crate::pci::PciDevice;
use alloc::vec::Vec;

pub mod synthesizer;
pub mod dsp;
pub mod flac_decoder;
pub mod mixer;
pub mod sound_bridge;

pub use synthesizer::{PolySynth, SynthVoice, Waveform, AdsrParameters, EnvelopePhase};
pub use dsp::{BiquadFilter, BiquadFilterType, ThreeBandEqualizer, CombFilter};
pub use flac_decoder::{FlacDecoder, FlacStreamInfo, FlacChannelAssignment};
pub use mixer::{MasterMixer, AudioTrack, AudioCompressor, StereoReverb};
pub use sound_bridge::{SoundBridge, SoundBridgeStats, GLOBAL_SOUND_BRIDGE};

// AC'97 Mixer Registers (NAMBAR - Native Audio Mixer Base Address)
pub const AC97_RESET: u16 = 0x00;
pub const AC97_MASTER_VOLUME: u16 = 0x02;
pub const AC97_PCM_OUT_VOLUME: u16 = 0x18;
pub const AC97_EXTENDED_AUDIO_ID: u16 = 0x28;
pub const AC97_EXTENDED_AUDIO_STAT: u16 = 0x2A;
pub const AC97_PCM_FRONT_DAC_RATE: u16 = 0x2C;

// AC'97 Bus Master Registers (NABMBAR - Native Audio Bus Master Base Address)
pub const AC97_PO_BDBAR: u16 = 0x10; // PCM Out Buffer Descriptor Base Address (32-bit physical)
pub const AC97_PO_CIV: u16 = 0x14;   // PCM Out Current Index Value (8-bit)
pub const AC97_PO_LVI: u16 = 0x15;   // PCM Out Last Valid Index (8-bit)
pub const AC97_PO_SR: u16 = 0x16;    // PCM Out Status Register (16-bit)
pub const AC97_PO_PICB: u16 = 0x18;  // PCM Out Position in Current Buffer (16-bit)
pub const AC97_PO_CR: u16 = 0x1B;    // PCM Out Control Register (8-bit)

// Control Register Bits
pub const CR_RPBM: u8 = 1 << 0;  // Run/Pause Bus Master (1: Run, 0: Pause)
pub const CR_RR: u8 = 1 << 1;    // Reset Registers
pub const CR_LVBIE: u8 = 1 << 2; // Last Valid Buffer Interrupt Enable
pub const CR_FEIE: u8 = 1 << 3;  // FIFO Error Interrupt Enable
pub const CR_IOCE: u8 = 1 << 4;  // Interrupt on Completion Enable

// Status Register Bits
pub const SR_DCH: u16 = 1 << 0;  // DMA Controller Halted
pub const SR_CELV: u16 = 1 << 1; // Current Equals Last Valid
pub const SR_LVBCI: u16 = 1 << 2;// Last Valid Buffer Completion Interrupt
pub const SR_BCIS: u16 = 1 << 3; // Buffer Completion Interrupt Status
pub const SR_FIFOE: u16 = 1 << 4;// FIFO Error

/// AC'97 Buffer Descriptor (8 bytes each, up to 32 entries)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct BufferDescriptor {
    pub buffer_pointer: u32, // 32-bit physical address of 16-bit stereo PCM samples
    pub sample_count: u16,   // Number of samples (up to 65535, 0 = 65536)
    pub flags: u16,          // Bit 15: IOC (Interrupt on Completion), Bit 14: BUP (Buffer Underrun Policy)
}

pub struct Ac97Controller {
    pub nam_bar: u16,  // BAR0 (I/O port)
    pub nabm_bar: u16, // BAR1 (I/O port)
    pub is_active: bool,
}

static mut GLOBAL_AC97: Option<Ac97Controller> = None;

// Pre-allocated static DMA buffers (Physical memory)
const DMA_BUF_SAMPLES: usize = 4096;
#[repr(align(16))]
struct DmaAudioBuffer([i16; DMA_BUF_SAMPLES * 2]); // Stereo 16-bit PCM

#[repr(align(16))]
struct BdList([BufferDescriptor; 32]);

static mut DMA_BUFFER: DmaAudioBuffer = DmaAudioBuffer([0; DMA_BUF_SAMPLES * 2]);
static mut BDL_LIST: BdList = BdList([BufferDescriptor { buffer_pointer: 0, sample_count: 0, flags: 0 }; 32]);

impl Ac97Controller {
    /// Attempts to initialize the AC'97 controller from the detected PCI device
    pub unsafe fn initialize(dev: &PciDevice) -> bool {
        dev.enable_bus_mastering();

        // AC'97 BAR0 is NAMBAR (I/O port, bit 0 must be 1)
        // BAR1 is NABMBAR (I/O port)
        let nam_bar = (dev.bar0 & 0xFFFC) as u16;
        let nabm_bar = (dev.bar1 & 0xFFFC) as u16;

        if nam_bar == 0 || nabm_bar == 0 {
            return false;
        }

        crate::diagnostics::serial::write_str("[AC'97] Initializing Audio Controller (NAM: 0x");
        crate::diagnostics::serial::write_u64("", nam_bar as u64);
        crate::diagnostics::serial::write_str(", NABM: 0x");
        crate::diagnostics::serial::write_u64("", nabm_bar as u64);
        crate::diagnostics::serial::write_str(")...\r\n");

        // 1. Cold Reset Codec
        cpu::out16(nam_bar + AC97_RESET, 0x0001);
        for _ in 0..10_000 { cpu::out8(0x80, 0); }

        // 2. Set Master Volume to 0 dB (0x0000 = max volume, 0x1F1F = muted)
        cpu::out16(nam_bar + AC97_MASTER_VOLUME, 0x0202); // Comfortable moderate volume
        cpu::out16(nam_bar + AC97_PCM_OUT_VOLUME, 0x0202);

        // 3. Reset Bus Master Registers
        cpu::out8(nabm_bar + AC97_PO_CR, CR_RR);
        for _ in 0..10_000 { cpu::out8(0x80, 0); }

        // Setup Buffer Descriptor List
        let p_buf = core::ptr::addr_of!(DMA_BUFFER.0) as u32;
        let p_bdl = core::ptr::addr_of!(BDL_LIST.0) as u32;

        BDL_LIST.0[0] = BufferDescriptor {
            buffer_pointer: p_buf,
            sample_count: DMA_BUF_SAMPLES as u16,
            flags: 0x8000, // IOC
        };

        // Write BDL physical address to AC'97 PO_BDBAR
        cpu::out32(nabm_bar + AC97_PO_BDBAR, p_bdl);

        crate::diagnostics::serial::write_str("[AC'97] Controller Online! Sound Engine Ready.\r\n");

        let controller = Self {
            nam_bar,
            nabm_bar,
            is_active: true,
        };
        GLOBAL_AC97 = Some(controller);
        true
    }

    /// Plays a synthesized tone or chord through AC'97 DMA buffer
    pub unsafe fn play_melody(&mut self, notes: &[(u32, u32)]) {
        // notes: &[(freq_hz, duration_ms)]
        let sample_rate = 44100u32;

        for &(freq, duration_ms) in notes {
            let total_samples = ((sample_rate * duration_ms) / 1000).min(DMA_BUF_SAMPLES as u32);
            let period = if freq > 0 { sample_rate / freq } else { 1 };

            // Fill stereo 16-bit PCM buffer
            for i in 0..(DMA_BUF_SAMPLES as usize) {
                if (i as u32) < total_samples && freq > 0 {
                    // Soft sine-like synthesized melodic harmonic wave
                    let phase = (i as u32 % period) as f32 / period as f32;
                    let val: i16 = if phase < 0.5 {
                        ((phase * 2.0 - 0.5) * 8000.0) as i16
                    } else {
                        (((1.0 - phase) * 2.0 - 0.5) * 8000.0) as i16
                    };
                    DMA_BUFFER.0[i * 2] = val;
                    DMA_BUFFER.0[i * 2 + 1] = val;
                } else {
                    DMA_BUFFER.0[i * 2] = 0;
                    DMA_BUFFER.0[i * 2 + 1] = 0;
                }
            }

            // Set LVI (Last Valid Index) = 0 and start playback
            cpu::out8(self.nabm_bar + AC97_PO_LVI, 0);
            cpu::out8(self.nabm_bar + AC97_PO_CR, CR_RPBM);

            // Wait for duration (approximate using lightweight TSC/pause)
            let start_tsc = crate::time::TscCounter::read_ticks().0;
            // 2.6 GHz CPU: ~2,600,000 cycles per ms
            let target_cycles = (duration_ms as u64) * 2_600_000;
            while crate::time::TscCounter::read_ticks().0.saturating_sub(start_tsc) < target_cycles {
                core::hint::spin_loop();
            }

            // Stop
            cpu::out8(self.nabm_bar + AC97_PO_CR, 0);
        }
    }
}

/// Plays the iconic Windows 11 Fluent Startup Chime
pub fn play_startup_chime() {
    unsafe {
        if let Some(ac97) = (*core::ptr::addr_of_mut!(GLOBAL_AC97)).as_mut() {
            // Windows 11 Melodic Major Chord Arpeggio: F#3 -> C#4 -> F#4 -> A#4 -> C#5
            let notes = [
                (185, 90),  // F#3
                (277, 90),  // C#4
                (370, 110), // F#4
                (466, 140), // A#4
                (554, 320), // C#5 (Long resonant sustain)
            ];
            ac97.play_melody(&notes);
        }
    }
}

/// Plays a gentle click sound effect for window or icon clicks
pub fn play_click_sound() {
    unsafe {
        if let Some(ac97) = (*core::ptr::addr_of_mut!(GLOBAL_AC97)).as_mut() {
            let notes = [
                (1200, 12),
                (800, 10),
            ];
            ac97.play_melody(&notes);
        }
    }
}

/// Plays a modern Windows 11 style notification alert chime
pub fn play_notification_sound() {
    unsafe {
        if let Some(ac97) = (*core::ptr::addr_of_mut!(GLOBAL_AC97)).as_mut() {
            let notes = [
                (659, 70),  // E5
                (880, 140), // A5
            ];
            ac97.play_melody(&notes);
        }
    }
}

/// Plays an 80s Cyberpunk synth arpeggio riff for CorOS Media Player
pub fn play_synth_riff() {
    unsafe {
        if let Some(ac97) = (*core::ptr::addr_of_mut!(GLOBAL_AC97)).as_mut() {
            let notes = [
                (220, 60),  // A3
                (261, 60),  // C4
                (329, 60),  // E4
                (440, 80),  // A4
                (392, 60),  // G4
                (329, 60),  // E4
                (293, 100), // D4
                (220, 180), // A3 (Sustain)
            ];
            ac97.play_melody(&notes);
        }
    }
}
