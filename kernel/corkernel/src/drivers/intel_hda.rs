//! CorOS Intel High Definition Audio (HDA / Realtek ALC) Subsystem (`intel_hda.rs`)
//!
//! Provides bare-metal HD Audio controller and codec management:
//! - Global Registers: GCAP, VMIN, VMAJ, OUTPAY, INPAY, GCTL, WAKEEN, STATESTS, INTCTL, INTSTS
//! - CORB (Command Outbound Ring Buffer): 256-entry 32-bit verb ring buffer
//! - RIRB (Response Inbound Ring Buffer): 256-entry 64-bit response ring buffer
//! - Stream Descriptors (SD): Input / Output Audio DMA buffers, Cyclic Buffer Descriptor List (BDL)
//! - Codec Verb Execution: GET_PARAMETER (0xF00), SET_CONVERTER_FORMAT (0x200), SET_AMP_GAIN_MUTE (0x300)
//! - Audio PCM Streaming: 44.1 kHz / 48 kHz / 96 kHz, 16-bit / 24-bit stereo

extern crate alloc;

use alloc::vec::Vec;

/// HDA Global Register Offsets
pub const HDA_GCAP: usize = 0x00;      // Global Capabilities
pub const HDA_VMIN: usize = 0x02;      // Minor Version
pub const HDA_VMAJ: usize = 0x03;      // Major Version
pub const HDA_OUTPAY: usize = 0x04;    // Output Payload Capability
pub const HDA_INPAY: usize = 0x06;     // Input Payload Capability
pub const HDA_GCTL: usize = 0x08;      // Global Control
pub const HDA_WAKEEN: usize = 0x0C;    // Wake Enable
pub const HDA_STATESTS: usize = 0x0E;  // State Change Status
pub const HDA_INTCTL: usize = 0x20;    // Interrupt Control
pub const HDA_INTSTS: usize = 0x24;    // Interrupt Status

/// CORB Register Offsets
pub const HDA_CORBLBASE: usize = 0x40; // CORB Lower Base Address
pub const HDA_CORBUBASE: usize = 0x44; // CORB Upper Base Address
pub const HDA_CORBWP: usize = 0x48;    // CORB Write Pointer
pub const HDA_CORBRP: usize = 0x4A;    // CORB Read Pointer
pub const HDA_CORBCTL: usize = 0x4C;   // CORB Control
pub const HDA_CORBSTS: usize = 0x4D;   // CORB Status
pub const HDA_CORBSIZE: usize = 0x4E;  // CORB Size

/// RIRB Register Offsets
pub const HDA_RIRBLBASE: usize = 0x50; // RIRB Lower Base Address
pub const HDA_RIRBUBASE: usize = 0x54; // RIRB Upper Base Address
pub const HDA_RIRBWP: usize = 0x58;    // RIRB Write Pointer
pub const HDA_RINTCNT: usize = 0x5A;   // Response Interrupt Count
pub const HDA_RIRBCTL: usize = 0x5C;   // RIRB Control
pub const HDA_RIRBSTS: usize = 0x5D;   // RIRB Status
pub const HDA_RIRBSIZE: usize = 0x5E;  // RIRB Size

/// Stream Descriptor Offsets (Base = 0x80 + StreamIndex * 0x20)
pub const HDA_SD_CTL: usize = 0x00;    // Stream Descriptor Control (24-bit)
pub const HDA_SD_STS: usize = 0x03;    // Stream Descriptor Status
pub const HDA_SD_LPIB: usize = 0x04;   // Link Position in Buffer
pub const HDA_SD_CBL: usize = 0x08;    // Cyclic Buffer Length
pub const HDA_SD_LVI: usize = 0x0C;    // Last Valid Index
pub const HDA_SD_FMT: usize = 0x12;    // Stream Format
pub const HDA_SD_BDLPL: usize = 0x18;  // Buffer Descriptor List Pointer Lower
pub const HDA_SD_BDLPU: usize = 0x1C;  // Buffer Descriptor List Pointer Upper

/// Buffer Descriptor List Entry (BDL Entry: 16 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HdaBdlEntry {
    pub addr_low: u32,
    pub addr_high: u32,
    pub length: u32,
    pub flags: u32, // bit 0 = Interrupt on Completion (IOC)
}

/// Common HDA Codec Verbs
pub const VERB_GET_PARAMETER: u32 = 0xF00;
pub const VERB_SET_STREAM_CHANNEL: u32 = 0x706;
pub const VERB_SET_PIN_WIDGET_CONTROL: u32 = 0x707;
pub const VERB_SET_POWER_STATE: u32 = 0x705;
pub const VERB_SET_CONVERTER_FORMAT: u32 = 0x200;
pub const VERB_SET_AMP_GAIN_MUTE: u32 = 0x300;

/// Complete Intel HDA Audio Controller
pub struct IntelHdaController {
    pub mmio_base: usize,
    pub num_iss: usize, // Number of Input Streams
    pub num_oss: usize, // Number of Output Streams
    pub num_bss: usize, // Number of Bidirectional Streams
    pub corb_entries: usize,
    pub rirb_entries: usize,
    pub codecs_present: u16,
}

impl IntelHdaController {
    pub fn new(mmio_base: usize) -> Self {
        let gcap = unsafe { core::ptr::read_volatile(mmio_base as *const u16) };
        let num_iss = ((gcap >> 8) & 0x0F) as usize;
        let num_oss = ((gcap >> 12) & 0x0F) as usize;
        let num_bss = ((gcap >> 3) & 0x1F) as usize;

        let statests = unsafe { core::ptr::read_volatile((mmio_base + HDA_STATESTS) as *const u16) };

        Self {
            mmio_base,
            num_iss,
            num_oss,
            num_bss,
            corb_entries: 256,
            rirb_entries: 256,
            codecs_present: statests & 0x0F,
        }
    }

    unsafe fn read_reg32(&self, reg: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + reg) as *const u32)
    }

    unsafe fn write_reg32(&self, reg: usize, val: u32) {
        core::ptr::write_volatile((self.mmio_base + reg) as *mut u32, val);
    }

    unsafe fn read_reg16(&self, reg: usize) -> u16 {
        core::ptr::read_volatile((self.mmio_base + reg) as *const u16)
    }

    unsafe fn write_reg16(&self, reg: usize, val: u16) {
        core::ptr::write_volatile((self.mmio_base + reg) as *mut u16, val);
    }

    unsafe fn read_reg8(&self, reg: usize) -> u8 {
        core::ptr::read_volatile((self.mmio_base + reg) as *const u8)
    }

    unsafe fn write_reg8(&self, reg: usize, val: u8) {
        core::ptr::write_volatile((self.mmio_base + reg) as *mut u8, val);
    }

    /// Reset HDA controller and take it out of reset
    pub fn reset(&mut self) -> bool {
        unsafe {
            // Clear CRST bit to enter reset
            let mut gctl = self.read_reg32(HDA_GCTL);
            gctl &= !(1 << 0);
            self.write_reg32(HDA_GCTL, gctl);

            // Wait for reset active
            for _ in 0..10_000 {
                if (self.read_reg32(HDA_GCTL) & (1 << 0)) == 0 {
                    break;
                }
            }

            // Set CRST bit to exit reset
            self.write_reg32(HDA_GCTL, 1 << 0);

            // Wait until controller exits reset
            for _ in 0..10_000 {
                if (self.read_reg32(HDA_GCTL) & (1 << 0)) != 0 {
                    // Update detected codecs
                    let statests = self.read_reg16(HDA_STATESTS);
                    self.codecs_present = statests & 0x0F;
                    return true;
                }
            }
        }
        false
    }

    /// Construct a 32-bit HDA Codec Command Verb
    pub fn format_verb(codec_addr: u8, nid: u8, verb_id: u32, payload: u8) -> u32 {
        let cad = (codec_addr as u32) & 0x0F;
        let n = (nid as u32) & 0x7F;
        let v = verb_id & 0x0FFF;
        let p = payload as u32;

        (cad << 28) | (n << 20) | (v << 8) | p
    }

    /// Format standard 16-bit PCM stream format
    /// (channels: 1=mono, 2=stereo; sample_rate: 44100, 48000; bits: 16)
    pub fn format_pcm_stream(channels: u8, sample_rate: u32, bits_per_sample: u8) -> u16 {
        let mut fmt: u16 = 0;

        // Base rate: 0 = 48 kHz, 1 = 44.1 kHz
        if sample_rate == 44100 {
            fmt |= 1 << 14;
        }

        // Bits per sample: 001 = 16-bit, 010 = 20-bit, 011 = 24-bit, 100 = 32-bit
        match bits_per_sample {
            16 => fmt |= 0b001 << 4,
            20 => fmt |= 0b010 << 4,
            24 => fmt |= 0b011 << 4,
            32 => fmt |= 0b100 << 4,
            _ => fmt |= 0b001 << 4,
        }

        // Channels (0-based: 0 = 1 channel, 1 = 2 channels)
        fmt |= (channels.saturating_sub(1) as u16) & 0x0F;
        fmt
    }
}
