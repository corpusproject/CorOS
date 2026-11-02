//! CorOS Hardware Driver Module: `intel_hda`
//!
//! Intel High Definition Audio (Azalia Rev 1.0a) Controller MMIO register layout
//! (`GCAP`, `GCTL`, `STATESTS`, `CORBLBASE`, `RIRBLBASE`), 32-bit Codec Command Verb
//! encoder (`CAd`, `NID`, `Verb`, `Payload`), 64-bit RIRB response ring entry,
//! 16-byte Stream Buffer Descriptor List entry (`HdaBdlEntry`), PCM Stream Format
//! Descriptor builder, and Audio Function Group (`AFG`) / DAC / Pin Complex widget discovery.

/// Intel HD Audio Controller MMIO Register offsets.
pub mod hda_regs {
    /// Global Capabilities (16-bit: `ISS`, `OSS`, `BSS`, `NSDO`, `64OK`).
    pub const GCAP: usize = 0x00;
    /// Minor Version (8-bit).
    pub const VMIN: usize = 0x02;
    /// Major Version (8-bit).
    pub const VMAJ: usize = 0x03;
    /// Global Control (32-bit: `CRST = bit 0`, `FCNTRL = bit 1`, `UNSOL = bit 8`).
    pub const GCTL: usize = 0x08;
    /// Wake Enable (16-bit).
    pub const WAKEEN: usize = 0x0C;
    /// State Change Status (16-bit: bitmask of discovered SDI codecs `0..14`).
    pub const STATESTS: usize = 0x0E;
    /// Interrupt Control (32-bit: `GIE = bit 31`, `CIE = bit 30`).
    pub const INTCTL: usize = 0x20;
    /// Interrupt Status (32-bit).
    pub const INTSTS: usize = 0x24;
    /// Wall Clock Counter (32-bit 24 MHz counter).
    pub const WALCLK: usize = 0x30;
    /// CORB Lower Base Address (32-bit).
    pub const CORBLBASE: usize = 0x40;
    /// CORB Upper Base Address (32-bit).
    pub const CORBUBASE: usize = 0x44;
    /// CORB Write Pointer (16-bit).
    pub const CORBWP: usize = 0x48;
    /// CORB Read Pointer (16-bit: bit 15 = `CORBRPRST`).
    pub const CORBRP: usize = 0x4A;
    /// CORB Control (8-bit: bit 1 = `CORBRUN`).
    pub const CORBCTL: usize = 0x4C;
    /// CORB Size (8-bit: `00b = 2`, `01b = 16`, `10b = 256` entries).
    pub const CORBSIZE: usize = 0x4E;
    /// RIRB Lower Base Address (32-bit).
    pub const RIRBLBASE: usize = 0x50;
    /// RIRB Upper Base Address (32-bit).
    pub const RIRBUBASE: usize = 0x54;
    /// RIRB Write Pointer (16-bit).
    pub const RIRBWP: usize = 0x58;
    /// Response Interrupt Count (16-bit).
    pub const RINTCNT: usize = 0x5A;
    /// RIRB Control (8-bit: bit 1 = `RIRBDMAEN`, bit 0 = `RINTCTL`).
    pub const RIRBCTL: usize = 0x5C;
    /// RIRB Status (8-bit).
    pub const RIRBSTS: usize = 0x5D;
    /// RIRB Size (8-bit).
    pub const RIRBSIZE: usize = 0x5E;
    /// Stream Descriptor Base Offset (`0x80`), 32 bytes per stream descriptor.
    pub const STREAM_DESC_BASE: usize = 0x80;
    pub const STREAM_DESC_STRIDE: usize = 0x20;
}

/// Decoded `GCAP` (Global Capabilities) register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdaGlobalCapabilities {
    pub num_output_streams: u8,
    pub num_input_streams: u8,
    pub num_bidirectional_streams: u8,
    pub num_sdo_lines: u8,
    pub dma_64bit_supported: bool,
}

impl HdaGlobalCapabilities {
    #[inline]
    pub const fn from_gcap(gcap: u16) -> Self {
        Self {
            num_output_streams: ((gcap >> 12) & 0x0F) as u8,
            num_input_streams: ((gcap >> 8) & 0x0F) as u8,
            num_bidirectional_streams: ((gcap >> 3) & 0x1F) as u8,
            num_sdo_lines: 1u8 << ((gcap >> 1) & 0x03),
            dma_64bit_supported: (gcap & 0x01) != 0,
        }
    }

    /// Computes the MMIO byte offset of the first Output Stream Descriptor (`0x80 + ISS * 0x20`).
    #[inline]
    pub const fn first_output_stream_offset(&self) -> usize {
        hda_regs::STREAM_DESC_BASE + (self.num_input_streams as usize) * hda_regs::STREAM_DESC_STRIDE
    }
}

/// Standard HD Audio Codec Verbs (`12-bit` or `4-bit` command forms).
pub mod hda_verbs {
    pub const GET_PARAMETER: u16 = 0xF00;
    pub const GET_CONN_LIST_LEN: u16 = 0xF02;
    pub const SET_STREAM_CHANNEL: u16 = 0x706;
    pub const SET_PIN_WIDGET_CONTROL: u16 = 0x707;
    pub const SET_EAPD_BTL_ENABLE: u16 = 0x70C;
    pub const SET_POWER_STATE: u16 = 0x705;
    /// 4-bit verb (`0x2` in bits `19:16`): Set Converter Format (16-bit payload).
    pub const SET_CONVERTER_FORMAT_4BIT: u8 = 0x2;
    /// 4-bit verb (`0x3` in bits `19:16`): Set Amplifier Gain/Mute (16-bit payload).
    pub const SET_AMP_GAIN_MUTE_4BIT: u8 = 0x3;
}

/// HDA Widget Type codes from `Audio Widget Capabilities` (`Parameter 0x09`, bits `23:20`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HdaWidgetType {
    AudioOutputDac = 0x0,
    AudioInputAdc = 0x1,
    AudioMixer = 0x2,
    AudioSelector = 0x3,
    PinComplex = 0x4,
    PowerWidget = 0x5,
    VolumeKnob = 0x6,
    BeepGenerator = 0x7,
    VendorDefined = 0xF,
    Unknown(u8),
}

impl HdaWidgetType {
    #[inline]
    pub const fn from_widget_caps(wcaps: u32) -> Self {
        match ((wcaps >> 20) & 0x0F) as u8 {
            0x0 => Self::AudioOutputDac,
            0x1 => Self::AudioInputAdc,
            0x2 => Self::AudioMixer,
            0x3 => Self::AudioSelector,
            0x4 => Self::PinComplex,
            0x5 => Self::PowerWidget,
            0x6 => Self::VolumeKnob,
            0x7 => Self::BeepGenerator,
            0xF => Self::VendorDefined,
            other => Self::Unknown(other),
        }
    }
}

/// Encodes a 32-bit HD Audio CORB Verb with a 12-bit Verb ID and 8-bit Payload:
/// `[31:28] CAd | [27:20] NID | [19:8] Verb12 | [7:0] Payload8`.
#[inline]
pub const fn encode_corb_verb12(codec_addr: u8, nid: u8, verb12: u16, payload8: u8) -> u32 {
    (((codec_addr & 0x0F) as u32) << 28)
        | (((nid & 0x7F) as u32) << 20)
        | (((verb12 & 0x0FFF) as u32) << 8)
        | (payload8 as u32)
}

/// Encodes a 32-bit HD Audio CORB Verb with a 4-bit Verb ID and 16-bit Payload:
/// `[31:28] CAd | [27:20] NID | [19:16] Verb4 | [15:0] Payload16`.
#[inline]
pub const fn encode_corb_verb4(codec_addr: u8, nid: u8, verb4: u8, payload16: u16) -> u32 {
    (((codec_addr & 0x0F) as u32) << 28)
        | (((nid & 0x7F) as u32) << 20)
        | (((verb4 & 0x0F) as u32) << 16)
        | (payload16 as u32)
}

/// 8-byte RIRB (Response Input Ring Buffer) entry written by the HDA controller.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdaRirbEntry {
    pub response: u32,
    pub response_ex: u32,
}

impl HdaRirbEntry {
    #[inline]
    pub const fn codec_address(&self) -> u8 {
        (self.response_ex & 0x0F) as u8
    }

    #[inline]
    pub const fn is_unsolicited(&self) -> bool {
        (self.response_ex & (1 << 4)) != 0
    }
}

/// 16-byte HDA Stream Buffer Descriptor List (`BDL`) entry (128-byte aligned table in RAM).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdaBdlEntry {
    pub address: u64,
    pub length_bytes: u32,
    /// Bit 0 = Interrupt on Completion (`IOC`).
    pub flags: u32,
}

impl HdaBdlEntry {
    #[inline]
    pub const fn new(address: u64, length_bytes: u32, ioc: bool) -> Self {
        Self {
            address: address & !0x7Fu64,
            length_bytes,
            flags: if ioc { 1 } else { 0 },
        }
    }
}

/// Encodes a 16-bit HDA Stream / Converter Format word (`SDnFMT`) for `sample_rate_hz`,
/// `bits_per_sample` (`8`, `16`, `20`, `24`, `32`), and `channels` (`1..=16`).
pub const fn encode_hda_stream_format(
    sample_rate_hz: u32,
    bits_per_sample: u8,
    channels: u8,
) -> Option<u16> {
    // Base rate: bit 14 (`0 = 48 kHz`, `1 = 44.1 kHz`)
    let (base_bit, mult, div): (u16, u16, u16) = match sample_rate_hz {
        8000 => (0, 0, 5),   // 48000 * 1 / 6
        16000 => (0, 0, 2),  // 48000 * 1 / 3
        22050 => (1, 0, 1),  // 44100 * 1 / 2
        32000 => (0, 1, 2),  // 48000 * 2 / 3
        44100 => (1, 0, 0),  // 44100 * 1 / 1
        48000 => (0, 0, 0),  // 48000 * 1 / 1
        88200 => (1, 1, 0),  // 44100 * 2 / 1
        96000 => (0, 1, 0),  // 48000 * 2 / 1
        176400 => (1, 3, 0), // 44100 * 4 / 1
        192000 => (0, 3, 0), // 48000 * 4 / 1
        _ => return None,
    };

    let bits_code: u16 = match bits_per_sample {
        8 => 0b000,
        16 => 0b001,
        20 => 0b010,
        24 => 0b011,
        32 => 0b100,
        _ => return None,
    };

    if channels == 0 || channels > 16 {
        return None;
    }
    let chan_code = (channels - 1) as u16;

    Some((base_bit << 14) | (mult << 11) | (div << 8) | (bits_code << 4) | chan_code)
}

/// Builds the 4-verb initialization sequence to configure an Output DAC (`dac_nid`) and
/// Speaker/Headphone Pin Complex (`pin_nid`) on `codec_addr` for `stream_tag` (`1..=15`).
pub const fn build_dac_pin_output_verbs(
    codec_addr: u8,
    dac_nid: u8,
    pin_nid: u8,
    stream_tag: u8,
    format_word: u16,
) -> [u32; 5] {
    [
        // 1. Power up DAC to D0 (0x00)
        encode_corb_verb12(codec_addr, dac_nid, hda_verbs::SET_POWER_STATE, 0x00),
        // 2. Bind DAC to Stream Tag (bits 7:4) and Channel 0 (bits 3:0)
        encode_corb_verb12(
            codec_addr,
            dac_nid,
            hda_verbs::SET_STREAM_CHANNEL,
            (stream_tag & 0x0F) << 4,
        ),
        // 3. Program Converter PCM Format on DAC
        encode_corb_verb4(
            codec_addr,
            dac_nid,
            hda_verbs::SET_CONVERTER_FORMAT_4BIT,
            format_word,
        ),
        // 4. Unmute Output Amplifier on DAC (Set Output, Left+Right, Gain 0x7F)
        encode_corb_verb4(
            codec_addr,
            dac_nid,
            hda_verbs::SET_AMP_GAIN_MUTE_4BIT,
            0xB07F,
        ),
        // 5. Enable Pin Widget Output + Headphone Amp (`OUT_ENABLE = 0x40 | HP_ENABLE = 0x80`)
        encode_corb_verb12(
            codec_addr,
            pin_nid,
            hda_verbs::SET_PIN_WIDGET_CONTROL,
            0xC0,
        ),
    ]
}

/// Self-test for `intel_hda` GCAP decoding, CORB verb builder, PCM stream format encoding, and BDL layout.
pub fn verify_driver_module_intel_hda() -> u32 {
    let mut passed = 0u32;

    // 1. Verify HdaBdlEntry (16B) and HdaRirbEntry (8B) sizes
    if core::mem::size_of::<HdaBdlEntry>() == 16 && core::mem::size_of::<HdaRirbEntry>() == 8 {
        passed += 1;
    }

    // 2. Verify GCAP decoding (4 ISS, 4 OSS, 64-bit DMA)
    let gcap = HdaGlobalCapabilities::from_gcap(0x4401);
    if gcap.num_output_streams == 4
        && gcap.num_input_streams == 4
        && gcap.dma_64bit_supported
        && gcap.first_output_stream_offset() == 0x100
    {
        passed += 1;
    }

    // 3. Verify 48 kHz / 16-bit / 2-channel stereo format word (`0x0011`) and 44.1 kHz / 24-bit / 2ch (`0x4031`)
    if encode_hda_stream_format(48_000, 16, 2) == Some(0x0011)
        && encode_hda_stream_format(44_100, 24, 2) == Some(0x4031)
    {
        passed += 1;
    }

    // 4. Verify CORB verb builder for DAC + Pin Complex output path
    let verbs = build_dac_pin_output_verbs(0, 0x02, 0x14, 1, 0x0011);
    if verbs[1] == 0x0027_0610 && verbs[2] == 0x0022_0011 && verbs[4] == 0x0147_07C0 {
        passed += 1;
    }

    passed
}
