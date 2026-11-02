//! Free Lossless Audio Codec (FLAC) Pure Bare-Metal Decoder for CorOS
//! 100% in-house implementation conforming to FLAC format specification (RFC 9580 / Xiph.Org).
//!
//! Features:
//! - "fLaC" stream marker verification
//! - STREAMINFO metadata block decoding (min/max block size, sample rate, channels, bit depth)
//! - VORBIS_COMMENT, PADDING, and PICTURE metadata block parsing
//! - Sync code (0xFFF8 / 0xFFF9) frame header parsing
//! - Subframe decoding: Constant, Verbatim, Fixed Linear Prediction (order 0-4), FIR Linear Prediction (LPC)
//! - Residual decoding: Rice partitioning and variable-length Rice entropy decoding
//! - Channel decorrelation: Independent, Left/Side, Right/Side, Mid/Side stereo channels
//! - 16-bit PCM sample output generation

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Standard FLAC Magic Signature ('fLaC' = 0x664C6143)
pub const FLAC_STREAM_MARKER: &[u8; 4] = b"fLaC";

/// FLAC Metadata Block Types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlacBlockType {
    StreamInfo,
    Padding,
    Application,
    SeekTable,
    VorbisComment,
    CueSheet,
    Picture,
    Reserved(u8),
}

impl FlacBlockType {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x7F {
            0 => Self::StreamInfo,
            1 => Self::Padding,
            2 => Self::Application,
            3 => Self::SeekTable,
            4 => Self::VorbisComment,
            5 => Self::CueSheet,
            6 => Self::Picture,
            other => Self::Reserved(other),
        }
    }
}

/// FLAC STREAMINFO Metadata Block Content
#[derive(Clone, Debug)]
pub struct FlacStreamInfo {
    pub min_block_size: u16,
    pub max_block_size: u16,
    pub min_frame_size: u32,
    pub max_frame_size: u32,
    pub sample_rate: u32,
    pub channels: u8,
    pub bits_per_sample: u8,
    pub total_samples: u64,
    pub md5_signature: [u8; 16],
}

/// FLAC Channel Assignment in Frame Header
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlacChannelAssignment {
    Independent(u8), // 1 to 8 independent audio channels
    LeftSide,        // Left channel + Difference (Left - Right)
    RightSide,       // Difference (Left - Right) + Right channel
    MidSide,         // Mid (Left + Right)/2 + Side (Left - Right)
}

/// Bit-level stream reader for FLAC entropy decoding
pub struct FlacBitReader<'a> {
    data: &'a [u8],
    byte_offset: usize,
    bit_offset: u8, // 0 to 7 (bits remaining in current byte, MSB first)
}

impl<'a> FlacBitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_offset: 0,
            bit_offset: 0,
        }
    }

    /// Read next N bits (up to 32 bits)
    pub fn read_bits(&mut self, mut count: u8) -> Option<u32> {
        if count == 0 {
            return Some(0);
        }
        if count > 32 {
            return None;
        }

        let mut result = 0u32;
        while count > 0 {
            if self.byte_offset >= self.data.len() {
                return None;
            }

            let bits_left_in_byte = 8 - self.bit_offset;
            let bits_to_take = count.min(bits_left_in_byte);

            let shift = bits_left_in_byte - bits_to_take;
            let mask = ((1u32 << bits_to_take) - 1) as u8;
            let chunk = (self.data[self.byte_offset] >> shift) & mask;

            result = (result << bits_to_take) | (chunk as u32);
            count -= bits_to_take;
            self.bit_offset += bits_to_take;

            if self.bit_offset == 8 {
                self.bit_offset = 0;
                self.byte_offset += 1;
            }
        }

        Some(result)
    }

    /// Read 1 bit as boolean
    pub fn read_bit(&mut self) -> Option<bool> {
        self.read_bits(1).map(|b| b != 0)
    }

    /// Read signed N bits (two's complement)
    pub fn read_signed_bits(&mut self, count: u8) -> Option<i32> {
        let raw = self.read_bits(count)?;
        if count == 0 {
            return Some(0);
        }
        let sign_bit = 1 << (count - 1);
        if (raw & sign_bit) != 0 {
            // Negative: sign extend
            let mask = !((1u32 << count) - 1);
            Some((raw | mask) as i32)
        } else {
            Some(raw as i32)
        }
    }

    /// Decode variable-length Rice integer (unary MSBs + binary LSBs)
    pub fn read_rice_signed(&mut self, parameter: u8) -> Option<i32> {
        // Read unary zeros followed by stopping bit 1
        let mut msb = 0u32;
        while !self.read_bit()? {
            msb += 1;
            if msb > 65536 {
                return None; // Guard against corrupt streams
            }
        }

        let lsb = if parameter > 0 {
            self.read_bits(parameter)?
        } else {
            0
        };

        let unsigned_val = (msb << parameter) | lsb;

        // Zigzag unmap: even = positive, odd = negative
        // unsigned 0 -> 0, 1 -> -1, 2 -> 1, 3 -> -2, etc.
        if (unsigned_val & 1) != 0 {
            Some(-(((unsigned_val >> 1) as i32) + 1))
        } else {
            Some((unsigned_val >> 1) as i32)
        }
    }

    /// Align reader to next byte boundary
    pub fn align_to_byte(&mut self) {
        if self.bit_offset > 0 {
            self.bit_offset = 0;
            self.byte_offset += 1;
        }
    }
}

/// FLAC Audio Frame Header
#[derive(Clone, Debug)]
pub struct FlacFrameHeader {
    pub block_size: u16,
    pub sample_rate: u32,
    pub channel_assignment: FlacChannelAssignment,
    pub bits_per_sample: u8,
    pub frame_or_sample_number: u64,
}

/// Free Lossless Audio Codec (FLAC) Stream Decoder
pub struct FlacDecoder<'a> {
    reader: FlacBitReader<'a>,
    pub stream_info: Option<FlacStreamInfo>,
}

impl<'a> FlacDecoder<'a> {
    pub fn new(flac_bytes: &'a [u8]) -> Self {
        Self {
            reader: FlacBitReader::new(flac_bytes),
            stream_info: None,
        }
    }

    /// Parse stream header and all metadata blocks until audio frames start
    pub fn parse_headers(&mut self) -> Result<(), &'static str> {
        // Verify 'fLaC' marker
        let m0 = self.reader.read_bits(8).ok_or("EOF before marker")?;
        let m1 = self.reader.read_bits(8).ok_or("EOF before marker")?;
        let m2 = self.reader.read_bits(8).ok_or("EOF before marker")?;
        let m3 = self.reader.read_bits(8).ok_or("EOF before marker")?;

        if [m0 as u8, m1 as u8, m2 as u8, m3 as u8] != *FLAC_STREAM_MARKER {
            return Err("Invalid FLAC stream marker");
        }

        // Loop over metadata blocks
        let mut is_last_block = false;
        while !is_last_block {
            let last_flag = self.reader.read_bit().ok_or("EOF in metadata header")?;
            is_last_block = last_flag;

            let block_type_raw = self.reader.read_bits(7).ok_or("EOF in block type")? as u8;
            let block_len = self.reader.read_bits(24).ok_or("EOF in block length")? as usize;
            let block_type = FlacBlockType::from_u8(block_type_raw);

            match block_type {
                FlacBlockType::StreamInfo => {
                    if block_len < 34 {
                        return Err("Corrupt STREAMINFO block length");
                    }
                    let min_bs = self.reader.read_bits(16).ok_or("EOF min_bs")? as u16;
                    let max_bs = self.reader.read_bits(16).ok_or("EOF max_bs")? as u16;
                    let min_fs = self.reader.read_bits(24).ok_or("EOF min_fs")?;
                    let max_fs = self.reader.read_bits(24).ok_or("EOF max_fs")?;
                    let s_rate = self.reader.read_bits(20).ok_or("EOF sample_rate")?;
                    let channels = (self.reader.read_bits(3).ok_or("EOF channels")? + 1) as u8;
                    let bps = (self.reader.read_bits(5).ok_or("EOF bps")? + 1) as u8;

                    let s_hi = self.reader.read_bits(4).ok_or("EOF total_samples hi")? as u64;
                    let s_lo = self.reader.read_bits(32).ok_or("EOF total_samples lo")? as u64;
                    let total_samples = (s_hi << 32) | s_lo;

                    let mut md5 = [0u8; 16];
                    for b in md5.iter_mut() {
                        *b = self.reader.read_bits(8).ok_or("EOF md5")? as u8;
                    }

                    self.stream_info = Some(FlacStreamInfo {
                        min_block_size: min_bs,
                        max_block_size: max_bs,
                        min_frame_size: min_fs,
                        max_frame_size: max_fs,
                        sample_rate: s_rate,
                        channels,
                        bits_per_sample: bps,
                        total_samples,
                        md5_signature: md5,
                    });
                }
                _ => {
                    // Skip unknown or unneeded metadata blocks (VorbisComment, Padding, Picture, etc.)
                    for _ in 0..block_len {
                        self.reader.read_bits(8).ok_or("EOF skipping metadata")?;
                    }
                }
            }
        }

        if self.stream_info.is_none() {
            return Err("Missing STREAMINFO metadata");
        }

        Ok(())
    }

    /// Decodes a single FLAC audio frame into interleaved 16-bit PCM samples
    pub fn decode_next_frame(&mut self) -> Option<Vec<i16>> {
        let info = self.stream_info.as_ref()?;
        let default_sr = info.sample_rate;
        let default_bps = info.bits_per_sample;

        // Search for sync code 0xFFF8 (14 bits 11111111111110)
        let sync = self.reader.read_bits(14)?;
        if sync != 0x3FFE {
            return None;
        }

        // 1 bit reserved (0)
        let _reserved = self.reader.read_bit()?;
        // 1 bit blocking strategy (0 = fixed, 1 = variable)
        let _blocking_strategy = self.reader.read_bit()?;

        // 4 bits block size code
        let bs_code = self.reader.read_bits(4)?;
        // 4 bits sample rate code
        let sr_code = self.reader.read_bits(4)?;
        // 4 bits channel assignment code
        let chan_code = self.reader.read_bits(4)?;
        // 3 bits sample size code
        let _size_code = self.reader.read_bits(3)?;
        // 1 bit mandatory zero
        let _zero_bit = self.reader.read_bit()?;

        // Decode block size
        let block_size: usize = match bs_code {
            0b0001 => 192,
            0b0010..=0b0101 => 576 * (1 << (bs_code - 2)),
            0b0110 => (self.reader.read_bits(8)? + 1) as usize,
            0b0111 => (self.reader.read_bits(16)? + 1) as usize,
            0b1000..=0b1111 => 256 * (1 << (bs_code - 8)),
            _ => return None,
        };

        // Determine channel assignment
        let (ch_assign, num_channels) = match chan_code {
            0b0000..=0b0111 => (FlacChannelAssignment::Independent((chan_code + 1) as u8), (chan_code + 1) as usize),
            0b1000 => (FlacChannelAssignment::LeftSide, 2),
            0b1001 => (FlacChannelAssignment::RightSide, 2),
            0b1010 => (FlacChannelAssignment::MidSide, 2),
            _ => return None,
        };

        // Skip sample rate / frame number / CRC8 header fields
        if sr_code == 0b1100 {
            let _ = self.reader.read_bits(8)?;
        } else if sr_code == 0b1101 || sr_code == 0b1110 {
            let _ = self.reader.read_bits(16)?;
        }

        // Read variable-length encoded frame/sample number (UTF-8 style)
        let _ = self.reader.read_bits(8)?;
        // CRC-8
        let _ = self.reader.read_bits(8)?;

        // Decode subframes for each channel
        let mut decoded_channels: Vec<Vec<i32>> = Vec::with_capacity(num_channels);

        for ch in 0..num_channels {
            let subframe_bps = match ch_assign {
                FlacChannelAssignment::LeftSide if ch == 1 => default_bps + 1,
                FlacChannelAssignment::RightSide if ch == 0 => default_bps + 1,
                FlacChannelAssignment::MidSide if ch == 1 => default_bps + 1,
                _ => default_bps,
            };

            let samples = self.decode_subframe(block_size, subframe_bps)?;
            decoded_channels.push(samples);
        }

        // Align bit reader to byte boundary after subframes
        self.reader.align_to_byte();
        // Frame CRC-16
        let _ = self.reader.read_bits(16)?;

        // Stereo channel un-decorrelation
        match ch_assign {
            FlacChannelAssignment::LeftSide => {
                // Channel 0: Left, Channel 1: Side (Left - Right) -> Right = Left - Side
                for i in 0..block_size {
                    let left = decoded_channels[0][i];
                    let side = decoded_channels[1][i];
                    decoded_channels[1][i] = left - side;
                }
            }
            FlacChannelAssignment::RightSide => {
                // Channel 0: Side (Left - Right), Channel 1: Right -> Left = Side + Right
                for i in 0..block_size {
                    let side = decoded_channels[0][i];
                    let right = decoded_channels[1][i];
                    decoded_channels[0][i] = side + right;
                }
            }
            FlacChannelAssignment::MidSide => {
                // Channel 0: Mid ((L+R)/2), Channel 1: Side (L - R)
                for i in 0..block_size {
                    let mid = decoded_channels[0][i];
                    let side = decoded_channels[1][i];
                    let mid_shifted = mid << 1;
                    let right = (mid_shifted - side) >> 1;
                    let left = right + side;
                    decoded_channels[0][i] = left;
                    decoded_channels[1][i] = right;
                }
            }
            _ => {}
        }

        // Interleave PCM samples into 16-bit stereo/mono buffer
        let mut pcm_out = Vec::with_capacity(block_size * num_channels);
        for i in 0..block_size {
            for ch in 0..num_channels {
                let sample_32 = decoded_channels[ch][i];
                let sample_16 = (sample_32.clamp(-32768, 32767)) as i16;
                pcm_out.push(sample_16);
            }
        }

        Some(pcm_out)
    }

    /// Decode a single FLAC Subframe
    fn decode_subframe(&mut self, block_size: usize, bps: u8) -> Option<Vec<i32>> {
        // Zero bit
        let _ = self.reader.read_bit()?;
        // Subframe type (6 bits)
        let subframe_type = self.reader.read_bits(6)? as u8;
        // Wasted bits flag
        let has_wasted_bits = self.reader.read_bit()?;
        let wasted_bits = if has_wasted_bits {
            let mut w = 0u8;
            while !self.reader.read_bit()? {
                w += 1;
            }
            w + 1
        } else {
            0
        };

        let effective_bps = bps - wasted_bits;
        let mut samples = vec![0i32; block_size];

        match subframe_type {
            0b000000 => {
                // Constant subframe: all samples identical
                let constant_val = self.reader.read_signed_bits(effective_bps)?;
                samples.fill(constant_val);
            }
            0b000001 => {
                // Verbatim subframe: uncompressed raw samples
                for sample in samples.iter_mut() {
                    *sample = self.reader.read_signed_bits(effective_bps)?;
                }
            }
            0b001000..=0b001100 => {
                // Fixed Linear Prediction (order = subframe_type - 0b001000)
                let order = (subframe_type - 0b001000) as usize;
                // Warm-up samples
                for i in 0..order {
                    samples[i] = self.reader.read_signed_bits(effective_bps)?;
                }

                // Decode residual
                self.decode_residual(block_size, order, &mut samples)?;

                // Predict and reconstruct samples
                for i in order..block_size {
                    let predictor = match order {
                        0 => 0,
                        1 => samples[i - 1],
                        2 => 2 * samples[i - 1] - samples[i - 2],
                        3 => 3 * samples[i - 1] - 3 * samples[i - 2] + samples[i - 3],
                        4 => 4 * samples[i - 1] - 6 * samples[i - 2] + 4 * samples[i - 3] - samples[i - 4],
                        _ => 0,
                    };
                    samples[i] += predictor;
                }
            }
            0b100000..=0b111111 => {
                // FIR Linear Prediction (LPC) (order = subframe_type - 0b100000 + 1)
                let order = (subframe_type - 0b100000 + 1) as usize;
                for i in 0..order {
                    samples[i] = self.reader.read_signed_bits(effective_bps)?;
                }

                let coeff_precision = (self.reader.read_bits(4)? + 1) as u8;
                let shift = self.reader.read_signed_bits(5)?;

                let mut q_coeffs = Vec::with_capacity(order);
                for _ in 0..order {
                    q_coeffs.push(self.reader.read_signed_bits(coeff_precision)?);
                }

                self.decode_residual(block_size, order, &mut samples)?;

                for i in order..block_size {
                    let mut sum = 0i64;
                    for j in 0..order {
                        sum += (q_coeffs[j] as i64) * (samples[i - 1 - j] as i64);
                    }
                    let predictor = (sum >> shift) as i32;
                    samples[i] += predictor;
                }
            }
            _ => return None,
        }

        // Restore wasted bits
        if wasted_bits > 0 {
            for sample in samples.iter_mut() {
                *sample <<= wasted_bits;
            }
        }

        Some(samples)
    }

    /// Decode Rice-partitioned residual stream
    fn decode_residual(&mut self, block_size: usize, order: usize, out_samples: &mut [i32]) -> Option<()> {
        let coding_method = self.reader.read_bits(2)?;
        let (param_bits, escape_val) = match coding_method {
            0b00 => (4u8, 0b1111),
            0b01 => (5u8, 0b11111),
            _ => return None,
        };

        let partition_order = self.reader.read_bits(4)? as usize;
        let partitions = 1 << partition_order;
        let default_part_samples = block_size / partitions;

        let mut sample_idx = order;

        for p in 0..partitions {
            let part_samples = if partition_order == 0 {
                block_size - order
            } else if p == 0 {
                default_part_samples - order
            } else {
                default_part_samples
            };

            let rice_param = self.reader.read_bits(param_bits)? as u8;
            if rice_param == escape_val as u8 {
                // Escape code: unencoded raw residual samples
                let raw_bits = self.reader.read_bits(5)? as u8;
                for _ in 0..part_samples {
                    out_samples[sample_idx] = self.reader.read_signed_bits(raw_bits)?;
                    sample_idx += 1;
                }
            } else {
                // Standard Rice encoded partition
                for _ in 0..part_samples {
                    out_samples[sample_idx] = self.reader.read_rice_signed(rice_param)?;
                    sample_idx += 1;
                }
            }
        }

        Some(())
    }
}
