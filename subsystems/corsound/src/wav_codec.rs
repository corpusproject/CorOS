//! RIFF/WAVE audio container parser and encoder supporting uncompressed Linear PCM (`FMT_PCM = 1`)
//! and 32-bit IEEE floating-point (`FMT_IEEE_FLOAT = 3`) streams.

/// WAVE format tag for Linear Integer PCM.
pub const FMT_PCM: u16 = 1;
/// WAVE format tag for IEEE 754 Floating-Point PCM.
pub const FMT_IEEE_FLOAT: u16 = 3;

/// Parsed or constructed WAVE `fmt ` subchunk metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavFormatChunk {
    /// Format category (`FMT_PCM = 1` or `FMT_IEEE_FLOAT = 3`).
    pub audio_format: u16,
    /// Number of interleaved audio channels.
    pub num_channels: u16,
    /// Sample frames per second (Hz).
    pub sample_rate: u32,
    /// Average bytes per second (`sample_rate * block_align`).
    pub byte_rate: u32,
    /// Bytes per complete multi-channel sample frame (`num_channels * bits_per_sample / 8`).
    pub block_align: u16,
    /// Bits per individual channel sample (`8`, `16`, `24`, or `32`).
    pub bits_per_sample: u16,
}

impl WavFormatChunk {
    /// Construct a validated PCM or IEEE Float `fmt ` chunk descriptor.
    pub const fn new(
        audio_format: u16,
        num_channels: u16,
        sample_rate: u32,
        bits_per_sample: u16,
    ) -> Self {
        let bytes_per_sample = bits_per_sample / 8;
        let block_align = num_channels * bytes_per_sample;
        let byte_rate = sample_rate * (block_align as u32);
        Self {
            audio_format,
            num_channels,
            sample_rate,
            byte_rate,
            block_align,
            bits_per_sample,
        }
    }
}

/// Complete RIFF/WAVE container descriptor including the byte offset and length of the `data` subchunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WavHeader {
    /// Format subchunk parameters.
    pub format: WavFormatChunk,
    /// Byte offset inside the container where the raw sample frames begin.
    pub data_offset: usize,
    /// Size in bytes of the `data` payload subchunk.
    pub data_size: u32,
}

/// Errors encountered while parsing or encoding a RIFF/WAVE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WavError {
    /// Buffer is shorter than the minimum 44-byte RIFF/WAVE header.
    TruncatedContainer,
    /// Missing `"RIFF"` or `"WAVE"` magic identifiers.
    InvalidRiffMagic,
    /// Unsupported format tag or inconsistent `block_align`/`bits_per_sample`.
    UnsupportedFormat,
    /// Container is missing either the `"fmt "` or `"data"` subchunk.
    MissingRequiredChunk,
}

impl WavHeader {
    /// Parse a RIFF/WAVE container from `bytes`, walking subchunks (`fmt `, `JUNK`, `LIST`, `data`, etc.).
    pub fn parse(bytes: &[u8]) -> Result<Self, WavError> {
        if bytes.len() < 44 {
            return Err(WavError::TruncatedContainer);
        }
        if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Err(WavError::InvalidRiffMagic);
        }

        let mut cursor = 12usize;
        let mut parsed_fmt: Option<WavFormatChunk> = None;
        let mut found_data: Option<(usize, u32)> = None;

        while cursor + 8 <= bytes.len() {
            let chunk_id = &bytes[cursor..cursor + 4];
            let chunk_size = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]);
            let payload_start = cursor + 8;
            let payload_end = payload_start.saturating_add(chunk_size as usize);

            if chunk_id == b"fmt " {
                if chunk_size < 16 || payload_end > bytes.len() {
                    return Err(WavError::TruncatedContainer);
                }
                let fmt_slice = &bytes[payload_start..payload_start + 16];
                let audio_format = u16::from_le_bytes([fmt_slice[0], fmt_slice[1]]);
                if audio_format != FMT_PCM && audio_format != FMT_IEEE_FLOAT {
                    return Err(WavError::UnsupportedFormat);
                }
                let num_channels = u16::from_le_bytes([fmt_slice[2], fmt_slice[3]]);
                let sample_rate =
                    u32::from_le_bytes([fmt_slice[4], fmt_slice[5], fmt_slice[6], fmt_slice[7]]);
                let byte_rate =
                    u32::from_le_bytes([fmt_slice[8], fmt_slice[9], fmt_slice[10], fmt_slice[11]]);
                let block_align = u16::from_le_bytes([fmt_slice[12], fmt_slice[13]]);
                let bits_per_sample = u16::from_le_bytes([fmt_slice[14], fmt_slice[15]]);

                if num_channels == 0
                    || sample_rate == 0
                    || (bits_per_sample != 8
                        && bits_per_sample != 16
                        && bits_per_sample != 24
                        && bits_per_sample != 32)
                {
                    return Err(WavError::UnsupportedFormat);
                }
                let expected_align = num_channels * (bits_per_sample / 8);
                if block_align != expected_align {
                    return Err(WavError::UnsupportedFormat);
                }

                parsed_fmt = Some(WavFormatChunk {
                    audio_format,
                    num_channels,
                    sample_rate,
                    byte_rate,
                    block_align,
                    bits_per_sample,
                });
            } else if chunk_id == b"data" {
                found_data = Some((payload_start, chunk_size));
                break;
            }

            // RIFF chunks are word-aligned (padded to an even number of bytes).
            let padded_size = (chunk_size as usize) + ((chunk_size as usize) & 1);
            cursor = payload_start.saturating_add(padded_size);
        }

        let format = parsed_fmt.ok_or(WavError::MissingRequiredChunk)?;
        let (data_offset, data_size) = found_data.ok_or(WavError::MissingRequiredChunk)?;
        Ok(Self {
            format,
            data_offset,
            data_size,
        })
    }

    /// Encode a canonical 44-byte RIFF/WAVE header into `out_header`.
    pub fn build_riff_header(&self) -> [u8; 44] {
        let mut buf = [0u8; 44];
        let riff_chunk_size = 36u32.saturating_add(self.data_size);

        buf[0..4].copy_from_slice(b"RIFF");
        buf[4..8].copy_from_slice(&riff_chunk_size.to_le_bytes());
        buf[8..12].copy_from_slice(b"WAVE");

        // "fmt " subchunk (16 bytes payload)
        buf[12..16].copy_from_slice(b"fmt ");
        buf[16..20].copy_from_slice(&16u32.to_le_bytes());
        buf[20..22].copy_from_slice(&self.format.audio_format.to_le_bytes());
        buf[22..24].copy_from_slice(&self.format.num_channels.to_le_bytes());
        buf[24..28].copy_from_slice(&self.format.sample_rate.to_le_bytes());
        buf[28..32].copy_from_slice(&self.format.byte_rate.to_le_bytes());
        buf[32..34].copy_from_slice(&self.format.block_align.to_le_bytes());
        buf[34..36].copy_from_slice(&self.format.bits_per_sample.to_le_bytes());

        // "data" subchunk header
        buf[36..40].copy_from_slice(b"data");
        buf[40..44].copy_from_slice(&self.data_size.to_le_bytes());
        buf
    }

    /// Return the total number of complete multi-channel sample frames in the `data` subchunk.
    #[inline]
    pub const fn total_frames(&self) -> usize {
        if self.format.block_align == 0 {
            0
        } else {
            (self.data_size as usize) / (self.format.block_align as usize)
        }
    }

    /// Slice out the raw bytes corresponding to frame range `[start_frame .. start_frame + frame_count]`
    /// from the container `container_bytes`.
    pub fn slice_sample_frames<'a>(
        &self,
        container_bytes: &'a [u8],
        start_frame: usize,
        frame_count: usize,
    ) -> Option<&'a [u8]> {
        let align = self.format.block_align as usize;
        if align == 0 {
            return None;
        }
        let data_end = self
            .data_offset
            .checked_add(self.data_size as usize)?
            .min(container_bytes.len());
        if self.data_offset > data_end {
            return None;
        }
        let data_slice = &container_bytes[self.data_offset..data_end];
        let byte_start = start_frame.checked_mul(align)?;
        let byte_len = frame_count.checked_mul(align)?;
        let byte_end = byte_start.checked_add(byte_len)?;
        if byte_end <= data_slice.len() {
            Some(&data_slice[byte_start..byte_end])
        } else {
            None
        }
    }

    /// Convert a 32-bit IEEE 754 float sample (in `-1.0 ..= +1.0` encoded as little-endian bytes)
    /// into signed 16-bit PCM using integer bit manipulation of the IEEE-754 binary32 representation.
    pub fn ieee_float32_le_to_s16(raw_four_bytes: [u8; 4]) -> i16 {
        let bits = u32::from_le_bytes(raw_four_bytes);
        let sign = (bits >> 31) != 0;
        let exp = ((bits >> 23) & 0xFF) as i32;
        let mantissa = (bits & 0x7F_FFFF) | 0x80_0000; // implicit leading 1 in Q23

        if exp == 0 {
            return 0;
        }
        if exp >= 127 {
            // Magnitude >= 1.0 saturates to full-scale i16
            return if sign { -32_767 } else { 32_767 };
        }
        let shift = 127 - exp;
        if shift > 16 {
            return 0;
        }
        // Scale Q23 mantissa to 15-bit magnitude: (mantissa * 32767) >> (23 + shift)
        let scaled = ((mantissa as u64 * 32_767) >> (23 + shift)) as i16;
        if sign {
            -scaled
        } else {
            scaled
        }
    }
}
