//! FLAC (Free Lossless Audio Codec) frame header parser, CRC-8 polynomial `0x07` verifier,
//! UTF-8 variable-length frame/sample number codec, and Constant / Verbatim / Fixed Linear
//! Predictor (orders `0..=4`) subframe decoder.

use alloc::vec::Vec;

/// Canonical 14-bit FLAC frame sync code (`0b11111111111110 == 0x3FFE`).
pub const FLAC_SYNC_CODE: u16 = 0x3FFE;

/// FLAC channel assignment modes encoded in the 4-bit header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlacChannelAssignment {
    /// `1..=8` independent channels.
    Independent(u8),
    /// Left + Side stereo (`ch0 = left`, `ch1 = left - right`).
    LeftSideStereo,
    /// Side + Right stereo (`ch0 = left - right`, `ch1 = right`).
    SideRightStereo,
    /// Mid + Side stereo (`ch0 = (left + right) >> 1`, `ch1 = left - right`).
    MidSideStereo,
}

/// Parsed FLAC frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlacFrameHeader {
    /// True if variable-blocksize stream (UTF-8 number is sample index); false if fixed-blocksize (frame index).
    pub variable_block_size: bool,
    /// Decoded block size in samples per channel.
    pub block_size: u32,
    /// Decoded sample rate in Hz (`0` means defer to STREAMINFO).
    pub sample_rate: u32,
    /// Channel count and stereo decorrelation mode.
    pub channel_assignment: FlacChannelAssignment,
    /// Bits per sample (`8`, `12`, `16`, `20`, `24`, `32`).
    pub bits_per_sample: u8,
    /// UTF-8 coded frame number or sample number.
    pub coded_number: u64,
    /// Header CRC-8 checksum byte (`x^8 + x^2 + x^1 + x^0`, polynomial `0x07`).
    pub crc8: u8,
    /// Total byte length of the frame header including the CRC-8 byte.
    pub header_byte_len: usize,
}

/// Errors returned during FLAC frame or subframe decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlacError {
    /// Input slice ended prematurely.
    UnexpectedEof,
    /// 14-bit sync code `0x3FFE` was not found at the start of the frame.
    BadSyncCode,
    /// Reserved bit or forbidden table entry encountered in frame header.
    ReservedHeaderField,
    /// Malformed UTF-8 coded frame/sample number.
    InvalidUtf8Number,
    /// Frame header CRC-8 verification failed.
    Crc8Mismatch,
    /// Unsupported subframe predictor order (`> 4`).
    InvalidFixedOrder,
}

/// Compute FLAC CRC-8 with generator polynomial `0x07` (`x^8 + x^2 + x + 1`), initialized to `0x00`.
pub fn compute_flac_crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &byte in bytes {
        crc ^= byte;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Decode a FLAC UTF-8 style variable-length integer (up to 36 bits, 1..=7 bytes),
/// returning `(decoded_value, bytes_consumed)`.
pub fn decode_utf8_coded_number(data: &[u8]) -> Result<(u64, usize), FlacError> {
    let first = *data.first().ok_or(FlacError::UnexpectedEof)?;
    if (first & 0x80) == 0 {
        return Ok((first as u64, 1));
    }

    let leading_ones = (!first).leading_zeros() as usize;
    if leading_ones < 2 || leading_ones > 7 || data.len() < leading_ones {
        return Err(FlacError::InvalidUtf8Number);
    }

    let mask = if leading_ones == 7 {
        0u8
    } else {
        (1u8 << (7 - leading_ones)) - 1
    };
    let mut value = (first & mask) as u64;

    for idx in 1..leading_ones {
        let cont = data[idx];
        if (cont & 0xC0) != 0x80 {
            return Err(FlacError::InvalidUtf8Number);
        }
        value = (value << 6) | ((cont & 0x3F) as u64);
    }

    Ok((value, leading_ones))
}

/// Decode the 4-bit FLAC block size code and optional trailing 8/16-bit size field.
fn decode_block_size_code(code: u8, tail: &[u8]) -> Result<(u32, usize), FlacError> {
    match code {
        0 => Err(FlacError::ReservedHeaderField),
        1 => Ok((192, 0)),
        2..=5 => Ok((576 * (1u32 << (code - 2)), 0)),
        6 => {
            let b = *tail.first().ok_or(FlacError::UnexpectedEof)?;
            Ok(((b as u32) + 1, 1))
        }
        7 => {
            if tail.len() < 2 {
                return Err(FlacError::UnexpectedEof);
            }
            let val = u16::from_be_bytes([tail[0], tail[1]]) as u32;
            Ok((val + 1, 2))
        }
        8..=15 => Ok((256 * (1u32 << (code - 8)), 0)),
        _ => Err(FlacError::ReservedHeaderField),
    }
}

/// Decode the 4-bit FLAC sample rate code and optional trailing 8/16-bit rate field.
fn decode_sample_rate_code(code: u8, tail: &[u8]) -> Result<(u32, usize), FlacError> {
    match code {
        0 => Ok((0, 0)),
        1 => Ok((88_200, 0)),
        2 => Ok((176_400, 0)),
        3 => Ok((192_000, 0)),
        4 => Ok((8_000, 0)),
        5 => Ok((16_000, 0)),
        6 => Ok((22_050, 0)),
        7 => Ok((24_000, 0)),
        8 => Ok((32_000, 0)),
        9 => Ok((44_100, 0)),
        10 => Ok((48_000, 0)),
        11 => Ok((96_000, 0)),
        12 => {
            let khz = *tail.first().ok_or(FlacError::UnexpectedEof)?;
            Ok(((khz as u32) * 1_000, 1))
        }
        13 => {
            if tail.len() < 2 {
                return Err(FlacError::UnexpectedEof);
            }
            let hz = u16::from_be_bytes([tail[0], tail[1]]) as u32;
            Ok((hz, 2))
        }
        14 => {
            if tail.len() < 2 {
                return Err(FlacError::UnexpectedEof);
            }
            let tens_of_hz = u16::from_be_bytes([tail[0], tail[1]]) as u32;
            Ok((tens_of_hz * 10, 2))
        }
        _ => Err(FlacError::ReservedHeaderField),
    }
}

impl FlacFrameHeader {
    /// Parse and CRC-8-validate a FLAC frame header from `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Self, FlacError> {
        if bytes.len() < 6 {
            return Err(FlacError::UnexpectedEof);
        }
        let sync_word = u16::from_be_bytes([bytes[0], bytes[1]]);
        if (sync_word >> 2) != FLAC_SYNC_CODE {
            return Err(FlacError::BadSyncCode);
        }
        if (sync_word & 0x02) != 0 {
            return Err(FlacError::ReservedHeaderField);
        }
        let variable_block_size = (sync_word & 0x01) != 0;

        let bs_sr_byte = bytes[2];
        let bs_code = bs_sr_byte >> 4;
        let sr_code = bs_sr_byte & 0x0F;

        let ch_bps_byte = bytes[3];
        if (ch_bps_byte & 0x01) != 0 {
            return Err(FlacError::ReservedHeaderField);
        }
        let ch_code = ch_bps_byte >> 4;
        let bps_code = (ch_bps_byte >> 1) & 0x07;

        let channel_assignment = match ch_code {
            0..=7 => FlacChannelAssignment::Independent(ch_code + 1),
            8 => FlacChannelAssignment::LeftSideStereo,
            9 => FlacChannelAssignment::SideRightStereo,
            10 => FlacChannelAssignment::MidSideStereo,
            _ => return Err(FlacError::ReservedHeaderField),
        };

        let bits_per_sample = match bps_code {
            0 => 16,
            1 => 8,
            2 => 12,
            3 => return Err(FlacError::ReservedHeaderField),
            4 => 16,
            5 => 20,
            6 => 24,
            7 => 32,
            _ => return Err(FlacError::ReservedHeaderField),
        };

        let (coded_number, utf8_len) = decode_utf8_coded_number(&bytes[4..])?;
        let mut cursor = 4 + utf8_len;

        let (block_size, bs_extra) = decode_block_size_code(bs_code, &bytes[cursor..])?;
        cursor += bs_extra;

        let (sample_rate, sr_extra) = decode_sample_rate_code(sr_code, &bytes[cursor..])?;
        cursor += sr_extra;

        if cursor >= bytes.len() {
            return Err(FlacError::UnexpectedEof);
        }
        let expected_crc8 = bytes[cursor];
        let computed_crc8 = compute_flac_crc8(&bytes[..cursor]);
        if expected_crc8 != computed_crc8 {
            return Err(FlacError::Crc8Mismatch);
        }

        Ok(Self {
            variable_block_size,
            block_size,
            sample_rate,
            channel_assignment,
            bits_per_sample,
            coded_number,
            crc8: expected_crc8,
            header_byte_len: cursor + 1,
        })
    }
}

/// Decode a Constant subframe by repeating `constant_sample` for `block_size` samples.
pub fn decode_constant_subframe(constant_sample: i32, block_size: usize) -> Vec<i32> {
    let mut out = Vec::with_capacity(block_size);
    for _ in 0..block_size {
        out.push(constant_sample);
    }
    out
}

/// Decode a Verbatim subframe by copying unencoded warm samples directly.
pub fn decode_verbatim_subframe(raw_samples: &[i32]) -> Vec<i32> {
    raw_samples.to_vec()
}

/// Decode a FLAC Fixed Linear Predictor (`FIXED`) subframe for predictor orders `0..=4`.
///
/// The predictor reconstructs each sample $x[n]$ from the warm-up samples and residual signal $e[n]$:
/// - Order 0: $x[n] = e[n]$
/// - Order 1: $x[n] = x[n-1] + e[n]$
/// - Order 2: $x[n] = 2 x[n-1] - x[n-2] + e[n]$
/// - Order 3: $x[n] = 3 x[n-1] - 3 x[n-2] + x[n-3] + e[n]$
/// - Order 4: $x[n] = 4 x[n-1] - 6 x[n-2] + 4 x[n-3] - x[n-4] + e[n]$
pub fn decode_fixed_lpc_subframe(
    order: usize,
    warm_up_samples: &[i32],
    residuals: &[i32],
) -> Result<Vec<i32>, FlacError> {
    if order > 4 || warm_up_samples.len() != order {
        return Err(FlacError::InvalidFixedOrder);
    }

    let total_samples = order + residuals.len();
    let mut decoded = Vec::with_capacity(total_samples);
    decoded.extend_from_slice(warm_up_samples);

    for &residual in residuals {
        let len = decoded.len();
        let predicted: i64 = match order {
            0 => 0,
            1 => decoded[len - 1] as i64,
            2 => 2 * (decoded[len - 1] as i64) - (decoded[len - 2] as i64),
            3 => {
                3 * (decoded[len - 1] as i64) - 3 * (decoded[len - 2] as i64)
                    + (decoded[len - 3] as i64)
            }
            4 => {
                4 * (decoded[len - 1] as i64) - 6 * (decoded[len - 2] as i64)
                    + 4 * (decoded[len - 3] as i64)
                    - (decoded[len - 4] as i64)
            }
            _ => return Err(FlacError::InvalidFixedOrder),
        };
        let reconstructed = (predicted + residual as i64) as i32;
        decoded.push(reconstructed);
    }

    Ok(decoded)
}
