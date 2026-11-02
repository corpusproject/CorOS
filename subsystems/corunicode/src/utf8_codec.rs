//! UTF-8 Byte Sequence Codec, Strict Decoder & Resilient Scanner.
//! Pure `#![no_std]` Rust Unicode registry without numbered repetition.

/// Decoding result of a single UTF-8 codepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Utf8DecodeResult {
    Valid { codepoint: char, bytes_consumed: usize },
    InvalidSequence { bytes_consumed: usize },
    Incomplete,
}

/// Decodes the first UTF-8 codepoint from a raw byte slice.
pub fn decode_utf8_char(bytes: &[u8]) -> Utf8DecodeResult {
    if bytes.is_empty() {
        return Utf8DecodeResult::Incomplete;
    }

    let b0 = bytes[0];
    if b0 < 0x80 {
        return Utf8DecodeResult::Valid {
            codepoint: b0 as char,
            bytes_consumed: 1,
        };
    }

    // 2-byte sequence (110xxxxx 10xxxxxx)
    if (b0 & 0xE0) == 0xC0 {
        if bytes.len() < 2 {
            return Utf8DecodeResult::Incomplete;
        }
        let b1 = bytes[1];
        if (b1 & 0xC0) != 0x80 || b0 < 0xC2 {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 1 };
        }
        let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
        if let Some(c) = core::char::from_u32(cp) {
            return Utf8DecodeResult::Valid {
                codepoint: c,
                bytes_consumed: 2,
            };
        } else {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 2 };
        }
    }

    // 3-byte sequence (1110xxxx 10xxxxxx 10xxxxxx)
    if (b0 & 0xF0) == 0xE0 {
        if bytes.len() < 3 {
            return Utf8DecodeResult::Incomplete;
        }
        let b1 = bytes[1];
        let b2 = bytes[2];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 1 };
        }
        let cp = (((b0 & 0x0F) as u32) << 12) | (((b1 & 0x3F) as u32) << 6) | ((b2 & 0x3F) as u32);
        // Exclude surrogates (0xD800 - 0xDFFF)
        if (0xD800..=0xDFFF).contains(&cp) {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 3 };
        }
        if let Some(c) = core::char::from_u32(cp) {
            return Utf8DecodeResult::Valid {
                codepoint: c,
                bytes_consumed: 3,
            };
        } else {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 3 };
        }
    }

    // 4-byte sequence (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
    if (b0 & 0xF8) == 0xF0 {
        if bytes.len() < 4 {
            return Utf8DecodeResult::Incomplete;
        }
        let b1 = bytes[1];
        let b2 = bytes[2];
        let b3 = bytes[3];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 1 };
        }
        let cp = (((b0 & 0x07) as u32) << 18)
            | (((b1 & 0x3F) as u32) << 12)
            | (((b2 & 0x3F) as u32) << 6)
            | ((b3 & 0x3F) as u32);
        if cp > 0x10FFFF {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 4 };
        }
        if let Some(c) = core::char::from_u32(cp) {
            return Utf8DecodeResult::Valid {
                codepoint: c,
                bytes_consumed: 4,
            };
        } else {
            return Utf8DecodeResult::InvalidSequence { bytes_consumed: 4 };
        }
    }

    Utf8DecodeResult::InvalidSequence { bytes_consumed: 1 }
}
