#![no_std]
//! `corunicode` — CorOS Unicode 15.1 Character Properties, Case Folding & Terminal Metrics.
//! Pure `#![no_std]` Rust Unicode registry without numbered template repetition.

extern crate alloc;

pub mod categories;
pub mod case_folding;
pub mod east_asian_width;
pub mod utf8_codec;
pub mod bidi;
pub mod decomposition;

/// Runs comprehensive self-tests verifying Unicode classifications, Turkish casing and UTF-8 decoding.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. General Category lookups
    if categories::lookup_general_category(0x0041) == categories::UnicodeGeneralCategory::UppercaseLetter {
        passed += 1;
    }
    if categories::lookup_general_category(0x0130) == categories::UnicodeGeneralCategory::UppercaseLetter {
        // Turkish İ
        passed += 1;
    }

    // 2. Turkish casing special rules (i <-> İ, ı <-> I)
    let tr_upper = case_folding::turkish_casing::to_uppercase_turkish('i');
    let tr_lower = case_folding::turkish_casing::to_lowercase_turkish('I');
    if tr_upper == '\u{0130}' && tr_lower == '\u{0131}' {
        passed += 1;
    }

    // 3. East Asian terminal column widths
    if east_asian_width::char_terminal_width('A') == 1 && east_asian_width::char_terminal_width('日') == 2 {
        passed += 1;
    }
    let cols = east_asian_width::str_terminal_columns("CorOS İşletim Sistemi");
    if cols == 21 {
        passed += 1;
    }

    // 4. UTF-8 Decoder verification
    let utf8_bytes = "CorOS 🚀 Ğ".as_bytes();
    let mut decoded_chars = 0;
    let mut offset = 0;
    while offset < utf8_bytes.len() {
        match utf8_codec::decode_utf8_char(&utf8_bytes[offset..]) {
            utf8_codec::Utf8DecodeResult::Valid { bytes_consumed, .. } => {
                decoded_chars += 1;
                offset += bytes_consumed;
            }
            _ => break,
        }
    }
    if decoded_chars == 8 {
        passed += 1;
    }

    // 5. BiDi Character Class verification
    if bidi::lookup_bidi_class('A' as u32) == bidi::BidiClass::L {
        passed += 1;
    }
    if bidi::is_rtl(0x05D0) && bidi::is_rtl(0x0627) {
        // Hebrew Alef and Arabic Alef
        passed += 1;
    }

    // 6. Canonical Decomposition verification
    if let Some((base, mark)) = decomposition::decompose_canonical('ç') {
        if base == 'c' && mark == '\u{0327}' {
            passed += 1;
        }
    }
    if let Some(composed) = decomposition::compose_canonical('g', '\u{0306}') {
        if composed == 'ğ' {
            passed += 1;
        }
    }

    passed
}
