//! UAX #11 East Asian Width (Fullwidth, Halfwidth, Wide, Narrow, Neutral) & Terminal Column Widths.
//! Pure `#![no_std]` Rust Unicode registry without numbered repetition.

/// East Asian Width property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EastAsianWidth {
    Neutral,   // N
    Ambiguous, // A
    Halfwidth, // H
    Fullwidth, // F
    Narrow,    // Na
    Wide,      // W
}

/// Computes the terminal column width (1 column or 2 columns) of a Unicode character.
/// Essential for clean terminal alignment in OS shells (`corcoreutils`).
pub fn char_terminal_width(c: char) -> usize {
    let cp = c as u32;

    // Control characters have 0 display width
    if cp < 0x20 || (cp >= 0x7F && cp < 0xA0) {
        return 0;
    }

    // Zero-width spaces and format characters
    if cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF {
        return 0;
    }

    // CJK Unified Ideographs, Fullwidth forms, Emojis take 2 columns
    if (0x1100..=0x115F).contains(&cp)    // Hangul Jamo
        || (0x2E80..=0x9FFF).contains(&cp)  // CJK Radicals, Ideographs
        || (0xAC00..=0xD7A3).contains(&cp)  // Hangul Syllables
        || (0xF900..=0xFAFF).contains(&cp)  // CJK Compatibility Ideographs
        || (0xFE10..=0xFE19).contains(&cp)  // Vertical forms
        || (0xFE30..=0xFE6F).contains(&cp)  // CJK Compatibility Forms
        || (0xFF01..=0xFF60).contains(&cp)  // Fullwidth ASCII variants
        || (0xFFE0..=0xFFE6).contains(&cp)  // Fullwidth symbols
        || (0x1F300..=0x1FAFF).contains(&cp) // Misc Symbols, Pictographs, Emojis
    {
        return 2;
    }

    // Standard Latin / Turkish / Cyrillic / Greek characters take 1 column
    1
}

/// Measures the display length in fixed terminal columns of a UTF-8 string slice.
pub fn str_terminal_columns(text: &str) -> usize {
    text.chars().map(char_terminal_width).sum()
}
