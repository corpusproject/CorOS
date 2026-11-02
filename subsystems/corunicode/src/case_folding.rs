//! Unicode 15.1 Case Folding, Turkish Dotted/Dotless I Special Mappings & Case Conversions.
//! Pure `#![no_std]` Rust Unicode registry without numbered repetition.

/// Turkish & Azeri Locale special casing rules.
pub mod turkish_casing {
    /// In Turkish: 'I' (U+0049) -> 'ı' (U+0131), and 'İ' (U+0130) -> 'i' (U+0069).
    pub fn to_lowercase_turkish(c: char) -> char {
        match c {
            'I' => '\u{0131}', // ı (Latin small letter dotless i)
            'İ' => 'i',        // Latin small letter i with dot
            'Ğ' => 'ğ',
            'Ü' => 'ü',
            'Ş' => 'ş',
            'Ö' => 'ö',
            'Ç' => 'ç',
            other => other.to_ascii_lowercase(),
        }
    }

    /// In Turkish: 'i' (U+0069) -> 'İ' (U+0130), and 'ı' (U+0131) -> 'I' (U+0049).
    pub fn to_uppercase_turkish(c: char) -> char {
        match c {
            'i' => '\u{0130}', // İ (Latin capital letter I with dot above)
            '\u{0131}' => 'I', // ı -> I
            'ğ' => 'Ğ',
            'ü' => 'Ü',
            'ş' => 'Ş',
            'ö' => 'Ö',
            'ç' => 'Ç',
            other => other.to_ascii_uppercase(),
        }
    }
}

/// Simple 1:1 Unicode Case Folding pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseFoldPair {
    pub from: u32,
    pub to: u32,
}

/// Standard Common & Simple Case Folding table (subset of CaseFolding.txt).
pub static COMMON_CASE_FOLDING_TABLE: &[CaseFoldPair] = &[
    // Greek
    CaseFoldPair { from: 0x0391, to: 0x03B1 }, // ALPHA -> alpha
    CaseFoldPair { from: 0x0392, to: 0x03B2 }, // BETA -> beta
    CaseFoldPair { from: 0x0393, to: 0x03B3 }, // GAMMA -> gamma
    CaseFoldPair { from: 0x0394, to: 0x03B4 }, // DELTA -> delta
    CaseFoldPair { from: 0x03A9, to: 0x03C9 }, // OMEGA -> omega
    // Cyrillic
    CaseFoldPair { from: 0x0410, to: 0x0430 }, // A -> a
    CaseFoldPair { from: 0x0411, to: 0x0431 }, // B -> b
    CaseFoldPair { from: 0x0412, to: 0x0432 }, // V -> v
    CaseFoldPair { from: 0x0413, to: 0x0433 }, // G -> g
    CaseFoldPair { from: 0x0414, to: 0x0434 }, // D -> d
    CaseFoldPair { from: 0x042F, to: 0x044F }, // YA -> ya
];

/// Applies simple Unicode case folding.
pub fn fold_case_codepoint(cp: u32) -> u32 {
    if cp >= 0x0041 && cp <= 0x005A {
        return cp + 32; // ASCII A-Z -> a-z
    }
    for pair in COMMON_CASE_FOLDING_TABLE {
        if pair.from == cp {
            return pair.to;
        }
    }
    cp
}
