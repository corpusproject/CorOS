//! Unicode 15.1 General Categories, Property Ranges & Character Classifications.
//! Pure `#![no_std]` Rust Unicode registry without numbered repetition.

/// Unicode General Category according to UAX #44.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnicodeGeneralCategory {
    UppercaseLetter,   // Lu
    LowercaseLetter,   // Ll
    TitlecaseLetter,   // Lt
    ModifierLetter,    // Lm
    OtherLetter,       // Lo
    DecimalDigitNumber,// Nd
    LetterNumber,      // Nl
    OtherNumber,       // No
    SpaceSeparator,    // Zs
    LineSeparator,     // Zl
    ParagraphSeparator,// Zp
    Control,           // Cc
    Format,            // Cf
    Surrogate,         // Cs
    PrivateUse,        // Co
    Unassigned,        // Cn
    ConnectorPunctuation, // Pc
    DashPunctuation,      // Pd
    OpenPunctuation,      // Ps
    ClosePunctuation,     // Pe
    InitialPunctuation,   // Pi
    FinalPunctuation,     // Pf
    OtherPunctuation,     // Po
    MathSymbol,           // Sm
    CurrencySymbol,       // Sc
    ModifierSymbol,       // Sk
    OtherSymbol,          // So
}

/// Contiguous Unicode codepoint range with assigned general category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnicodeCategoryRange {
    pub start: u32,
    pub end: u32,
    pub category: UnicodeGeneralCategory,
}

/// Fundamental Unicode 15.1 basic multilingual plane (BMP) category ranges.
pub static UNICODE_CATEGORY_RANGES: &[UnicodeCategoryRange] = &[
    // Basic Latin C0 Controls
    UnicodeCategoryRange { start: 0x0000, end: 0x001F, category: UnicodeGeneralCategory::Control },
    // Space
    UnicodeCategoryRange { start: 0x0020, end: 0x0020, category: UnicodeGeneralCategory::SpaceSeparator },
    // ASCII Punctuation & Symbols
    UnicodeCategoryRange { start: 0x0021, end: 0x002F, category: UnicodeGeneralCategory::OtherPunctuation },
    // ASCII Digits (0 - 9)
    UnicodeCategoryRange { start: 0x0030, end: 0x0039, category: UnicodeGeneralCategory::DecimalDigitNumber },
    // Punctuation
    UnicodeCategoryRange { start: 0x003A, end: 0x0040, category: UnicodeGeneralCategory::OtherPunctuation },
    // ASCII Uppercase (A - Z)
    UnicodeCategoryRange { start: 0x0041, end: 0x005A, category: UnicodeGeneralCategory::UppercaseLetter },
    // Punctuation
    UnicodeCategoryRange { start: 0x005B, end: 0x0060, category: UnicodeGeneralCategory::OtherPunctuation },
    // ASCII Lowercase (a - z)
    UnicodeCategoryRange { start: 0x0061, end: 0x007A, category: UnicodeGeneralCategory::LowercaseLetter },
    // Punctuation & C0 DEL
    UnicodeCategoryRange { start: 0x007B, end: 0x007E, category: UnicodeGeneralCategory::OtherPunctuation },
    UnicodeCategoryRange { start: 0x007F, end: 0x009F, category: UnicodeGeneralCategory::Control },

    // Latin-1 Supplement: Turkish & European Letters
    UnicodeCategoryRange { start: 0x00C0, end: 0x00D6, category: UnicodeGeneralCategory::UppercaseLetter },
    UnicodeCategoryRange { start: 0x00D8, end: 0x00DE, category: UnicodeGeneralCategory::UppercaseLetter },
    UnicodeCategoryRange { start: 0x00DF, end: 0x00F6, category: UnicodeGeneralCategory::LowercaseLetter },
    UnicodeCategoryRange { start: 0x00F8, end: 0x00FF, category: UnicodeGeneralCategory::LowercaseLetter },

    // Latin Extended-A (Turkish Ç, ç, Ğ, ğ, İ, ı, Ö, ö, Ş, ş, Ü, ü)
    UnicodeCategoryRange { start: 0x011E, end: 0x011E, category: UnicodeGeneralCategory::UppercaseLetter }, // Ğ
    UnicodeCategoryRange { start: 0x011F, end: 0x011F, category: UnicodeGeneralCategory::LowercaseLetter }, // ğ
    UnicodeCategoryRange { start: 0x0130, end: 0x0130, category: UnicodeGeneralCategory::UppercaseLetter }, // İ (Dotted I)
    UnicodeCategoryRange { start: 0x0131, end: 0x0131, category: UnicodeGeneralCategory::LowercaseLetter }, // ı (Dotless i)
    UnicodeCategoryRange { start: 0x015E, end: 0x015E, category: UnicodeGeneralCategory::UppercaseLetter }, // Ş
    UnicodeCategoryRange { start: 0x015F, end: 0x015F, category: UnicodeGeneralCategory::LowercaseLetter }, // ş

    // Mathematical Operators
    UnicodeCategoryRange { start: 0x2200, end: 0x22FF, category: UnicodeGeneralCategory::MathSymbol },
    // Box Drawing Characters (useful for terminal UIs)
    UnicodeCategoryRange { start: 0x2500, end: 0x257F, category: UnicodeGeneralCategory::OtherSymbol },
    // Block Elements
    UnicodeCategoryRange { start: 0x2580, end: 0x259F, category: UnicodeGeneralCategory::OtherSymbol },
];

/// Looks up the General Category of a Unicode codepoint.
pub fn lookup_general_category(cp: u32) -> UnicodeGeneralCategory {
    for r in UNICODE_CATEGORY_RANGES {
        if cp >= r.start && cp <= r.end {
            return r.category;
        }
    }
    UnicodeGeneralCategory::Unassigned
}

/// Returns true if codepoint represents an alphabetic letter.
pub fn is_alphabetic(cp: u32) -> bool {
    match lookup_general_category(cp) {
        UnicodeGeneralCategory::UppercaseLetter
        | UnicodeGeneralCategory::LowercaseLetter
        | UnicodeGeneralCategory::TitlecaseLetter
        | UnicodeGeneralCategory::ModifierLetter
        | UnicodeGeneralCategory::OtherLetter => true,
        _ => false,
    }
}
