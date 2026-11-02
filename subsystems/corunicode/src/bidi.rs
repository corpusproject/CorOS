//! `bidi` — Unicode 15.1 Bidirectional Algorithm (UAX #9) Character Classification.
//! Determines directional properties of code points for BiDi layout engines (Arabic, Hebrew, Latin).

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BidiClass {
    /// Left-to-Right (Latin, Greek, Cyrillic, etc.)
    L,
    /// Right-to-Left (Hebrew, etc.)
    R,
    /// Right-to-Left Arabic (Arabic, Syriac, Thaana, etc.)
    AL,
    /// European Number
    EN,
    /// European Separator (plus, minus)
    ES,
    /// European Terminator (degree, dollar, percent)
    ET,
    /// Arabic Number
    AN,
    /// Common Separator (colon, comma, slash)
    CS,
    /// Nonspacing Mark
    NSM,
    /// Boundary Neutral
    BN,
    /// Paragraph Separator
    B,
    /// Segment Separator (tab)
    S,
    /// Whitespace (space)
    WS,
    /// Other Neutral
    ON,
    /// Left-to-Right Embedding
    LRE,
    /// Left-to-Right Override
    LRO,
    /// Right-to-Left Embedding
    RLE,
    /// Right-to-Left Override
    RLO,
    /// Pop Directional Format
    PDF,
    /// Left-to-Right Isolate
    LRI,
    /// Right-to-Left Isolate
    RLI,
    /// First Strong Isolate
    FSI,
    /// Pop Directional Isolate
    PDI,
}

struct BidiRange {
    start: u32,
    end: u32,
    class: BidiClass,
}

static BIDI_RANGES: &[BidiRange] = &[
    // Controls / Formatting
    BidiRange { start: 0x0009, end: 0x0009, class: BidiClass::S },
    BidiRange { start: 0x000A, end: 0x000A, class: BidiClass::B },
    BidiRange { start: 0x000D, end: 0x000D, class: BidiClass::B },
    BidiRange { start: 0x0020, end: 0x0020, class: BidiClass::WS },
    BidiRange { start: 0x002B, end: 0x002B, class: BidiClass::ES },
    BidiRange { start: 0x002C, end: 0x002C, class: BidiClass::CS },
    BidiRange { start: 0x002D, end: 0x002D, class: BidiClass::ES },
    BidiRange { start: 0x002F, end: 0x002F, class: BidiClass::CS },
    BidiRange { start: 0x0030, end: 0x0039, class: BidiClass::EN },
    BidiRange { start: 0x003A, end: 0x003A, class: BidiClass::CS },

    // ASCII Latin
    BidiRange { start: 0x0041, end: 0x005A, class: BidiClass::L },
    BidiRange { start: 0x0061, end: 0x007A, class: BidiClass::L },

    // Latin Extended
    BidiRange { start: 0x00C0, end: 0x02AF, class: BidiClass::L },

    // Nonspacing combining diacritics
    BidiRange { start: 0x0300, end: 0x036F, class: BidiClass::NSM },

    // Greek and Coptic
    BidiRange { start: 0x0370, end: 0x03FF, class: BidiClass::L },

    // Cyrillic
    BidiRange { start: 0x0400, end: 0x04FF, class: BidiClass::L },

    // Hebrew (R)
    BidiRange { start: 0x0590, end: 0x05BE, class: BidiClass::R },
    BidiRange { start: 0x05BF, end: 0x05BF, class: BidiClass::NSM },
    BidiRange { start: 0x05C0, end: 0x05C0, class: BidiClass::R },
    BidiRange { start: 0x05C1, end: 0x05C2, class: BidiClass::NSM },
    BidiRange { start: 0x05C3, end: 0x05C3, class: BidiClass::R },
    BidiRange { start: 0x05C4, end: 0x05C5, class: BidiClass::NSM },
    BidiRange { start: 0x05C6, end: 0x05C6, class: BidiClass::R },
    BidiRange { start: 0x05C7, end: 0x05C7, class: BidiClass::NSM },
    BidiRange { start: 0x05D0, end: 0x05EA, class: BidiClass::R },
    BidiRange { start: 0x05EB, end: 0x05FF, class: BidiClass::R },

    // Arabic (AL and AN)
    BidiRange { start: 0x0600, end: 0x0605, class: BidiClass::AL },
    BidiRange { start: 0x0660, end: 0x0669, class: BidiClass::AN },
    BidiRange { start: 0x066B, end: 0x066C, class: BidiClass::AN },
    BidiRange { start: 0x0610, end: 0x061A, class: BidiClass::NSM },
    BidiRange { start: 0x064B, end: 0x065F, class: BidiClass::NSM },
    BidiRange { start: 0x0621, end: 0x064A, class: BidiClass::AL },
    BidiRange { start: 0x066E, end: 0x06D3, class: BidiClass::AL },

    // Directional control characters
    BidiRange { start: 0x202A, end: 0x202A, class: BidiClass::LRE },
    BidiRange { start: 0x202B, end: 0x202B, class: BidiClass::RLE },
    BidiRange { start: 0x202C, end: 0x202C, class: BidiClass::PDF },
    BidiRange { start: 0x202D, end: 0x202D, class: BidiClass::LRO },
    BidiRange { start: 0x202E, end: 0x202E, class: BidiClass::RLO },
    BidiRange { start: 0x2066, end: 0x2066, class: BidiClass::LRI },
    BidiRange { start: 0x2067, end: 0x2067, class: BidiClass::RLI },
    BidiRange { start: 0x2068, end: 0x2068, class: BidiClass::FSI },
    BidiRange { start: 0x2069, end: 0x2069, class: BidiClass::PDI },

    // CJK Unified Ideographs
    BidiRange { start: 0x4E00, end: 0x9FFF, class: BidiClass::L },
];

/// Looks up the UAX #9 Bidirectional class for a given Unicode code point.
pub fn lookup_bidi_class(cp: u32) -> BidiClass {
    for range in BIDI_RANGES {
        if cp >= range.start && cp <= range.end {
            return range.class;
        }
    }
    BidiClass::ON
}

/// Returns true if the code point has strong Right-to-Left directionality (R or AL).
pub fn is_rtl(cp: u32) -> bool {
    let cls = lookup_bidi_class(cp);
    cls == BidiClass::R || cls == BidiClass::AL
}
