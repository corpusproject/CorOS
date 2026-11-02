//! `decomposition` — Unicode 15.1 Normalization (UAX #15) Canonical Decomposition & CCC.
//! Canonical Combining Classes (ccc) and two-character NFD decomposition pairs.

pub struct CanonicalDecompositionPair {
    pub composed: char,
    pub base: char,
    pub combining_mark: char,
    pub ccc: u8,
}

pub static CANONICAL_DECOMPOSITIONS: &[CanonicalDecompositionPair] = &[
    // Turkish specific
    CanonicalDecompositionPair { composed: 'ç', base: 'c', combining_mark: '\u{0327}', ccc: 202 }, // Cedilla
    CanonicalDecompositionPair { composed: 'Ç', base: 'C', combining_mark: '\u{0327}', ccc: 202 },
    CanonicalDecompositionPair { composed: 'ğ', base: 'g', combining_mark: '\u{0306}', ccc: 230 }, // Breve
    CanonicalDecompositionPair { composed: 'Ğ', base: 'G', combining_mark: '\u{0306}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ö', base: 'o', combining_mark: '\u{0308}', ccc: 230 }, // Diaeresis
    CanonicalDecompositionPair { composed: 'Ö', base: 'O', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ü', base: 'u', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ü', base: 'U', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ş', base: 's', combining_mark: '\u{0327}', ccc: 202 },
    CanonicalDecompositionPair { composed: 'Ş', base: 'S', combining_mark: '\u{0327}', ccc: 202 },

    // Western European / Latin-1
    CanonicalDecompositionPair { composed: 'á', base: 'a', combining_mark: '\u{0301}', ccc: 230 }, // Acute
    CanonicalDecompositionPair { composed: 'Á', base: 'A', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'à', base: 'a', combining_mark: '\u{0300}', ccc: 230 }, // Grave
    CanonicalDecompositionPair { composed: 'À', base: 'A', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ä', base: 'a', combining_mark: '\u{0308}', ccc: 230 }, // Diaeresis
    CanonicalDecompositionPair { composed: 'Ä', base: 'A', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'â', base: 'a', combining_mark: '\u{0302}', ccc: 230 }, // Circumflex
    CanonicalDecompositionPair { composed: 'Â', base: 'A', combining_mark: '\u{0302}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ã', base: 'a', combining_mark: '\u{0303}', ccc: 230 }, // Tilde
    CanonicalDecompositionPair { composed: 'Ã', base: 'A', combining_mark: '\u{0303}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'å', base: 'a', combining_mark: '\u{030A}', ccc: 230 }, // Ring above
    CanonicalDecompositionPair { composed: 'Å', base: 'A', combining_mark: '\u{030A}', ccc: 230 },

    CanonicalDecompositionPair { composed: 'é', base: 'e', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'É', base: 'E', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'è', base: 'e', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'È', base: 'E', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ë', base: 'e', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ë', base: 'E', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ê', base: 'e', combining_mark: '\u{0302}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ê', base: 'E', combining_mark: '\u{0302}', ccc: 230 },

    CanonicalDecompositionPair { composed: 'í', base: 'i', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Í', base: 'I', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ì', base: 'i', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ì', base: 'I', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ï', base: 'i', combining_mark: '\u{0308}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ï', base: 'I', combining_mark: '\u{0308}', ccc: 230 },

    CanonicalDecompositionPair { composed: 'ó', base: 'o', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ó', base: 'O', combining_mark: '\u{0301}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ò', base: 'o', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ò', base: 'O', combining_mark: '\u{0300}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'ô', base: 'o', combining_mark: '\u{0302}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ô', base: 'O', combining_mark: '\u{0302}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'õ', base: 'o', combining_mark: '\u{0303}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Õ', base: 'O', combining_mark: '\u{0303}', ccc: 230 },

    CanonicalDecompositionPair { composed: 'ñ', base: 'n', combining_mark: '\u{0303}', ccc: 230 },
    CanonicalDecompositionPair { composed: 'Ñ', base: 'N', combining_mark: '\u{0303}', ccc: 230 },
];

/// Decomposes a precomposed character into its base character and combining mark.
pub fn decompose_canonical(c: char) -> Option<(char, char)> {
    for pair in CANONICAL_DECOMPOSITIONS {
        if pair.composed == c {
            return Some((pair.base, pair.combining_mark));
        }
    }
    None
}

/// Composes a base character and combining mark into a precomposed character.
pub fn compose_canonical(base: char, mark: char) -> Option<char> {
    for pair in CANONICAL_DECOMPOSITIONS {
        if pair.base == base && pair.combining_mark == mark {
            return Some(pair.composed);
        }
    }
    None
}
