//! Glyph metrics, 8x16 console bitmap font renderer & UTF-8 text line layout.

/// 8x16 Console Bitmap Font glyph representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitmapGlyph {
    pub codepoint: char,
    pub width: u8,
    pub height: u8,
    pub rows: [u8; 16],
}

impl BitmapGlyph {
    /// Generates a fallback bitmap glyph with an outline box.
    pub fn fallback_glyph(c: char) -> Self {
        let mut rows = [0u8; 16];
        rows[0] = 0x7E;
        rows[15] = 0x7E;
        for i in 1..15 {
            rows[i] = 0x42;
        }
        Self {
            codepoint: c,
            width: 8,
            height: 16,
            rows,
        }
    }
}

/// Text layout run bounding box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextBounds {
    pub width: u32,
    pub height: u32,
}

/// Lightweight text shaper and layout calculator.
pub struct FontShaper {
    pub glyph_width: u32,
    pub glyph_height: u32,
    pub letter_spacing: u32,
}

impl FontShaper {
    pub fn new(glyph_width: u32, glyph_height: u32) -> Self {
        Self {
            glyph_width,
            glyph_height,
            letter_spacing: 1,
        }
    }

    /// Measures single-line text dimensions in pixels.
    pub fn measure_text_line(&self, text: &str) -> TextBounds {
        let char_count = text.chars().count() as u32;
        if char_count == 0 {
            return TextBounds { width: 0, height: 0 };
        }
        let total_w = char_count * self.glyph_width + (char_count - 1) * self.letter_spacing;
        TextBounds {
            width: total_w,
            height: self.glyph_height,
        }
    }

    /// Renders a glyph into a destination 32-bit ARGB framebuffer slice.
    pub fn blit_glyph_to_buffer(
        &self,
        glyph: &BitmapGlyph,
        dst_x: i32,
        dst_y: i32,
        color: u32,
        fb: &mut [u32],
        fb_stride: u32,
        fb_h: u32,
    ) {
        for row_idx in 0..16 {
            let py = dst_y + row_idx as i32;
            if py < 0 || (py as u32) >= fb_h {
                continue;
            }
            let row_byte = glyph.rows[row_idx];
            for col_idx in 0..8 {
                let px = dst_x + col_idx as i32;
                if px < 0 || (px as u32) >= fb_stride {
                    continue;
                }
                if (row_byte & (0x80 >> col_idx)) != 0 {
                    let offset = (py as usize) * (fb_stride as usize) + (px as usize);
                    if offset < fb.len() {
                        fb[offset] = color;
                    }
                }
            }
        }
    }
}
