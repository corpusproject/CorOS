//! Ultra-Modern Anti-Aliased Segoe UI Font for CorOS
//! Zero-dependency bare-metal font table with subpixel alpha blending.

#[derive(Clone, Copy)]
pub struct Glyph {
    pub width: u8,
    pub height: u8,
    pub x_offset: i8,
    pub y_offset: i8,
    pub advance: u8,
    pub data: &'static [u8],
}

pub static GLYPH_32: Glyph = Glyph { width: 0, height: 0, x_offset: 0, y_offset: 0, advance: 3, data: &[] };
pub static GLYPH_33_DATA: [u8; 18] = [174, 51, 174, 51, 174, 51, 174, 25, 174, 0, 174, 0, 0, 0, 195, 38, 195, 38];
pub static GLYPH_33: Glyph = Glyph { width: 2, height: 9, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_33_DATA };
pub static GLYPH_34_DATA: [u8; 9] = [174, 0, 174, 174, 0, 174, 174, 0, 174];
pub static GLYPH_34: Glyph = Glyph { width: 3, height: 3, x_offset: 1, y_offset: 2, advance: 5, data: &GLYPH_34_DATA };
pub static GLYPH_35_DATA: [u8; 56] = [0, 0, 51, 107, 0, 174, 0, 0, 0, 92, 64, 51, 107, 0, 51, 255, 255, 255, 255, 255, 174, 0, 0, 174, 0, 139, 25, 0, 0, 0, 174, 0, 174, 0, 0, 174, 255, 255, 255, 255, 255, 92, 0, 92, 64, 51, 107, 0, 0, 0, 139, 12, 107, 51, 0, 0];
pub static GLYPH_35: Glyph = Glyph { width: 7, height: 8, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_35_DATA };
pub static GLYPH_36_DATA: [u8; 55] = [0, 0, 107, 0, 0, 38, 218, 255, 218, 25, 218, 51, 107, 51, 38, 255, 0, 107, 0, 0, 174, 139, 107, 0, 0, 12, 139, 255, 64, 0, 0, 0, 156, 195, 78, 0, 0, 107, 64, 174, 122, 12, 107, 139, 139, 139, 255, 255, 139, 12, 0, 0, 107, 0, 0];
pub static GLYPH_36: Glyph = Glyph { width: 5, height: 11, x_offset: 1, y_offset: 1, advance: 6, data: &GLYPH_36_DATA };
pub static GLYPH_37_DATA: [u8; 90] = [12, 174, 255, 174, 12, 0, 25, 174, 0, 0, 92, 92, 0, 139, 78, 0, 174, 25, 0, 0, 92, 92, 0, 139, 64, 64, 107, 0, 0, 0, 12, 174, 255, 174, 12, 174, 12, 0, 0, 0, 0, 0, 0, 0, 107, 64, 0, 0, 0, 0, 0, 0, 0, 25, 174, 12, 174, 255, 174, 12, 0, 0, 0, 174, 25, 92, 92, 0, 139, 51, 0, 0, 51, 107, 0, 107, 92, 0, 139, 51, 0, 0, 174, 12, 0, 12, 195, 255, 156, 0];
pub static GLYPH_37: Glyph = Glyph { width: 10, height: 9, x_offset: 0, y_offset: 2, advance: 11, data: &GLYPH_37_DATA };
pub static GLYPH_38_DATA: [u8; 90] = [0, 0, 122, 255, 255, 78, 0, 0, 0, 0, 0, 51, 218, 12, 38, 255, 0, 0, 0, 0, 0, 38, 195, 0, 38, 218, 0, 107, 107, 0, 0, 0, 156, 174, 174, 38, 0, 107, 107, 0, 0, 78, 174, 92, 218, 78, 0, 139, 78, 0, 25, 218, 0, 0, 12, 195, 78, 218, 12, 0, 51, 174, 0, 0, 0, 38, 255, 92, 0, 0, 25, 255, 51, 0, 25, 122, 255, 174, 12, 12, 0, 64, 218, 255, 255, 107, 12, 139, 255, 92];
pub static GLYPH_38: Glyph = Glyph { width: 10, height: 9, x_offset: 0, y_offset: 2, advance: 11, data: &GLYPH_38_DATA };
pub static GLYPH_39_DATA: [u8; 3] = [174, 174, 174];
pub static GLYPH_39: Glyph = Glyph { width: 1, height: 3, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_39_DATA };
pub static GLYPH_40_DATA: [u8; 44] = [0, 0, 195, 38, 0, 78, 122, 0, 0, 174, 25, 0, 0, 218, 0, 0, 38, 174, 0, 0, 51, 174, 0, 0, 38, 174, 0, 0, 0, 218, 0, 0, 0, 195, 25, 0, 0, 78, 107, 0, 0, 0, 195, 38];
pub static GLYPH_40: Glyph = Glyph { width: 4, height: 11, x_offset: 0, y_offset: 2, advance: 5, data: &GLYPH_40_DATA };
pub static GLYPH_41_DATA: [u8; 33] = [107, 107, 0, 12, 218, 12, 0, 139, 78, 0, 78, 139, 0, 51, 174, 0, 51, 174, 0, 51, 174, 0, 78, 139, 0, 139, 78, 12, 218, 12, 107, 107, 0];
pub static GLYPH_41: Glyph = Glyph { width: 3, height: 11, x_offset: 0, y_offset: 2, advance: 4, data: &GLYPH_41_DATA };
pub static GLYPH_42_DATA: [u8; 20] = [0, 0, 156, 0, 0, 92, 139, 139, 107, 92, 0, 78, 195, 92, 0, 0, 139, 0, 156, 0];
pub static GLYPH_42: Glyph = Glyph { width: 5, height: 4, x_offset: 0, y_offset: 2, advance: 6, data: &GLYPH_42_DATA };
pub static GLYPH_43_DATA: [u8; 30] = [0, 0, 51, 107, 0, 0, 0, 0, 51, 107, 0, 0, 174, 255, 255, 255, 255, 255, 0, 0, 51, 107, 0, 0, 0, 0, 51, 107, 0, 0];
pub static GLYPH_43: Glyph = Glyph { width: 6, height: 5, x_offset: 1, y_offset: 5, advance: 8, data: &GLYPH_43_DATA };
pub static GLYPH_44_DATA: [u8; 6] = [38, 156, 92, 78, 139, 25];
pub static GLYPH_44: Glyph = Glyph { width: 2, height: 3, x_offset: 0, y_offset: 10, advance: 3, data: &GLYPH_44_DATA };
pub static GLYPH_45_DATA: [u8; 4] = [51, 255, 255, 255];
pub static GLYPH_45: Glyph = Glyph { width: 4, height: 1, x_offset: 0, y_offset: 7, advance: 5, data: &GLYPH_45_DATA };
pub static GLYPH_46_DATA: [u8; 4] = [38, 218, 38, 218];
pub static GLYPH_46: Glyph = Glyph { width: 2, height: 2, x_offset: 0, y_offset: 9, advance: 3, data: &GLYPH_46_DATA };
pub static GLYPH_47_DATA: [u8; 50] = [0, 0, 0, 78, 122, 0, 0, 0, 174, 25, 0, 0, 25, 174, 0, 0, 0, 122, 78, 0, 0, 0, 218, 0, 0, 0, 78, 107, 0, 0, 0, 195, 25, 0, 0, 38, 156, 0, 0, 0, 139, 64, 0, 0, 0, 195, 0, 0, 0, 0];
pub static GLYPH_47: Glyph = Glyph { width: 5, height: 10, x_offset: 0, y_offset: 2, advance: 6, data: &GLYPH_47_DATA };
pub static GLYPH_48_DATA: [u8; 54] = [0, 38, 218, 255, 174, 12, 0, 218, 51, 0, 156, 107, 51, 174, 0, 0, 51, 195, 107, 107, 0, 0, 0, 255, 107, 107, 0, 0, 0, 255, 107, 107, 0, 0, 0, 255, 64, 156, 0, 0, 38, 174, 12, 255, 51, 12, 156, 78, 0, 64, 218, 255, 122, 0];
pub static GLYPH_48: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_48_DATA };
pub static GLYPH_49_DATA: [u8; 36] = [0, 64, 174, 51, 156, 107, 195, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51];
pub static GLYPH_49: Glyph = Glyph { width: 4, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_49_DATA };
pub static GLYPH_50_DATA: [u8; 54] = [0, 122, 255, 255, 139, 0, 0, 107, 12, 12, 174, 92, 0, 0, 0, 0, 107, 107, 0, 0, 0, 0, 139, 78, 0, 0, 0, 78, 195, 0, 0, 0, 139, 139, 12, 0, 0, 139, 78, 0, 0, 0, 38, 174, 0, 0, 0, 0, 78, 255, 255, 255, 255, 255];
pub static GLYPH_50: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_50_DATA };
pub static GLYPH_51_DATA: [u8; 54] = [0, 139, 255, 255, 122, 0, 0, 92, 0, 25, 218, 38, 0, 0, 0, 0, 174, 51, 0, 0, 0, 51, 218, 12, 0, 107, 255, 255, 64, 0, 0, 0, 0, 25, 195, 64, 0, 0, 0, 0, 107, 107, 38, 51, 0, 25, 195, 78, 25, 218, 255, 255, 107, 0];
pub static GLYPH_51: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_51_DATA };
pub static GLYPH_52_DATA: [u8; 54] = [0, 0, 0, 51, 255, 0, 0, 0, 0, 156, 255, 0, 0, 0, 78, 107, 255, 0, 0, 12, 195, 12, 255, 0, 0, 174, 51, 0, 255, 0, 107, 122, 0, 0, 255, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 0];
pub static GLYPH_52: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_52_DATA };
pub static GLYPH_53_DATA: [u8; 45] = [107, 255, 255, 255, 51, 156, 51, 0, 0, 0, 174, 51, 0, 0, 0, 174, 255, 255, 122, 0, 0, 0, 25, 195, 92, 0, 0, 0, 64, 174, 0, 0, 0, 64, 174, 25, 0, 25, 195, 78, 218, 255, 255, 107, 0];
pub static GLYPH_53: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_53_DATA };
pub static GLYPH_54_DATA: [u8; 54] = [0, 0, 107, 255, 255, 92, 0, 107, 156, 25, 0, 0, 0, 218, 12, 0, 0, 0, 38, 195, 174, 255, 218, 38, 51, 255, 78, 0, 107, 195, 51, 174, 0, 0, 0, 255, 38, 195, 0, 0, 0, 255, 0, 218, 78, 0, 107, 156, 0, 38, 218, 255, 174, 12];
pub static GLYPH_54: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_54_DATA };
pub static GLYPH_55_DATA: [u8; 54] = [107, 255, 255, 255, 255, 255, 0, 0, 0, 0, 107, 107, 0, 0, 0, 0, 218, 12, 0, 0, 0, 78, 107, 0, 0, 0, 0, 218, 25, 0, 0, 0, 38, 156, 0, 0, 0, 0, 122, 92, 0, 0, 0, 0, 195, 25, 0, 0, 0, 0, 255, 0, 0, 0];
pub static GLYPH_55: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_55_DATA };
pub static GLYPH_56_DATA: [u8; 54] = [0, 38, 218, 255, 139, 0, 0, 218, 64, 12, 156, 92, 0, 255, 0, 0, 107, 107, 0, 174, 78, 12, 174, 64, 0, 51, 255, 255, 174, 12, 25, 195, 25, 0, 107, 139, 107, 107, 0, 0, 0, 255, 51, 218, 25, 0, 107, 218, 0, 92, 255, 255, 174, 38];
pub static GLYPH_56: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_56_DATA };
pub static GLYPH_57_DATA: [u8; 54] = [0, 64, 218, 255, 139, 0, 25, 218, 38, 12, 156, 107, 78, 139, 0, 0, 51, 174, 92, 139, 0, 0, 25, 255, 25, 255, 38, 0, 139, 255, 0, 78, 255, 255, 92, 195, 0, 0, 0, 0, 64, 139, 0, 0, 0, 51, 218, 25, 0, 218, 255, 218, 64, 0];
pub static GLYPH_57: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_57_DATA };
pub static GLYPH_58_DATA: [u8; 12] = [38, 218, 38, 218, 0, 0, 0, 0, 38, 218, 38, 218];
pub static GLYPH_58: Glyph = Glyph { width: 2, height: 6, x_offset: 0, y_offset: 5, advance: 3, data: &GLYPH_58_DATA };
pub static GLYPH_59_DATA: [u8; 16] = [38, 218, 38, 218, 0, 0, 0, 0, 0, 0, 38, 156, 92, 78, 139, 25];
pub static GLYPH_59: Glyph = Glyph { width: 2, height: 8, x_offset: 0, y_offset: 5, advance: 3, data: &GLYPH_59_DATA };
pub static GLYPH_60_DATA: [u8; 36] = [0, 0, 0, 0, 64, 139, 0, 0, 25, 174, 122, 12, 12, 122, 174, 38, 0, 0, 38, 195, 107, 12, 0, 0, 0, 0, 78, 195, 107, 12, 0, 0, 0, 0, 78, 139];
pub static GLYPH_60: Glyph = Glyph { width: 6, height: 6, x_offset: 1, y_offset: 4, advance: 8, data: &GLYPH_60_DATA };
pub static GLYPH_61_DATA: [u8; 24] = [174, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 174, 255, 255, 255, 255, 255];
pub static GLYPH_61: Glyph = Glyph { width: 6, height: 4, x_offset: 1, y_offset: 6, advance: 8, data: &GLYPH_61_DATA };
pub static GLYPH_62_DATA: [u8; 36] = [92, 107, 0, 0, 0, 0, 0, 92, 195, 51, 0, 0, 0, 0, 12, 139, 174, 25, 0, 0, 0, 78, 218, 64, 0, 78, 195, 107, 12, 0, 92, 107, 12, 0, 0, 0];
pub static GLYPH_62: Glyph = Glyph { width: 6, height: 6, x_offset: 1, y_offset: 4, advance: 8, data: &GLYPH_62_DATA };
pub static GLYPH_63_DATA: [u8; 45] = [25, 174, 255, 218, 38, 38, 51, 0, 92, 174, 0, 0, 0, 64, 139, 0, 0, 38, 174, 12, 0, 12, 218, 12, 0, 0, 38, 195, 0, 0, 0, 0, 0, 0, 0, 0, 25, 218, 0, 0, 0, 25, 218, 0, 0];
pub static GLYPH_63: Glyph = Glyph { width: 5, height: 9, x_offset: 0, y_offset: 2, advance: 6, data: &GLYPH_63_DATA };
pub static GLYPH_64_DATA: [u8; 100] = [0, 0, 78, 195, 255, 255, 156, 51, 0, 0, 0, 139, 156, 38, 0, 0, 64, 195, 78, 0, 78, 156, 0, 122, 255, 156, 174, 12, 195, 25, 174, 25, 51, 174, 12, 92, 156, 0, 92, 78, 195, 0, 122, 64, 0, 51, 107, 0, 51, 107, 174, 0, 174, 51, 0, 64, 107, 0, 92, 92, 218, 12, 122, 92, 12, 174, 139, 12, 195, 25, 107, 107, 25, 218, 255, 38, 195, 255, 78, 0, 12, 195, 139, 38, 0, 0, 0, 0, 0, 0, 0, 12, 107, 218, 255, 255, 195, 38, 0, 0];
pub static GLYPH_64: Glyph = Glyph { width: 10, height: 10, x_offset: 1, y_offset: 2, advance: 11, data: &GLYPH_64_DATA };
pub static GLYPH_65_DATA: [u8; 72] = [0, 0, 0, 195, 122, 0, 0, 0, 0, 0, 38, 174, 218, 0, 0, 0, 0, 0, 122, 78, 156, 64, 0, 0, 0, 0, 218, 12, 78, 139, 0, 0, 0, 51, 156, 0, 12, 255, 12, 0, 0, 139, 78, 0, 0, 156, 78, 0, 0, 255, 255, 255, 255, 255, 156, 0, 78, 156, 0, 0, 0, 0, 255, 25, 156, 78, 0, 0, 0, 0, 139, 92];
pub static GLYPH_65: Glyph = Glyph { width: 8, height: 9, x_offset: 0, y_offset: 2, advance: 9, data: &GLYPH_65_DATA };
pub static GLYPH_66_DATA: [u8; 54] = [255, 255, 255, 195, 38, 0, 255, 51, 0, 107, 156, 0, 255, 51, 0, 51, 174, 0, 255, 51, 12, 139, 92, 0, 255, 255, 255, 195, 38, 0, 255, 51, 0, 51, 218, 12, 255, 51, 0, 0, 174, 51, 255, 51, 0, 51, 218, 12, 255, 255, 255, 218, 64, 0];
pub static GLYPH_66: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_66_DATA };
pub static GLYPH_67_DATA: [u8; 63] = [0, 0, 64, 195, 255, 255, 78, 0, 78, 195, 51, 0, 25, 92, 12, 255, 25, 0, 0, 0, 0, 64, 156, 0, 0, 0, 0, 0, 107, 107, 0, 0, 0, 0, 0, 78, 139, 0, 0, 0, 0, 0, 25, 255, 12, 0, 0, 0, 0, 0, 122, 195, 38, 0, 25, 92, 0, 0, 107, 218, 255, 218, 51];
pub static GLYPH_67: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_67_DATA };
pub static GLYPH_68_DATA: [u8; 63] = [255, 255, 255, 255, 156, 38, 0, 255, 51, 0, 12, 107, 255, 25, 255, 51, 0, 0, 0, 107, 139, 255, 51, 0, 0, 0, 51, 174, 255, 51, 0, 0, 0, 51, 174, 255, 51, 0, 0, 0, 51, 174, 255, 51, 0, 0, 0, 156, 92, 255, 51, 0, 25, 122, 195, 12, 255, 255, 255, 218, 107, 12, 0];
pub static GLYPH_68: Glyph = Glyph { width: 7, height: 9, x_offset: 1, y_offset: 2, advance: 8, data: &GLYPH_68_DATA };
pub static GLYPH_69_DATA: [u8; 45] = [255, 255, 255, 255, 107, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 255, 255, 255, 51, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 255, 255, 255, 107];
pub static GLYPH_69: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_69_DATA };
pub static GLYPH_70_DATA: [u8; 45] = [255, 255, 255, 255, 107, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 255, 255, 255, 51, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0];
pub static GLYPH_70: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_70_DATA };
pub static GLYPH_71_DATA: [u8; 72] = [0, 0, 64, 195, 255, 255, 156, 25, 0, 78, 195, 51, 0, 12, 92, 51, 12, 255, 25, 0, 0, 0, 0, 0, 64, 156, 0, 0, 0, 0, 0, 0, 107, 107, 0, 0, 107, 255, 255, 107, 78, 156, 0, 0, 0, 0, 107, 107, 25, 255, 12, 0, 0, 0, 107, 107, 0, 122, 195, 38, 0, 12, 139, 107, 0, 0, 107, 218, 255, 255, 139, 25];
pub static GLYPH_71: Glyph = Glyph { width: 8, height: 9, x_offset: 0, y_offset: 2, advance: 9, data: &GLYPH_71_DATA };
pub static GLYPH_72_DATA: [u8; 63] = [255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107, 255, 255, 255, 255, 255, 255, 107, 255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107, 255, 51, 0, 0, 0, 107, 107];
pub static GLYPH_72: Glyph = Glyph { width: 7, height: 9, x_offset: 1, y_offset: 2, advance: 9, data: &GLYPH_72_DATA };
pub static GLYPH_73_DATA: [u8; 18] = [255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51];
pub static GLYPH_73: Glyph = Glyph { width: 2, height: 9, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_73_DATA };
pub static GLYPH_74_DATA: [u8; 36] = [0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 38, 255, 12, 174, 255, 78, 0];
pub static GLYPH_74: Glyph = Glyph { width: 4, height: 9, x_offset: 0, y_offset: 2, advance: 5, data: &GLYPH_74_DATA };
pub static GLYPH_75_DATA: [u8; 54] = [255, 51, 0, 12, 195, 78, 255, 51, 0, 156, 107, 0, 255, 51, 107, 139, 0, 0, 255, 122, 195, 12, 0, 0, 255, 255, 78, 0, 0, 0, 255, 92, 218, 38, 0, 0, 255, 51, 78, 218, 12, 0, 255, 51, 0, 122, 174, 0, 255, 51, 0, 0, 174, 139];
pub static GLYPH_75: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_75_DATA };
pub static GLYPH_76_DATA: [u8; 45] = [255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 51, 0, 0, 0, 255, 255, 255, 255, 107];
pub static GLYPH_76: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_76_DATA };
pub static GLYPH_77_DATA: [u8; 81] = [255, 156, 0, 0, 0, 0, 0, 156, 174, 255, 195, 25, 0, 0, 0, 25, 255, 174, 255, 107, 107, 0, 0, 0, 122, 139, 174, 255, 78, 218, 0, 0, 12, 218, 51, 174, 255, 51, 139, 64, 0, 78, 122, 51, 174, 255, 51, 51, 174, 0, 195, 25, 51, 174, 255, 51, 0, 218, 64, 174, 0, 51, 174, 255, 51, 0, 78, 255, 64, 0, 51, 174, 255, 51, 0, 12, 195, 0, 0, 51, 174];
pub static GLYPH_77: Glyph = Glyph { width: 9, height: 9, x_offset: 1, y_offset: 2, advance: 11, data: &GLYPH_77_DATA };
pub static GLYPH_78_DATA: [u8; 63] = [255, 174, 0, 0, 0, 0, 255, 255, 174, 64, 0, 0, 0, 255, 255, 78, 218, 12, 0, 0, 255, 255, 51, 122, 107, 0, 0, 255, 255, 51, 12, 255, 25, 0, 255, 255, 51, 0, 78, 174, 0, 255, 255, 51, 0, 0, 174, 64, 255, 255, 51, 0, 0, 38, 218, 255, 255, 51, 0, 0, 0, 122, 255];
pub static GLYPH_78: Glyph = Glyph { width: 7, height: 9, x_offset: 1, y_offset: 2, advance: 9, data: &GLYPH_78_DATA };
pub static GLYPH_79_DATA: [u8; 81] = [0, 0, 107, 218, 255, 255, 107, 0, 0, 0, 122, 195, 38, 0, 25, 156, 139, 0, 25, 255, 12, 0, 0, 0, 12, 218, 38, 64, 156, 0, 0, 0, 0, 0, 122, 92, 107, 107, 0, 0, 0, 0, 0, 107, 107, 78, 156, 0, 0, 0, 0, 0, 122, 92, 25, 255, 12, 0, 0, 0, 12, 218, 25, 0, 122, 195, 25, 0, 25, 156, 122, 0, 0, 0, 107, 218, 255, 218, 107, 0, 0];
pub static GLYPH_79: Glyph = Glyph { width: 9, height: 9, x_offset: 0, y_offset: 2, advance: 10, data: &GLYPH_79_DATA };
pub static GLYPH_80_DATA: [u8; 54] = [255, 255, 255, 218, 38, 0, 255, 51, 0, 51, 255, 12, 255, 51, 0, 0, 174, 51, 255, 51, 0, 0, 195, 38, 255, 51, 0, 92, 218, 0, 255, 255, 255, 174, 38, 0, 255, 51, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0];
pub static GLYPH_80: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_80_DATA };
pub static GLYPH_81_DATA: [u8; 90] = [0, 0, 107, 218, 255, 255, 122, 0, 0, 0, 122, 195, 38, 0, 25, 156, 156, 0, 25, 255, 25, 0, 0, 0, 0, 218, 38, 64, 174, 0, 0, 0, 0, 0, 122, 107, 107, 107, 0, 0, 0, 0, 0, 107, 107, 78, 174, 0, 0, 0, 0, 0, 122, 92, 25, 255, 12, 0, 0, 0, 12, 218, 38, 0, 122, 195, 38, 0, 25, 156, 139, 0, 0, 0, 107, 218, 255, 218, 255, 64, 0, 0, 0, 0, 0, 0, 0, 51, 255, 122];
pub static GLYPH_81: Glyph = Glyph { width: 9, height: 10, x_offset: 0, y_offset: 2, advance: 10, data: &GLYPH_81_DATA };
pub static GLYPH_82_DATA: [u8; 54] = [255, 255, 255, 218, 78, 0, 255, 51, 0, 51, 255, 12, 255, 51, 0, 0, 174, 51, 255, 51, 0, 51, 195, 0, 255, 255, 255, 174, 12, 0, 255, 51, 38, 255, 38, 0, 255, 51, 0, 78, 174, 0, 255, 51, 0, 0, 218, 51, 255, 51, 0, 0, 64, 218];
pub static GLYPH_82: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_82_DATA };
pub static GLYPH_83_DATA: [u8; 54] = [0, 64, 218, 255, 218, 38, 25, 218, 25, 0, 51, 92, 51, 174, 0, 0, 0, 0, 12, 218, 107, 12, 0, 0, 0, 12, 139, 255, 64, 0, 0, 0, 0, 51, 195, 64, 0, 0, 0, 0, 64, 174, 38, 78, 12, 0, 139, 139, 12, 156, 255, 255, 139, 12];
pub static GLYPH_83: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_83_DATA };
pub static GLYPH_84_DATA: [u8; 63] = [174, 255, 255, 255, 255, 255, 51, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0, 0, 0, 51, 174, 0, 0, 0];
pub static GLYPH_84: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_84_DATA };
pub static GLYPH_85_DATA: [u8; 63] = [255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 25, 0, 0, 0, 218, 25, 139, 156, 12, 0, 92, 195, 0, 12, 139, 255, 255, 156, 38, 0];
pub static GLYPH_85: Glyph = Glyph { width: 7, height: 9, x_offset: 1, y_offset: 2, advance: 8, data: &GLYPH_85_DATA };
pub static GLYPH_86_DATA: [u8; 72] = [156, 78, 0, 0, 0, 0, 218, 25, 78, 156, 0, 0, 0, 38, 195, 0, 12, 255, 12, 0, 0, 122, 92, 0, 0, 156, 78, 0, 0, 218, 25, 0, 0, 78, 156, 0, 38, 195, 0, 0, 0, 12, 255, 0, 122, 92, 0, 0, 0, 0, 156, 64, 218, 12, 0, 0, 0, 0, 78, 195, 156, 0, 0, 0, 0, 0, 12, 255, 78, 0, 0, 0];
pub static GLYPH_86: Glyph = Glyph { width: 8, height: 9, x_offset: 0, y_offset: 2, advance: 9, data: &GLYPH_86_DATA };
pub static GLYPH_87_DATA: [u8; 99] = [156, 78, 0, 0, 0, 218, 64, 0, 0, 25, 255, 78, 139, 0, 0, 25, 255, 122, 0, 0, 78, 156, 25, 255, 0, 0, 92, 139, 195, 0, 0, 139, 78, 0, 218, 38, 0, 156, 51, 218, 12, 0, 218, 25, 0, 139, 92, 0, 218, 0, 139, 64, 25, 218, 0, 0, 64, 156, 51, 156, 0, 78, 139, 78, 139, 0, 0, 12, 255, 107, 92, 0, 25, 218, 139, 78, 0, 0, 0, 195, 255, 38, 0, 0, 218, 195, 25, 0, 0, 0, 107, 218, 0, 0, 0, 122, 195, 0, 0];
pub static GLYPH_87: Glyph = Glyph { width: 11, height: 9, x_offset: 0, y_offset: 2, advance: 12, data: &GLYPH_87_DATA };
pub static GLYPH_88_DATA: [u8; 63] = [51, 218, 0, 0, 0, 122, 107, 0, 174, 78, 0, 25, 218, 12, 0, 25, 255, 12, 156, 78, 0, 0, 0, 122, 156, 174, 0, 0, 0, 0, 25, 255, 78, 0, 0, 0, 0, 156, 139, 195, 0, 0, 0, 51, 195, 0, 174, 92, 0, 0, 218, 51, 0, 25, 255, 12, 107, 156, 0, 0, 0, 139, 122];
pub static GLYPH_88: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_88_DATA };
pub static GLYPH_89_DATA: [u8; 63] = [139, 92, 0, 0, 0, 139, 78, 38, 218, 0, 0, 25, 218, 0, 0, 174, 78, 0, 107, 92, 0, 0, 51, 174, 12, 218, 12, 0, 0, 0, 218, 122, 122, 0, 0, 0, 0, 78, 255, 25, 0, 0, 0, 0, 51, 255, 0, 0, 0, 0, 0, 51, 255, 0, 0, 0, 0, 0, 51, 255, 0, 0, 0];
pub static GLYPH_89: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_89_DATA };
pub static GLYPH_90_DATA: [u8; 63] = [107, 255, 255, 255, 255, 255, 107, 0, 0, 0, 0, 51, 195, 0, 0, 0, 0, 0, 195, 38, 0, 0, 0, 0, 107, 122, 0, 0, 0, 0, 25, 218, 12, 0, 0, 0, 0, 174, 51, 0, 0, 0, 0, 92, 139, 0, 0, 0, 0, 25, 218, 12, 0, 0, 0, 0, 139, 255, 255, 255, 255, 255, 107];
pub static GLYPH_90: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_90_DATA };
pub static GLYPH_91_DATA: [u8; 33] = [174, 255, 107, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 51, 0, 174, 255, 107];
pub static GLYPH_91: Glyph = Glyph { width: 3, height: 11, x_offset: 1, y_offset: 2, advance: 4, data: &GLYPH_91_DATA };
pub static GLYPH_92_DATA: [u8; 50] = [218, 0, 0, 0, 0, 139, 78, 0, 0, 0, 38, 156, 0, 0, 0, 0, 195, 25, 0, 0, 0, 78, 107, 0, 0, 0, 12, 195, 0, 0, 0, 0, 139, 64, 0, 0, 0, 38, 156, 0, 0, 0, 0, 195, 25, 0, 0, 0, 78, 107];
pub static GLYPH_92: Glyph = Glyph { width: 5, height: 10, x_offset: 0, y_offset: 2, advance: 6, data: &GLYPH_92_DATA };
pub static GLYPH_93_DATA: [u8; 33] = [174, 255, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 0, 107, 174, 174, 255, 174];
pub static GLYPH_93: Glyph = Glyph { width: 3, height: 11, x_offset: 0, y_offset: 2, advance: 4, data: &GLYPH_93_DATA };
pub static GLYPH_94_DATA: [u8; 30] = [0, 0, 78, 107, 0, 0, 0, 0, 174, 174, 12, 0, 0, 78, 92, 51, 107, 0, 0, 195, 12, 0, 174, 25, 78, 107, 0, 0, 51, 139];
pub static GLYPH_94: Glyph = Glyph { width: 6, height: 5, x_offset: 1, y_offset: 2, advance: 8, data: &GLYPH_94_DATA };
pub static GLYPH_95_DATA: [u8; 5] = [255, 255, 255, 255, 255];
pub static GLYPH_95: Glyph = Glyph { width: 5, height: 1, x_offset: 0, y_offset: 12, advance: 6, data: &GLYPH_95_DATA };
pub static GLYPH_96_DATA: [u8; 6] = [38, 174, 0, 0, 64, 107];
pub static GLYPH_96: Glyph = Glyph { width: 3, height: 2, x_offset: 0, y_offset: 2, advance: 4, data: &GLYPH_96_DATA };
pub static GLYPH_97_DATA: [u8; 36] = [0, 174, 255, 255, 122, 0, 0, 0, 0, 12, 195, 51, 0, 78, 174, 218, 255, 51, 64, 195, 51, 12, 174, 51, 92, 156, 0, 38, 255, 51, 12, 174, 255, 139, 174, 51];
pub static GLYPH_97: Glyph = Glyph { width: 6, height: 6, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_97_DATA };
pub static GLYPH_98_DATA: [u8; 54] = [255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 78, 255, 255, 122, 0, 255, 122, 0, 25, 218, 51, 255, 0, 0, 0, 107, 107, 255, 0, 0, 0, 122, 107, 255, 107, 0, 38, 255, 25, 255, 78, 255, 255, 78, 0];
pub static GLYPH_98: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_98_DATA };
pub static GLYPH_99_DATA: [u8; 30] = [0, 38, 195, 255, 255, 25, 255, 51, 0, 0, 78, 139, 0, 0, 0, 92, 139, 0, 0, 0, 25, 255, 51, 0, 0, 0, 64, 218, 255, 218];
pub static GLYPH_99: Glyph = Glyph { width: 5, height: 6, x_offset: 0, y_offset: 5, advance: 6, data: &GLYPH_99_DATA };
pub static GLYPH_100_DATA: [u8; 63] = [0, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0, 0, 255, 51, 0, 64, 218, 255, 122, 255, 51, 25, 255, 51, 0, 78, 255, 51, 92, 139, 0, 0, 0, 255, 51, 107, 122, 0, 0, 0, 255, 51, 38, 255, 38, 0, 92, 255, 51, 0, 92, 255, 255, 78, 255, 51];
pub static GLYPH_100: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_100_DATA };
pub static GLYPH_101_DATA: [u8; 36] = [0, 64, 218, 255, 174, 38, 25, 174, 25, 0, 92, 156, 92, 255, 255, 255, 255, 218, 92, 139, 0, 0, 0, 0, 25, 255, 51, 0, 0, 0, 0, 78, 218, 255, 255, 78];
pub static GLYPH_101: Glyph = Glyph { width: 6, height: 6, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_101_DATA };
pub static GLYPH_102_DATA: [u8; 36] = [0, 38, 218, 255, 0, 139, 107, 0, 0, 174, 51, 0, 174, 255, 255, 174, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0];
pub static GLYPH_102: Glyph = Glyph { width: 4, height: 9, x_offset: 0, y_offset: 2, advance: 5, data: &GLYPH_102_DATA };
pub static GLYPH_103_DATA: [u8; 63] = [0, 78, 218, 255, 122, 255, 51, 25, 255, 51, 0, 78, 255, 51, 78, 139, 0, 0, 0, 255, 51, 107, 122, 0, 0, 0, 255, 51, 38, 255, 38, 0, 92, 255, 51, 0, 78, 255, 255, 78, 255, 38, 0, 0, 0, 0, 12, 255, 0, 0, 0, 0, 12, 139, 174, 0, 0, 195, 255, 255, 156, 12, 0];
pub static GLYPH_103: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 5, advance: 8, data: &GLYPH_103_DATA };
pub static GLYPH_104_DATA: [u8; 45] = [255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 78, 255, 255, 78, 255, 92, 0, 78, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255];
pub static GLYPH_104: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 7, data: &GLYPH_104_DATA };
pub static GLYPH_105_DATA: [u8; 18] = [218, 25, 0, 0, 0, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0];
pub static GLYPH_105: Glyph = Glyph { width: 2, height: 9, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_105_DATA };
pub static GLYPH_106_DATA: [u8; 36] = [0, 218, 25, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 92, 156, 0, 218, 38, 0];
pub static GLYPH_106: Glyph = Glyph { width: 3, height: 12, x_offset: 0, y_offset: 2, advance: 4, data: &GLYPH_106_DATA };
pub static GLYPH_107_DATA: [u8; 45] = [255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 0, 12, 195, 78, 255, 12, 195, 78, 0, 255, 174, 78, 0, 0, 255, 139, 139, 0, 0, 255, 0, 174, 139, 0, 255, 0, 12, 195, 78];
pub static GLYPH_107: Glyph = Glyph { width: 5, height: 9, x_offset: 1, y_offset: 2, advance: 6, data: &GLYPH_107_DATA };
pub static GLYPH_108_DATA: [u8; 9] = [255, 255, 255, 255, 255, 255, 255, 255, 255];
pub static GLYPH_108: Glyph = Glyph { width: 1, height: 9, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_108_DATA };
pub static GLYPH_109_DATA: [u8; 54] = [255, 64, 255, 195, 25, 174, 255, 174, 0, 255, 64, 0, 156, 255, 38, 12, 218, 51, 255, 0, 0, 51, 174, 0, 0, 174, 78, 255, 0, 0, 51, 174, 0, 0, 174, 107, 255, 0, 0, 51, 174, 0, 0, 174, 107, 255, 0, 0, 51, 174, 0, 0, 174, 107];
pub static GLYPH_109: Glyph = Glyph { width: 9, height: 6, x_offset: 1, y_offset: 5, advance: 10, data: &GLYPH_109_DATA };
pub static GLYPH_110_DATA: [u8; 30] = [255, 78, 255, 255, 78, 255, 92, 0, 92, 218, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 255];
pub static GLYPH_110: Glyph = Glyph { width: 5, height: 6, x_offset: 1, y_offset: 5, advance: 7, data: &GLYPH_110_DATA };
pub static GLYPH_111_DATA: [u8; 42] = [0, 64, 218, 255, 218, 78, 0, 25, 255, 51, 0, 51, 255, 38, 92, 139, 0, 0, 0, 122, 107, 92, 139, 0, 0, 0, 122, 107, 25, 255, 51, 0, 38, 255, 25, 0, 64, 218, 255, 218, 64, 0];
pub static GLYPH_111: Glyph = Glyph { width: 7, height: 6, x_offset: 0, y_offset: 5, advance: 8, data: &GLYPH_111_DATA };
pub static GLYPH_112_DATA: [u8; 54] = [255, 78, 255, 255, 122, 0, 255, 122, 0, 25, 218, 51, 255, 0, 0, 0, 107, 107, 255, 0, 0, 0, 122, 107, 255, 107, 0, 38, 255, 25, 255, 78, 255, 255, 78, 0, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0];
pub static GLYPH_112: Glyph = Glyph { width: 6, height: 9, x_offset: 1, y_offset: 5, advance: 7, data: &GLYPH_112_DATA };
pub static GLYPH_113_DATA: [u8; 63] = [0, 78, 218, 255, 122, 255, 51, 25, 255, 51, 0, 78, 255, 51, 92, 139, 0, 0, 0, 255, 51, 107, 122, 0, 0, 0, 255, 51, 38, 255, 38, 0, 92, 255, 51, 0, 78, 255, 255, 78, 255, 51, 0, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0, 0, 255, 51, 0, 0, 0, 0, 0, 255, 51];
pub static GLYPH_113: Glyph = Glyph { width: 7, height: 9, x_offset: 0, y_offset: 5, advance: 8, data: &GLYPH_113_DATA };
pub static GLYPH_114_DATA: [u8; 24] = [255, 78, 255, 51, 255, 92, 0, 0, 255, 12, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0];
pub static GLYPH_114: Glyph = Glyph { width: 4, height: 6, x_offset: 1, y_offset: 5, advance: 5, data: &GLYPH_114_DATA };
pub static GLYPH_115_DATA: [u8; 30] = [12, 139, 255, 255, 78, 51, 195, 0, 0, 0, 25, 218, 107, 25, 0, 0, 12, 92, 218, 64, 0, 0, 0, 122, 107, 78, 255, 255, 174, 38];
pub static GLYPH_115: Glyph = Glyph { width: 5, height: 6, x_offset: 0, y_offset: 5, advance: 6, data: &GLYPH_115_DATA };
pub static GLYPH_116_DATA: [u8; 32] = [0, 122, 51, 0, 0, 174, 51, 0, 174, 255, 255, 174, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 174, 92, 0, 0, 64, 255, 174];
pub static GLYPH_116: Glyph = Glyph { width: 4, height: 8, x_offset: 0, y_offset: 3, advance: 5, data: &GLYPH_116_DATA };
pub static GLYPH_117_DATA: [u8; 36] = [51, 255, 0, 0, 51, 255, 51, 255, 0, 0, 51, 255, 51, 255, 0, 0, 51, 255, 25, 255, 0, 0, 51, 255, 0, 255, 51, 0, 139, 255, 0, 78, 255, 255, 107, 255];
pub static GLYPH_117: Glyph = Glyph { width: 6, height: 6, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_117_DATA };
pub static GLYPH_118_DATA: [u8; 36] = [174, 64, 0, 0, 107, 107, 78, 139, 0, 0, 218, 25, 12, 218, 12, 38, 156, 0, 0, 139, 78, 139, 64, 0, 0, 38, 156, 195, 0, 0, 0, 0, 195, 107, 0, 0];
pub static GLYPH_118: Glyph = Glyph { width: 6, height: 6, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_118_DATA };
pub static GLYPH_119_DATA: [u8; 54] = [156, 64, 0, 25, 255, 12, 0, 122, 78, 92, 122, 0, 92, 195, 64, 0, 195, 25, 25, 195, 0, 174, 64, 122, 12, 195, 0, 0, 195, 38, 156, 0, 195, 78, 107, 0, 0, 107, 174, 78, 0, 156, 174, 38, 0, 0, 38, 255, 12, 0, 78, 218, 0, 0];
pub static GLYPH_119: Glyph = Glyph { width: 9, height: 6, x_offset: 0, y_offset: 5, advance: 10, data: &GLYPH_119_DATA };
pub static GLYPH_120_DATA: [u8; 30] = [92, 139, 0, 12, 218, 0, 174, 51, 122, 64, 0, 25, 195, 156, 0, 0, 25, 195, 156, 0, 0, 174, 51, 156, 64, 107, 122, 0, 25, 218];
pub static GLYPH_120: Glyph = Glyph { width: 5, height: 6, x_offset: 0, y_offset: 5, advance: 6, data: &GLYPH_120_DATA };
pub static GLYPH_121_DATA: [u8; 54] = [174, 64, 0, 0, 92, 122, 78, 139, 0, 0, 195, 25, 0, 255, 12, 25, 174, 0, 0, 122, 78, 122, 78, 0, 0, 25, 156, 195, 0, 0, 0, 0, 195, 122, 0, 0, 0, 0, 195, 25, 0, 0, 0, 64, 174, 0, 0, 0, 174, 218, 38, 0, 0, 0];
pub static GLYPH_121: Glyph = Glyph { width: 6, height: 9, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_121_DATA };
pub static GLYPH_122_DATA: [u8; 36] = [107, 255, 255, 255, 255, 25, 0, 0, 0, 139, 64, 0, 0, 0, 78, 107, 0, 0, 0, 38, 156, 0, 0, 0, 12, 195, 12, 0, 0, 0, 139, 255, 255, 255, 255, 51];
pub static GLYPH_122: Glyph = Glyph { width: 6, height: 6, x_offset: 0, y_offset: 5, advance: 7, data: &GLYPH_122_DATA };
pub static GLYPH_123_DATA: [u8; 44] = [0, 25, 218, 107, 0, 107, 156, 0, 0, 107, 107, 0, 0, 107, 107, 0, 0, 174, 78, 0, 107, 218, 0, 0, 0, 174, 78, 0, 0, 107, 107, 0, 0, 107, 107, 0, 0, 107, 122, 0, 0, 25, 218, 107];
pub static GLYPH_123: Glyph = Glyph { width: 4, height: 11, x_offset: 0, y_offset: 2, advance: 5, data: &GLYPH_123_DATA };
pub static GLYPH_124_DATA: [u8; 12] = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];
pub static GLYPH_124: Glyph = Glyph { width: 1, height: 12, x_offset: 1, y_offset: 2, advance: 3, data: &GLYPH_124_DATA };
pub static GLYPH_125_DATA: [u8; 44] = [174, 174, 0, 0, 12, 218, 51, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 139, 107, 0, 0, 25, 255, 51, 0, 139, 107, 0, 0, 174, 51, 0, 0, 174, 51, 0, 0, 195, 51, 0, 174, 174, 0, 0];
pub static GLYPH_125: Glyph = Glyph { width: 4, height: 11, x_offset: 0, y_offset: 2, advance: 5, data: &GLYPH_125_DATA };
pub static GLYPH_126_DATA: [u8; 12] = [64, 255, 218, 64, 12, 195, 174, 25, 51, 174, 255, 78];
pub static GLYPH_126: Glyph = Glyph { width: 6, height: 2, x_offset: 1, y_offset: 7, advance: 8, data: &GLYPH_126_DATA };

pub static ASCII_GLYPHS: [Glyph; 95] = [
    GLYPH_32,
    GLYPH_33,
    GLYPH_34,
    GLYPH_35,
    GLYPH_36,
    GLYPH_37,
    GLYPH_38,
    GLYPH_39,
    GLYPH_40,
    GLYPH_41,
    GLYPH_42,
    GLYPH_43,
    GLYPH_44,
    GLYPH_45,
    GLYPH_46,
    GLYPH_47,
    GLYPH_48,
    GLYPH_49,
    GLYPH_50,
    GLYPH_51,
    GLYPH_52,
    GLYPH_53,
    GLYPH_54,
    GLYPH_55,
    GLYPH_56,
    GLYPH_57,
    GLYPH_58,
    GLYPH_59,
    GLYPH_60,
    GLYPH_61,
    GLYPH_62,
    GLYPH_63,
    GLYPH_64,
    GLYPH_65,
    GLYPH_66,
    GLYPH_67,
    GLYPH_68,
    GLYPH_69,
    GLYPH_70,
    GLYPH_71,
    GLYPH_72,
    GLYPH_73,
    GLYPH_74,
    GLYPH_75,
    GLYPH_76,
    GLYPH_77,
    GLYPH_78,
    GLYPH_79,
    GLYPH_80,
    GLYPH_81,
    GLYPH_82,
    GLYPH_83,
    GLYPH_84,
    GLYPH_85,
    GLYPH_86,
    GLYPH_87,
    GLYPH_88,
    GLYPH_89,
    GLYPH_90,
    GLYPH_91,
    GLYPH_92,
    GLYPH_93,
    GLYPH_94,
    GLYPH_95,
    GLYPH_96,
    GLYPH_97,
    GLYPH_98,
    GLYPH_99,
    GLYPH_100,
    GLYPH_101,
    GLYPH_102,
    GLYPH_103,
    GLYPH_104,
    GLYPH_105,
    GLYPH_106,
    GLYPH_107,
    GLYPH_108,
    GLYPH_109,
    GLYPH_110,
    GLYPH_111,
    GLYPH_112,
    GLYPH_113,
    GLYPH_114,
    GLYPH_115,
    GLYPH_116,
    GLYPH_117,
    GLYPH_118,
    GLYPH_119,
    GLYPH_120,
    GLYPH_121,
    GLYPH_122,
    GLYPH_123,
    GLYPH_124,
    GLYPH_125,
    GLYPH_126,
];

pub static GLYPH_TR_LOWER_C_DATA: [u8; 45] = [0, 38, 195, 255, 255, 25, 255, 51, 0, 0, 78, 139, 0, 0, 0, 92, 139, 0, 0, 0, 25, 255, 51, 0, 0, 0, 64, 218, 255, 218, 0, 0, 51, 255, 64, 0, 0, 0, 78, 107, 0, 0, 174, 218, 38];
pub static GLYPH_TR_LOWER_C: Glyph = Glyph { width: 5, height: 9, x_offset: 0, y_offset: 5, advance: 6, data: &GLYPH_TR_LOWER_C_DATA };
pub static GLYPH_TR_UPPER_C_DATA: [u8; 84] = [0, 0, 64, 195, 255, 255, 78, 0, 78, 195, 51, 0, 25, 92, 12, 255, 25, 0, 0, 0, 0, 64, 156, 0, 0, 0, 0, 0, 107, 107, 0, 0, 0, 0, 0, 78, 139, 0, 0, 0, 0, 0, 25, 255, 12, 0, 0, 0, 0, 0, 122, 195, 38, 0, 25, 92, 0, 0, 107, 218, 255, 218, 51, 0, 0, 0, 51, 255, 64, 0, 0, 0, 0, 0, 64, 107, 0, 0, 0, 0, 174, 255, 51, 0];
pub static GLYPH_TR_UPPER_C: Glyph = Glyph { width: 7, height: 12, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_TR_UPPER_C_DATA };
pub static GLYPH_TR_LOWER_G_DATA: [u8; 84] = [0, 0, 139, 12, 107, 51, 0, 0, 0, 64, 255, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 218, 255, 122, 255, 51, 25, 255, 51, 0, 78, 255, 51, 78, 139, 0, 0, 0, 255, 51, 107, 122, 0, 0, 0, 255, 51, 38, 255, 38, 0, 92, 255, 51, 0, 78, 255, 255, 78, 255, 38, 0, 0, 0, 0, 12, 255, 0, 0, 0, 0, 12, 139, 174, 0, 0, 195, 255, 255, 156, 12, 0];
pub static GLYPH_TR_LOWER_G: Glyph = Glyph { width: 7, height: 12, x_offset: 0, y_offset: 2, advance: 8, data: &GLYPH_TR_LOWER_G_DATA };
pub static GLYPH_TR_UPPER_G_DATA: [u8; 96] = [0, 0, 0, 139, 12, 64, 92, 0, 0, 0, 0, 38, 255, 195, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 195, 255, 255, 156, 25, 0, 78, 195, 51, 0, 12, 92, 51, 12, 255, 25, 0, 0, 0, 0, 0, 64, 156, 0, 0, 0, 0, 0, 0, 107, 107, 0, 0, 107, 255, 255, 107, 78, 156, 0, 0, 0, 0, 107, 107, 25, 255, 12, 0, 0, 0, 107, 107, 0, 122, 195, 38, 0, 12, 139, 107, 0, 0, 107, 218, 255, 255, 139, 25];
pub static GLYPH_TR_UPPER_G: Glyph = Glyph { width: 8, height: 12, x_offset: 0, y_offset: -1, advance: 9, data: &GLYPH_TR_UPPER_G_DATA };
pub static GLYPH_TR_LOWER_I_DATA: [u8; 6] = [255, 255, 255, 255, 255, 255];
pub static GLYPH_TR_LOWER_I: Glyph = Glyph { width: 1, height: 6, x_offset: 1, y_offset: 5, advance: 3, data: &GLYPH_TR_LOWER_I_DATA };
pub static GLYPH_TR_UPPER_I_DATA: [u8; 22] = [107, 51, 0, 0, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51, 255, 51];
pub static GLYPH_TR_UPPER_I: Glyph = Glyph { width: 2, height: 11, x_offset: 1, y_offset: 0, advance: 3, data: &GLYPH_TR_UPPER_I_DATA };
pub static GLYPH_TR_LOWER_O_DATA: [u8; 56] = [0, 0, 218, 25, 139, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 218, 255, 218, 78, 0, 25, 255, 51, 0, 51, 255, 38, 92, 139, 0, 0, 0, 122, 107, 92, 139, 0, 0, 0, 122, 107, 25, 255, 51, 0, 38, 255, 25, 0, 64, 218, 255, 218, 64, 0];
pub static GLYPH_TR_LOWER_O: Glyph = Glyph { width: 7, height: 8, x_offset: 0, y_offset: 3, advance: 8, data: &GLYPH_TR_LOWER_O_DATA };
pub static GLYPH_TR_UPPER_O_DATA: [u8; 99] = [0, 0, 0, 218, 25, 139, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 107, 218, 255, 255, 107, 0, 0, 0, 122, 195, 38, 0, 25, 156, 139, 0, 25, 255, 12, 0, 0, 0, 12, 218, 38, 64, 156, 0, 0, 0, 0, 0, 122, 92, 107, 107, 0, 0, 0, 0, 0, 107, 107, 78, 156, 0, 0, 0, 0, 0, 122, 92, 25, 255, 12, 0, 0, 0, 12, 218, 25, 0, 122, 195, 25, 0, 25, 156, 122, 0, 0, 0, 107, 218, 255, 218, 107, 0, 0];
pub static GLYPH_TR_UPPER_O: Glyph = Glyph { width: 9, height: 11, x_offset: 0, y_offset: 0, advance: 10, data: &GLYPH_TR_UPPER_O_DATA };
pub static GLYPH_TR_LOWER_S_DATA: [u8; 45] = [12, 139, 255, 255, 78, 51, 195, 0, 0, 0, 25, 218, 107, 25, 0, 0, 12, 92, 218, 64, 0, 0, 0, 122, 107, 78, 255, 255, 174, 38, 0, 0, 255, 122, 0, 0, 0, 25, 174, 0, 0, 107, 255, 78, 0];
pub static GLYPH_TR_LOWER_S: Glyph = Glyph { width: 5, height: 9, x_offset: 0, y_offset: 5, advance: 6, data: &GLYPH_TR_LOWER_S_DATA };
pub static GLYPH_TR_UPPER_S_DATA: [u8; 72] = [0, 64, 218, 255, 218, 38, 25, 218, 25, 0, 51, 92, 51, 174, 0, 0, 0, 0, 12, 218, 107, 12, 0, 0, 0, 12, 139, 255, 64, 0, 0, 0, 0, 51, 195, 64, 0, 0, 0, 0, 64, 174, 38, 78, 12, 0, 139, 139, 12, 156, 255, 255, 139, 12, 0, 0, 51, 255, 51, 0, 0, 0, 0, 78, 107, 0, 0, 0, 174, 218, 25, 0];
pub static GLYPH_TR_UPPER_S: Glyph = Glyph { width: 6, height: 12, x_offset: 0, y_offset: 2, advance: 7, data: &GLYPH_TR_UPPER_S_DATA };
pub static GLYPH_TR_LOWER_U_DATA: [u8; 48] = [0, 0, 218, 25, 139, 78, 0, 0, 0, 0, 0, 0, 51, 255, 0, 0, 51, 255, 51, 255, 0, 0, 51, 255, 51, 255, 0, 0, 51, 255, 25, 255, 0, 0, 51, 255, 0, 255, 51, 0, 139, 255, 0, 78, 255, 255, 107, 255];
pub static GLYPH_TR_LOWER_U: Glyph = Glyph { width: 6, height: 8, x_offset: 0, y_offset: 3, advance: 7, data: &GLYPH_TR_LOWER_U_DATA };
pub static GLYPH_TR_UPPER_U_DATA: [u8; 77] = [0, 25, 174, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 0, 0, 0, 0, 174, 51, 255, 25, 0, 0, 0, 218, 25, 139, 156, 12, 0, 92, 195, 0, 12, 139, 255, 255, 156, 38, 0];
pub static GLYPH_TR_UPPER_U: Glyph = Glyph { width: 7, height: 11, x_offset: 1, y_offset: 0, advance: 8, data: &GLYPH_TR_UPPER_U_DATA };

pub fn get_glyph(c: char) -> Option<&'static Glyph> {
    match c {
        ' '..='~' => ASCII_GLYPHS.get((c as usize).saturating_sub(32)),
        '\u{00E7}' => Some(&GLYPH_TR_LOWER_C), // Ã§
        '\u{00C7}' => Some(&GLYPH_TR_UPPER_C), // Ã‡
        '\u{011F}' => Some(&GLYPH_TR_LOWER_G), // ÄŸ
        '\u{011E}' => Some(&GLYPH_TR_UPPER_G), // Ä
        '\u{0131}' => Some(&GLYPH_TR_LOWER_I), // Ä±
        '\u{0130}' => Some(&GLYPH_TR_UPPER_I), // Ä°
        '\u{00F6}' => Some(&GLYPH_TR_LOWER_O), // Ã¶
        '\u{00D6}' => Some(&GLYPH_TR_UPPER_O), // Ã–
        '\u{015F}' => Some(&GLYPH_TR_LOWER_S), // ÅŸ
        '\u{015E}' => Some(&GLYPH_TR_UPPER_S), // Å
        '\u{00FC}' => Some(&GLYPH_TR_LOWER_U), // Ã¼
        '\u{00DC}' => Some(&GLYPH_TR_UPPER_U), // Ãœ
        '\u{2014}' => ASCII_GLYPHS.get(('-' as usize).saturating_sub(32)), // â€”
        _ => ASCII_GLYPHS.get(('?' as usize).saturating_sub(32)),
    }
}

pub fn string_width(s: &str) -> usize {
    let mut w = 0;
    for c in s.chars() {
        if let Some(g) = get_glyph(c) {
            w += g.advance as usize;
        } else {
            w += 6;
        }
    }
    w
}
