use corboot_info::{BootInfo, PIXEL_BIT_MASK, PIXEL_BLUE_GREEN_RED_RESERVED_8, PIXEL_RED_GREEN_BLUE_RESERVED_8};
use core::ptr::NonNull;

const SCALE: usize = 2;
const CHAR_WIDTH: usize = 6 * SCALE;
const CHAR_HEIGHT: usize = 8 * SCALE;
const MARGIN: usize = 16;
const BACKGROUND: (u8, u8, u8) = (10, 18, 34);
const FOREGROUND: (u8, u8, u8) = (232, 240, 248);

pub struct EarlyConsole {
    framebuffer: Option<FramebufferConsole>,
}

impl EarlyConsole {
    pub const fn new(framebuffer: Option<FramebufferConsole>) -> Self {
        Self { framebuffer }
    }

    pub fn write_line(&mut self, line: &str) {
        if let Some(framebuffer) = &mut self.framebuffer {
            framebuffer.write_line(line);
        }
    }

    pub fn write_u64_line(&mut self, label: &str, value: u64) {
        if let Some(framebuffer) = &mut self.framebuffer {
            framebuffer.write_u64_line(label, value);
        }
    }
}

pub struct FramebufferConsole {
    base: *mut u8,
    size: usize,
    width: usize,
    height: usize,
    stride: usize,
    format: u32,
    masks: [u32; 4],
    cursor_x: usize,
    cursor_y: usize,
}

impl FramebufferConsole {
    /// Builds a console only from a caller-provided virtual mapping.
    /// # Safety
    /// `mapped_base` must alias exactly `info.framebuffer_address`, be writable
    /// device memory for the full `mapped_size`, and remain mapped for this console's lifetime.
    pub unsafe fn from_mapped_base(info: &BootInfo, mapped_base: NonNull<u8>, mapped_size: usize, line: usize, clear: bool) -> Option<Self> {
        if info.validate().is_err() || info.flags & corboot_info::FLAG_FRAMEBUFFER == 0 {
            return None;
        }
        let size = usize::try_from(info.framebuffer_size).ok()?;
        let base = mapped_base.as_ptr() as usize;
        let virtual_end = base.checked_add(mapped_size)?;
        if size == 0 || mapped_size < size || virtual_end == 0
            || crate::memory::VirtualAddress::new(base as u64).is_none()
            || crate::memory::VirtualAddress::new((virtual_end - 1) as u64).is_none()
            || (base >> 47) != ((virtual_end - 1) >> 47)
            || info.framebuffer_width == 0
            || info.framebuffer_height == 0
            || info.framebuffer_stride < info.framebuffer_width
            || !matches!(
                info.framebuffer_format,
                PIXEL_RED_GREEN_BLUE_RESERVED_8
                    | PIXEL_BLUE_GREEN_RED_RESERVED_8
                    | PIXEL_BIT_MASK
            )
        {
            return None;
        }
        let required_size = (info.framebuffer_stride as u64)
            .checked_mul(info.framebuffer_height as u64)?
            .checked_mul(4)?;
        if info.framebuffer_size < required_size
            || (info.framebuffer_format == PIXEL_BIT_MASK
                && (info.red_mask == 0 || info.green_mask == 0 || info.blue_mask == 0))
        {
            return None;
        }
        let mut console = Self {
            base: mapped_base.as_ptr(),
            size: size.min(mapped_size),
            width: info.framebuffer_width as usize,
            height: info.framebuffer_height as usize,
            stride: info.framebuffer_stride as usize,
            format: info.framebuffer_format,
            masks: [info.red_mask, info.green_mask, info.blue_mask, info.reserved_mask],
            cursor_x: MARGIN,
            cursor_y: MARGIN.saturating_add(line.saturating_mul(CHAR_HEIGHT)),
        };
        if clear { console.clear(); }
        Some(console)
    }

    pub fn write_line(&mut self, line: &str) {
        for byte in line.bytes() {
            if byte == b'\n' {
                self.new_line();
            } else if byte != b'\r' {
                self.draw_char(byte as char);
            }
        }
        self.new_line();
    }

    pub fn write_u64_line(&mut self, label: &str, value: u64) {
        for byte in label.bytes() {
            self.draw_char(byte as char);
        }
        let mut digits = [0u8; 20];
        let mut value = value;
        let mut count = 0;
        if value == 0 {
            digits[0] = b'0';
            count = 1;
        } else {
            while value != 0 && count < digits.len() {
                digits[count] = b'0' + (value % 10) as u8;
                value /= 10;
                count += 1;
            }
        }
        while count != 0 {
            count -= 1;
            self.draw_char(digits[count] as char);
        }
        self.new_line();
    }

    fn clear(&mut self) {
        let pixel_u32 = match self.format {
            PIXEL_RED_GREEN_BLUE_RESERVED_8 => (BACKGROUND.0 as u32) | ((BACKGROUND.1 as u32) << 8) | ((BACKGROUND.2 as u32) << 16),
            PIXEL_BLUE_GREEN_RED_RESERVED_8 => (BACKGROUND.2 as u32) | ((BACKGROUND.1 as u32) << 8) | ((BACKGROUND.0 as u32) << 16),
            PIXEL_BIT_MASK => {
                component(BACKGROUND.0, self.masks[0])
                    | component(BACKGROUND.1, self.masks[1])
                    | component(BACKGROUND.2, self.masks[2])
                    | component(0, self.masks[3])
            }
            _ => return,
        };
        let double_pixel = (pixel_u32 as u64) | ((pixel_u32 as u64) << 32);
        let total_pixels = self.stride.saturating_mul(self.height);
        let count_u64 = total_pixels / 2;
        let dst_u64 = self.base as *mut u64;
        for i in 0..count_u64 {
            unsafe { core::ptr::write_volatile(dst_u64.add(i), double_pixel); }
        }
        if total_pixels % 2 != 0 {
            unsafe { core::ptr::write_volatile(self.base.add((total_pixels - 1) * 4) as *mut u32, pixel_u32); }
        }
    }

    fn new_line(&mut self) {
        self.cursor_x = MARGIN;
        self.cursor_y = self.cursor_y.saturating_add(CHAR_HEIGHT);
    }

    fn draw_char(&mut self, character: char) {
        if self.cursor_x.saturating_add(CHAR_WIDTH) > self.width {
            self.new_line();
        }
        if self.cursor_y.saturating_add(CHAR_HEIGHT) > self.height {
            return;
        }
        let columns = glyph(character);
        for (x, column) in columns.iter().enumerate() {
            for y in 0..7 {
                if *column & (1u8 << y) != 0 {
                    for dy in 0..SCALE {
                        for dx in 0..SCALE {
                            self.pixel(
                                self.cursor_x + x * SCALE + dx,
                                self.cursor_y + y * SCALE + dy,
                                FOREGROUND,
                            );
                        }
                    }
                }
            }
        }
        self.cursor_x += CHAR_WIDTH;
    }

    fn pixel(&mut self, x: usize, y: usize, color: (u8, u8, u8)) {
        if x >= self.width || y >= self.height || x >= self.stride {
            return;
        }
        let Some(index) = y
            .checked_mul(self.stride)
            .and_then(|row| row.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(4))
        else {
            return;
        };
        if match index.checked_add(4) {
            Some(end) => end > self.size,
            None => true,
        } {
            return;
        }
        let pixel_u32 = match self.format {
            PIXEL_RED_GREEN_BLUE_RESERVED_8 => (color.0 as u32) | ((color.1 as u32) << 8) | ((color.2 as u32) << 16),
            PIXEL_BLUE_GREEN_RED_RESERVED_8 => (color.2 as u32) | ((color.1 as u32) << 8) | ((color.0 as u32) << 16),
            PIXEL_BIT_MASK => {
                component(color.0, self.masks[0])
                    | component(color.1, self.masks[1])
                    | component(color.2, self.masks[2])
                    | component(0, self.masks[3])
            }
            _ => return,
        };
        unsafe {
            let dest = (self.base as *mut u32).add(index / 4);
            core::ptr::write_volatile(dest, pixel_u32);
        }
    }
}

fn component(value: u8, mask: u32) -> u32 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let maximum = mask >> shift;
    ((((value as u64 * maximum as u64 + 127) / 255) as u32) << shift) & mask
}

pub fn glyph(character: char) -> [u8; 5] {
    match character {
        'A' => [0x7e, 0x11, 0x11, 0x11, 0x7e],
        'B' => [0x7f, 0x49, 0x49, 0x49, 0x36],
        'C' => [0x3e, 0x41, 0x41, 0x41, 0x22],
        'D' => [0x7f, 0x41, 0x41, 0x22, 0x1c],
        'E' => [0x7f, 0x49, 0x49, 0x49, 0x41],
        'F' => [0x7f, 0x09, 0x09, 0x09, 0x01],
        'G' => [0x3e, 0x41, 0x49, 0x49, 0x7a],
        'H' => [0x7f, 0x08, 0x08, 0x08, 0x7f],
        'I' => [0x00, 0x41, 0x7f, 0x41, 0x00],
        'J' => [0x20, 0x40, 0x41, 0x3f, 0x01],
        'K' => [0x7f, 0x08, 0x14, 0x22, 0x41],
        'L' => [0x7f, 0x40, 0x40, 0x40, 0x40],
        'M' => [0x7f, 0x02, 0x04, 0x02, 0x7f],
        'N' => [0x7f, 0x04, 0x08, 0x10, 0x7f],
        'O' => [0x3e, 0x41, 0x41, 0x41, 0x3e],
        'P' => [0x7f, 0x09, 0x09, 0x09, 0x06],
        'Q' => [0x3e, 0x41, 0x51, 0x21, 0x5e],
        'R' => [0x7f, 0x09, 0x19, 0x29, 0x46],
        'S' => [0x46, 0x49, 0x49, 0x49, 0x31],
        'T' => [0x01, 0x01, 0x7f, 0x01, 0x01],
        'U' => [0x3f, 0x40, 0x40, 0x40, 0x3f],
        'V' => [0x1f, 0x20, 0x40, 0x20, 0x1f],
        'W' => [0x3f, 0x40, 0x38, 0x40, 0x3f],
        'X' => [0x63, 0x14, 0x08, 0x14, 0x63],
        'Y' => [0x07, 0x08, 0x70, 0x08, 0x07],
        'Z' => [0x61, 0x51, 0x49, 0x45, 0x43],
        '0' => [0x3e, 0x51, 0x49, 0x45, 0x3e],
        '1' => [0x00, 0x42, 0x7f, 0x40, 0x00],
        '2' => [0x42, 0x61, 0x51, 0x49, 0x46],
        '3' => [0x21, 0x41, 0x45, 0x4b, 0x31],
        '4' => [0x18, 0x14, 0x12, 0x7f, 0x10],
        '5' => [0x27, 0x45, 0x45, 0x45, 0x39],
        '6' => [0x3c, 0x4a, 0x49, 0x49, 0x30],
        '7' => [0x01, 0x71, 0x09, 0x05, 0x03],
        '8' => [0x36, 0x49, 0x49, 0x49, 0x36],
        '9' => [0x06, 0x49, 0x49, 0x29, 0x1e],
        ':' => [0x00, 0x36, 0x36, 0x00, 0x00],
        '-' => [0x08, 0x08, 0x08, 0x08, 0x08],
        '(' => [0x00, 0x1c, 0x22, 0x41, 0x00],
        ')' => [0x00, 0x41, 0x22, 0x1c, 0x00],
        '[' => [0x00, 0x7f, 0x41, 0x41, 0x00],
        ']' => [0x00, 0x41, 0x41, 0x7f, 0x00],
        '.' => [0x00, 0x60, 0x60, 0x00, 0x00],
        ',' => [0x00, 0x50, 0x30, 0x00, 0x00],
        '%' => [0x23, 0x13, 0x08, 0x64, 0x62],
        '+' => [0x08, 0x08, 0x3e, 0x08, 0x08],
        '=' => [0x14, 0x14, 0x14, 0x14, 0x14],
        '/' => [0x20, 0x10, 0x08, 0x04, 0x02],
        '_' => [0x40, 0x40, 0x40, 0x40, 0x40],
        '!' => [0x00, 0x00, 0x5f, 0x00, 0x00],
        '?' => [0x02, 0x01, 0x51, 0x09, 0x06],
        '<' => [0x08, 0x14, 0x22, 0x41, 0x00],
        '>' => [0x41, 0x22, 0x14, 0x08, 0x00],
        '*' => [0x14, 0x08, 0x3e, 0x08, 0x14],
        '|' => [0x00, 0x00, 0x7f, 0x00, 0x00],
        '#' => [0x14, 0x7f, 0x14, 0x7f, 0x14],
        '&' => [0x36, 0x49, 0x35, 0x22, 0x54],
        'a' => [0x20, 0x54, 0x54, 0x54, 0x78],
        'b' => [0x7f, 0x48, 0x44, 0x44, 0x38],
        'c' => [0x38, 0x44, 0x44, 0x44, 0x20],
        'd' => [0x38, 0x44, 0x44, 0x48, 0x7f],
        'e' => [0x38, 0x54, 0x54, 0x54, 0x18],
        'f' => [0x08, 0x7e, 0x09, 0x01, 0x02],
        'g' => [0x08, 0x14, 0x54, 0x54, 0x3c],
        'h' => [0x7f, 0x08, 0x04, 0x04, 0x78],
        'i' => [0x00, 0x44, 0x7d, 0x40, 0x00],
        'j' => [0x20, 0x40, 0x44, 0x3d, 0x00],
        'k' => [0x7f, 0x10, 0x28, 0x44, 0x00],
        'l' => [0x00, 0x41, 0x7f, 0x40, 0x00],
        'm' => [0x7c, 0x04, 0x18, 0x04, 0x78],
        'n' => [0x7c, 0x08, 0x04, 0x04, 0x78],
        'o' => [0x38, 0x44, 0x44, 0x44, 0x38],
        'p' => [0x7c, 0x14, 0x14, 0x14, 0x08],
        'q' => [0x08, 0x14, 0x14, 0x18, 0x7c],
        'r' => [0x7c, 0x08, 0x04, 0x04, 0x08],
        's' => [0x48, 0x54, 0x54, 0x54, 0x20],
        't' => [0x04, 0x3f, 0x44, 0x40, 0x20],
        'u' => [0x3c, 0x40, 0x40, 0x20, 0x7c],
        'v' => [0x1c, 0x20, 0x40, 0x20, 0x1c],
        'w' => [0x3c, 0x40, 0x30, 0x40, 0x3c],
        'x' => [0x44, 0x28, 0x10, 0x28, 0x44],
        'y' => [0x0c, 0x50, 0x50, 0x50, 0x3c],
        'z' => [0x44, 0x64, 0x54, 0x4c, 0x44],
        '@' => [0x32, 0x49, 0x79, 0x41, 0x3e],
        '~' => [0x08, 0x04, 0x08, 0x10, 0x08],
        '$' => [0x24, 0x2a, 0x7f, 0x2a, 0x12],
        '"' => [0x00, 0x07, 0x00, 0x07, 0x00],
        '\'' => [0x00, 0x00, 0x07, 0x00, 0x00],
        ';' => [0x00, 0x56, 0x30, 0x00, 0x00],
        '\\' => [0x02, 0x04, 0x08, 0x10, 0x20],
        '{' => [0x00, 0x08, 0x36, 0x41, 0x00],
        '}' => [0x00, 0x41, 0x36, 0x08, 0x00],
        '^' => [0x04, 0x02, 0x01, 0x02, 0x04],
        '`' => [0x00, 0x01, 0x02, 0x00, 0x00],
        ' ' => [0; 5],
        _ => [0; 5],
    }
}
