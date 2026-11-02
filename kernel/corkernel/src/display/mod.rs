//! High-Performance Graphics & Display Subsystem for CorOS
//!
//! Provides hardware-accelerated software rasterization, double-buffering,
//! and 128-bit SSE non-temporal streaming blits to bypass cache pollution
//! when transferring rendered frames to PCIe video memory.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use corboot_info::{BootInfo, PIXEL_BIT_MASK, PIXEL_BLUE_GREEN_RED_RESERVED_8, PIXEL_RED_GREEN_BLUE_RESERVED_8};
use core::ptr;

pub mod rasterizer;
pub mod shader_core;
pub mod truetype;
pub mod drm_kms_bridge;

pub use drm_kms_bridge::{DrmKmsBridge, GLOBAL_DRM_KMS_BRIDGE};
pub use truetype::{TrueTypeFont, GlyphOutline, GlyphPoint};
pub use rasterizer::{SoftwareRasterizer, RasterVertex, DepthFunc, StencilOp, Texture2D, TextureFilter, TextureWrapMode, BlendMode};
pub use shader_core::{Mat4, Mat3, ShaderPipeline, Vertex3D, Mesh3D, PointLight, DirectionalLight, Material};


/// 24/32-bit Color representation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const BLACK: Self = Self::rgb(0, 0, 0);
    pub const WHITE: Self = Self::rgb(255, 255, 255);
    pub const RED: Self = Self::rgb(255, 0, 0);
    pub const GREEN: Self = Self::rgb(0, 255, 0);
    pub const BLUE: Self = Self::rgb(0, 100, 255);
    pub const CYAN: Self = Self::rgb(0, 220, 220);
    pub const DARK_SLATE: Self = Self::rgb(15, 23, 42);   // Modern OS background
    pub const ACCENT_BLUE: Self = Self::rgb(37, 99, 235);  // High-performance accent
    pub const EMERALD: Self = Self::rgb(16, 185, 129);     // Performance green
    pub const YELLOW: Self = Self::rgb(234, 179, 8);       // Warning / Pending amber
    pub const MAGENTA: Self = Self::rgb(217, 70, 239);     // Neon synthwave magenta
    pub const PURPLE: Self = Self::rgb(147, 51, 234);      // Cyber purple

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Converts Color to native 32-bit framebuffer pixel according to format
    #[inline(always)]
    pub fn to_pixel_u32(self, format: u32, masks: [u32; 4]) -> u32 {
        match format {
            PIXEL_RED_GREEN_BLUE_RESERVED_8 => {
                (self.r as u32) | ((self.g as u32) << 8) | ((self.b as u32) << 16)
            }
            PIXEL_BLUE_GREEN_RED_RESERVED_8 => {
                (self.b as u32) | ((self.g as u32) << 8) | ((self.r as u32) << 16)
            }
            PIXEL_BIT_MASK => {
                let r = component_mask(self.r, masks[0]);
                let g = component_mask(self.g, masks[1]);
                let b = component_mask(self.b, masks[2]);
                r | g | b
            }
            _ => (self.b as u32) | ((self.g as u32) << 8) | ((self.r as u32) << 16),
        }
    }

    /// Decodes native 32-bit framebuffer pixel according to format
    #[inline(always)]
    pub fn from_pixel_u32(pixel: u32, format: u32) -> (u8, u8, u8) {
        match format {
            PIXEL_RED_GREEN_BLUE_RESERVED_8 => {
                ((pixel & 0xFF) as u8, ((pixel >> 8) & 0xFF) as u8, ((pixel >> 16) & 0xFF) as u8)
            }
            PIXEL_BLUE_GREEN_RED_RESERVED_8 => {
                (((pixel >> 16) & 0xFF) as u8, ((pixel >> 8) & 0xFF) as u8, (pixel & 0xFF) as u8)
            }
            _ => (((pixel >> 16) & 0xFF) as u8, ((pixel >> 8) & 0xFF) as u8, (pixel & 0xFF) as u8),
        }
    }
}

#[inline(always)]
fn component_mask(value: u8, mask: u32) -> u32 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let maximum = mask >> shift;
    ((((value as u64 * maximum as u64 + 127) / 255) as u32) << shift) & mask
}

/// High-Performance Display Surface with SIMD Blitting
pub struct DisplayEngine {
    vram_base: *mut u32,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub format: u32,
    pub masks: [u32; 4],
    backbuffer: Vec<u32>,
    use_double_buffering: bool,
}

// DisplayEngine encapsulates a raw pointer that is uniquely owned or mapped.
unsafe impl Send for DisplayEngine {}
unsafe impl Sync for DisplayEngine {}

impl DisplayEngine {
    /// Initializes DisplayEngine from verified BootInfo and mapped virtual framebuffer.
    ///
    /// # Safety
    /// `vram_ptr` must be a valid, writable pointer to the frame buffer memory mapped with
    /// Write-Combining or normal caching, with size at least `stride * height * 4` bytes.
    pub unsafe fn new(info: &BootInfo, vram_ptr: *mut u8) -> Option<Self> {
        if info.framebuffer_width == 0 || info.framebuffer_height == 0 {
            return None;
        }
        let width = info.framebuffer_width as usize;
        let height = info.framebuffer_height as usize;
        let stride = info.framebuffer_stride as usize;
        if stride < width {
            return None;
        }

        let total_pixels = stride.checked_mul(height)?;
        let masks = [info.red_mask, info.green_mask, info.blue_mask, info.reserved_mask];

        // Allocate high-speed 64-byte aligned backbuffer in RAM for zero-latency drawing
        let mut backbuffer = Vec::new();
        let use_double_buffering = if backbuffer.try_reserve_exact(total_pixels).is_ok() {
            backbuffer.resize(total_pixels, 0);
            true
        } else {
            false
        };

        Some(Self {
            vram_base: vram_ptr as *mut u32,
            width,
            height,
            stride,
            format: info.framebuffer_format,
            masks,
            backbuffer,
            use_double_buffering,
        })
    }

    /// Applies smooth brightness / fade factor (0..256) for seamless alpha transitions
    pub fn fade_backbuffer(&mut self, factor_256: u32) {
        if !self.use_double_buffering { return; }
        for pixel in self.backbuffer.iter_mut() {
            let p = *pixel;
            let r = (((p >> 16) & 0xFF) * factor_256) >> 8;
            let g = (((p >> 8) & 0xFF) * factor_256) >> 8;
            let b = ((p & 0xFF) * factor_256) >> 8;
            *pixel = (r << 16) | (g << 8) | b;
        }
    }

    /// Fast clear of the entire screen using 64-bit double-pixel stores
    pub fn clear(&mut self, color: Color) {
        let pixel = color.to_pixel_u32(self.format, self.masks);
        let double_pixel = (pixel as u64) | ((pixel as u64) << 32);

        if self.use_double_buffering {
            let slice = &mut self.backbuffer[..];
            let chunks_exact = slice.len() / 2;
            let u64_ptr = slice.as_mut_ptr() as *mut u64;
            for i in 0..chunks_exact {
                unsafe { ptr::write(u64_ptr.add(i), double_pixel); }
            }
            if slice.len() % 2 != 0 {
                slice[slice.len() - 1] = pixel;
            }
        } else {
            let total_pixels = self.stride * self.height;
            let chunks_exact = total_pixels / 2;
            let u64_ptr = self.vram_base as *mut u64;
            for i in 0..chunks_exact {
                unsafe { ptr::write_volatile(u64_ptr.add(i), double_pixel); }
            }
            if total_pixels % 2 != 0 {
                unsafe { ptr::write_volatile(self.vram_base.add(total_pixels - 1), pixel); }
            }
        }
    }

    /// High-performance multi-theme desktop wallpaper rasterizer
    pub fn draw_wallpaper(&mut self, theme_idx: usize, show_grid: bool) {
        let sw = self.width;
        let sh = self.height;
        if sw == 0 || sh == 0 { return; }

        let cx = (sw / 2) as isize;
        let cy = ((sh + 26) / 2) as isize;

        // Precompute 641-entry palette based on theme_idx
        let mut palette = [0u32; 641];
        for r in 0..=640 {
            let (cr, cg, cb) = match theme_idx % 6 {
                // Theme 0: Kali Blue (Classic)
                0 => {
                    if r < 220 {
                        let t = r;
                        let red = 38 - (14 * t / 220);
                        let green = 152 - (56 * t / 220);
                        let blue = 212 - (44 * t / 220);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 460 {
                        let t = r - 220;
                        let red = 24 - (10 * t / 240);
                        let green = 96 - (36 * t / 240);
                        let blue = 168 - (46 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 460).min(180);
                        let red = 14 - (6 * t / 180);
                        let green = 60 - (20 * t / 180);
                        let blue = 122 - (34 * t / 180);
                        (red as u8, green as u8, blue as u8)
                    }
                }
                // Theme 1: CorOS Cyber Synthwave (Purple to Deep Indigo/Cyan)
                1 => {
                    if r < 200 {
                        let t = r;
                        let red = 92 - (44 * t / 200);
                        let green = 28 - (14 * t / 200);
                        let blue = 152 - (54 * t / 200);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 440 {
                        let t = r - 200;
                        let red = 48 - (28 * t / 240);
                        let green = 14 - (8 * t / 240);
                        let blue = 98 - (48 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 440).min(200);
                        let red = 20 - (12 * t / 200);
                        let green = 6 - (3 * t / 200);
                        let blue = 50 - (30 * t / 200);
                        (red as u8, green as u8, blue as u8)
                    }
                }
                // Theme 2: Deep Space Cosmic Void (Deep Violet/Blue to Obsidian)
                2 => {
                    if r < 180 {
                        let t = r;
                        let red = 42 - (24 * t / 180);
                        let green = 40 - (24 * t / 180);
                        let blue = 110 - (50 * t / 180);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 420 {
                        let t = r - 180;
                        let red = 18 - (12 * t / 240);
                        let green = 16 - (10 * t / 240);
                        let blue = 60 - (36 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 420).min(220);
                        let red = 6 - (3 * t / 220);
                        let green = 6 - (3 * t / 220);
                        let blue = 24 - (14 * t / 220);
                        (red as u8, green as u8, blue as u8)
                    }
                }
                // Theme 3: Minimalist Modern macOS Slate (Clean Dark Dunes)
                3 => {
                    if r < 240 {
                        let t = r;
                        let red = 45 - (18 * t / 240);
                        let green = 55 - (20 * t / 240);
                        let blue = 75 - (24 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 480 {
                        let t = r - 240;
                        let red = 27 - (12 * t / 240);
                        let green = 35 - (15 * t / 240);
                        let blue = 51 - (21 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 480).min(160);
                        let red = 15 - (6 * t / 160);
                        let green = 20 - (8 * t / 160);
                        let blue = 30 - (12 * t / 160);
                        (red as u8, green as u8, blue as u8)
                    }
                }
                // Theme 4: Matrix Cyber Green (Hacker Emerald)
                4 => {
                    if r < 220 {
                        let t = r;
                        let red = 10 - (6 * t / 220);
                        let green = 110 - (50 * t / 220);
                        let blue = 65 - (30 * t / 220);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 460 {
                        let t = r - 220;
                        let red = 4 - (2 * t / 240);
                        let green = 60 - (35 * t / 240);
                        let blue = 35 - (20 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 460).min(180);
                        let red = 2;
                        let green = 25 - (15 * t / 180);
                        let blue = 15 - (9 * t / 180);
                        (red as u8, green as u8, blue as u8)
                    }
                }
                // Theme 5: Windows 11 Fluent Light (Crisp White to Soft Cloud Blue/Silver)
                _ => {
                    if r < 200 {
                        let t = r;
                        let red = 255 - (10 * t / 200);
                        let green = 255 - (12 * t / 200);
                        let blue = 255 - (8 * t / 200);
                        (red as u8, green as u8, blue as u8)
                    } else if r < 440 {
                        let t = r - 200;
                        let red = 245 - (18 * t / 240);
                        let green = 243 - (14 * t / 240);
                        let blue = 247 - (8 * t / 240);
                        (red as u8, green as u8, blue as u8)
                    } else {
                        let t = (r - 440).min(200);
                        let red = 227 - (16 * t / 200);
                        let green = 229 - (14 * t / 200);
                        let blue = 239 - (10 * t / 200);
                        (red as u8, green as u8, blue as u8)
                    }
                }
            };
            palette[r] = Color::rgb(cr, cg, cb).to_pixel_u32(self.format, self.masks);
        }

        if self.use_double_buffering {
            for y in 26..sh {
                let dy = (y as isize - cy).abs() as usize;
                let row_offset = y * self.stride;
                let slice = &mut self.backbuffer[row_offset..row_offset + sw];

                let half_w = sw / 2;
                for x in 0..=half_w {
                    let dx = (x as isize - cx).abs() as usize;
                    let max_d = dx.max(dy);
                    let min_d = dx.min(dy);
                    let r = (max_d + ((min_d * 3) >> 3)).min(640);
                    let px = palette[r];
                    slice[x] = px;
                    slice[sw - 1 - x] = px;
                }
            }
        } else {
            for y in 26..sh {
                let dy = (y as isize - cy).abs() as usize;
                let row_offset = y * self.stride;
                let half_w = sw / 2;
                for x in 0..=half_w {
                    let dx = (x as isize - cx).abs() as usize;
                    let max_d = dx.max(dy);
                    let min_d = dx.min(dy);
                    let r = (max_d + ((min_d * 3) >> 3)).min(640);
                    let px = palette[r];
                    unsafe {
                        ptr::write_volatile(self.vram_base.add(row_offset + x), px);
                        ptr::write_volatile(self.vram_base.add(row_offset + sw - 1 - x), px);
                    }
                }
            }
        }

        // Atmosphere 1: Deep Space Stars (Theme 2)
        if (theme_idx % 5) == 2 {
            let star_coords = [
                (120, 80), (280, 140), (450, 95), (680, 120), (840, 75), (920, 160),
                (95, 230), (220, 310), (340, 260), (710, 290), (880, 340), (960, 280),
                (140, 420), (290, 490), (430, 440), (620, 470), (790, 430), (910, 510),
                (80, 600), (210, 640), (370, 590), (660, 620), (830, 650), (940, 610),
            ];
            for &(sx, sy) in &star_coords {
                if sx < sw && sy < sh {
                    self.fill_circle(sx as isize, sy as isize, 1, Color::rgb(220, 230, 255));
                }
            }
            // Planetary cosmic ring
            for rx in (cx - 160)..(cx + 160) {
                let off = (rx - cx) as isize;
                let ry = cy + 45 - (off * off) / 950;
                if rx >= 0 && (rx as usize) < sw && ry >= 26 && (ry as usize) < sh {
                    self.draw_pixel(rx as usize, ry as usize, Color::rgb(79, 70, 229));
                }
            }
        }

        // Atmosphere 2: macOS Dunes & Waves (Theme 3)
        if (theme_idx % 5) == 3 {
            for x in 0..sw {
                let x_rel = x as isize;
                let wave1_y = (sh as isize) - 220 + ((x_rel * 3) % 20) / 4 + ((x_rel - 512) * (x_rel - 512)) / 3200;
                let wave2_y = (sh as isize) - 160 - ((x_rel - 400) * (x_rel - 400)) / 4000;
                if wave1_y >= 26 && (wave1_y as usize) < sh {
                    self.draw_pixel(x, wave1_y as usize, Color::rgb(71, 85, 105));
                }
                if wave2_y >= 26 && (wave2_y as usize) < sh {
                    self.draw_pixel(x, wave2_y as usize, Color::rgb(51, 65, 85));
                }
            }
        }

        // Cyber Grid Overlay (Optional)
        if show_grid {
            let grid_color = match theme_idx % 5 {
                1 => Color::rgb(35, 15, 60),  // Purple grid
                4 => Color::rgb(5, 45, 25),   // Matrix green grid
                _ => Color::rgb(18, 30, 48),  // Cyber blue grid
            };
            self.draw_grid_lines(grid_color);
        }
    }

    /// Renders cyber grid overlay across the desktop
    pub fn draw_grid_lines(&mut self, grid_color: Color) {
        let sw = self.width;
        let sh = self.height;
        for gy in (26..sh).step_by(40) {
            self.draw_hline(0, gy, sw, grid_color);
        }
        for gx in (0..sw).step_by(40) {
            self.draw_vline(gx, 26, sh - 26, grid_color);
        }
    }

    /// Backward-compatible wrapper for Kali Linux default wallpaper
    pub fn draw_kali_wallpaper(&mut self) {
        self.draw_wallpaper(0, false);
    }

    /// Fast plot of a single pixel with boundary checks
    #[inline(always)]
    pub fn draw_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = y * self.stride + x;
        let pixel = color.to_pixel_u32(self.format, self.masks);

        if self.use_double_buffering {
            if offset < self.backbuffer.len() {
                self.backbuffer[offset] = pixel;
            }
        } else {
            unsafe { ptr::write_volatile(self.vram_base.add(offset), pixel); }
        }
    }

    /// Smoothly blends a pixel with an alpha coverage value (0..255) for anti-aliasing
    #[inline(always)]
    pub fn blend_pixel(&mut self, x: usize, y: usize, color: Color, alpha: u8) {
        if x >= self.width || y >= self.height || alpha == 0 {
            return;
        }
        let offset = y * self.stride + x;

        if alpha >= 240 {
            let pixel = color.to_pixel_u32(self.format, self.masks);
            if self.use_double_buffering {
                if offset < self.backbuffer.len() {
                    self.backbuffer[offset] = pixel;
                }
            } else {
                unsafe { ptr::write_volatile(self.vram_base.add(offset), pixel); }
            }
            return;
        }

        let current = if self.use_double_buffering {
            if offset < self.backbuffer.len() {
                self.backbuffer[offset]
            } else {
                return;
            }
        } else {
            unsafe { ptr::read_volatile(self.vram_base.add(offset)) }
        };

        let (bg_r, bg_g, bg_b) = Color::from_pixel_u32(current, self.format);
        let a = alpha as u32;
        let inv_a = 255 - a;

        let r = ((color.r as u32 * a + bg_r as u32 * inv_a + 127) / 255) as u8;
        let g = ((color.g as u32 * a + bg_g as u32 * inv_a + 127) / 255) as u8;
        let b = ((color.b as u32 * a + bg_b as u32 * inv_a + 127) / 255) as u8;

        let blended = Color::rgb(r, g, b).to_pixel_u32(self.format, self.masks);
        if self.use_double_buffering {
            self.backbuffer[offset] = blended;
        } else {
            unsafe { ptr::write_volatile(self.vram_base.add(offset), blended); }
        }
    }

    /// High-performance filled rectangle
    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }
        let max_x = (x + w).min(self.width);
        let max_y = (y + h).min(self.height);
        let fill_w = max_x - x;
        let pixel = color.to_pixel_u32(self.format, self.masks);
        let double_pixel = (pixel as u64) | ((pixel as u64) << 32);

        if self.use_double_buffering {
            for row in y..max_y {
                let row_offset = row * self.stride + x;
                let row_slice = &mut self.backbuffer[row_offset..row_offset + fill_w];
                let chunks = fill_w / 2;
                let u64_ptr = row_slice.as_mut_ptr() as *mut u64;
                for i in 0..chunks {
                    unsafe { ptr::write(u64_ptr.add(i), double_pixel); }
                }
                if fill_w % 2 != 0 {
                    row_slice[fill_w - 1] = pixel;
                }
            }
        } else {
            for row in y..max_y {
                let row_offset = row * self.stride + x;
                let chunks = fill_w / 2;
                let u64_ptr = unsafe { self.vram_base.add(row_offset) as *mut u64 };
                for i in 0..chunks {
                    unsafe { ptr::write_volatile(u64_ptr.add(i), double_pixel); }
                }
                if fill_w % 2 != 0 {
                    unsafe { ptr::write_volatile(self.vram_base.add(row_offset + fill_w - 1), pixel); }
                }
            }
        }
    }

    /// Draws an unfilled rectangle boundary
    pub fn draw_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: Color) {
        if w == 0 || h == 0 {
            return;
        }
        self.fill_rect(x, y, w, 1, color);
        self.fill_rect(x, y + h.saturating_sub(1), w, 1, color);
        self.fill_rect(x, y, 1, h, color);
        self.fill_rect(x + w.saturating_sub(1), y, 1, h, color);
    }

    /// Fast horizontal line
    #[inline(always)]
    pub fn draw_hline(&mut self, x: usize, y: usize, length: usize, color: Color) {
        self.fill_rect(x, y, length, 1, color);
    }

    /// Fast vertical line
    #[inline(always)]
    pub fn draw_vline(&mut self, x: usize, y: usize, length: usize, color: Color) {
        self.fill_rect(x, y, 1, length, color);
    }

    /// Renders a single character glyph using anti-aliased Segoe UI typography
    pub fn draw_char(&mut self, x: usize, y: usize, c: char, fg: Color, scale: usize) -> usize {
        if let Some(glyph) = crate::font::get_glyph(c) {
            let gw = glyph.width as usize;
            let gh = glyph.height as usize;
            let eff_scale = scale.max(1);

            if eff_scale == 1 {
                let start_x = (x as isize + glyph.x_offset as isize).max(0) as usize;
                let start_y = (y as isize + glyph.y_offset as isize).max(0) as usize;

                for row in 0..gh {
                    let py = start_y + row;
                    let row_offset = row * gw;
                    for col in 0..gw {
                        let alpha = glyph.data[row_offset + col];
                        if alpha > 15 {
                            let px = start_x + col;
                            self.blend_pixel(px, py, fg, alpha);
                        }
                    }
                }
                glyph.advance as usize
            } else {
                let start_x = (x as isize + glyph.x_offset as isize * eff_scale as isize).max(0) as usize;
                let start_y = (y as isize + glyph.y_offset as isize * eff_scale as isize).max(0) as usize;

                for row in 0..gh {
                    let row_offset = row * gw;
                    for col in 0..gw {
                        let alpha = glyph.data[row_offset + col];
                        if alpha > 15 {
                            for dy in 0..eff_scale {
                                for dx in 0..eff_scale {
                                    self.blend_pixel(
                                        start_x + col * eff_scale + dx,
                                        start_y + row * eff_scale + dy,
                                        fg,
                                        alpha,
                                    );
                                }
                            }
                        }
                    }
                }
                glyph.advance as usize * eff_scale
            }
        } else {
            6 * scale.max(1)
        }
    }

    /// Renders a string of text onto the display with true anti-aliasing
    pub fn draw_string(&mut self, mut x: usize, y: usize, text: &str, fg: Color, scale: usize) -> usize {
        let mut total_w = 0;
        for c in text.chars() {
            if c == '\n' {
                break;
            }
            let adv = self.draw_char(x, y, c, fg, scale);
            x += adv;
            total_w += adv;
        }
        total_w
    }

    /// Draws an unsigned integer without allocating any heap string
    pub fn draw_number(&mut self, mut x: usize, y: usize, mut value: u64, fg: Color, scale: usize) -> usize {
        if value == 0 {
            return self.draw_char(x, y, '0', fg, scale);
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while value > 0 && count < digits.len() {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        let mut total_w = 0;
        while count > 0 {
            count -= 1;
            let adv = self.draw_char(x, y, digits[count] as char, fg, scale);
            x += adv;
            total_w += adv;
        }
        total_w
    }

    /// Measures the pixel width of a rendered string
    pub fn string_width(&self, text: &str) -> usize {
        crate::font::string_width(text)
    }

    /// Renders a dynamic graphical progress / metric gauge (e.g. CPU load, FPS, RAM bar)
    pub fn draw_metric_bar(&mut self, x: usize, y: usize, w: usize, h: usize, percent: u32, fill: Color, bg: Color) {
        if w < 4 || h < 4 { return; }
        // Draw background
        self.fill_rect(x, y, w, h, bg);
        self.draw_rect(x, y, w, h, Color::rgb(71, 85, 105));
        // Draw filled portion
        let clamped = percent.min(100) as usize;
        let inner_w = (w.saturating_sub(4) * clamped) / 100;
        if inner_w > 0 {
            self.fill_rect(x + 2, y + 2, inner_w, h.saturating_sub(4), fill);
        }
    }

    /// Draws an interactive button with hover and active click states
    pub fn draw_button(&mut self, x: usize, y: usize, w: usize, h: usize, label: &str, is_hover: bool, is_active: bool) {
        let (bg, border, fg) = if is_active {
            (Color::EMERALD, Color::WHITE, Color::rgb(15, 23, 42))
        } else if is_hover {
            (Color::rgb(37, 99, 235), Color::CYAN, Color::WHITE)
        } else {
            (Color::rgb(30, 41, 59), Color::rgb(71, 85, 105), Color::rgb(226, 232, 240))
        };

        self.fill_rect(x, y, w, h, bg);
        self.draw_rect(x, y, w, h, border);
        let text_w = label.len() * 6;
        let pad_x = if w > text_w { (w - text_w) / 2 } else { 4 };
        let pad_y = if h > 7 { (h - 7) / 2 } else { 2 };
        self.draw_string(x + pad_x, y + pad_y, label, fg, 1);
    }

    /// Draws a filled circle at (cx, cy) with specified radius (for macOS traffic lights and status pills)
    pub fn fill_circle(&mut self, cx: isize, cy: isize, radius: isize, color: Color) {
        let r2 = radius * radius;
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= r2 {
                    let px = cx + dx;
                    let py = cy + dy;
                    if px >= 0 && (px as usize) < self.width && py >= 0 && (py as usize) < self.height {
                        self.draw_pixel(px as usize, py as usize, color);
                    }
                }
            }
        }
    }

    /// Draws an outlined circle at (cx, cy) with specified radius
    pub fn draw_circle(&mut self, cx: isize, cy: isize, radius: isize, color: Color) {
        if radius <= 0 { return; }
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            let pts = [
                (cx + x, cy + y),
                (cx + y, cy + x),
                (cx - y, cy + x),
                (cx - x, cy + y),
                (cx - x, cy - y),
                (cx - y, cy - x),
                (cx + y, cy - x),
                (cx + x, cy - y),
            ];
            for &(px, py) in &pts {
                if px >= 0 && (px as usize) < self.width && py >= 0 && (py as usize) < self.height {
                    self.draw_pixel(px as usize, py as usize, color);
                }
            }

            if err <= 0 {
                y += 1;
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// Draws a filled rounded rectangle (for modern macOS / Kali cards and dock capsules)
    pub fn fill_rounded_rect(&mut self, x: usize, y: usize, w: usize, h: usize, r: usize, color: Color) {
        if w == 0 || h == 0 { return; }
        let r = r.min(w / 2).min(h / 2);
        // Center rectangle
        self.fill_rect(x + r, y, w.saturating_sub(2 * r), h, color);
        // Left and right edges
        if h > 2 * r && r > 0 {
            self.fill_rect(x, y + r, r, h - 2 * r, color);
            self.fill_rect(x + w.saturating_sub(r), y + r, r, h - 2 * r, color);
        }
        // 4 corner circles
        let r_isize = r as isize;
        self.fill_circle((x + r) as isize, (y + r) as isize, r_isize, color);
        self.fill_circle((x + w.saturating_sub(r + 1)) as isize, (y + r) as isize, r_isize, color);
        self.fill_circle((x + r) as isize, (y + h.saturating_sub(r + 1)) as isize, r_isize, color);
        self.fill_circle((x + w.saturating_sub(r + 1)) as isize, (y + h.saturating_sub(r + 1)) as isize, r_isize, color);
    }

    /// Draws a sleek, hardware-accelerated 12x18 mouse cursor at (x, y)
    pub fn draw_cursor(&mut self, x: usize, y: usize, clicked: bool) {
        const CURSOR_W: usize = 12;
        const CURSOR_H: usize = 18;
        const BITMAP: [[u8; CURSOR_W]; CURSOR_H] = [
            [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0],
            [2, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0],
            [2, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0],
            [2, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0],
            [2, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0],
            [2, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0],
            [2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0],
            [2, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 0],
            [2, 1, 1, 2, 1, 1, 2, 0, 0, 0, 0, 0],
            [2, 1, 2, 0, 2, 1, 1, 2, 0, 0, 0, 0],
            [2, 2, 0, 0, 2, 1, 1, 2, 0, 0, 0, 0],
            [2, 0, 0, 0, 0, 2, 1, 1, 2, 0, 0, 0],
            [0, 0, 0, 0, 0, 2, 1, 1, 2, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];

        let interior = if clicked {
            Color::EMERALD
        } else {
            Color::WHITE
        };
        let border = Color::rgb(15, 23, 42);

        for row in 0..CURSOR_H {
            for col in 0..CURSOR_W {
                let pixel_type = BITMAP[row][col];
                if pixel_type == 1 {
                    self.draw_pixel(x + col, y + row, interior);
                } else if pixel_type == 2 {
                    self.draw_pixel(x + col, y + row, border);
                }
            }
        }
    }

    /// Bresenham integer line drawing algorithm (zero floating point)
    pub fn draw_line(&mut self, mut x0: isize, mut y0: isize, x1: isize, y1: isize, color: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x0 >= 0 && (x0 as usize) < self.width && y0 >= 0 && (y0 as usize) < self.height {
                self.draw_pixel(x0 as usize, y0 as usize, color);
            }
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    /// Fast integer line with strict bounding-box clipping for 3D viewports
    pub fn draw_line_clipped(&mut self, mut x0: isize, mut y0: isize, x1: isize, y1: isize, min_x: isize, min_y: isize, max_x: isize, max_y: isize, color: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x0 >= min_x && x0 < max_x && y0 >= min_y && y0 < max_y && x0 >= 0 && (x0 as usize) < self.width && y0 >= 0 && (y0 as usize) < self.height {
                self.draw_pixel(x0 as usize, y0 as usize, color);
            }
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                err += dx;
                y0 += sy;
            }
        }
    }

    /// Renders a dynamic oscilloscope / sparkline graph from integer samples
    pub fn draw_sparkline(&mut self, x: usize, y: usize, w: usize, h: usize, data: &[u32], max_val: u32, color: Color) {
        if w < 2 || h < 2 || data.len() < 2 || max_val == 0 {
            return;
        }
        let step_x = w / (data.len() - 1).max(1);
        for i in 0..(data.len() - 1) {
            let v0 = data[i].min(max_val) as usize;
            let v1 = data[i + 1].min(max_val) as usize;
            let py0 = y + h - (v0 * (h - 2)) / (max_val as usize) - 1;
            let py1 = y + h - (v1 * (h - 2)) / (max_val as usize) - 1;
            let px0 = x + i * step_x;
            let px1 = x + (i + 1) * step_x;
            self.draw_line(px0 as isize, py0 as isize, px1 as isize, py1 as isize, color);
        }
    }

    /// Flushes backbuffer to VRAM and returns the elapsed time in CPU cycles
    pub fn present_timed(&mut self) -> u64 {
        let start = crate::time::TscCounter::read_ticks().0;
        self.present();
        let end = crate::time::TscCounter::read_ticks().0;
        end.saturating_sub(start)
    }

    /// Flushes the RAM backbuffer to video memory using 64-byte unrolled SSE non-temporal streaming transfers.
    ///
    /// Streams 64 bytes (full CPU cacheline / 16 pixels) per unrolled vector burst directly to PCIe
    /// write-combining fill buffers, completely bypassing L1/L2/L3 cache pollution.
    pub fn present(&mut self) {
        if !self.use_double_buffering {
            return;
        }
        let total_pixels = self.stride * self.height;
        let total_bytes = total_pixels * 4;
        let src = self.backbuffer.as_ptr() as *const u8;
        let dst = self.vram_base as *mut u8;

        let chunks_64 = total_bytes / 64;
        let mut offset = 0usize;

        for _ in 0..chunks_64 {
            unsafe {
                let s = src.add(offset);
                let d = dst.add(offset);
                core::arch::asm!(
                    "movdqu xmm0, [{s}]",
                    "movdqu xmm1, [{s} + 16]",
                    "movdqu xmm2, [{s} + 32]",
                    "movdqu xmm3, [{s} + 48]",
                    "movntdq [{d}], xmm0",
                    "movntdq [{d} + 16], xmm1",
                    "movntdq [{d} + 32], xmm2",
                    "movntdq [{d} + 48], xmm3",
                    s = in(reg) s,
                    d = in(reg) d,
                    options(nostack, preserves_flags)
                );
            }
            offset += 64;
        }

        let remaining_16 = (total_bytes - offset) / 16;
        for _ in 0..remaining_16 {
            unsafe {
                let s = src.add(offset);
                let d = dst.add(offset);
                core::arch::asm!(
                    "movdqu xmm0, [{s}]",
                    "movntdq [{d}], xmm0",
                    s = in(reg) s,
                    d = in(reg) d,
                    options(nostack, preserves_flags)
                );
            }
            offset += 16;
        }

        let rem_bytes = total_bytes - offset;
        if rem_bytes > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem_bytes);
            }
        }

        // Drain write-combining fill buffers out to PCIe VRAM
        unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)); }
    }

    /// Draws a 24-bit or 32-bit uncompressed BMP image with alpha transparency support
    pub fn draw_bmp(&mut self, start_x: usize, start_y: usize, bmp: &[u8]) -> bool {
        if bmp.len() < 54 || bmp[0] != b'B' || bmp[1] != b'M' {
            return false;
        }

        let data_offset = u32::from_le_bytes([bmp[10], bmp[11], bmp[12], bmp[13]]) as usize;
        let width = i32::from_le_bytes([bmp[18], bmp[19], bmp[20], bmp[21]]);
        let height = i32::from_le_bytes([bmp[22], bmp[23], bmp[24], bmp[25]]);
        let bpp = u16::from_le_bytes([bmp[28], bmp[29]]) as usize;

        if width <= 0 || height == 0 || (bpp != 32 && bpp != 24) {
            return false;
        }

        let w = width as usize;
        let h = height.unsigned_abs() as usize;
        let is_bottom_up = height > 0;
        let bytes_per_pixel = bpp / 8;
        let row_stride = (w * bytes_per_pixel + 3) & !3; // BMP rows are 4-byte padded

        for row in 0..h {
            let py = if is_bottom_up {
                start_y + (h - 1 - row)
            } else {
                start_y + row
            };

            let row_offset = data_offset + row * row_stride;
            if row_offset + w * bytes_per_pixel > bmp.len() {
                break;
            }

            for col in 0..w {
                let px = start_x + col;
                let p_idx = row_offset + col * bytes_per_pixel;
                let b = bmp[p_idx];
                let g = bmp[p_idx + 1];
                let r = bmp[p_idx + 2];
                let a = if bpp == 32 { bmp[p_idx + 3] } else { 255 };

                if a == 255 {
                    self.draw_pixel(px, py, Color::rgb(r, g, b));
                } else if a > 8 {
                    if px < self.width && py < self.height {
                        let offset = py * self.stride + px;
                        let bg_pixel = if self.use_double_buffering && offset < self.backbuffer.len() {
                            self.backbuffer[offset]
                        } else {
                            unsafe { ptr::read_volatile(self.vram_base.add(offset)) }
                        };
                        let (bg_r, bg_g, bg_b) = Color::from_pixel_u32(bg_pixel, self.format);
                        let alpha = a as u32;
                        let inv_a = 255 - alpha;
                        let out_r = ((r as u32 * alpha + bg_r as u32 * inv_a + 127) / 255) as u8;
                        let out_g = ((g as u32 * alpha + bg_g as u32 * inv_a + 127) / 255) as u8;
                        let out_b = ((b as u32 * alpha + bg_b as u32 * inv_a + 127) / 255) as u8;
                        self.draw_pixel(px, py, Color::rgb(out_r, out_g, out_b));
                    }
                }
            }
        }
        true
    }
}
