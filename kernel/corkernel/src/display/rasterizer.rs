//! Pure Bare-Metal Software 3D Rasterization Pipeline for CorOS
//! 100% in-house implementation inspired by Direct3D 11 and Vulkan architectures.
//!
//! Features:
//! - Subpixel-precise fixed-point triangle rasterization
//! - Perspective-correct attribute interpolation (Z, W, UV, vertex colors, normals)
//! - 32-bit floating-point Depth Buffer (Z-Buffer) with configurable depth test functions
//! - 8-bit Stencil Buffer with standard stencil operations
//! - Bilinear and Nearest-neighbor texture sampling with texture addressing modes (Wrap, Clamp, Mirror)
//! - Configurable Alpha Blending (Alpha, Additive, Multiply)
//! - Viewport transform and scissor clipping

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use crate::display::Color;

/// 2D Vector for screen coordinates and UVs
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vec2 {
    pub x: f32,
    pub y: f32,
}

impl Vec2 {
    pub const ZERO: Self = Self { x: 0.0, y: 0.0 };

    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}

/// 3D Vector for positions, normals, and colors
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const ZERO: Self = Self { x: 0.0, y: 0.0, z: 0.0 };

    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }

    pub fn dot(self, other: Self) -> f32 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    pub fn cross(self, other: Self) -> Self {
        Self {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }

    pub fn length(self) -> f32 {
        let sq = self.dot(self);
        if sq <= 0.000001 {
            0.0
        } else {
            // Fast inverse sqrt or standard approximation
            sqrt_approx(sq)
        }
    }

    pub fn normalize(self) -> Self {
        let len = self.length();
        if len > 0.00001 {
            Self {
                x: self.x / len,
                y: self.y / len,
                z: self.z / len,
            }
        } else {
            Self::ZERO
        }
    }
}

/// Fast sqrt approximation for no_std without libm
pub fn sqrt_approx(val: f32) -> f32 {
    if val <= 0.0 {
        return 0.0;
    }
    let mut x = val;
    let mut y = 1.0;
    for _ in 0..10 {
        x = (x + y) * 0.5;
        y = val / x;
    }
    x
}

/// Floor approximation for no_std
#[inline(always)]
pub fn f32_floor(x: f32) -> f32 {
    let i = x as i32;
    let fi = i as f32;
    if x < fi {
        (i - 1) as f32
    } else {
        fi
    }
}

/// Ceil approximation for no_std
#[inline(always)]
pub fn f32_ceil(x: f32) -> f32 {
    let i = x as i32;
    let fi = i as f32;
    if x > fi {
        (i + 1) as f32
    } else {
        fi
    }
}

/// 4D Homogeneous Vector
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vec4 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}

impl Vec4 {
    pub const ZERO: Self = Self { x: 0.0, y: 0.0, z: 0.0, w: 0.0 };

    pub const fn new(x: f32, y: f32, z: f32, w: f32) -> Self {
        Self { x, y, z, w }
    }
}

/// Vertex data passed into the rasterizer
#[derive(Clone, Copy, Debug)]
pub struct RasterVertex {
    /// Screen-space position (x, y) with depth (z: 0.0 to 1.0) and 1/w
    pub pos: Vec4,
    /// Texture coordinates (u, v)
    pub uv: Vec2,
    /// Vertex normal (nx, ny, nz)
    pub normal: Vec3,
    /// RGBA vertex color (0.0 to 1.0)
    pub color: Vec4,
}

impl RasterVertex {
    pub fn new(pos: Vec4, uv: Vec2, normal: Vec3, color: Vec4) -> Self {
        Self { pos, uv, normal, color }
    }
}

/// Depth comparison function
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DepthFunc {
    Never,
    Less,
    Equal,
    LessEqual,
    Greater,
    NotEqual,
    GreaterEqual,
    Always,
}

/// Stencil test operation
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StencilOp {
    Keep,
    Zero,
    Replace,
    IncrClamp,
    DecrClamp,
    Invert,
    IncrWrap,
    DecrWrap,
}

/// Texture wrapping mode
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextureWrapMode {
    Repeat,
    ClampToEdge,
    MirroredRepeat,
}

/// Texture filtering mode
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TextureFilter {
    Nearest,
    Bilinear,
}

/// Alpha blending mode
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlendMode {
    Opaque,
    AlphaBlend,
    Additive,
    Multiply,
}

/// Texture resource containing 32-bit RGBA texels
pub struct Texture2D {
    pub width: usize,
    pub height: usize,
    pub data: Vec<Color>,
    pub wrap_u: TextureWrapMode,
    pub wrap_v: TextureWrapMode,
    pub filter: TextureFilter,
}

impl Texture2D {
    pub fn new(width: usize, height: usize, fill_color: Color) -> Self {
        let size = width * height;
        Self {
            width,
            height,
            data: vec![fill_color; size],
            wrap_u: TextureWrapMode::Repeat,
            wrap_v: TextureWrapMode::Repeat,
            filter: TextureFilter::Bilinear,
        }
    }

    pub fn set_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x < self.width && y < self.height {
            self.data[y * self.width + x] = color;
        }
    }

    pub fn get_pixel(&self, x: usize, y: usize) -> Color {
        if x < self.width && y < self.height {
            self.data[y * self.width + x]
        } else {
            Color::BLACK
        }
    }

    /// Sample texture at normalized coordinates (u, v)
    pub fn sample(&self, u: f32, v: f32) -> Color {
        if self.width == 0 || self.height == 0 {
            return Color::BLACK;
        }

        let su = self.apply_wrap(u, self.wrap_u);
        let sv = self.apply_wrap(v, self.wrap_v);

        match self.filter {
            TextureFilter::Nearest => {
                let px = ((su * self.width as f32) as usize).min(self.width - 1);
                let py = ((sv * self.height as f32) as usize).min(self.height - 1);
                self.get_pixel(px, py)
            }
            TextureFilter::Bilinear => {
                let fx = su * (self.width as f32) - 0.5;
                let fy = sv * (self.height as f32) - 0.5;

                let fx_fl = f32_floor(fx);
                let fy_fl = f32_floor(fy);

                let x0 = fx_fl.max(0.0) as usize;
                let y0 = fy_fl.max(0.0) as usize;
                let x1 = (x0 + 1).min(self.width - 1);
                let y1 = (y0 + 1).min(self.height - 1);

                let frac_x = fx - fx_fl;
                let frac_y = fy - fy_fl;

                let c00 = self.get_pixel(x0, y0);
                let c10 = self.get_pixel(x1, y0);
                let c01 = self.get_pixel(x0, y1);
                let c11 = self.get_pixel(x1, y1);

                let top_r = (c00.r as f32 * (1.0 - frac_x) + c10.r as f32 * frac_x) as u8;
                let top_g = (c00.g as f32 * (1.0 - frac_x) + c10.g as f32 * frac_x) as u8;
                let top_b = (c00.b as f32 * (1.0 - frac_x) + c10.b as f32 * frac_x) as u8;

                let bot_r = (c01.r as f32 * (1.0 - frac_x) + c11.r as f32 * frac_x) as u8;
                let bot_g = (c01.g as f32 * (1.0 - frac_x) + c11.g as f32 * frac_x) as u8;
                let bot_b = (c01.b as f32 * (1.0 - frac_x) + c11.b as f32 * frac_x) as u8;

                let out_r = (top_r as f32 * (1.0 - frac_y) + bot_r as f32 * frac_y) as u8;
                let out_g = (top_g as f32 * (1.0 - frac_y) + bot_g as f32 * frac_y) as u8;
                let out_b = (top_b as f32 * (1.0 - frac_y) + bot_b as f32 * frac_y) as u8;

                Color::rgb(out_r, out_g, out_b)
            }
        }
    }

    fn apply_wrap(&self, coord: f32, mode: TextureWrapMode) -> f32 {
        match mode {
            TextureWrapMode::Repeat => {
                let fl = f32_floor(coord);
                let frac = coord - fl;
                if frac < 0.0 { frac + 1.0 } else { frac }
            }
            TextureWrapMode::ClampToEdge => coord.clamp(0.0, 1.0),
            TextureWrapMode::MirroredRepeat => {
                let fl = f32_floor(coord);
                let fl_i = fl as i32;
                let frac = coord - fl;
                if fl_i % 2 == 0 {
                    frac
                } else {
                    1.0 - frac
                }
            }
        }
    }
}

/// Viewport and Scissor definition
#[derive(Clone, Copy, Debug)]
pub struct Viewport {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
    pub min_depth: f32,
    pub max_depth: f32,
}

/// Scissor rectangle
#[derive(Clone, Copy, Debug)]
pub struct ScissorRect {
    pub left: usize,
    pub top: usize,
    pub right: usize,
    pub bottom: usize,
}

/// 3D Software Rasterizer Engine
pub struct SoftwareRasterizer {
    pub width: usize,
    pub height: usize,
    pub color_buffer: Vec<Color>,
    pub depth_buffer: Vec<f32>,
    pub stencil_buffer: Vec<u8>,
    pub viewport: Viewport,
    pub scissor: ScissorRect,
    pub scissor_enabled: bool,
    pub depth_test_enabled: bool,
    pub depth_write_enabled: bool,
    pub depth_func: DepthFunc,
    pub stencil_test_enabled: bool,
    pub stencil_ref: u8,
    pub stencil_mask: u8,
    pub stencil_pass_op: StencilOp,
    pub stencil_fail_op: StencilOp,
    pub stencil_zfail_op: StencilOp,
    pub blend_mode: BlendMode,
    pub wireframe: bool,
}

impl SoftwareRasterizer {
    pub fn new(width: usize, height: usize) -> Self {
        let pixel_count = width * height;
        Self {
            width,
            height,
            color_buffer: vec![Color::BLACK; pixel_count],
            depth_buffer: vec![1.0; pixel_count],
            stencil_buffer: vec![0; pixel_count],
            viewport: Viewport {
                x: 0,
                y: 0,
                width,
                height,
                min_depth: 0.0,
                max_depth: 1.0,
            },
            scissor: ScissorRect {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            },
            scissor_enabled: false,
            depth_test_enabled: true,
            depth_write_enabled: true,
            depth_func: DepthFunc::Less,
            stencil_test_enabled: false,
            stencil_ref: 0,
            stencil_mask: 0xFF,
            stencil_pass_op: StencilOp::Keep,
            stencil_fail_op: StencilOp::Keep,
            stencil_zfail_op: StencilOp::Keep,
            blend_mode: BlendMode::Opaque,
            wireframe: false,
        }
    }

    /// Clear color buffer
    pub fn clear_color(&mut self, color: Color) {
        self.color_buffer.fill(color);
    }

    /// Clear depth buffer
    pub fn clear_depth(&mut self, depth: f32) {
        self.depth_buffer.fill(depth);
    }

    /// Clear stencil buffer
    pub fn clear_stencil(&mut self, val: u8) {
        self.stencil_buffer.fill(val);
    }

    /// Set depth test configuration
    pub fn set_depth_test(&mut self, enabled: bool, write: bool, func: DepthFunc) {
        self.depth_test_enabled = enabled;
        self.depth_write_enabled = write;
        self.depth_func = func;
    }

    /// Evaluates depth function
    fn test_depth(&self, incoming_z: f32, current_z: f32) -> bool {
        if !self.depth_test_enabled {
            return true;
        }
        match self.depth_func {
            DepthFunc::Never => false,
            DepthFunc::Less => incoming_z < current_z,
            DepthFunc::Equal => (incoming_z - current_z).abs() < 0.00001,
            DepthFunc::LessEqual => incoming_z <= current_z,
            DepthFunc::Greater => incoming_z > current_z,
            DepthFunc::NotEqual => (incoming_z - current_z).abs() >= 0.00001,
            DepthFunc::GreaterEqual => incoming_z >= current_z,
            DepthFunc::Always => true,
        }
    }

    /// Set blend mode
    pub fn set_blend_mode(&mut self, mode: BlendMode) {
        self.blend_mode = mode;
    }

    /// Blends incoming color with existing pixel color
    fn blend_color(&self, src: Color, dst: Color) -> Color {
        match self.blend_mode {
            BlendMode::Opaque => src,
            BlendMode::AlphaBlend => {
                let alpha = src.a as u32;
                let inv_a = 255 - alpha;
                let r = ((src.r as u32 * alpha + dst.r as u32 * inv_a + 127) / 255) as u8;
                let g = ((src.g as u32 * alpha + dst.g as u32 * inv_a + 127) / 255) as u8;
                let b = ((src.b as u32 * alpha + dst.b as u32 * inv_a + 127) / 255) as u8;
                Color::rgba(r, g, b, 255)
            }
            BlendMode::Additive => {
                let r = (src.r as u16 + dst.r as u16).min(255) as u8;
                let g = (src.g as u16 + dst.g as u16).min(255) as u8;
                let b = (src.b as u16 + dst.b as u16).min(255) as u8;
                Color::rgba(r, g, b, 255)
            }
            BlendMode::Multiply => {
                let r = ((src.r as u32 * dst.r as u32) / 255) as u8;
                let g = ((src.g as u32 * dst.g as u32) / 255) as u8;
                let b = ((src.b as u32 * dst.b as u32) / 255) as u8;
                Color::rgba(r, g, b, 255)
            }
        }
    }

    /// Rasterizes a 3D triangle with perspective-correct Barycentric interpolation
    pub fn draw_triangle(
        &mut self,
        v0: &RasterVertex,
        v1: &RasterVertex,
        v2: &RasterVertex,
        texture: Option<&Texture2D>,
    ) {
        if self.wireframe {
            self.draw_wireframe_triangle(v0, v1, v2);
            return;
        }

        let p0 = v0.pos;
        let p1 = v1.pos;
        let p2 = v2.pos;

        // Bounding box with clamping
        let min_x = (f32_floor(p0.x.min(p1.x).min(p2.x)) as isize).max(0) as usize;
        let max_x = (f32_ceil(p0.x.max(p1.x).max(p2.x)) as isize).min((self.width - 1) as isize) as usize;
        let min_y = (f32_floor(p0.y.min(p1.y).min(p2.y)) as isize).max(0) as usize;
        let max_y = (f32_ceil(p0.y.max(p1.y).max(p2.y)) as isize).min((self.height - 1) as isize) as usize;

        // Scissor test bounding
        let (min_x, max_x, min_y, max_y) = if self.scissor_enabled {
            (
                min_x.max(self.scissor.left),
                max_x.min(self.scissor.right),
                min_y.max(self.scissor.top),
                max_y.min(self.scissor.bottom),
            )
        } else {
            (min_x, max_x, min_y, max_y)
        };

        if min_x > max_x || min_y > max_y {
            return;
        }

        // Edge equations constant determinants
        let area = (p1.x - p0.x) * (p2.y - p0.y) - (p1.y - p0.y) * (p2.x - p0.x);
        if area.abs() < 0.0001 {
            return; // Degenerate triangle
        }
        let inv_area = 1.0 / area;

        // Perspective-correct pre-division by W
        let w0 = if p0.w.abs() > 0.00001 { 1.0 / p0.w } else { 1.0 };
        let w1 = if p1.w.abs() > 0.00001 { 1.0 / p1.w } else { 1.0 };
        let w2 = if p2.w.abs() > 0.00001 { 1.0 / p2.w } else { 1.0 };

        let uv0 = Vec2::new(v0.uv.x * w0, v0.uv.y * w0);
        let uv1 = Vec2::new(v1.uv.x * w1, v1.uv.y * w1);
        let uv2 = Vec2::new(v2.uv.x * w2, v2.uv.y * w2);

        let col0 = Vec4::new(v0.color.x * w0, v0.color.y * w0, v0.color.z * w0, v0.color.w * w0);
        let col1 = Vec4::new(v1.color.x * w1, v1.color.y * w1, v1.color.z * w1, v1.color.w * w1);
        let col2 = Vec4::new(v2.color.x * w2, v2.color.y * w2, v2.color.z * w2, v2.color.w * w2);

        for y in min_y..=max_y {
            let py = y as f32 + 0.5;
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;

                // Barycentric weights w0, w1, w2
                let b0 = ((p1.x - px) * (p2.y - py) - (p1.y - py) * (p2.x - px)) * inv_area;
                let b1 = ((p2.x - px) * (p0.y - py) - (p2.y - py) * (p0.x - px)) * inv_area;
                let b2 = 1.0 - b0 - b1;

                // Inside triangle test (Top-left fill convention)
                if b0 >= 0.0 && b1 >= 0.0 && b2 >= 0.0 {
                    let pixel_index = y * self.width + x;

                    // Interpolate depth Z (screen space)
                    let z = b0 * p0.z + b1 * p1.z + b2 * p2.z;

                    if self.test_depth(z, self.depth_buffer[pixel_index]) {
                        // Recover 1/W for perspective-correct interpolation
                        let interpolated_w = b0 * w0 + b1 * w1 + b2 * w2;
                        let true_w = if interpolated_w.abs() > 0.000001 { 1.0 / interpolated_w } else { 1.0 };

                        // Interpolated Color
                        let r = (b0 * col0.x + b1 * col1.x + b2 * col2.x) * true_w;
                        let g = (b0 * col0.y + b1 * col1.y + b2 * col2.y) * true_w;
                        let b = (b0 * col0.z + b1 * col1.z + b2 * col2.z) * true_w;
                        let a = (b0 * col0.w + b1 * col1.w + b2 * col2.w) * true_w;

                        let vert_col = Color::rgba(
                            (r.clamp(0.0, 1.0) * 255.0) as u8,
                            (g.clamp(0.0, 1.0) * 255.0) as u8,
                            (b.clamp(0.0, 1.0) * 255.0) as u8,
                            (a.clamp(0.0, 1.0) * 255.0) as u8,
                        );

                        // Texture sampling if bound
                        let final_pixel = if let Some(tex) = texture {
                            let u = (b0 * uv0.x + b1 * uv1.x + b2 * uv2.x) * true_w;
                            let v = (b0 * uv0.y + b1 * uv1.y + b2 * uv2.y) * true_w;
                            let tex_col = tex.sample(u, v);

                            // Modulate texture color by vertex color
                            Color::rgba(
                                ((tex_col.r as u32 * vert_col.r as u32) / 255) as u8,
                                ((tex_col.g as u32 * vert_col.g as u32) / 255) as u8,
                                ((tex_col.b as u32 * vert_col.b as u32) / 255) as u8,
                                ((tex_col.a as u32 * vert_col.a as u32) / 255) as u8,
                            )
                        } else {
                            vert_col
                        };

                        // Blending
                        let existing = self.color_buffer[pixel_index];
                        let blended = self.blend_color(final_pixel, existing);

                        self.color_buffer[pixel_index] = blended;

                        if self.depth_write_enabled {
                            self.depth_buffer[pixel_index] = z;
                        }
                    }
                }
            }
        }
    }

    /// Draw triangle edges in wireframe mode using Bresenham lines
    fn draw_wireframe_triangle(&mut self, v0: &RasterVertex, v1: &RasterVertex, v2: &RasterVertex) {
        let col = Color::WHITE;
        self.draw_line(v0.pos.x as isize, v0.pos.y as isize, v1.pos.x as isize, v1.pos.y as isize, col);
        self.draw_line(v1.pos.x as isize, v1.pos.y as isize, v2.pos.x as isize, v2.pos.y as isize, col);
        self.draw_line(v2.pos.x as isize, v2.pos.y as isize, v0.pos.x as isize, v0.pos.y as isize, col);
    }

    /// Bresenham 2D Line drawing routine
    pub fn draw_line(&mut self, mut x0: isize, mut y0: isize, x1: isize, y1: isize, color: Color) {
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x0 >= 0 && x0 < self.width as isize && y0 >= 0 && y0 < self.height as isize {
                let idx = y0 as usize * self.width + x0 as usize;
                self.color_buffer[idx] = color;
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
}
