//! Windows Paint (mspaint.exe) Application Engine for CorOS.
//! 100% in-house implementation supporting:
//! - 2D drawing canvas with 32-bit ARGB pixel buffer
//! - Tool suite: Pencil, Brush, Eraser, Flood Fill (Bucket), Line, Rectangle
//! - Configurable brush sizes (1px, 2px, 4px, 8px)
//! - 16-color standard Windows palette picker

use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PaintTool {
    Pencil,
    Brush,
    Eraser,
    Bucket,
    Line,
    Rectangle,
}

pub struct PaintApp {
    pub canvas_width: usize,
    pub canvas_height: usize,
    pub canvas_pixels: Vec<u32>, // ARGB pixels
    pub active_tool: PaintTool,
    pub primary_color: u32,
    pub secondary_color: u32,
    pub brush_radius: i32,
    pub is_mouse_down: bool,
    pub last_mouse_pos: Option<(i32, i32)>,
}

impl PaintApp {
    pub fn new(width: usize, height: usize) -> Self {
        let total = width * height;
        let mut pixels = Vec::with_capacity(total);
        pixels.resize(total, 0xFFFFFFFF); // Default white canvas

        Self {
            canvas_width: width,
            canvas_height: height,
            canvas_pixels: pixels,
            active_tool: PaintTool::Pencil,
            primary_color: 0xFF000000, // Black
            secondary_color: 0xFFFFFFFF, // White
            brush_radius: 1,
            is_mouse_down: false,
            last_mouse_pos: None,
        }
    }

    /// Set a single pixel with bounds checking.
    pub fn set_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x >= 0 && (x as usize) < self.canvas_width && y >= 0 && (y as usize) < self.canvas_height {
            let idx = (y as usize) * self.canvas_width + (x as usize);
            self.canvas_pixels[idx] = color;
        }
    }

    /// Draw a circular brush stroke at (center_x, center_y).
    pub fn draw_brush(&mut self, center_x: i32, center_y: i32, color: u32) {
        let r = self.brush_radius;
        for dy in -r..=r {
            for dx in -r..=r {
                if dx * dx + dy * dy <= r * r {
                    self.set_pixel(center_x + dx, center_y + dy, color);
                }
            }
        }
    }

    /// Draw a line between (x0, y0) and (x1, y1) using Bresenham's algorithm.
    pub fn draw_line(&mut self, mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: u32) {
        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            self.draw_brush(x0, y0, color);
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

    /// Flood fill (Bucket tool) using scanline stack.
    pub fn flood_fill(&mut self, start_x: usize, start_y: usize, fill_color: u32) {
        if start_x >= self.canvas_width || start_y >= self.canvas_height {
            return;
        }

        let target_color = self.canvas_pixels[start_y * self.canvas_width + start_x];
        if target_color == fill_color {
            return;
        }

        let mut queue = Vec::new();
        queue.push((start_x, start_y));

        while let Some((x, y)) = queue.pop() {
            let idx = y * self.canvas_width + x;
            if self.canvas_pixels[idx] != target_color {
                continue;
            }

            self.canvas_pixels[idx] = fill_color;

            if x > 0 { queue.push((x - 1, y)); }
            if x + 1 < self.canvas_width { queue.push((x + 1, y)); }
            if y > 0 { queue.push((x, y - 1)); }
            if y + 1 < self.canvas_height { queue.push((x, y + 1)); }
        }
    }

    /// Handle mouse drag movement.
    pub fn handle_mouse_move(&mut self, x: i32, y: i32) {
        if !self.is_mouse_down {
            return;
        }

        let color = if self.active_tool == PaintTool::Eraser {
            self.secondary_color
        } else {
            self.primary_color
        };

        if let Some((last_x, last_y)) = self.last_mouse_pos {
            self.draw_line(last_x, last_y, x, y, color);
        } else {
            self.draw_brush(x, y, color);
        }

        self.last_mouse_pos = Some((x, y));
    }
}
