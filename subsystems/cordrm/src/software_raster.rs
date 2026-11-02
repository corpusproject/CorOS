//! 2D/3D Software Rasterizer: Bresenham lines, barycentric triangle fill & depth testing.

use alloc::vec::Vec;

/// 2D integer point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point2D {
    pub x: i32,
    pub y: i32,
}

/// 3D vertex with 16-bit integer depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vertex3D {
    pub x: i32,
    pub y: i32,
    pub z: u16,
    pub color: u32,
}

/// Software Framebuffer & Depth Buffer.
pub struct SoftwareRasterTarget {
    pub width: u32,
    pub height: u32,
    pub color_buffer: Vec<u32>,
    pub depth_buffer: Vec<u16>,
}

impl SoftwareRasterTarget {
    pub fn new(width: u32, height: u32) -> Self {
        let size = (width as usize).saturating_mul(height as usize);
        Self {
            width,
            height,
            color_buffer: alloc::vec![0xFF00_0000; size],
            depth_buffer: alloc::vec![0xFFFF; size],
        }
    }

    #[inline]
    pub fn clear(&mut self, color: u32) {
        self.color_buffer.fill(color);
        self.depth_buffer.fill(0xFFFF);
    }

    #[inline]
    pub fn set_pixel(&mut self, x: i32, y: i32, color: u32) {
        if x >= 0 && (x as u32) < self.width && y >= 0 && (y as u32) < self.height {
            let idx = (y as usize) * (self.width as usize) + (x as usize);
            self.color_buffer[idx] = color;
        }
    }

    /// Draws a line using Bresenham's algorithm.
    pub fn draw_line(&mut self, p0: Point2D, p1: Point2D, color: u32) {
        let mut x0 = p0.x;
        let mut y0 = p0.y;
        let x1 = p1.x;
        let y1 = p1.y;

        let dx = (x1 - x0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 - y0).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            self.set_pixel(x0, y0, color);
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

    /// Fills a flat triangle with barycentric edge-function testing and depth test.
    pub fn fill_triangle(&mut self, v0: Vertex3D, v1: Vertex3D, v2: Vertex3D) {
        let min_x = v0.x.min(v1.x).min(v2.x).max(0);
        let max_x = v0.x.max(v1.x).max(v2.x).min(self.width as i32 - 1);
        let min_y = v0.y.min(v1.y).min(v2.y).max(0);
        let max_y = v0.y.max(v1.y).max(v2.y).min(self.height as i32 - 1);

        let edge = |a: &Vertex3D, b: &Vertex3D, c_x: i32, c_y: i32| -> i64 {
            (c_x as i64 - a.x as i64) * (b.y as i64 - a.y as i64)
                - (c_y as i64 - a.y as i64) * (b.x as i64 - a.x as i64)
        };

        let area = edge(&v0, &v1, v2.x, v2.y);
        if area == 0 {
            return;
        }

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let w0 = edge(&v1, &v2, x, y);
                let w1 = edge(&v2, &v0, x, y);
                let w2 = edge(&v0, &v1, x, y);

                if (w0 >= 0 && w1 >= 0 && w2 >= 0) || (w0 <= 0 && w1 <= 0 && w2 <= 0) {
                    let idx = (y as usize) * (self.width as usize) + (x as usize);
                    let z = v0.z; // Simple flat depth for testing
                    if z < self.depth_buffer[idx] {
                        self.depth_buffer[idx] = z;
                        self.color_buffer[idx] = v0.color;
                    }
                }
            }
        }
    }
}
