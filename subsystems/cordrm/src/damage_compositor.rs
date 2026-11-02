//! Dirty-rectangle region algebra, damage tracking, and Porter-Duff alpha blending compositor.

use alloc::vec::Vec;

/// 2D integer bounding box rectangle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DamageRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl DamageRect {
    #[inline]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    /// Computes union bounding box containing both rectangles.
    pub fn union(&self, other: &Self) -> Self {
        if self.width == 0 || self.height == 0 {
            return *other;
        }
        if other.width == 0 || other.height == 0 {
            return *self;
        }
        let x1 = self.x.min(other.x);
        let y1 = self.y.min(other.y);
        let x2 = (self.x + self.width as i32).max(other.x + other.width as i32);
        let y2 = (self.y + self.height as i32).max(other.y + other.height as i32);
        Self {
            x: x1,
            y: y1,
            width: (x2 - x1).max(0) as u32,
            height: (y2 - y1).max(0) as u32,
        }
    }

    /// Computes intersection between two rectangles.
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let x1 = self.x.max(other.x);
        let y1 = self.y.max(other.y);
        let x2 = (self.x + self.width as i32).min(other.x + other.width as i32);
        let y2 = (self.y + self.height as i32).min(other.y + other.height as i32);
        if x2 > x1 && y2 > y1 {
            Some(Self {
                x: x1,
                y: y1,
                width: (x2 - x1) as u32,
                height: (y2 - y1) as u32,
            })
        } else {
            None
        }
    }
}

/// Porter-Duff SrcOver alpha blending for 32-bit ARGB8888 pixels.
#[inline]
pub fn blend_src_over(dst: u32, src: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 255 {
        return src;
    }
    if sa == 0 {
        return dst;
    }

    let da = (dst >> 24) & 0xFF;
    let inv_sa = 255 - sa;

    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;

    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;

    let out_a = sa + (da * inv_sa) / 255;
    let out_r = (sr * sa + dr * inv_sa) / 255;
    let out_g = (sg * sa + dg * inv_sa) / 255;
    let out_b = (sb * sa + db * inv_sa) / 255;

    (out_a << 24) | (out_r << 16) | (out_g << 8) | out_b
}

/// Compositor surface layer with damage tracking.
#[derive(Clone, Debug)]
pub struct CompositorSurface {
    pub id: u32,
    pub bounds: DamageRect,
    pub z_order: i32,
    pub opacity: u8,
    pub damage_list: Vec<DamageRect>,
}

impl CompositorSurface {
    pub fn new(id: u32, x: i32, y: i32, width: u32, height: u32, z_order: i32) -> Self {
        Self {
            id,
            bounds: DamageRect::new(x, y, width, height),
            z_order,
            opacity: 255,
            damage_list: Vec::new(),
        }
    }

    pub fn add_damage(&mut self, damage: DamageRect) {
        if let Some(clipped) = self.bounds.intersect(&damage) {
            self.damage_list.push(clipped);
        }
    }

    pub fn take_accumulated_damage(&mut self) -> DamageRect {
        let mut total = DamageRect::default();
        for d in &self.damage_list {
            total = total.union(d);
        }
        self.damage_list.clear();
        total
    }
}
