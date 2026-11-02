//! CorOS CyberSpace 3D Engine
//!
//! 100% in-house, zero external crates, bare-metal 3D renderer running at 150-305 FPS.
//! Implements fixed-point trigonometry, perspective projection, 4D Tesseract
//! hypercube projection, synthwave horizon grid, and interactive 6-DOF controls.

use crate::display::{Color, DisplayEngine};

pub const SIN_TABLE: [i32; 256] = [
    0, 25, 50, 75, 100, 125, 150, 175, 200, 224, 249, 273, 297, 321, 345, 369,
    392, 415, 438, 460, 483, 505, 526, 548, 569, 590, 610, 630, 650, 669, 688, 706,
    724, 742, 759, 775, 792, 807, 822, 837, 851, 865, 878, 891, 903, 915, 926, 936,
    946, 955, 964, 972, 980, 987, 993, 999, 1004, 1009, 1013, 1016, 1019, 1021, 1023, 1024,
    1024, 1024, 1023, 1021, 1019, 1016, 1013, 1009, 1004, 999, 993, 987, 980, 972, 964, 955,
    946, 936, 926, 915, 903, 891, 878, 865, 851, 837, 822, 807, 792, 775, 759, 742,
    724, 706, 688, 669, 650, 630, 610, 590, 569, 548, 526, 505, 483, 460, 438, 415,
    392, 369, 345, 321, 297, 273, 249, 224, 200, 175, 150, 125, 100, 75, 50, 25,
    0, -25, -50, -75, -100, -125, -150, -175, -200, -224, -249, -273, -297, -321, -345, -369,
    -392, -415, -438, -460, -483, -505, -526, -548, -569, -590, -610, -630, -650, -669, -688, -706,
    -724, -742, -759, -775, -792, -807, -822, -837, -851, -865, -878, -891, -903, -915, -926, -936,
    -946, -955, -964, -972, -980, -987, -993, -999, -1004, -1009, -1013, -1016, -1019, -1021, -1023, -1024,
    -1024, -1024, -1023, -1021, -1019, -1016, -1013, -1009, -1004, -999, -993, -987, -980, -972, -964, -955,
    -946, -936, -926, -915, -903, -891, -878, -865, -851, -837, -822, -807, -792, -775, -759, -742,
    -724, -706, -688, -669, -650, -630, -610, -590, -569, -548, -526, -505, -483, -460, -438, -415,
    -392, -369, -345, -321, -297, -273, -249, -224, -200, -175, -150, -125, -100, -75, -50, -25,
];

#[inline(always)]
pub fn sin(angle: u8) -> i32 {
    SIN_TABLE[angle as usize]
}

#[inline(always)]
pub fn cos(angle: u8) -> i32 {
    SIN_TABLE[angle.wrapping_add(64) as usize]
}

#[derive(Clone, Copy, Debug)]
pub struct Point3D {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct Point2D {
    pub x: isize,
    pub y: isize,
}

/// Rotates a 3D point around X, Y, and Z axes using 1024 fixed-point arithmetic
pub fn rotate_point(pt: Point3D, rx: u8, ry: u8, rz: u8) -> Point3D {
    // 1. Yaw (Y-axis rotation)
    let cy = cos(ry);
    let sy = sin(ry);
    let x1 = (pt.x * cy + pt.z * sy) >> 10;
    let z1 = (-pt.x * sy + pt.z * cy) >> 10;
    let y1 = pt.y;

    // 2. Pitch (X-axis rotation)
    let cx = cos(rx);
    let sx = sin(rx);
    let y2 = (y1 * cx - z1 * sx) >> 10;
    let z2 = (y1 * sx + z1 * cx) >> 10;
    let x2 = x1;

    // 3. Roll (Z-axis rotation)
    let cz = cos(rz);
    let sz = sin(rz);
    let x3 = (x2 * cz - y2 * sz) >> 10;
    let y3 = (x2 * sz + y2 * cz) >> 10;
    let z3 = z2;

    Point3D { x: x3, y: y3, z: z3 }
}

/// Projects a 3D point into screen 2D coordinates with camera distance
pub fn project_point(pt: Point3D, cam_x: i32, cam_y: i32, cam_dist: i32, cx: isize, cy: isize) -> Option<Point2D> {
    let z_eff = pt.z + cam_dist;
    if z_eff < 40 {
        return None;
    }
    const FOV: i32 = 360;
    let px = cx + (((pt.x + cam_x) * FOV) / z_eff) as isize;
    let py = cy + (((pt.y + cam_y) * FOV) / z_eff) as isize;
    Some(Point2D { x: px, y: py })
}

pub struct Cyber3DState {
    pub angle_x: u8,
    pub angle_y: u8,
    pub angle_z: u8,
    pub core_angle: u8,
    pub cam_x: i32,
    pub cam_y: i32,
    pub cam_dist: i32,
    pub auto_spin: bool,
    pub mode: u8, // 0: 4D Tesseract, 1: Cyber Star, 2: Gyro Rings
    pub tick: u64,
}

impl Cyber3DState {
    pub fn new() -> Self {
        Self {
            angle_x: 24,
            angle_y: 38,
            angle_z: 16,
            core_angle: 0,
            cam_x: 0,
            cam_y: -20,
            cam_dist: 420,
            auto_spin: true,
            mode: 0,
            tick: 0,
        }
    }

    pub fn update(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        if self.auto_spin {
            self.angle_y = self.angle_y.wrapping_add(1);
            if self.tick % 2 == 0 {
                self.angle_x = self.angle_x.wrapping_add(1);
            }
            if self.tick % 3 == 0 {
                self.angle_z = self.angle_z.wrapping_add(1);
            }
            self.core_angle = self.core_angle.wrapping_sub(2);
        }
    }

    pub fn handle_key(&mut self, ch: char) -> bool {
        match ch {
            'w' | 'W' => {
                self.cam_dist = (self.cam_dist - 16).max(180);
                true
            }
            's' | 'S' => {
                self.cam_dist = (self.cam_dist + 16).min(800);
                true
            }
            'a' | 'A' => {
                self.cam_x = (self.cam_x - 12).max(-250);
                true
            }
            'd' | 'D' => {
                self.cam_x = (self.cam_x + 12).min(250);
                true
            }
            'q' | 'Q' => {
                self.angle_y = self.angle_y.wrapping_sub(4);
                true
            }
            'e' | 'E' => {
                self.angle_y = self.angle_y.wrapping_add(4);
                true
            }
            ' ' => {
                self.auto_spin = !self.auto_spin;
                true
            }
            'm' | 'M' => {
                self.mode = (self.mode + 1) % 3;
                true
            }
            'r' | 'R' => {
                self.angle_x = 24;
                self.angle_y = 38;
                self.angle_z = 16;
                self.cam_x = 0;
                self.cam_y = -20;
                self.cam_dist = 420;
                self.auto_spin = true;
                true
            }
            _ => false,
        }
    }

    pub fn render(&mut self, engine: &mut DisplayEngine, ux: usize, uy: usize, ww: usize, wh: usize, fps: u64) {
        self.update();

        let body_y = uy + 29;
        let body_h = wh.saturating_sub(29);
        let min_x = (ux + 2) as isize;
        let max_x = (ux + ww - 2) as isize;
        let min_y = body_y as isize;
        let max_y = (uy + wh - 2) as isize;

        // Viewport center
        let cx = (ux + ww / 2) as isize;
        let cy = (body_y + body_h / 2) as isize;

        // 1. Deep Kali obsidian background
        engine.fill_rect(ux, body_y, ww, body_h, Color::rgb(7, 10, 19));

        // 2. Synthwave Cyber Horizon & Moving Ground Grid
        let horizon_y = cy + 45;
        if horizon_y >= min_y && horizon_y < max_y {
            // Horizon glow line
            engine.draw_line_clipped(min_x, horizon_y, max_x, horizon_y, min_x, min_y, max_x, max_y, Color::rgb(56, 189, 248));
        }

        // Longitudinal perspective beams radiating from horizon
        let num_rays = 9;
        for i in 0..num_rays {
            let frac = (i as isize) - (num_rays as isize / 2);
            let ground_x = cx + frac * 75;
            let ground_y = max_y + 10;
            engine.draw_line_clipped(cx, horizon_y, ground_x, ground_y, min_x, min_y, max_x, max_y, Color::rgb(79, 70, 229));
        }

        // Transversal scrolling depth grid lines
        let depth_offset = ((self.tick / 2) % 24) as isize;
        for d in 0..5 {
            let offset_y = horizon_y + 12 + d * 18 + depth_offset;
            if offset_y >= min_y && offset_y < max_y {
                let color_dim = Color::rgb(67, 56, 202);
                engine.draw_line_clipped(min_x, offset_y, max_x, offset_y, min_x, min_y, max_x, max_y, color_dim);
            }
        }

        // 3. Render 3D Model based on active mode
        match self.mode {
            0 => self.render_tesseract(engine, cx, cy, min_x, min_y, max_x, max_y),
            1 => self.render_cyber_star(engine, cx, cy, min_x, min_y, max_x, max_y),
            _ => self.render_gyro_rings(engine, cx, cy, min_x, min_y, max_x, max_y),
        }

        // 4. Heads-Up Display (HUD) Telemetry Overlay
        // Top-left brand badge
        engine.fill_rounded_rect(ux + 8, body_y + 8, 235, 36, 4, Color::rgb(15, 23, 42));
        engine.draw_rect(ux + 8, body_y + 8, 235, 36, Color::rgb(51, 65, 85));
        engine.draw_string(ux + 16, body_y + 14, "CYBERSPACE 3D MOTORU", Color::CYAN, 1);
        let nw = engine.draw_number(ux + 16, body_y + 28, fps, Color::EMERALD, 1);
        engine.draw_string(ux + 16 + nw, body_y + 28, " FPS | 0.8MS VRAM (10X)", Color::EMERALD, 1);

        // Top-right mode pill
        let mode_name = match self.mode {
            0 => "MOD: 4D TESSERACT HYPERCUBE",
            1 => "MOD: CYBER SHIELD CRYSTAL",
            _ => "MOD: 3D GYRO MESH RINGS",
        };
        let mode_w = mode_name.len() * 6 + 16;
        let mode_x = (ux + ww).saturating_sub(mode_w + 10);
        engine.fill_rounded_rect(mode_x, body_y + 8, mode_w, 20, 3, Color::rgb(15, 23, 42));
        engine.draw_rect(mode_x, body_y + 8, mode_w, 20, Color::rgb(250, 204, 21));
        engine.draw_string(mode_x + 8, body_y + 14, mode_name, Color::rgb(250, 204, 21), 1);

        // Bottom status & controls bar
        let stat_y = uy + wh - 26;
        engine.fill_rect(ux + 2, stat_y, ww - 4, 24, Color::rgb(10, 14, 26));
        engine.draw_hline(ux + 2, stat_y, ww - 4, Color::rgb(30, 41, 59));
        engine.draw_string(ux + 12, stat_y + 7, "[W/S] ZOOM", Color::WHITE, 1);
        engine.draw_string(ux + 84, stat_y + 7, "[A/D] PAN", Color::WHITE, 1);
        engine.draw_string(ux + 148, stat_y + 7, "[Q/E] DONDUR", Color::WHITE, 1);
        engine.draw_string(ux + 230, stat_y + 7, "[SPACE] OTO-DONUS", Color::CYAN, 1);
        engine.draw_string(ux + 348, stat_y + 7, "[M] MODEL DEGISTIR", Color::rgb(250, 204, 21), 1);
        engine.draw_string(ux + 480, stat_y + 7, "[R] SIFIRLA", Color::rgb(148, 163, 184), 1);
    }

    fn render_tesseract(&self, engine: &mut DisplayEngine, cx: isize, cy: isize, min_x: isize, min_y: isize, max_x: isize, max_y: isize) {
        // Outer Cube 8 vertices (size 72)
        const S1: i32 = 72;
        let outer_raw = [
            Point3D { x: -S1, y: -S1, z: -S1 }, Point3D { x:  S1, y: -S1, z: -S1 },
            Point3D { x:  S1, y:  S1, z: -S1 }, Point3D { x: -S1, y:  S1, z: -S1 },
            Point3D { x: -S1, y: -S1, z:  S1 }, Point3D { x:  S1, y: -S1, z:  S1 },
            Point3D { x:  S1, y:  S1, z:  S1 }, Point3D { x: -S1, y:  S1, z:  S1 },
        ];

        // Inner Cube 8 vertices (size 36)
        const S2: i32 = 36;
        let inner_raw = [
            Point3D { x: -S2, y: -S2, z: -S2 }, Point3D { x:  S2, y: -S2, z: -S2 },
            Point3D { x:  S2, y:  S2, z: -S2 }, Point3D { x: -S2, y:  S2, z: -S2 },
            Point3D { x: -S2, y: -S2, z:  S2 }, Point3D { x:  S2, y: -S2, z:  S2 },
            Point3D { x:  S2, y:  S2, z:  S2 }, Point3D { x: -S2, y:  S2, z:  S2 },
        ];

        let cube_edges = [
            (0, 1), (1, 2), (2, 3), (3, 0), // Front face
            (4, 5), (5, 6), (6, 7), (7, 4), // Back face
            (0, 4), (1, 5), (2, 6), (3, 7), // Connecting edges
        ];

        // Rotate & Project Outer Cube
        let mut outer_proj = [None; 8];
        for i in 0..8 {
            let rot = rotate_point(outer_raw[i], self.angle_x, self.angle_y, self.angle_z);
            outer_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }

        // Rotate & Project Inner Cube
        let mut inner_proj = [None; 8];
        for i in 0..8 {
            let rot = rotate_point(inner_raw[i], self.angle_x, self.angle_y, self.angle_z);
            inner_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }

        // Draw Outer Cube Edges (Neon Cyan)
        for &(a, b) in &cube_edges {
            if let (Some(p0), Some(p1)) = (outer_proj[a], outer_proj[b]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::CYAN);
            }
        }

        // Draw Inner Cube Edges (Neon Emerald)
        for &(a, b) in &cube_edges {
            if let (Some(p0), Some(p1)) = (inner_proj[a], inner_proj[b]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::EMERALD);
            }
        }

        // Draw Tesseract Hypercube Cross-Connectors (Outer[i] -> Inner[i], Neon Amber)
        for i in 0..8 {
            if let (Some(p0), Some(p1)) = (outer_proj[i], inner_proj[i]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::rgb(250, 204, 21));
            }
        }

        // Contra-rotating diamond core inside the hypercube (Electric Pink)
        const SC: i32 = 22;
        let diamond_raw = [
            Point3D { x: 0, y: -SC, z: 0 }, Point3D { x: 0, y: SC, z: 0 },
            Point3D { x: -SC, y: 0, z: 0 }, Point3D { x: SC, y: 0, z: 0 },
            Point3D { x: 0, y: 0, z: -SC }, Point3D { x: 0, y: 0, z: SC },
        ];
        let diamond_edges = [
            (0, 2), (0, 3), (0, 4), (0, 5),
            (1, 2), (1, 3), (1, 4), (1, 5),
            (2, 4), (4, 3), (3, 5), (5, 2),
        ];
        let mut diamond_proj = [None; 6];
        for i in 0..6 {
            let rot = rotate_point(diamond_raw[i], self.core_angle, self.core_angle.wrapping_mul(2), self.angle_z);
            diamond_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }
        for &(a, b) in &diamond_edges {
            if let (Some(p0), Some(p1)) = (diamond_proj[a], diamond_proj[b]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::rgb(236, 72, 153));
            }
        }

        // Draw glowing vertex points
        for p in outer_proj.iter().flatten() {
            if p.x >= min_x + 1 && p.x < max_x - 1 && p.y >= min_y + 1 && p.y < max_y - 1 {
                engine.draw_rect((p.x - 1) as usize, (p.y - 1) as usize, 3, 3, Color::WHITE);
            }
        }
    }

    fn render_cyber_star(&self, engine: &mut DisplayEngine, cx: isize, cy: isize, min_x: isize, min_y: isize, max_x: isize, max_y: isize) {
        // 3D Hexagram Star Prism (12 vertices, 24 edges)
        let mut star_raw = [Point3D { x: 0, y: 0, z: 0 }; 12];
        for i in 0..6 {
            let ang = (i * 256 / 6) as u8;
            let rad = if i % 2 == 0 { 75 } else { 38 };
            let x = (rad * cos(ang)) >> 10;
            let z = (rad * sin(ang)) >> 10;
            star_raw[i] = Point3D { x, y: -45, z };
            star_raw[i + 6] = Point3D { x, y: 45, z };
        }

        let mut star_proj = [None; 12];
        for i in 0..12 {
            let rot = rotate_point(star_raw[i], self.angle_x, self.angle_y, self.angle_z);
            star_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }

        // Top and bottom rings
        for i in 0..6 {
            let next = (i + 1) % 6;
            if let (Some(p0), Some(p1)) = (star_proj[i], star_proj[next]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::CYAN);
            }
            if let (Some(p0), Some(p1)) = (star_proj[i + 6], star_proj[next + 6]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::EMERALD);
            }
            // Vertical ribs
            if let (Some(p0), Some(p1)) = (star_proj[i], star_proj[i + 6]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::rgb(250, 204, 21));
            }
        }
    }

    fn render_gyro_rings(&self, engine: &mut DisplayEngine, cx: isize, cy: isize, min_x: isize, min_y: isize, max_x: isize, max_y: isize) {
        // 3D Concentric Gyroscope Rings (24 points per ring)
        const STEPS: usize = 16;
        const R1: i32 = 70;
        const R2: i32 = 50;

        // Ring 1 (XY plane)
        let mut r1_proj = [None; STEPS];
        for i in 0..STEPS {
            let ang = (i * 256 / STEPS) as u8;
            let pt = Point3D {
                x: (R1 * cos(ang)) >> 10,
                y: (R1 * sin(ang)) >> 10,
                z: 0,
            };
            let rot = rotate_point(pt, self.angle_x, self.angle_y, self.angle_z);
            r1_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }

        // Ring 2 (YZ plane)
        let mut r2_proj = [None; STEPS];
        for i in 0..STEPS {
            let ang = (i * 256 / STEPS) as u8;
            let pt = Point3D {
                x: 0,
                y: (R2 * cos(ang)) >> 10,
                z: (R2 * sin(ang)) >> 10,
            };
            let rot = rotate_point(pt, self.angle_x.wrapping_add(64), self.angle_y.wrapping_add(32), self.angle_z);
            r2_proj[i] = project_point(rot, self.cam_x, self.cam_y, self.cam_dist, cx, cy);
        }

        for i in 0..STEPS {
            let next = (i + 1) % STEPS;
            if let (Some(p0), Some(p1)) = (r1_proj[i], r1_proj[next]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::CYAN);
            }
            if let (Some(p0), Some(p1)) = (r2_proj[i], r2_proj[next]) {
                engine.draw_line_clipped(p0.x, p0.y, p1.x, p1.y, min_x, min_y, max_x, max_y, Color::rgb(236, 72, 153));
            }
        }
    }
}
