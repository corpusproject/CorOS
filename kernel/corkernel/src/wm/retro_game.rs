//! CorDoom 3D - Bare-Metal Raycasting Retro FPS Engine (`retro_game.rs`)
//!
//! 100% in-house bare-metal raycaster rendering 3D walls, player HUD,
//! minimap, and dynamic lighting onto CorOS double-buffered display.

use alloc::format;
use crate::display::{Color, DisplayEngine};

// 16x16 Game Map (1 = Outer Wall, 2 = Tech Wall, 3 = Cyber Pillar, 0 = Empty)
pub const MAP_W: usize = 16;
pub const MAP_H: usize = 16;
pub const GAME_MAP: [u8; MAP_W * MAP_H] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 0, 2, 2, 0, 0, 1, 0, 3, 0, 3, 0, 0, 2, 0, 1,
    1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1,
    1, 0, 0, 0, 0, 2, 2, 0, 3, 0, 3, 0, 0, 0, 0, 1,
    1, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 0, 0, 1, 0, 0, 2, 2, 0, 1, 0, 0, 1,
    1, 0, 3, 0, 3, 0, 1, 0, 0, 2, 2, 0, 1, 0, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1,
    1, 0, 2, 2, 0, 0, 3, 0, 0, 1, 1, 0, 0, 0, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1,
    1, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 1,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];

pub struct RetroGameState {
    pub player_x: f32,
    pub player_y: f32,
    pub player_angle: f32, // In degrees (0..360)
    pub health: u32,
    pub armor: u32,
    pub ammo: u32,
    pub score: u32,
    pub muzzle_flash_frames: u32,
}

impl Default for RetroGameState {
    fn default() -> Self {
        Self {
            player_x: 3.5,
            player_y: 3.5,
            player_angle: 45.0,
            health: 100,
            armor: 75,
            ammo: 64,
            score: 13370,
            muzzle_flash_frames: 0,
        }
    }
}

pub fn render_retro_game(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    state: &RetroGameState,
    _mx: usize,
    _my: usize,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);
    let hud_h = 44;
    let view_h = body_h.saturating_sub(hud_h);
    let view_w = ww;

    // 1. Render Sky & Floor
    let half_h = view_h / 2;
    // Ceiling: Dark Slate Cyber Sky
    engine.fill_rect(ux, body_y, view_w, half_h, Color::rgb(14, 18, 28));
    // Floor: Dark Charcoal Grid
    engine.fill_rect(ux, body_y + half_h, view_w, half_h, Color::rgb(24, 26, 34));

    // 2. Raycasting 3D Projection
    let num_rays = view_w / 4; // 1 ray per 4 pixels for high FPS
    let fov = 60.0f32;
    let rad_conv = 0.0174533f32;

    for i in 0..num_rays {
        let ray_screen_pct = (i as f32) / (num_rays as f32) - 0.5;
        let ray_angle = (state.player_angle + ray_screen_pct * fov) * rad_conv;

        let sin_a = sin_approx(ray_angle);
        let cos_a = cos_approx(ray_angle);

        // Ray stepping
        let mut dist = 0.1f32;
        let max_dist = 16.0f32;
        let mut hit_wall = 0u8;
        let mut hit_side = 0u8; // 0: X-hit, 1: Y-hit

        while dist < max_dist {
            let cx = (state.player_x + cos_a * dist) as usize;
            let cy = (state.player_y + sin_a * dist) as usize;

            if cx < MAP_W && cy < MAP_H {
                let cell = GAME_MAP[cy * MAP_W + cx];
                if cell > 0 {
                    hit_wall = cell;
                    let prev_x = (state.player_x + cos_a * (dist - 0.05)) as usize;
                    hit_side = if prev_x != cx { 0 } else { 1 };
                    break;
                }
            }
            dist += 0.05;
        }

        if hit_wall > 0 {
            // Fish-eye correction
            let correct_dist = dist * cos_approx((ray_screen_pct * fov) * rad_conv).max(0.1);
            let wall_h = ((view_h as f32 * 1.2) / correct_dist.max(0.5)) as usize;
            let wall_h = wall_h.min(view_h);

            let wall_top = body_y + (view_h.saturating_sub(wall_h)) / 2;
            let ray_x = ux + i * 4;

            // Shading & color by wall type and distance
            let dist_shade = (1.0 - (correct_dist / max_dist)).max(0.15);
            let (base_r, base_g, base_b) = match hit_wall {
                1 => (0, 160, 255), // Cyan/Blue High-Tech Wall
                2 => (240, 90, 40),  // Orange Rust Tech Wall
                3 => (160, 32, 240), // Purple Cyber Pillar
                _ => (120, 120, 120),
            };

            let side_mul = if hit_side == 1 { 0.75 } else { 1.0 };
            let r = ((base_r as f32) * dist_shade * side_mul) as u8;
            let g = ((base_g as f32) * dist_shade * side_mul) as u8;
            let b = ((base_b as f32) * dist_shade * side_mul) as u8;

            engine.fill_rect(ray_x, wall_top, 4, wall_h, Color::rgb(r, g, b));
        }
    }

    // 3. Muzzle Flash Animation
    if state.muzzle_flash_frames > 0 {
        let center_x = ux + view_w / 2;
        let muzzle_y = body_y + view_h - 60;
        engine.fill_circle(center_x as isize, muzzle_y as isize, 24, Color::rgb(255, 230, 80));
        engine.fill_circle(center_x as isize, muzzle_y as isize, 14, Color::WHITE);
    }

    // 4. Weapon Crosshair & Gun Sprite (Minimalist Retro Blaster)
    let cx = ux + view_w / 2;
    let cy = body_y + view_h / 2;
    engine.fill_rect(cx.saturating_sub(6), cy, 13, 1, Color::rgb(0, 255, 128));
    engine.fill_rect(cx, cy.saturating_sub(6), 1, 13, Color::rgb(0, 255, 128));

    // Blaster Barrel
    let gun_x = cx.saturating_sub(18);
    let gun_y = body_y + view_h - 48;
    engine.fill_rounded_rect(gun_x, gun_y, 36, 48, 4, Color::rgb(45, 55, 75));
    engine.fill_rect(gun_x + 8, gun_y + 4, 20, 40, Color::rgb(65, 80, 110));
    engine.fill_rect(gun_x + 14, gun_y - 8, 8, 12, Color::rgb(20, 180, 255)); // Glowing Energy Emitter

    // 5. Minimap (Top-Right overlay)
    let map_size = 72;
    let map_x = ux + view_w.saturating_sub(map_size + 12);
    let map_y = body_y + 12;
    engine.fill_rounded_rect(map_x, map_y, map_size, map_size, 4, Color::rgb(10, 14, 22));
    engine.draw_rect(map_x, map_y, map_size, map_size, Color::rgb(0, 180, 255));

    let tile_w = map_size / MAP_W;
    for my in 0..MAP_H {
        for mx in 0..MAP_W {
            if GAME_MAP[my * MAP_W + mx] > 0 {
                engine.fill_rect(map_x + mx * tile_w, map_y + my * tile_w, tile_w, tile_w, Color::rgb(70, 90, 120));
            }
        }
    }
    // Player dot on minimap
    let p_map_x = map_x + (state.player_x * tile_w as f32) as usize;
    let p_map_y = map_y + (state.player_y * tile_w as f32) as usize;
    engine.fill_circle(p_map_x as isize, p_map_y as isize, 2, Color::rgb(0, 255, 128));

    // 6. Retro Doom / Cyberpunk HUD Bar
    let hud_y = body_y + view_h;
    engine.fill_rect(ux, hud_y, ww, hud_h, Color::rgb(20, 24, 34));
    engine.draw_line(ux as isize, hud_y as isize, (ux + ww) as isize, hud_y as isize, Color::rgb(45, 58, 82));

    // Health Box
    let hp_str = format!("SAGLIK: %{}", state.health);
    engine.draw_string(ux + 16, hud_y + 14, &hp_str, Color::rgb(255, 75, 75), 1);

    // Armor Box
    let armor_str = format!("ZIRH: %{}", state.armor);
    engine.draw_string(ux + 150, hud_y + 14, &armor_str, Color::rgb(75, 160, 255), 1);

    // Ammo Box
    let ammo_str = format!("MERMI: {}/200", state.ammo);
    engine.draw_string(ux + 270, hud_y + 14, &ammo_str, Color::rgb(255, 200, 50), 1);

    // Score
    let score_str = format!("PUAN: {}", state.score);
    engine.draw_string(ux + 390, hud_y + 14, &score_str, Color::WHITE, 1);
}

// Fast integer/polynomial approximations for no_std math
fn sin_approx(rad: f32) -> f32 {
    let mut x = rad;
    // Normalize to -PI..PI
    while x > 3.141592 { x -= 6.283185; }
    while x < -3.141592 { x += 6.283185; }
    // Taylor series: x - x^3/6 + x^5/120
    let x2 = x * x;
    let x3 = x * x2;
    let x5 = x3 * x2;
    x - (x3 / 6.0) + (x5 / 120.0)
}

fn cos_approx(rad: f32) -> f32 {
    sin_approx(rad + 1.570796)
}
