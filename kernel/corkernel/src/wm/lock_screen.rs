//! CorOS Windows 11 Fluent Lock & Login Screen Subsystem (`lock_screen.rs`)
//!
//! Provides a secure, frosted-glass acrylic lock screen triggered on boot
//! or via the Win + L keyboard shortcut.

use alloc::format;
use crate::display::{Color, DisplayEngine};

pub fn render_lock_screen(
    engine: &mut DisplayEngine,
    sw: usize,
    sh: usize,
    mx: usize,
    my: usize,
    password_len: usize,
    _anim_tick: usize,
) {
    // 1. Acrylic Deep Gradient Background (Simulated wallpaper blur)
    for y in 0..sh {
        let pct = (y as f32) / (sh as f32);
        let r = (10.0 + pct * 15.0) as u8;
        let g = (14.0 + pct * 20.0) as u8;
        let b = (28.0 + pct * 42.0) as u8;
        engine.fill_rect(0, y, sw, 1, Color::rgb(r, g, b));
    }

    // Top subtle ambient glow
    engine.fill_circle((sw / 2) as isize, -100, (sw / 2) as isize, Color::rgb(20, 60, 140));

    // 2. Large Windows 11 Digital Clock
    let clock_y = sh / 6;
    let time_str = "16:45";
    let tw = engine.string_width(time_str) * 3;
    let tx = (sw.saturating_sub(tw)) / 2;
    engine.draw_string(tx, clock_y, time_str, Color::WHITE, 3);

    // Date String
    let date_str = "26 Ekim Pazartesi • CorOS 2026";
    let dw = engine.string_width(date_str);
    let dx = (sw.saturating_sub(dw)) / 2;
    engine.draw_string(dx, clock_y + 60, date_str, Color::rgb(200, 215, 235), 1);

    // 3. User Avatar & Login Panel
    let avatar_y = clock_y + 130;
    let center_x = (sw / 2) as isize;

    // Glowing avatar circle
    engine.fill_circle(center_x, (avatar_y + 40) as isize, 44, Color::rgb(0, 120, 212));
    engine.fill_circle(center_x, (avatar_y + 40) as isize, 40, Color::rgb(25, 35, 55));
    // User Glyph / Initials
    engine.draw_string((center_x - 12) as usize, avatar_y + 26, "CD", Color::WHITE, 2);

    // User Display Name
    let user_name = "Corpus Developer";
    let unw = engine.string_width(user_name);
    let unx = (sw.saturating_sub(unw)) / 2;
    engine.draw_string(unx, avatar_y + 96, user_name, Color::WHITE, 1);

    // 4. Password / PIN Input Box
    let input_w = 220;
    let input_h = 34;
    let input_x = (sw.saturating_sub(input_w)) / 2;
    let input_y = avatar_y + 125;

    engine.fill_rounded_rect(input_x, input_y, input_w, input_h, 6, Color::rgb(18, 24, 38));
    engine.draw_rect(input_x, input_y, input_w, input_h, Color::rgb(60, 80, 115));

    // Masked dots or placeholder
    if password_len > 0 {
        let dots = "••••••••••••";
        let display_dots = &dots[..dots.len().min(password_len * 3)];
        engine.draw_string(input_x + 16, input_y + 10, display_dots, Color::WHITE, 1);
    } else {
        engine.draw_string(input_x + 16, input_y + 10, "PIN veya parola girin...", Color::rgb(120, 135, 160), 1);
    }

    // Submit Arrow Button
    let btn_size = 28;
    let btn_x = input_x + input_w + 8;
    let btn_y = input_y + 3;
    let is_btn_hover = (mx as isize) >= (btn_x as isize) && (mx as isize) <= (btn_x + btn_size) as isize && (my as isize) >= (btn_y as isize) && (my as isize) <= (btn_y + btn_size) as isize;
    let btn_bg = if is_btn_hover { Color::rgb(0, 140, 240) } else { Color::rgb(0, 120, 212) };

    engine.fill_circle((btn_x + btn_size / 2) as isize, (btn_y + btn_size / 2) as isize, 14, btn_bg);
    engine.draw_string(btn_x + 9, btn_y + 6, ">", Color::WHITE, 1);

    // 5. Bottom Right System Status
    let br_x = sw.saturating_sub(180);
    let br_y = sh.saturating_sub(32);
    engine.draw_string(br_x, br_y, "Pil: %100 • Wi-Fi OK", Color::rgb(180, 195, 215), 1);
}
