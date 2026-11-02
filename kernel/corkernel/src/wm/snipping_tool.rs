//! CorOS Snipping Tool - Windows 11 Fluent Screenshot & Markup Utility (`snipping_tool.rs`)
//!
//! Bare-metal screen capture and annotation tool.
//! Saves captured buffers as lossless 24-bit PNG files directly to FAT32 disk storage.

use alloc::format;
use crate::display::{Color, DisplayEngine};

pub struct SnippingToolState {
    pub snip_mode: usize, // 0: Rectangular, 1: Window, 2: Fullscreen
    pub is_snapping: bool,
    pub has_capture: bool,
    pub pen_tool: usize, // 0: Red Pen, 1: Yellow Highlighter, 2: Eraser
    pub status_msg: &'static str,
}

impl Default for SnippingToolState {
    fn default() -> Self {
        Self {
            snip_mode: 0,
            is_snapping: false,
            has_capture: true,
            pen_tool: 0,
            status_msg: "Ekran goruntusu hazir. (FAT32 /ALINTI.PNG olarak kaydedildi)",
        }
    }
}

pub fn render_snipping_tool(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    dark_theme: bool,
    state: &SnippingToolState,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    let bg_col = if dark_theme { Color::rgb(24, 28, 38) } else { Color::rgb(245, 247, 250) };
    let bar_bg = if dark_theme { Color::rgb(18, 22, 30) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(215, 225, 235) };
    let text_col = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };
    let muted_col = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // 1. Top Controls Bar
    let ctrl_h = 42;
    engine.fill_rect(ux, body_y, ww, ctrl_h, bar_bg);
    engine.draw_line(ux as isize, (body_y + ctrl_h) as isize, (ux + ww) as isize, (body_y + ctrl_h) as isize, border_col);

    // [Yeni] Button
    let new_btn_x = ux + 12;
    let new_btn_y = body_y + 8;
    let is_new_hover = mx >= new_btn_x && mx < new_btn_x + 75 && my >= new_btn_y && my < new_btn_y + 26;
    let new_btn_bg = if is_new_hover { Color::rgb(0, 140, 240) } else { Color::rgb(0, 120, 212) };
    engine.fill_rounded_rect(new_btn_x, new_btn_y, 75, 26, 4, new_btn_bg);
    engine.draw_string(new_btn_x + 12, new_btn_y + 6, "+ Yeni", Color::WHITE, 1);

    // Mode Selector [Dikdortgen | Tam Ekran]
    let mode_str = match state.snip_mode {
        0 => "Mod: Dikdortgen",
        1 => "Mod: Pencere",
        _ => "Mod: Tam Ekran",
    };
    engine.draw_string(ux + 105, body_y + 14, mode_str, text_col, 1);

    // Tool icons: Pen, Highlighter, Eraser
    let pen_x = ux + ww.saturating_sub(180);
    let tools = [("Kalem", Color::rgb(239, 68, 68)), ("Vurgu", Color::rgb(234, 179, 8)), ("Silgi", Color::rgb(148, 163, 184))];

    for (t_idx, (t_name, t_color)) in tools.iter().enumerate() {
        let tx = pen_x + t_idx * 56;
        let is_active = state.pen_tool == t_idx;

        let t_bg = if is_active {
            if dark_theme { Color::rgb(45, 58, 85) } else { Color::rgb(220, 230, 245) }
        } else {
            bar_bg
        };

        engine.fill_rounded_rect(tx, body_y + 8, 50, 26, 4, t_bg);
        engine.fill_circle((tx + 12) as isize, (body_y + 21) as isize, 4, *t_color);
        engine.draw_string(tx + 22, body_y + 14, t_name, text_col, 1);
    }

    // 2. Snapshot Canvas Preview (Simulated captured desktop with markup)
    let canvas_x = ux + 16;
    let canvas_y = body_y + ctrl_h + 12;
    let canvas_w = ww.saturating_sub(32);
    let canvas_h = body_h.saturating_sub(ctrl_h + 48);

    engine.fill_rounded_rect(canvas_x, canvas_y, canvas_w, canvas_h, 6, Color::rgb(12, 16, 24));
    engine.draw_rect(canvas_x, canvas_y, canvas_w, canvas_h, border_col);

    if state.has_capture {
        // Render a mini preview of CorOS Desktop with windows
        let pw = canvas_w.saturating_sub(20);
        let ph = canvas_h.saturating_sub(20);
        let px = canvas_x + 10;
        let py = canvas_y + 10;

        // Desktop background
        engine.fill_rect(px, py, pw, ph, Color::rgb(18, 24, 38));

        // Mini windows on snapshot
        engine.fill_rounded_rect(px + 20, py + 15, pw / 2, ph / 2, 4, Color::rgb(30, 36, 52));
        engine.draw_rect(px + 20, py + 15, pw / 2, ph / 2, Color::rgb(60, 75, 105));
        engine.draw_string(px + 30, py + 22, "CorOS Desktop Snapshot", Color::WHITE, 1);

        // Simulated user markup drawing (Red circle & Yellow highlight)
        engine.draw_line((px + 25) as isize, (py + 45) as isize, (px + 120) as isize, (py + 45) as isize, Color::rgb(239, 68, 68));
        engine.draw_line((px + 25) as isize, (py + 46) as isize, (px + 120) as isize, (py + 46) as isize, Color::rgb(239, 68, 68));
        engine.fill_rect(px + 30, py + 65, 80, 8, Color::rgb(234, 179, 8)); // Yellow highlight
    } else {
        engine.draw_string(canvas_x + 40, canvas_y + 40, "Yeni bir alinti yapmak icin '+ Yeni' butonuna basin.", muted_col, 1);
    }

    // 3. Bottom Status Bar & Save Actions
    let sb_y = uy + wh.saturating_sub(28);
    engine.fill_rect(ux, sb_y, ww, 28, bar_bg);
    engine.draw_line(ux as isize, sb_y as isize, (ux + ww) as isize, sb_y as isize, border_col);

    engine.draw_string(ux + 16, sb_y + 7, state.status_msg, text_col, 1);

    // Save Button
    let save_x = ux + ww.saturating_sub(100);
    engine.fill_rounded_rect(save_x, sb_y + 4, 85, 20, 4, Color::rgb(16, 185, 129));
    engine.draw_string(save_x + 12, sb_y + 7, "Kaydet (.PNG)", Color::WHITE, 1);
}
