//! CorOS Notepad Application Module
//!
//! Provides text rendering, line gutter numbers, cursor blinking,
//! and status bar for the built-in desktop Notepad.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{DisplayEngine, Color};

pub fn render_notepad(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    dark_theme: bool,
    saved_status: bool,
    content: &[String],
    cursor_row: usize,
    cursor_col: usize,
    cursor_blink: u64,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    // 1. Menu & Toolbar area
    let tb_bg = if dark_theme { Color::rgb(30, 36, 48) } else { Color::rgb(241, 245, 249) };
    let tb_border = if dark_theme { Color::rgb(50, 60, 80) } else { Color::rgb(226, 232, 240) };
    engine.fill_rect(ux, body_y, ww, 28, tb_bg);
    engine.draw_hline(ux, body_y + 28, ww, tb_border);

    // Save Button [ KAYDET ]
    let save_bg = if dark_theme { Color::rgb(14, 116, 144) } else { Color::rgb(0, 120, 212) };
    engine.fill_rounded_rect(ux + 10, body_y + 4, 70, 20, 3, save_bg);
    engine.draw_rect(ux + 10, body_y + 4, 70, 20, if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) });
    engine.draw_string(ux + 18, body_y + 8, "KAYDET", Color::WHITE, 1);

    // Status on right of toolbar
    if saved_status {
        engine.draw_string(ux + 90, body_y + 8, "[ KAYDEDILDI - C:\\NOTLAR.TXT ]", Color::EMERALD, 1);
    } else {
        let edit_flag_col = if dark_theme { Color::YELLOW } else { Color::rgb(180, 83, 9) };
        engine.draw_string(ux + 90, body_y + 8, "[ DUZENLENDI * ] (Kaydetmek icin butona tiklayin)", edit_flag_col, 1);
    }

    // 2. Editor Canvas area
    let edit_y = body_y + 29;
    let edit_h = body_h.saturating_sub(29 + 22);
    let canvas_bg = if dark_theme { Color::rgb(18, 22, 30) } else { Color::rgb(255, 255, 255) };
    engine.fill_rect(ux, edit_y, ww, edit_h, canvas_bg);

    // Line number gutter (width 40)
    let gutter_w = 40;
    let gutter_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(248, 250, 252) };
    let gutter_border = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
    engine.fill_rect(ux, edit_y, gutter_w, edit_h, gutter_bg);
    engine.draw_vline(ux + gutter_w, edit_y, edit_h, gutter_border);

    // Render Lines
    let text_fg = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };
    let gutter_num_fg = Color::rgb(100, 116, 139);

    for (i, line) in content.iter().enumerate() {
        let ly = edit_y + 8 + i * 18;
        if ly + 16 > edit_y + edit_h {
            break;
        }

        // Gutter line number
        let line_num_str = format!("{:2}", i + 1);
        engine.draw_string(ux + 8, ly, &line_num_str, gutter_num_fg, 1);

        // Text content
        let text_x = ux + gutter_w + 10;
        engine.draw_string(text_x, ly, line, text_fg, 1);

        // Cursor blink
        if i == cursor_row && (cursor_blink / 25) % 2 == 0 {
            let cur_x = text_x + cursor_col.min(line.len()) * 6;
            let cur_col = if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) };
            engine.fill_rect(cur_x, ly, 2, 14, cur_col);
        }
    }

    // 3. Status bar at bottom
    let stat_y = uy + wh - 22;
    let stat_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(241, 245, 249) };
    let stat_border = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
    engine.fill_rect(ux, stat_y, ww, 22, stat_bg);
    engine.draw_hline(ux, stat_y, ww, stat_border);
    let cur_pos_str = format!("Satir: {} | Sutun: {} | UTF-8 | FAT32 ESP", cursor_row + 1, cursor_col + 1);
    let stat_fg = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(71, 85, 105) };
    engine.draw_string(ux + 12, stat_y + 5, &cur_pos_str, stat_fg, 1);
}
