//! CorOS Calculator & Paint Application Rendering Subsystems

use alloc::format;
use crate::display::{Color, DisplayEngine};

pub fn render_calculator(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    dark_theme: bool,
    calc_display: &str,
    calc_accumulator: i64,
    calc_op: Option<char>,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);
    let calc_bg = if dark_theme { Color::rgb(24, 28, 38) } else { Color::rgb(248, 250, 252) };
    engine.fill_rect(ux, body_y, ww, body_h, calc_bg);

    let disp_y = body_y + 12;
    let disp_h = 52;
    let disp_bg = if dark_theme { Color::rgb(15, 19, 26) } else { Color::rgb(255, 255, 255) };
    let disp_border = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(203, 213, 225) };
    engine.fill_rounded_rect(ux + 12, disp_y, ww - 24, disp_h, 6, disp_bg);
    engine.draw_rect(ux + 12, disp_y, ww - 24, disp_h, disp_border);

    if let Some(op) = calc_op {
        let op_str = format!("{} {}", calc_accumulator, op);
        let op_fg = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };
        engine.draw_string(ux + 20, disp_y + 8, &op_str, op_fg, 1);
    }

    let num_w = engine.string_width(calc_display);
    let num_x = (ux + ww - 24).saturating_sub(num_w + 12);
    let num_col = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };
    engine.draw_string(num_x, disp_y + 24, calc_display, num_col, 1);

    let pad_y = disp_y + disp_h + 12;
    let pad_w = (ww - 24) / 4;
    let pad_h = 44;

    let labels = [
        ["C", "/", "*", "-"],
        ["7", "8", "9", "+"],
        ["4", "5", "6", "="],
        ["1", "2", "3", "0"],
    ];

    for row in 0..4 {
        for col in 0..4 {
            let kx = ux + 12 + col * pad_w;
            let ky = pad_y + row * pad_h;
            let kw = pad_w - 4;
            let kh = pad_h - 4;

            let is_hover = mx >= kx && mx < kx + kw && my >= ky && my < ky + kh;
            let is_op = col == 3 || (row == 0 && col > 0) || (row == 2 && col == 3);
            let is_clear = row == 0 && col == 0;

            let bg_col = if dark_theme {
                if is_hover {
                    Color::rgb(60, 75, 105)
                } else if is_clear {
                    Color::rgb(70, 30, 35)
                } else if is_op {
                    Color::rgb(35, 50, 75)
                } else {
                    Color::rgb(32, 38, 52)
                }
            } else {
                if is_hover {
                    Color::rgb(224, 242, 254)
                } else if is_clear {
                    Color::rgb(254, 226, 226)
                } else if is_op {
                    Color::rgb(238, 242, 255)
                } else {
                    Color::rgb(255, 255, 255)
                }
            };

            let border_col = if dark_theme {
                if is_hover {
                    Color::CYAN
                } else if is_clear {
                    Color::rgb(239, 68, 68)
                } else if is_op {
                    Color::rgb(56, 189, 248)
                } else {
                    Color::rgb(50, 60, 80)
                }
            } else {
                if is_hover {
                    Color::rgb(0, 120, 212)
                } else if is_clear {
                    Color::rgb(239, 68, 68)
                } else if is_op {
                    Color::rgb(0, 120, 212)
                } else {
                    Color::rgb(203, 213, 225)
                }
            };

            engine.fill_rounded_rect(kx, ky, kw, kh, 4, bg_col);
            engine.draw_rect(kx, ky, kw, kh, border_col);

            let label = labels[row][col];
            let lw = engine.string_width(label);
            let lx = kx + (kw.saturating_sub(lw)) / 2;
            let ly = ky + (kh.saturating_sub(8)) / 2;
            let fg_col = if is_clear {
                Color::rgb(239, 68, 68)
            } else if is_op {
                if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) }
            } else {
                if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) }
            };
            engine.draw_string(lx, ly, label, fg_col, 1);
        }
    }
}

pub fn render_paint(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    paint_tool: usize,
    paint_color_idx: usize,
    paint_custom_color: u32,
    paint_hex_input: &str,
    paint_brush_size: usize,
    paint_pixels: &[u32],
    paint_status_msg: &str,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);
    engine.fill_rect(ux, body_y, ww, body_h, Color::rgb(24, 28, 38));

    let row1_h = 32;
    let row1_y = body_y + 4;
    engine.fill_rect(ux, row1_y, ww, row1_h, Color::rgb(30, 36, 50));
    engine.draw_hline(ux, row1_y + row1_h, ww, Color::rgb(45, 55, 75));

    let tools = [
        ("Firca", 0),
        ("Silgi", 1),
        ("Doldur", 2),
        ("Kare", 3),
        ("Cizgi", 4),
        ("Damla", 5),
    ];

    let mut tx_cursor = ux + 10;
    for (name, id) in tools {
        let tw = 46;
        let is_sel = paint_tool == id;
        let is_h = mx >= tx_cursor && mx < tx_cursor + tw && my >= row1_y + 3 && my < row1_y + 27;

        let bg = if is_sel { Color::rgb(14, 116, 144) } else if is_h { Color::rgb(45, 55, 75) } else { Color::rgb(35, 42, 56) };
        let border = if is_sel { Color::CYAN } else { Color::rgb(60, 70, 90) };
        engine.fill_rounded_rect(tx_cursor, row1_y + 3, tw, 24, 3, bg);
        engine.draw_rect(tx_cursor, row1_y + 3, tw, 24, border);

        let nw = engine.string_width(name);
        let lx = tx_cursor + (tw.saturating_sub(nw)) / 2;
        let fg = if is_sel { Color::WHITE } else { Color::rgb(203, 213, 225) };
        engine.draw_string(lx, row1_y + 8, name, fg, 1);
        tx_cursor += tw + 4;
    }

    tx_cursor += 10;
    let undo_w = 56;
    let is_undo_h = mx >= tx_cursor && mx < tx_cursor + undo_w && my >= row1_y + 3 && my < row1_y + 27;
    engine.fill_rounded_rect(tx_cursor, row1_y + 3, undo_w, 24, 3, if is_undo_h { Color::rgb(50, 60, 80) } else { Color::rgb(35, 42, 56) });
    engine.draw_rect(tx_cursor, row1_y + 3, undo_w, 24, Color::rgb(70, 85, 110));
    engine.draw_string(tx_cursor + 6, row1_y + 8, "GERI AL", Color::rgb(203, 213, 225), 1);
    tx_cursor += undo_w + 4;

    let clr_w = 56;
    let is_clr_h = mx >= tx_cursor && mx < tx_cursor + clr_w && my >= row1_y + 3 && my < row1_y + 27;
    engine.fill_rounded_rect(tx_cursor, row1_y + 3, clr_w, 24, 3, if is_clr_h { Color::rgb(185, 28, 28) } else { Color::rgb(127, 29, 29) });
    engine.draw_rect(tx_cursor, row1_y + 3, clr_w, 24, Color::rgb(239, 68, 68));
    engine.draw_string(tx_cursor + 6, row1_y + 8, "TEMIZLE", Color::WHITE, 1);
    tx_cursor += clr_w + 6;

    let save_w = 78;
    let is_save_h = mx >= tx_cursor && mx < tx_cursor + save_w && my >= row1_y + 3 && my < row1_y + 27;
    engine.fill_rounded_rect(tx_cursor, row1_y + 3, save_w, 24, 3, if is_save_h { Color::rgb(16, 185, 129) } else { Color::rgb(5, 150, 105) });
    engine.draw_rect(tx_cursor, row1_y + 3, save_w, 24, Color::EMERALD);
    engine.draw_string(tx_cursor + 6, row1_y + 8, "KAYDET PNG", Color::WHITE, 1);

    let row2_h = 36;
    let row2_y = row1_y + row1_h + 1;
    engine.fill_rect(ux, row2_y, ww, row2_h, Color::rgb(28, 32, 44));
    engine.draw_hline(ux, row2_y + row2_h, ww, Color::rgb(45, 55, 75));

    let preset_colors = [
        (Color::rgb(0, 0, 0), 0x00000000),
        (Color::rgb(255, 255, 255), 0x00FFFFFF),
        (Color::rgb(120, 144, 156), 0x0078909C),
        (Color::rgb(239, 68, 68), 0x00EF4444),
        (Color::rgb(249, 115, 22), 0x00F97316),
        (Color::rgb(234, 179, 8), 0x00EAB308),
        (Color::rgb(34, 197, 94), 0x0022C55E),
        (Color::rgb(16, 185, 129), 0x0010B981),
        (Color::rgb(6, 182, 212), 0x0006B6D4),
        (Color::rgb(59, 130, 246), 0x003B82F6),
        (Color::rgb(30, 58, 138), 0x001E3A8A),
        (Color::rgb(168, 85, 247), 0x00A855F7),
        (Color::rgb(236, 72, 153), 0x00EC4899),
        (Color::rgb(146, 64, 14), 0x0092400E),
        (Color::rgb(254, 240, 138), 0x00FEF08A),
        (Color::rgb(15, 23, 42), 0x000F172A),
    ];

    let sw_sz = 14;
    let pal_start_x = ux + 10;
    for i in 0..16 {
        let row = i / 8;
        let col = i % 8;
        let cx = pal_start_x + col * 18;
        let cy = row2_y + 4 + row * 16;
        let is_sel = paint_color_idx == i;
        let is_h = mx >= cx && mx < cx + sw_sz && my >= cy && my < cy + sw_sz;

        if is_sel {
            engine.draw_rect(cx.saturating_sub(1), cy.saturating_sub(1), sw_sz + 2, sw_sz + 2, Color::CYAN);
        } else if is_h {
            engine.draw_rect(cx.saturating_sub(1), cy.saturating_sub(1), sw_sz + 2, sw_sz + 2, Color::WHITE);
        }
        engine.fill_rect(cx, cy, sw_sz, sw_sz, preset_colors[i].0);
        engine.draw_rect(cx, cy, sw_sz, sw_sz, Color::rgb(60, 70, 90));
    }

    let active_preview_x = pal_start_x + 8 * 18 + 12;
    let cur_col_u32 = if paint_color_idx < 16 {
        preset_colors[paint_color_idx].1
    } else {
        paint_custom_color
    };
    let cur_color = Color::rgb(
        ((cur_col_u32 >> 16) & 0xFF) as u8,
        ((cur_col_u32 >> 8) & 0xFF) as u8,
        (cur_col_u32 & 0xFF) as u8,
    );
    engine.fill_rounded_rect(active_preview_x, row2_y + 4, 30, 28, 4, cur_color);
    engine.draw_rect(active_preview_x, row2_y + 4, 30, 28, Color::WHITE);

    let hex_x = active_preview_x + 36;
    let is_hex_sel = paint_color_idx == 16;
    let hex_border = if is_hex_sel { Color::CYAN } else { Color::rgb(60, 70, 90) };
    engine.fill_rounded_rect(hex_x, row2_y + 6, 84, 24, 3, Color::rgb(18, 22, 32));
    engine.draw_rect(hex_x, row2_y + 6, 84, 24, hex_border);

    let hex_disp = format!("#{}", paint_hex_input);
    engine.draw_string(hex_x + 6, row2_y + 11, &hex_disp, if is_hex_sel { Color::CYAN } else { Color::WHITE }, 1);

    let bsz_start_x = hex_x + 94;
    let b_sizes = [1, 2, 4];
    for (i, &b_sz) in b_sizes.iter().enumerate() {
        let bx = bsz_start_x + i * 28;
        let is_sel = paint_brush_size == b_sz;
        let is_h = mx >= bx && mx < bx + 24 && my >= row2_y + 6 && my < row2_y + 30;

        let bg = if is_sel { Color::rgb(14, 116, 144) } else if is_h { Color::rgb(45, 55, 75) } else { Color::rgb(35, 42, 56) };
        let border = if is_sel { Color::CYAN } else { Color::rgb(60, 70, 90) };
        engine.fill_rounded_rect(bx, row2_y + 6, 24, 24, 3, bg);
        engine.draw_rect(bx, row2_y + 6, 24, 24, border);

        let lbl = match b_sz { 1 => "1p", 2 => "2p", _ => "4p" };
        engine.draw_string(bx + 4, row2_y + 11, lbl, Color::WHITE, 1);
    }

    let canvas_w = 320;
    let canvas_h = 240;
    let cv_x = ux + (ww.saturating_sub(canvas_w)) / 2;
    let cv_y = row2_y + row2_h + 16;

    engine.fill_rect(cv_x + 3, cv_y + 3, canvas_w, canvas_h, Color::rgb(10, 12, 18));
    engine.draw_rect(cv_x.saturating_sub(1), cv_y.saturating_sub(1), canvas_w + 2, canvas_h + 2, Color::rgb(80, 95, 120));

    for py in 0..120 {
        for px in 0..160 {
            let col_u32 = paint_pixels[py * 160 + px];
            let color = Color::rgb(
                ((col_u32 >> 16) & 0xFF) as u8,
                ((col_u32 >> 8) & 0xFF) as u8,
                (col_u32 & 0xFF) as u8,
            );
            let dx = cv_x + px * 2;
            let dy = cv_y + py * 2;
            engine.fill_rect(dx, dy, 2, 2, color);
        }
    }

    let stat_y = uy + wh - 24;
    engine.fill_rect(ux, stat_y, ww, 24, Color::rgb(18, 22, 30));
    engine.draw_hline(ux, stat_y, ww, Color::rgb(40, 50, 70));
    engine.draw_string(ux + 14, stat_y + 6, paint_status_msg, Color::rgb(148, 163, 184), 1);
}
