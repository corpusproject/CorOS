//! CorOS Windows 11 Fluent File Explorer Subsystem
//!
//! Replicates the authentic Windows 11 File Explorer layout:
//! - Navigation row: Back/Forward/Up/Refresh, Breadcrumbs Address Pill, Search Box
//! - Command Ribbon bar: [+ Yeni v] | [Kes] [Kopyala] [Yapistir] [Yeniden adlandir] [Paylas] [Sil] | [...] | [Onizleme]
//! - Left Navigation Sidebar: Giris, Galeri, OneDrive, Pinned Folders, Bu Bilgisayar, Ag, Ring 3
//! - Main Content Grid: Windows 11 2-column large folder cards with subtitles ("Yerel olarak depola...")
//! - Bottom Favoriler & Paylasilan tabs and status bar ("10 oge |")

use alloc::format;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;
use super::FileItem;

pub struct ExplorerRibbonAction;

impl ExplorerRibbonAction {
    pub const NEW_FILE: usize = 0;
    pub const CUT: usize = 1;
    pub const COPY: usize = 2;
    pub const PASTE: usize = 3;
    pub const RENAME: usize = 4;
    pub const SHARE: usize = 5;
    pub const DELETE: usize = 6;
    pub const MORE: usize = 7;
    pub const REFRESH: usize = 8;
}

pub fn render_file_explorer(
    selected_file: usize,
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    palette: &ThemePalette,
    current_folder: &str,
    files: &[FileItem],
    renaming_file_idx: Option<usize>,
    rename_buffer: &str,
    cursor_blink: u64,
    _file_status_msg: &str,
    has_clipboard: bool,
) {
    let sidebar_w = 150;
    let body_y = uy + 30;
    let body_h = wh.saturating_sub(30);

    // 1. Navigation & Breadcrumb Row (Height: 36px)
    let nav_h = 36;
    let nav_y = body_y;
    engine.fill_rect(ux, nav_y, ww, nav_h, Color::rgb(30, 30, 30));
    engine.draw_hline(ux, nav_y + nav_h, ww, Color::rgb(44, 44, 44));

    // Navigation buttons on left: <- -> ^ ( )
    let nav_btns = ["<", ">", "^", "O"];
    for (i, &sym) in nav_btns.iter().enumerate() {
        let bx = ux + 10 + i * 26;
        let is_h = mx >= bx && mx < bx + 22 && my >= nav_y + 7 && my < nav_y + 29;
        if is_h {
            engine.fill_rounded_rect(bx, nav_y + 7, 22, 22, 4, Color::rgb(50, 50, 50));
        }
        let col = if i == 0 || i == 2 || i == 3 { Color::rgb(220, 220, 220) } else { Color::rgb(110, 110, 110) };
        engine.draw_string(bx + 7, nav_y + 11, sym, col, 1);
    }

    // Breadcrumbs Address Pill (Windows 11 style)
    let pill_x = ux + 122;
    let search_w = 150.min(ww.saturating_sub(sidebar_w + 240));
    let pill_w = ww.saturating_sub(pill_x - ux + search_w + 24);

    engine.fill_rounded_rect(pill_x, nav_y + 6, pill_w, 24, 4, Color::rgb(40, 40, 40));
    engine.draw_rect(pill_x, nav_y + 6, pill_w, 24, Color::rgb(56, 56, 56));

    // Home / Folder icon in address bar
    engine.draw_string(pill_x + 8, nav_y + 11, "[D]", Color::rgb(96, 205, 255), 1);

    let formatted_path = if current_folder == "C:\\" {
        "Giris >"
    } else if current_folder == "C:\\EFI" {
        "Bu Bilgisayar > Yerel Disk (C:) > EFI >"
    } else {
        "Bu Bilgisayar > Yerel Disk (C:) > EFI > COROS >"
    };
    engine.draw_string(pill_x + 30, nav_y + 11, formatted_path, Color::rgb(240, 240, 240), 1);

    // Search bar on the right
    let search_x = pill_x + pill_w + 10;
    if search_w > 50 {
        engine.fill_rounded_rect(search_x, nav_y + 6, search_w, 24, 4, Color::rgb(40, 40, 40));
        engine.draw_rect(search_x, nav_y + 6, search_w, 24, Color::rgb(56, 56, 56));
        engine.draw_string(search_x + 8, nav_y + 11, "?", Color::rgb(140, 140, 140), 1);
        engine.draw_string(search_x + 22, nav_y + 11, "Giris'te ara...", Color::rgb(140, 140, 140), 1);
    }

    // 2. Command Ribbon Bar (Height: 38px, matching Image 1)
    let ribbon_y = nav_y + nav_h + 1;
    let ribbon_h = 38;
    engine.fill_rect(ux, ribbon_y, ww, ribbon_h, Color::rgb(26, 26, 26));
    engine.draw_hline(ux, ribbon_y + ribbon_h, ww, Color::rgb(44, 44, 44));

    // [+ Yeni v] Button
    let new_btn_w = 66;
    let is_new_h = mx >= ux + 10 && mx < ux + 10 + new_btn_w && my >= ribbon_y + 6 && my < ribbon_y + 32;
    if is_new_h {
        engine.fill_rounded_rect(ux + 10, ribbon_y + 6, new_btn_w, 26, 4, Color::rgb(46, 46, 46));
    }
    engine.draw_string(ux + 16, ribbon_y + 12, "+ Yeni v", Color::rgb(240, 240, 240), 1);

    // Divider |
    let div1_x = ux + 84;
    engine.draw_vline(div1_x, ribbon_y + 8, 22, Color::rgb(50, 50, 50));

    // Action Icons strip: [Kes] [Kopyala] [Yapistir] [Ad Degistir] [Paylas] [Sil]
    let action_icons = [
        ("X", ExplorerRibbonAction::CUT, "Kes"),
        ("C", ExplorerRibbonAction::COPY, "Kopyala"),
        ("V", ExplorerRibbonAction::PASTE, "Yapistir"),
        ("A", ExplorerRibbonAction::RENAME, "Ad Degistir"),
        ("Y", ExplorerRibbonAction::SHARE, "Paylas"),
        ("D", ExplorerRibbonAction::DELETE, "Sil"),
    ];

    let mut ax = div1_x + 10;
    for &(_tag, act_id, lbl) in &action_icons {
        let is_disabled = (act_id == ExplorerRibbonAction::PASTE && !has_clipboard)
            || (act_id == ExplorerRibbonAction::CUT && files.is_empty())
            || (act_id == ExplorerRibbonAction::COPY && files.is_empty())
            || (act_id == ExplorerRibbonAction::DELETE && files.is_empty());

        let btn_w = 28;
        let is_h = mx >= ax && mx < ax + btn_w && my >= ribbon_y + 6 && my < ribbon_y + 32;

        if !is_disabled && is_h {
            let h_bg = if act_id == ExplorerRibbonAction::DELETE {
                Color::rgb(70, 20, 20)
            } else {
                Color::rgb(46, 46, 46)
            };
            engine.fill_rounded_rect(ax, ribbon_y + 6, btn_w, 26, 4, h_bg);
        }

        let col = if is_disabled {
            Color::rgb(100, 100, 100)
        } else if act_id == ExplorerRibbonAction::DELETE && is_h {
            Color::rgb(248, 113, 113)
        } else if is_h {
            Color::WHITE
        } else {
            Color::rgb(200, 200, 200)
        };

        // Render sleek symbolic letter or symbol
        let sym = match act_id {
            ExplorerRibbonAction::CUT => "[X]",
            ExplorerRibbonAction::COPY => "[C]",
            ExplorerRibbonAction::PASTE => "[V]",
            ExplorerRibbonAction::RENAME => "[A]",
            ExplorerRibbonAction::SHARE => "[Y]",
            ExplorerRibbonAction::DELETE => "[D]",
            _ => "",
        };
        engine.draw_string(ax + 5, ribbon_y + 12, sym, col, 1);
        ax += btn_w + 6;
    }

    // Divider |
    engine.draw_vline(ax + 2, ribbon_y + 8, 22, Color::rgb(50, 50, 50));
    ax += 12;

    // [...] More button
    let is_more_h = mx >= ax && mx < ax + 24 && my >= ribbon_y + 6 && my < ribbon_y + 32;
    if is_more_h {
        engine.fill_rounded_rect(ax, ribbon_y + 6, 24, 26, 4, Color::rgb(46, 46, 46));
    }
    engine.draw_string(ax + 4, ribbon_y + 12, "...", Color::rgb(200, 200, 200), 1);

    // Far right: [Onizleme] toggle
    let prev_w = 64;
    let prev_x = ux + ww.saturating_sub(prev_w + 14);
    if prev_x > ax + 30 {
        let is_prev_h = mx >= prev_x && mx < prev_x + prev_w && my >= ribbon_y + 6 && my < ribbon_y + 32;
        if is_prev_h {
            engine.fill_rounded_rect(prev_x, ribbon_y + 6, prev_w, 26, 4, Color::rgb(46, 46, 46));
        }
        engine.draw_string(prev_x + 6, ribbon_y + 12, "[#] Onizle", Color::rgb(180, 180, 180), 1);
    }

    // 3. Left Navigation Sidebar (Width: sidebar_w, Height: body_h - 75px)
    let content_y = ribbon_y + ribbon_h + 1;
    let content_h = body_h.saturating_sub(ribbon_h + nav_h + 24);

    engine.fill_rect(ux, content_y, sidebar_w, content_h, Color::rgb(22, 22, 22));
    engine.draw_vline(ux + sidebar_w, content_y, content_h, Color::rgb(44, 44, 44));

    // Sidebar items matching Image 1:
    let sidebar_items = [
        ("Giris", "[D]", true, false),
        ("Galeri", "[P]", false, false),
        ("OneDrive", "[C]", false, true),
        ("Masaustu", "[M]", false, false),
        ("Indirilenler", "[v]", false, false),
        ("Belgeler", "[T]", false, false),
        ("Resimler", "[I]", false, false),
        ("Muzikler", "[S]", false, false),
        ("Videolar", "[V]", false, false),
        ("Bu Bilgisayar", "[B]", false, true),
        ("Ag", "[N]", false, true),
        ("Ring 3 Linux", "[L]", false, true),
    ];

    let mut sy = content_y + 8;
    for &(label, tag, is_selected, has_chevron) in &sidebar_items {
        if sy + 22 > content_y + content_h {
            break;
        }

        let is_h = mx >= ux + 6 && mx < ux + sidebar_w - 6 && my >= sy && my < sy + 22;

        if is_selected {
            // Rounded highlight capsule for selected folder
            engine.fill_rounded_rect(ux + 6, sy, sidebar_w - 12, 22, 4, Color::rgb(44, 44, 44));
        } else if is_h {
            engine.fill_rounded_rect(ux + 6, sy, sidebar_w - 12, 22, 4, Color::rgb(34, 34, 34));
        }

        let chevron = if has_chevron { "> " } else { "  " };
        engine.draw_string(ux + 10, sy + 5, chevron, Color::rgb(140, 140, 140), 1);

        let icon_col = if is_selected { Color::rgb(96, 205, 255) } else { Color::rgb(180, 180, 180) };
        engine.draw_string(ux + 24, sy + 5, tag, icon_col, 1);

        let text_col = if is_selected { Color::WHITE } else { Color::rgb(220, 220, 220) };
        engine.draw_string(ux + 46, sy + 5, label, text_col, 1);

        sy += 24;
    }

    // 4. Main Content Area (Two-Column Folder Cards matching Image 1)
    let main_x = ux + sidebar_w + 1;
    let main_w = ww.saturating_sub(sidebar_w + 1);

    engine.fill_rect(main_x, content_y, main_w, content_h, Color::rgb(20, 20, 20));

    // Section 1: "v Hizli erisim"
    let header_y = content_y + 10;
    engine.draw_string(main_x + 16, header_y, "v  Hizli erisim", Color::WHITE, 1);

    // Two-column grid of large Windows 11 folder cards
    let card_start_y = header_y + 24;
    let col_w = (main_w.saturating_sub(36)) / 2;
    let card_h = 42;

    // Combine system quick folders and actual FAT32 files
    let mut cards: alloc::vec::Vec<(&str, &str, &str, Color, usize)> = alloc::vec![
        ("Masaustu", "Yerel olarak depola...", "[D]", Color::rgb(96, 205, 255), 0),
        ("Indirilenler", "Yerel olarak depola...", "[v]", Color::rgb(16, 185, 129), 1),
        ("Belgeler", "Yerel olarak depola...", "[T]", Color::rgb(200, 200, 200), 2),
        ("Resimler", "Yerel olarak depola...", "[P]", Color::rgb(59, 130, 246), 3),
        ("Muzikler", "Yerel olarak depola...", "[S]", Color::rgb(245, 158, 11), 4),
        ("Videolar", "Yerel olarak depola...", "[V]", Color::rgb(168, 85, 247), 5),
    ];

    // Add FAT32 files
    for (f_idx, f) in files.iter().enumerate() {
        let (tag, tag_col) = if f.is_dir {
            ("[D]", Color::rgb(245, 158, 11))
        } else if f.name.ends_with(".ELF") {
            ("[E]", Color::rgb(16, 185, 129))
        } else if f.name.ends_with(".PNG") {
            ("[P]", Color::rgb(59, 130, 246))
        } else {
            ("[T]", Color::rgb(200, 200, 200))
        };
        cards.push((&f.name, &f.desc, tag, tag_col, f_idx + 6));
    }

    let max_display_cards = 10;
    for (i, &(title, subtitle, tag, tag_col, c_id)) in cards.iter().take(max_display_cards).enumerate() {
        let col_idx = i % 2;
        let row_idx = i / 2;

        let cx = main_x + 14 + col_idx * (col_w + 8);
        let cy = card_start_y + row_idx * (card_h + 6);

        if cy + card_h > content_y + content_h - 40 {
            break;
        }

        let is_sel = selected_file + 6 == c_id;
        let is_h = mx >= cx && mx < cx + col_w && my >= cy && my < cy + card_h;

        // Card Container Surface
        if is_sel {
            engine.fill_rounded_rect(cx, cy, col_w, card_h, 6, Color::rgb(48, 48, 48));
            engine.draw_rect(cx, cy, col_w, card_h, Color::rgb(0, 120, 212));
        } else if is_h {
            engine.fill_rounded_rect(cx, cy, col_w, card_h, 6, Color::rgb(36, 36, 36));
            engine.draw_rect(cx, cy, col_w, card_h, Color::rgb(54, 54, 54));
        } else {
            engine.fill_rounded_rect(cx, cy, col_w, card_h, 6, Color::rgb(28, 28, 28));
        }

        // Folder Icon Badge
        engine.draw_string(cx + 10, cy + 14, tag, tag_col, 1);

        // Rename Editor or File Title
        let is_renaming = renaming_file_idx.map_or(false, |ridx| ridx + 6 == c_id);
        if is_renaming {
            let cursor = if (cursor_blink / 20) % 2 == 0 { "|" } else { "" };
            let edit_str = format!("{}{}", rename_buffer, cursor);
            engine.fill_rect(cx + 34, cy + 6, col_w - 42, 16, Color::rgb(15, 23, 42));
            engine.draw_rect(cx + 34, cy + 6, col_w - 42, 16, Color::rgb(0, 120, 212));
            engine.draw_string(cx + 38, cy + 9, &edit_str, Color::WHITE, 1);
        } else {
            engine.draw_string(cx + 36, cy + 8, title, Color::WHITE, 1);
        }

        // Subtitle ("Yerel olarak depola..." or size)
        engine.draw_string(cx + 36, cy + 24, subtitle, Color::rgb(140, 140, 140), 1);
    }

    // Section 2: "v Favoriler  |  Paylasilan"
    let fav_y = card_start_y + 5 * (card_h + 6) + 12;
    if fav_y + 30 < content_y + content_h {
        engine.draw_string(main_x + 16, fav_y, "v  Favoriler", Color::WHITE, 1);
        engine.draw_string(main_x + 110, fav_y, "Paylasilan", Color::rgb(140, 140, 140), 1);
        engine.draw_hline(main_x + 16, fav_y + 16, 75, Color::rgb(96, 205, 255));
    }

    // 5. Bottom Status Bar (Height: 22px)
    let status_y = uy + wh.saturating_sub(22);
    engine.fill_rect(ux, status_y, ww, 22, Color::rgb(26, 26, 26));
    engine.draw_hline(ux, status_y, ww, Color::rgb(44, 44, 44));

    let status_str = format!("{} oge  |", files.len().max(10));
    engine.draw_string(ux + 14, status_y + 6, &status_str, Color::rgb(180, 180, 180), 1);
    engine.draw_string(ux + 100, status_y + 6, "1 oge secildi", Color::rgb(140, 140, 140), 1);
}
