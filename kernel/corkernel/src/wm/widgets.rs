//! CorOS Desktop UI Widgets: Desktop HUD (Conky/Telemetry), Context Menu, Quick Settings & Action Center, Calendar

use alloc::format;
use crate::display::{Color, DisplayEngine};

pub fn render_context_menu(
    engine: &mut DisplayEngine,
    cm_x: usize,
    cm_y: usize,
    mx: usize,
    my: usize,
    dark_theme: bool,
) {
    let cm_w = 190;
    let cm_h = 150;

    let cm_bg = if dark_theme { Color::rgb(28, 34, 46) } else { Color::rgb(255, 255, 255) };
    let cm_border = if dark_theme { Color::rgb(60, 75, 105) } else { Color::rgb(203, 213, 225) };
    let cm_shadow = if dark_theme { Color::rgb(10, 14, 22) } else { Color::rgb(200, 210, 225) };
    let cm_txt = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };
    let cm_hover_bg = if dark_theme { Color::rgb(45, 60, 90) } else { Color::rgb(224, 242, 254) };
    let cm_hover_border = if dark_theme { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };

    engine.fill_rounded_rect(cm_x + 3, cm_y + 3, cm_w, cm_h, 6, cm_shadow);
    engine.fill_rounded_rect(cm_x, cm_y, cm_w, cm_h, 6, cm_bg);
    engine.draw_rect(cm_x, cm_y, cm_w, cm_h, cm_border);

    let items = [
        ("Yeni Not Defteri", ">"),
        ("Gorunumu Degistir", "H"),
        ("Masaustunu Yenile", "R"),
        ("Kisisellestir", "T"),
        ("Hesap Makinesi", "="),
    ];

    for (i, &(label, icon)) in items.iter().enumerate() {
        let iy = cm_y + 6 + i * 28;
        let is_h = mx >= cm_x + 4 && mx < cm_x + cm_w - 4 && my >= iy && my < iy + 26;

        if is_h {
            engine.fill_rounded_rect(cm_x + 4, iy, cm_w - 8, 26, 4, cm_hover_bg);
            engine.draw_rect(cm_x + 4, iy, cm_w - 8, 26, cm_hover_border);
        }

        engine.draw_string(cm_x + 14, iy + 7, icon, if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) }, 1);
        engine.draw_string(cm_x + 32, iy + 7, label, cm_txt, 1);

        if i < items.len() - 1 {
            let div_col = if dark_theme { Color::rgb(38, 46, 62) } else { Color::rgb(241, 245, 249) };
            engine.draw_hline(cm_x + 8, iy + 27, cm_w - 16, div_col);
        }
    }
}

pub fn render_quick_settings(
    engine: &mut DisplayEngine,
    screen_w: usize,
    screen_h: usize,
    mx: usize,
    my: usize,
    dark_theme: bool,
    wifi_enabled: bool,
    volume_level: u8,
    brightness_level: u8,
) {
    let qs_w = 280;
    let qs_h = 200;
    let qs_x = screen_w.saturating_sub(qs_w + 16);
    let qs_y = screen_h.saturating_sub(48 + qs_h + 8);

    let qs_bg = if dark_theme { Color::rgb(26, 32, 44) } else { Color::rgb(248, 250, 252) };
    let qs_border = if dark_theme { Color::rgb(55, 68, 92) } else { Color::rgb(203, 213, 225) };
    let qs_title_col = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };

    engine.fill_rounded_rect(qs_x, qs_y, qs_w, qs_h, 8, qs_bg);
    engine.draw_rect(qs_x, qs_y, qs_w, qs_h, qs_border);

    engine.draw_string(qs_x + 16, qs_y + 10, "Hizli Ayarlar & Eylem Merkezi", qs_title_col, 1);
    let div_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
    engine.draw_hline(qs_x + 12, qs_y + 24, qs_w - 24, div_col);

    let toggles = [
        ("Wi-Fi", wifi_enabled),
        ("BT", true),
        ("Koyu", dark_theme),
        ("Gece", false),
    ];

    let t_y = qs_y + 30;
    for (i, &(title, enabled)) in toggles.iter().enumerate() {
        let tx = qs_x + 14 + i * 64;
        let is_h = mx >= tx && mx < tx + 56 && my >= t_y && my < t_y + 40;

        let bg_col = if enabled {
            if dark_theme { Color::rgb(14, 116, 144) } else { Color::rgb(0, 120, 212) }
        } else if is_h {
            if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) }
        } else {
            if dark_theme { Color::rgb(35, 42, 56) } else { Color::rgb(255, 255, 255) }
        };

        let border_col = if enabled {
            if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) }
        } else {
            if dark_theme { Color::rgb(55, 68, 92) } else { Color::rgb(203, 213, 225) }
        };

        engine.fill_rounded_rect(tx, t_y, 56, 40, 6, bg_col);
        engine.draw_rect(tx, t_y, 56, 40, border_col);

        let tw = engine.string_width(title);
        let lx = tx + (56usize.saturating_sub(tw)) / 2;
        let btn_txt = if enabled { Color::WHITE } else { qs_title_col };
        engine.draw_string(lx, t_y + 10, title, btn_txt, 1);
        let state_str = if enabled { "ACIK" } else { "KPL" };
        let sw = engine.string_width(state_str);
        let sx = tx + (56usize.saturating_sub(sw)) / 2;
        let s_col = if enabled { if dark_theme { Color::CYAN } else { Color::WHITE } } else { Color::rgb(148, 163, 184) };
        engine.draw_string(sx, t_y + 24, state_str, s_col, 1);
    }

    let s1_y = qs_y + 84;
    engine.draw_string(qs_x + 16, s1_y + 2, "Ses:", qs_title_col, 1);
    let sl_x = qs_x + 48;
    let sl_w = 170;
    let track_bg = if dark_theme { Color::rgb(35, 45, 65) } else { Color::rgb(226, 232, 240) };
    engine.fill_rounded_rect(sl_x, s1_y + 4, sl_w, 8, 3, track_bg);
    let fill_w = (sl_w * (volume_level as usize)) / 100;
    let accent_fill = if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) };
    engine.fill_rounded_rect(sl_x, s1_y + 4, fill_w, 8, 3, accent_fill);
    engine.fill_circle((sl_x + fill_w) as isize, (s1_y + 8) as isize, 6, if dark_theme { Color::WHITE } else { Color::rgb(0, 120, 212) });
    let vol_str = format!("{}%", volume_level);
    engine.draw_string(sl_x + sl_w + 10, s1_y + 2, &vol_str, accent_fill, 1);

    let s2_y = qs_y + 120;
    engine.draw_string(qs_x + 16, s2_y + 2, "Isik:", qs_title_col, 1);
    engine.fill_rounded_rect(sl_x, s2_y + 4, sl_w, 8, 3, track_bg);
    let bri_fill_w = (sl_w * (brightness_level as usize)) / 100;
    engine.fill_rounded_rect(sl_x, s2_y + 4, bri_fill_w, 8, 3, Color::rgb(250, 204, 21));
    engine.fill_circle((sl_x + bri_fill_w) as isize, (s2_y + 8) as isize, 6, Color::WHITE);
    let bri_str = format!("{}%", brightness_level);
    engine.draw_string(sl_x + sl_w + 10, s2_y + 2, &bri_str, Color::YELLOW, 1);

    let foot_y = qs_y + 160;
    let foot_bg = if dark_theme { Color::rgb(20, 25, 35) } else { Color::rgb(241, 245, 249) };
    engine.fill_rect(qs_x, foot_y, qs_w, 40, foot_bg);
    engine.draw_hline(qs_x, foot_y, qs_w, div_col);
    engine.draw_string(qs_x + 16, foot_y + 8, "Pil: %100 (AC Bagli - Sarj Tam)", Color::EMERALD, 1);
    engine.draw_string(qs_x + 16, foot_y + 22, "Intel PRO/1000 Gigabit Bagli", Color::rgb(148, 163, 184), 1);
}

pub fn render_calendar(
    engine: &mut DisplayEngine,
    screen_w: usize,
    screen_h: usize,
    dark_theme: bool,
) {
    let cal_w = 260;
    let cal_h = 220;
    let cal_x = screen_w.saturating_sub(cal_w + 16);
    let cal_y = screen_h.saturating_sub(48 + cal_h + 8);

    let cal_bg = if dark_theme { Color::rgb(26, 32, 44) } else { Color::rgb(248, 250, 252) };
    let cal_border = if dark_theme { Color::rgb(55, 68, 92) } else { Color::rgb(203, 213, 225) };

    engine.fill_rounded_rect(cal_x, cal_y, cal_w, cal_h, 8, cal_bg);
    engine.draw_rect(cal_x, cal_y, cal_w, cal_h, cal_border);

    let dt = crate::time::read_rtc();
    let header_str = format!("{:02}.{:02}.{:04} - Takvim", dt.day, dt.month, dt.year);
    let head_col = if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) };
    engine.draw_string(cal_x + 16, cal_y + 10, &header_str, head_col, 1);
    let div_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
    engine.draw_hline(cal_x + 12, cal_y + 26, cal_w - 24, div_col);

    let days = ["Pz", "Pt", "Sa", "Ca", "Pe", "Cu", "Ct"];
    let cell_w = (cal_w - 24) / 7;
    for (i, day) in days.iter().enumerate() {
        let dx = cal_x + 12 + i * cell_w;
        engine.draw_string(dx + 6, cal_y + 34, day, Color::rgb(148, 163, 184), 1);
    }

    let cur_day = dt.day as usize;
    for d in 1..=31 {
        let day_idx = (d + 2) % 7;
        let week_idx = (d + 2) / 7;
        let cx = cal_x + 12 + day_idx * cell_w;
        let cy = cal_y + 54 + week_idx * 26;

        if d == cur_day {
            engine.fill_rounded_rect(cx + 2, cy - 2, cell_w - 4, 22, 4, Color::ACCENT_BLUE);
            engine.draw_rect(cx + 2, cy - 2, cell_w - 4, 22, Color::CYAN);
        }

        let d_str = format!("{:2}", d);
        let fg = if d == cur_day { Color::WHITE } else { Color::rgb(203, 213, 225) };
        engine.draw_string(cx + 6, cy + 2, &d_str, fg, 1);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapPreview {
    None,
    LeftHalf,
    RightHalf,
    Maximize,
}

/// Renders authentic Windows 11 Aero Snap glass preview outline and badge
pub fn render_aero_snap_preview(
    engine: &mut DisplayEngine,
    screen_w: usize,
    screen_h: usize,
    snap: SnapPreview,
    dark_theme: bool,
) {
    let (sx, sy, sw, sh, badge_text) = match snap {
        SnapPreview::LeftHalf => (6, 6, (screen_w / 2) - 12, screen_h.saturating_sub(58), "AERO SNAP: 50/50 SOLA YERLESTIR"),
        SnapPreview::RightHalf => ((screen_w / 2) + 6, 6, (screen_w / 2) - 12, screen_h.saturating_sub(58), "AERO SNAP: 50/50 SAGA YERLESTIR"),
        SnapPreview::Maximize => (6, 6, screen_w - 12, screen_h.saturating_sub(58), "AERO SNAP: TAM EKRAN KAPLA"),
        SnapPreview::None => return,
    };

    let preview_bg = if dark_theme { Color::rgb(14, 45, 80) } else { Color::rgb(219, 234, 254) };
    let preview_border = if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) };

    // Glass preview area
    engine.fill_rounded_rect(sx, sy, sw, sh, 10, preview_bg);
    engine.draw_rect(sx, sy, sw, sh, preview_border);
    engine.draw_rect(sx + 1, sy + 1, sw - 2, sh - 2, preview_border);

    // Centered pill badge
    let badge_w = badge_text.len() * 6 + 28;
    let badge_h = 28;
    let badge_x = sx + (sw.saturating_sub(badge_w)) / 2;
    let badge_y = sy + (sh.saturating_sub(badge_h)) / 2;

    let badge_bg = if dark_theme { Color::rgb(15, 23, 42) } else { Color::rgb(255, 255, 255) };
    engine.fill_rounded_rect(badge_x, badge_y, badge_w, badge_h, 6, badge_bg);
    engine.draw_rect(badge_x, badge_y, badge_w, badge_h, preview_border);
    engine.draw_string(badge_x + 14, badge_y + 8, badge_text, preview_border, 1);
}

/// Renders authentic Windows 11 Alt + Tab Task Switcher Acrylic Dialog
pub fn render_alt_tab_switcher(
    engine: &mut DisplayEngine,
    screen_w: usize,
    screen_h: usize,
    open_windows: &[(&str, usize, &'static str)], // (title, id, icon_tag)
    selected_idx: usize,
    dark_theme: bool,
) {
    if open_windows.is_empty() {
        return;
    }

    let card_w = 96;
    let card_h = 100;
    let gap = 12;
    let count = open_windows.len();
    let total_cards_w = count * card_w + (count.saturating_sub(1)) * gap;
    let modal_w = (total_cards_w + 48).max(360);
    let modal_h = 180;
    let modal_x = (screen_w.saturating_sub(modal_w)) / 2;
    let modal_y = (screen_h.saturating_sub(modal_h)) / 2 - 30;

    let modal_bg = if dark_theme { Color::rgb(20, 26, 38) } else { Color::rgb(241, 245, 249) };
    let modal_border = if dark_theme { Color::rgb(50, 65, 95) } else { Color::rgb(203, 213, 225) };
    let modal_shadow = Color::rgb(5, 8, 15);

    // Acrylic shadow & body
    engine.fill_rounded_rect(modal_x + 6, modal_y + 6, modal_w, modal_h, 12, modal_shadow);
    engine.fill_rounded_rect(modal_x, modal_y, modal_w, modal_h, 10, modal_bg);
    engine.draw_rect(modal_x, modal_y, modal_w, modal_h, modal_border);

    // Title Header
    let title_fg = if dark_theme { Color::CYAN } else { Color::rgb(0, 120, 212) };
    engine.draw_string(modal_x + 20, modal_y + 14, "GOREV DEGISTIRICI (ALT + TAB) - ACIK PENCERELER", title_fg, 1);
    let sub_fg = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };
    engine.draw_string(modal_x + 20, modal_y + 28, "Gecis yapmak icin Tab / F3 basin, birakinca pencereye odaklanir.", sub_fg, 1);

    // Cards list
    let cards_start_x = modal_x + (modal_w.saturating_sub(total_cards_w)) / 2;
    let cards_y = modal_y + 52;

    for (i, &(title, _id, tag)) in open_windows.iter().enumerate() {
        let cx = cards_start_x + i * (card_w + gap);
        let is_sel = i == selected_idx;

        let card_bg = if is_sel {
            if dark_theme { Color::rgb(30, 58, 100) } else { Color::rgb(219, 234, 254) }
        } else {
            if dark_theme { Color::rgb(28, 36, 52) } else { Color::rgb(255, 255, 255) }
        };
        let card_border = if is_sel { Color::CYAN } else { modal_border };

        engine.fill_rounded_rect(cx, cards_y, card_w, card_h, 8, card_bg);
        engine.draw_rect(cx, cards_y, card_w, card_h, card_border);
        if is_sel {
            engine.draw_rect(cx + 1, cards_y + 1, card_w - 2, card_h - 2, Color::CYAN);
        }

        // Icon Pill
        let icon_col = if is_sel { Color::CYAN } else { Color::EMERALD };
        let tag_x = cx + (card_w.saturating_sub(tag.len() * 6)) / 2;
        engine.draw_string(tag_x, cards_y + 18, tag, icon_col, 1);

        // Window Title (truncated)
        let max_chars = 11;
        let display_title = if title.len() > max_chars { &title[..max_chars] } else { title };
        let title_x = cx + (card_w.saturating_sub(display_title.len() * 6)) / 2;
        let name_fg = if is_sel { Color::WHITE } else { sub_fg };
        engine.draw_string(title_x, cards_y + 48, display_title, name_fg, 1);

        // Status badge
        if is_sel {
            let sel_badge_x = cx + (card_w.saturating_sub(44)) / 2;
            engine.fill_rounded_rect(sel_badge_x, cards_y + 72, 44, 16, 3, Color::CYAN);
            engine.draw_string(sel_badge_x + 6, cards_y + 76, "AKTIF", Color::BLACK, 1);
        }
    }
}
