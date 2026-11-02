//! CorOS Windows 11 Fluent Taskbar Subsystem
//!
//! Replicates the authentic Windows 11 Taskbar:
//! - Far left: Live Weather Widget ("10°C  Hafif yagmur")
//! - Center:
//!   - Windows 11 4-tile cyan logo [⊞]
//!   - Modern Search Capsule Pill ("[?] Ara")
//!   - Task View & Running App icons (Dosya Gezgini, Edge, Teams, Corpus Terminal, Notepad, Calc, Paint)
//!   - Underline indicators for running / active windows
//! - Right System Tray:
//!   - Overflow chevron ^
//!   - Network, Audio 100%, Battery
//!   - Digital Clock & Date
//!   - Notification Bell Badge
//!   - Desktop Peek strip

use alloc::format;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;
use super::icons;
use super::Window;

pub struct TaskbarRenderer;

impl TaskbarRenderer {
    /// Renders the complete Windows 11 Taskbar at the bottom of the screen
    pub fn render(
        engine: &mut DisplayEngine,
        screen_w: usize,
        screen_h: usize,
        mx: usize,
        my: usize,
        fps: u64,
        palette: &ThemePalette,
        windows: &[Window],
        active_window_idx: usize,
        start_menu_open: bool,
        notification_count: usize,
    ) {
        let bar_h = 48;
        let bar_y = screen_h.saturating_sub(bar_h);

        // 1. Frosted Acrylic Taskbar Body
        engine.fill_rect(0, bar_y, screen_w, bar_h, Color::rgb(26, 26, 26));
        engine.draw_hline(0, bar_y, screen_w, Color::rgb(42, 42, 42));

        // 2. Far Left Weather Widget ("10°C  Hafif yagmur", matching Image 1)
        let weather_w = 130;
        let is_weather_h = mx >= 12 && mx < 12 + weather_w && my >= bar_y;
        if is_weather_h {
            engine.fill_rounded_rect(8, bar_y + 4, weather_w, 40, 6, Color::rgb(40, 40, 40));
        }
        engine.draw_string(14, bar_y + 12, "10°C", Color::rgb(240, 240, 240), 1);
        engine.draw_string(14, bar_y + 26, "Hafif yagmur", Color::rgb(160, 160, 160), 1);

        // 3. Centered Windows 11 Application Cluster
        // Windows Start Logo + Search Capsule + App Icons
        let search_capsule_w = 72;
        let slot_w = 42;
        let dock_items: [(&str, &[u8], Option<usize>); 8] = [
            ("Dosya Gezgini", icons::ICON_FINDER_BMP, Some(0)),
            ("Microsoft Edge", icons::ICON_FINDER_BMP, None),
            ("Sohbet (Teams)", icons::ICON_MONITOR_BMP, None),
            ("Corpus Terminal", icons::ICON_TERMINAL_BMP, Some(1)),
            ("Not Defteri", icons::ICON_NOTEPAD_BMP, Some(5)),
            ("Hesap Makinesi", icons::ICON_CALC_BMP, Some(6)),
            ("CorOS Paint", icons::ICON_PAINT_BMP, Some(7)),
            ("Geri Donusum", icons::ICON_TRASH_BMP, None),
        ];

        let total_dock_w = slot_w + search_capsule_w + dock_items.len() * slot_w + 16;
        let dock_start_x = (screen_w.saturating_sub(total_dock_w)) / 2;

        let mut hovered_tip: Option<(&str, usize)> = None;

        // 3.1 Windows 11 Start Button (4-tile cyan blue square grid ⊞)
        let start_x = dock_start_x;
        let is_start_h = mx >= start_x && mx < start_x + slot_w && my >= bar_y;
        if start_menu_open {
            engine.fill_rounded_rect(start_x + 2, bar_y + 4, slot_w - 4, bar_h - 8, 5, Color::rgb(50, 50, 50));
            engine.draw_rect(start_x + 2, bar_y + 4, slot_w - 4, bar_h - 8, Color::rgb(0, 120, 212));
        } else if is_start_h {
            engine.fill_rounded_rect(start_x + 2, bar_y + 4, slot_w - 4, bar_h - 8, 5, Color::rgb(42, 42, 42));
            hovered_tip = Some(("Baslat", start_x + slot_w / 2));
        }

        // Draw authentic 4-square Windows 11 cyan logo
        let win_logo_x = start_x + 13;
        let win_logo_y = bar_y + 16;
        let sq_size = 7;
        let sq_col = Color::rgb(0, 164, 239); // Authentic Windows 11 Cyan Blue
        engine.fill_rect(win_logo_x, win_logo_y, sq_size, sq_size, sq_col);
        engine.fill_rect(win_logo_x + sq_size + 2, win_logo_y, sq_size, sq_size, sq_col);
        engine.fill_rect(win_logo_x, win_logo_y + sq_size + 2, sq_size, sq_size, sq_col);
        engine.fill_rect(win_logo_x + sq_size + 2, win_logo_y + sq_size + 2, sq_size, sq_size, sq_col);

        // 3.2 Windows 11 Search Capsule Pill ("[?] Ara", matching Image 1)
        let search_x = start_x + slot_w + 4;
        let is_search_h = mx >= search_x && mx < search_x + search_capsule_w && my >= bar_y + 8 && my < bar_y + bar_h - 8;
        let search_bg = if is_search_h { Color::rgb(46, 46, 46) } else { Color::rgb(36, 36, 36) };
        engine.fill_rounded_rect(search_x, bar_y + 8, search_capsule_w, 32, 16, search_bg);
        engine.draw_rect(search_x, bar_y + 8, search_capsule_w, 32, Color::rgb(56, 56, 56));
        engine.draw_string(search_x + 10, bar_y + 18, "?", Color::rgb(160, 160, 160), 1);
        engine.draw_string(search_x + 24, bar_y + 18, "Ara", Color::rgb(220, 220, 220), 1);

        // 3.3 Application Dock Icons
        let mut cur_app_x = search_x + search_capsule_w + 8;
        for &(title, icon_bmp, win_opt) in &dock_items {
            let sx = cur_app_x;
            let is_h = mx >= sx && mx < sx + slot_w && my >= bar_y;

            // Check if window is open or active
            let is_win_open = win_opt.map_or(false, |wid| {
                windows.iter().any(|w| w.id == wid && w.is_open)
            });
            let is_win_focused = win_opt.map_or(false, |wid| {
                active_window_idx < windows.len() && windows[active_window_idx].id == wid && windows[active_window_idx].is_open && !windows[active_window_idx].is_minimized
            });

            // Button Hover / Active Surface
            if is_win_focused {
                engine.fill_rounded_rect(sx + 2, bar_y + 4, slot_w - 4, bar_h - 8, 5, Color::rgb(48, 48, 48));
                engine.draw_rect(sx + 2, bar_y + 4, slot_w - 4, bar_h - 8, Color::rgb(64, 64, 64));
            } else if is_h {
                engine.fill_rounded_rect(sx + 2, bar_y + 4, slot_w - 4, bar_h - 8, 5, Color::rgb(40, 40, 40));
                hovered_tip = Some((title, sx + slot_w / 2));
            }

            // Draw Icon
            let icon_x = sx + (slot_w - 32) / 2;
            let icon_y = bar_y + (bar_h - 32) / 2;
            engine.draw_bmp(icon_x, icon_y, icon_bmp);

            // Active / Running Indicator line under icon (Windows 11 style)
            if is_win_focused {
                // Focused: Vibrant cyan elongated bar
                engine.fill_rounded_rect(sx + 13, bar_y + bar_h - 3, 16, 2, 1, Color::rgb(96, 205, 255));
            } else if is_win_open {
                // Open but background: Dim small dot/pill
                engine.fill_rounded_rect(sx + 18, bar_y + bar_h - 3, 6, 2, 1, Color::rgb(140, 140, 140));
            }

            cur_app_x += slot_w;
        }

        // 4. System Tray on Right Side (matching Image 1)
        let tray_x = screen_w.saturating_sub(230);

        // Overflow chevron ^
        engine.draw_string(tray_x - 16, bar_y + 18, "^", Color::rgb(180, 180, 180), 1);

        // Network / Sound / Battery Capsule Pill
        let pill_x = tray_x + 6;
        let is_pill_h = mx >= pill_x && mx < pill_x + 88 && my >= bar_y;
        if is_pill_h {
            engine.fill_rounded_rect(pill_x - 4, bar_y + 6, 92, 36, 4, Color::rgb(40, 40, 40));
        }

        // Network Icon [N]
        engine.draw_string(pill_x + 4, bar_y + 18, "[N]", Color::rgb(96, 205, 255), 1);
        // Audio Icon 4))
        engine.draw_string(pill_x + 30, bar_y + 18, "4))", Color::WHITE, 1);
        // Battery Icon
        engine.draw_rect(pill_x + 58, bar_y + 18, 14, 8, Color::WHITE);
        engine.fill_rect(pill_x + 72, bar_y + 20, 2, 4, Color::WHITE);
        engine.fill_rect(pill_x + 60, bar_y + 20, 10, 4, Color::rgb(16, 185, 129));

        // Digital Clock & Date: 20:52 / 16.10.2026
        let clock_x = pill_x + 92;
        let dt = crate::time::read_rtc();
        let time_str = format!("{:02}:{:02}", dt.hour, dt.minute);
        let date_str = format!("{:02}.{:02}.{:04}", dt.day, dt.month, dt.year);

        let is_clock_h = mx >= clock_x && mx < clock_x + 64 && my >= bar_y;
        if is_clock_h {
            engine.fill_rounded_rect(clock_x - 4, bar_y + 6, 68, 36, 4, Color::rgb(40, 40, 40));
        }
        engine.draw_string(clock_x, bar_y + 12, &time_str, Color::WHITE, 1);
        engine.draw_string(clock_x, bar_y + 26, &date_str, Color::rgb(160, 160, 160), 1);

        // Notification Center Bell Icon & Live Badge [B <count>]
        let notif_bell_x = clock_x + 66;
        let is_bell_h = mx >= notif_bell_x && mx < screen_w.saturating_sub(10) && my >= bar_y;
        if is_bell_h {
            engine.fill_rounded_rect(notif_bell_x - 4, bar_y + 6, 32, 36, 4, Color::rgb(40, 40, 40));
        }

        let notif_col = if notification_count > 0 { Color::rgb(96, 205, 255) } else { Color::rgb(140, 140, 140) };
        engine.draw_string(notif_bell_x, bar_y + 18, "[B", notif_col, 1);

        // Desktop Peek line on far right
        let peek_x = screen_w.saturating_sub(4);
        engine.draw_vline(peek_x, bar_y + 8, 32, Color::rgb(60, 60, 60));

        // 5. Hover Tooltip
        if let Some((tip, cx)) = hovered_tip {
            let tip_w = engine.string_width(tip) + 18;
            let tx = cx.saturating_sub(tip_w / 2);
            let ty = bar_y.saturating_sub(26);
            engine.fill_rounded_rect(tx, ty, tip_w, 20, 4, Color::rgb(32, 32, 32));
            engine.draw_rect(tx, ty, tip_w, 20, Color::rgb(56, 56, 56));
            engine.draw_string(tx + 9, ty + 5, tip, Color::WHITE, 1);
        }
    }
}
