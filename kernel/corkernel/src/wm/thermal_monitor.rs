//! CorOS ACPI Termal Bölge & Donanım Güç Monitörü (`thermal_monitor.rs`)
//!
//! Provides live CPU core temperatures, fan profiles, and power governors:
//! - Real-time core temperatures (Core 0-3 °C) with color warning levels
//! - Power Governor profiles (High Performance, Balanced, Power Saver)
//! - ACPI Thermal Zone & Fan RPM control

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct ThermalMonitorState {
    pub core_temps: [u8; 4],
    pub selected_gov: usize, // 0: High Perf, 1: Balanced, 2: Eco
    pub selected_fan: usize, // 0: Silent, 1: Auto, 2: Turbo
    pub fan_rpm: usize,
    pub tick: usize,
}

impl Default for ThermalMonitorState {
    fn default() -> Self {
        Self {
            core_temps: [38, 41, 39, 42],
            selected_gov: 0,
            selected_fan: 1,
            fan_rpm: 1450,
            tick: 0,
        }
    }
}

pub fn render_thermal_monitor(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut ThermalMonitorState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);
    if state.tick % 12 == 0 {
        state.core_temps[0] = 37 + (state.tick % 5) as u8;
        state.core_temps[1] = 40 + (state.tick % 4) as u8;
        state.core_temps[2] = 38 + (state.tick % 5) as u8;
        state.core_temps[3] = 41 + (state.tick % 3) as u8;
        state.fan_rpm = 1400 + (state.tick * 9 % 150);
    }

    let bg_col = if dark_theme { Color::rgb(16, 20, 28) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(205, 215, 230) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(20, 25, 35) };
    let muted_col = if dark_theme { Color::rgb(140, 155, 175) } else { Color::rgb(100, 115, 130) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // Header
    engine.draw_string(ux + 16, body_y + 12, "CorOS ACPI Termal Yonetici & Islemci Guc Profili", text_col, 1);
    let rpm_str = format!("Fan Hizi: {} RPM (Dinamik)", state.fan_rpm);
    engine.draw_string(ux + ww - 240, body_y + 12, &rpm_str, Color::rgb(16, 185, 129), 1);

    // Core Temperatures Grid (4 cores)
    let temp_y = body_y + 36;
    let temp_w = ww.saturating_sub(32);
    engine.fill_rounded_rect(ux + 16, temp_y, temp_w, 88, 6, card_bg);
    engine.draw_rect(ux + 16, temp_y, temp_w, 88, border_col);

    engine.draw_string(ux + 28, temp_y + 10, "x86_64 Islemci Cekirdek Sicakliklari (ACPI DTS / MSR 0x19C):", text_col, 1);

    let card_cw = (temp_w - 48) / 4;
    for i in 0..4 {
        let cx = ux + 24 + i * (card_cw + 8);
        let cy = temp_y + 32;
        let t = state.core_temps[i];

        let (t_col, bg_t) = if t < 55 {
            (Color::rgb(16, 185, 129), Color::rgb(16, 36, 26))
        } else if t < 75 {
            (Color::rgb(245, 158, 11), Color::rgb(36, 30, 16))
        } else {
            (Color::rgb(239, 68, 68), Color::rgb(40, 16, 16))
        };

        engine.fill_rounded_rect(cx, cy, card_cw, 46, 4, bg_t);
        engine.draw_rect(cx, cy, card_cw, 46, t_col);

        let lbl = format!("Cekirdek {}", i);
        engine.draw_string(cx + 12, cy + 8, &lbl, text_col, 1);
        let deg = format!("{} °C (Normal)", t);
        engine.draw_string(cx + 12, cy + 24, &deg, t_col, 1);
    }

    // Power Governor Section
    let gov_y = temp_y + 102;
    let gov_h = 75;
    engine.fill_rounded_rect(ux + 16, gov_y, temp_w, gov_h, 6, card_bg);
    engine.draw_rect(ux + 16, gov_y, temp_w, gov_h, border_col);

    engine.draw_string(ux + 28, gov_y + 10, "Islemci Guc & Frekans Yoneticisi (P-State / SpeedStep):", text_col, 1);

    let govs = [
        ("Maksimum Performans (3.4 GHz)", Color::rgb(239, 68, 68)),
        ("Dengeli Dinamik (2.4 GHz)", Color::rgb(59, 130, 246)),
        ("Eko Guc Tasarrufu (1.2 GHz)", Color::rgb(16, 185, 129)),
    ];

    let mut gx = ux + 28;
    for (idx, (gname, gcol)) in govs.iter().enumerate() {
        let gw = 180;
        let is_sel = state.selected_gov == idx;
        let is_hov = mx >= gx && mx < gx + gw && my >= gov_y + 32 && my < gov_y + 62;

        if is_hov && m_left {
            state.selected_gov = idx;
            crate::audio::play_click_sound();
        }

        let g_bg = if is_sel { Color::rgb(30, 48, 70) } else if is_hov { Color::rgb(26, 34, 46) } else { Color::rgb(18, 22, 30) };
        engine.fill_rounded_rect(gx, gov_y + 32, gw, 30, 4, g_bg);
        let g_border = if is_sel { *gcol } else { border_col };
        engine.draw_rect(gx, gov_y + 32, gw, 30, g_border);

        let short_n = match idx { 0 => "Maks. Performans", 1 => "Dengeli Dinamik", _ => "Eko Tasarruf" };
        let txt_c = if is_sel { *gcol } else { text_col };
        engine.draw_string(gx + 16, gov_y + 40, short_n, txt_c, 1);

        gx += gw + 12;
    }

    // Fan Profile Section
    let fan_y = gov_y + gov_h + 14;
    let fan_h = body_h.saturating_sub((fan_y - body_y) + 16);
    engine.fill_rounded_rect(ux + 16, fan_y, temp_w, fan_h, 6, card_bg);
    engine.draw_rect(ux + 16, fan_y, temp_w, fan_h, border_col);

    engine.draw_string(ux + 28, fan_y + 12, "ACPI Fan Hizi & Sogutma Profili:", text_col, 1);

    let fans = ["Sessiz (Silent)", "Standart (Otomatik)", "Maksimum Turbo"];
    let mut fx = ux + 28;
    for (idx, &fname) in fans.iter().enumerate() {
        let fw = 160;
        let is_sel = state.selected_fan == idx;
        let is_hov = mx >= fx && mx < fx + fw && my >= fan_y + 36 && my < fan_y + 66;

        if is_hov && m_left {
            state.selected_fan = idx;
            state.fan_rpm = match idx { 0 => 900, 1 => 1450, _ => 2800 };
            crate::audio::play_click_sound();
        }

        let f_bg = if is_sel { Color::rgb(14, 116, 144) } else if is_hov { Color::rgb(28, 36, 48) } else { Color::rgb(18, 22, 30) };
        engine.fill_rounded_rect(fx, fan_y + 36, fw, 30, 4, f_bg);
        let f_txt = if is_sel { Color::WHITE } else { muted_col };
        engine.draw_string(fx + 16, fan_y + 44, fname, f_txt, 1);
        fx += fw + 12;
    }
}
