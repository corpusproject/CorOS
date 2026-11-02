//! CorOS Görev Zamanlayıcı & Cron Daemon (`task_scheduler.rs`)
//!
//! Provides automated background task scheduling and cron management:
//! - Visual cron tasks table with syntax (Hourly, Daily, Periodic)
//! - Task execution history and exit status
//! - Interactive instant run and enable/disable toggles

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct CronJob {
    pub id: usize,
    pub name: &'static str,
    pub schedule: &'static str,
    pub next_run: &'static str,
    pub last_status: &'static str,
    pub is_enabled: bool,
}

#[derive(Clone, Debug)]
pub struct TaskSchedulerState {
    pub selected_job: usize,
    pub jobs: Vec<CronJob>,
    pub status_msg: String,
    pub tick: usize,
}

impl Default for TaskSchedulerState {
    fn default() -> Self {
        let jobs = alloc::vec![
            CronJob { id: 1, name: "TmpFS RAMDisk Otomatik Temizligi", schedule: "0 * * * * (Her saat)", next_run: "19:00:00", last_status: "Basarili (0)", is_enabled: true },
            CronJob { id: 2, name: "FAT32 ESP Gunluk Snapshot Yedegi", schedule: "0 0 * * * (Her gece)", next_run: "00:00:00", last_status: "Basarili (0)", is_enabled: true },
            CronJob { id: 3, name: "Intel e1000 Ag Gecidi Ping Heartbeat", schedule: "*/5 * * * * (5 dk)", next_run: "18:50:00", last_status: "Basarili (0)", is_enabled: true },
            CronJob { id: 4, name: "ZRAM / VFS Cekirdek Sayfa Temizligi", schedule: "*/30 * * * * (30 dk)", next_run: "19:15:00", last_status: "Basarili (0)", is_enabled: true },
        ];

        Self {
            selected_job: 0,
            jobs,
            status_msg: String::from("CorCron Servisi calisiyor: 4 gorev zamanlanmis durumda."),
            tick: 0,
        }
    }
}

pub fn render_task_scheduler(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut TaskSchedulerState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);

    let bg_col = if dark_theme { Color::rgb(16, 20, 28) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(205, 215, 230) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(20, 25, 35) };
    let muted_col = if dark_theme { Color::rgb(140, 155, 175) } else { Color::rgb(100, 115, 130) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // Header
    engine.draw_string(ux + 16, body_y + 12, "CorCron - Gorev Zamanlayici & Arka Plan Yoneticisi", text_col, 1);
    engine.draw_string(ux + ww - 200, body_y + 12, "[ DAEMON AKTIF ]", Color::rgb(16, 185, 129), 1);

    // Status Banner
    let ban_y = body_y + 36;
    let ban_w = ww.saturating_sub(32);
    engine.fill_rounded_rect(ux + 16, ban_y, ban_w, 36, 6, card_bg);
    engine.draw_rect(ux + 16, ban_y, ban_w, 36, border_col);
    engine.draw_string(ux + 28, ban_y + 10, &state.status_msg, Color::rgb(96, 205, 255), 1);

    // Jobs Table
    let tbl_y = ban_y + 46;
    let tbl_h = 165;
    engine.fill_rounded_rect(ux + 16, tbl_y, ban_w, tbl_h, 6, card_bg);
    engine.draw_rect(ux + 16, tbl_y, ban_w, tbl_h, border_col);

    // Header row
    engine.fill_rect(ux + 18, tbl_y + 2, ban_w - 4, 22, Color::rgb(30, 38, 52));
    engine.draw_string(ux + 28, tbl_y + 6, "Gorev Adi", Color::rgb(148, 163, 184), 1);
    engine.draw_string(ux + 250, tbl_y + 6, "Zamanlama", Color::rgb(148, 163, 184), 1);
    engine.draw_string(ux + 390, tbl_y + 6, "Son Durum", Color::rgb(148, 163, 184), 1);
    engine.draw_string(ux + 480, tbl_y + 6, "Durum", Color::rgb(148, 163, 184), 1);

    for (idx, j) in state.jobs.iter().enumerate() {
        let jy = tbl_y + 30 + idx * 32;
        if jy + 26 > tbl_y + tbl_h { break; }

        let is_sel = state.selected_job == idx;
        let is_hov = mx >= ux + 20 && mx < ux + ban_w + 10 && my >= jy && my < jy + 28;

        if is_hov && m_left {
            state.selected_job = idx;
            crate::audio::play_click_sound();
        }

        let row_bg = if is_sel { Color::rgb(35, 55, 80) } else if is_hov { Color::rgb(28, 36, 48) } else { card_bg };
        engine.fill_rounded_rect(ux + 20, jy, ban_w - 8, 26, 3, row_bg);

        engine.draw_string(ux + 28, jy + 6, j.name, text_col, 1);
        engine.draw_string(ux + 250, jy + 6, j.schedule, muted_col, 1);
        engine.draw_string(ux + 390, jy + 6, j.last_status, Color::rgb(16, 185, 129), 1);

        let (en_str, en_col) = if j.is_enabled { ("AKTIF", Color::rgb(16, 185, 129)) } else { ("KAPALI", Color::rgb(248, 113, 113)) };
        engine.draw_string(ux + 480, jy + 6, en_str, en_col, 1);
    }

    // Action Buttons
    let btn_y = tbl_y + tbl_h + 12;
    let b1_w = 190;
    let is_b1_hov = mx >= ux + 16 && mx < ux + 16 + b1_w && my >= btn_y && my < btn_y + 28;
    if is_b1_hov && m_left {
        let jname = state.jobs[state.selected_job].name;
        state.status_msg = format!("'{}' gorevi simdi calistirildi [Kod 0 OK].", jname);
        crate::audio::play_click_sound();
    }
    let b1_bg = if is_b1_hov { Color::rgb(37, 99, 235) } else { Color::rgb(14, 116, 144) };
    engine.fill_rounded_rect(ux + 16, btn_y, b1_w, 28, 4, b1_bg);
    engine.draw_string(ux + 24, btn_y + 8, "[ Gorevi Simdi Calistir ]", Color::WHITE, 1);

    let b2_x = ux + 16 + b1_w + 14;
    let b2_w = 175;
    let is_b2_hov = mx >= b2_x && mx < b2_x + b2_w && my >= btn_y && my < btn_y + 28;
    if is_b2_hov && m_left {
        state.jobs[state.selected_job].is_enabled = !state.jobs[state.selected_job].is_enabled;
        crate::audio::play_click_sound();
    }
    let b2_bg = if is_b2_hov { Color::rgb(59, 130, 246) } else { Color::rgb(30, 41, 59) };
    engine.fill_rounded_rect(b2_x, btn_y, b2_w, 28, 4, b2_bg);
    let b2_lbl = if state.jobs[state.selected_job].is_enabled { "[ Devre Disi Birak ]" } else { "[ Etkinlestir ]" };
    engine.draw_string(b2_x + 20, btn_y + 8, b2_lbl, Color::WHITE, 1);

    // Cron syntax tip
    let tip_y = btn_y + 40;
    let tip_h = body_h.saturating_sub((tip_y - body_y) + 16);
    engine.fill_rounded_rect(ux + 16, tip_y, ban_w, tip_h, 6, card_bg);
    engine.draw_rect(ux + 16, tip_y, ban_w, tip_h, border_col);

    engine.draw_string(ux + 28, tip_y + 10, "Cron Sozdizimi Yardim Kilavuzu:", text_col, 1);
    engine.draw_string(ux + 32, tip_y + 28, "* * * * *  ->  [Dakika] [Saat] [Ayin Gunu] [Ay] [Haftanin Gunu]", Color::rgb(96, 205, 255), 1);
    engine.draw_string(ux + 32, tip_y + 46, "Ornekler: '*/15 * * * *' (15 dk bir), '0 12 * * *' (Her oglen 12:00)", muted_col, 1);
}
