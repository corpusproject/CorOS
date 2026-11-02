//! CorOS Windows 11 Fluent Media Player Application (`media_player.rs`)
//!
//! Bare-metal native audio player featuring real-time visualizer bars,
//! AC'97 hardware playback controls, volume attenuation, and track queue.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct AudioTrackItem {
    pub title: &'static str,
    pub artist: &'static str,
    pub duration: &'static str,
}

pub struct MediaPlayerState {
    pub is_playing: bool,
    pub track_index: usize,
    pub volume: u8,
    pub progress_pct: u8,
    pub tick: usize,
    pub playlist: Vec<AudioTrackItem>,
}

impl Default for MediaPlayerState {
    fn default() -> Self {
        let playlist = alloc::vec![
            AudioTrackItem { title: "Windows 11 Startup Chime", artist: "CorOS Audio Team", duration: "00:04" },
            AudioTrackItem { title: "Cyberpunk Synthwave 2026", artist: "Corpus Synthesizer", duration: "02:45" },
            AudioTrackItem { title: "8-Bit Retro Odyssey", artist: "PolySynth Engine", duration: "01:52" },
            AudioTrackItem { title: "Lo-Fi Kernel Chillout", artist: "AC'97 Bus Master", duration: "03:10" },
            AudioTrackItem { title: "Ambient Deep Space Pad", artist: "Stereo Reverb 16-Bit", duration: "03:18" },
        ];

        Self {
            is_playing: true,
            track_index: 0,
            volume: 85,
            progress_pct: 25,
            tick: 0,
            playlist,
        }
    }
}

impl MediaPlayerState {
    pub fn toggle_play(&mut self) {
        self.is_playing = !self.is_playing;
        if self.is_playing {
            crate::audio::play_startup_chime();
        } else {
            crate::audio::play_click_sound();
        }
    }

    pub fn next_track(&mut self) {
        if !self.playlist.is_empty() {
            self.track_index = (self.track_index + 1) % self.playlist.len();
            self.progress_pct = 0;
            if self.is_playing {
                crate::audio::play_startup_chime();
            }
        }
    }

    pub fn prev_track(&mut self) {
        if !self.playlist.is_empty() {
            if self.track_index == 0 {
                self.track_index = self.playlist.len() - 1;
            } else {
                self.track_index -= 1;
            }
            self.progress_pct = 0;
            if self.is_playing {
                crate::audio::play_startup_chime();
            }
        }
    }
}

pub fn render_media_player(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut MediaPlayerState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);
    if state.is_playing && state.tick % 8 == 0 {
        state.progress_pct = (state.progress_pct + 1) % 100;
    }

    // Fluent Acrylic background
    let bg_col = if dark_theme { Color::rgb(18, 22, 32) } else { Color::rgb(245, 247, 250) };
    let card_bg = if dark_theme { Color::rgb(25, 32, 46) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 58, 80) } else { Color::rgb(205, 218, 232) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(15, 23, 42) };
    let muted_col = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    let cur_track = if !state.playlist.is_empty() {
        &state.playlist[state.track_index % state.playlist.len()]
    } else {
        &AudioTrackItem { title: "Bilinmeyen Parca", artist: "CorOS", duration: "00:00" }
    };

    // 1. Equalizer Spectrum Visualizer Panel
    let viz_y = body_y + 12;
    let viz_h = 100;
    let viz_w = ww.saturating_sub(32);

    engine.fill_rounded_rect(ux + 16, viz_y, viz_w, viz_h, 8, card_bg);
    engine.draw_rect(ux + 16, viz_y, viz_w, viz_h, border_col);

    // 16 Frequency Equalizer Bars
    let num_bars = 16;
    let bar_spacing = (viz_w - 32) / num_bars;
    for i in 0..num_bars {
        let bx = ux + 32 + i * bar_spacing;
        let phase = (state.tick * 6 + i * 27) % 64;
        let wave = if phase < 32 { phase } else { 64 - phase };
        let dynamic_h = if state.is_playing {
            (wave * 2 + (i * 2)).min(72).max(8)
        } else {
            10
        };
        let by = viz_y + viz_h - 14 - dynamic_h;

        let bar_col = if state.is_playing {
            let r = (30 + i * 14).min(255) as u8;
            let g = (130 + i * 7).min(255) as u8;
            let b = 255u8;
            Color::rgb(r, g, b)
        } else {
            muted_col
        };

        engine.fill_rounded_rect(bx, by, bar_spacing.saturating_sub(4).max(4), dynamic_h, 2, bar_col);
    }

    // 2. Track Title & Artist Metadata
    let info_y = viz_y + viz_h + 14;
    engine.draw_string(ux + 20, info_y, cur_track.title, text_col, 1);
    let sub_text = format!("{} • AC'97 44.1 kHz Stereo DMA", cur_track.artist);
    engine.draw_string(ux + 20, info_y + 16, &sub_text, muted_col, 1);

    // 3. Interactive Progress Bar
    let prog_y = info_y + 38;
    let prog_w = ww.saturating_sub(40);
    engine.fill_rounded_rect(ux + 20, prog_y, prog_w, 6, 2, card_bg);

    // Click on progress bar to seek
    if m_left && mx >= ux + 20 && mx <= ux + 20 + prog_w && my >= prog_y.saturating_sub(4) && my <= prog_y + 10 {
        let pct = ((mx - (ux + 20)) * 100) / prog_w;
        state.progress_pct = pct.clamp(0, 100) as u8;
    }

    let active_bar_w = ((prog_w * (state.progress_pct as usize)) / 100).max(6);
    engine.fill_rounded_rect(ux + 20, prog_y, active_bar_w, 6, 2, Color::rgb(37, 99, 235));

    // Time text
    let cur_sec = (state.progress_pct as usize * 165) / 100;
    let time_str = format!("{:02}:{:02} / {}", cur_sec / 60, cur_sec % 60, cur_track.duration);
    engine.draw_string(ux + ww - 140, info_y + 48, &time_str, muted_col, 1);

    // 4. Transport Controls: Prev, Play/Pause, Next, Volume
    let ctrl_y = prog_y + 24;

    // Prev Button
    let btn_prev_x = ux + 20;
    let is_prev_hover = mx >= btn_prev_x && mx < btn_prev_x + 50 && my >= ctrl_y && my < ctrl_y + 28;
    engine.fill_rounded_rect(btn_prev_x, ctrl_y, 50, 28, 4, if is_prev_hover { Color::rgb(37, 99, 235) } else { card_bg });
    engine.draw_rect(btn_prev_x, ctrl_y, 50, 28, border_col);
    engine.draw_string(btn_prev_x + 14, ctrl_y + 8, "|<<", text_col, 1);
    if m_left && is_prev_hover {
        state.prev_track();
    }

    // Play/Pause Button
    let btn_play_x = btn_prev_x + 58;
    let play_label = if state.is_playing { "[ ⏸ Duraklat ]" } else { "[ ▶ Oynat ]" };
    let is_play_hover = mx >= btn_play_x && mx < btn_play_x + 110 && my >= ctrl_y && my < ctrl_y + 28;
    let play_bg = if is_play_hover { Color::rgb(22, 163, 74) } else { Color::rgb(16, 185, 129) };
    engine.fill_rounded_rect(btn_play_x, ctrl_y, 110, 28, 4, play_bg);
    engine.draw_rect(btn_play_x, ctrl_y, 110, 28, Color::rgb(134, 239, 172));
    engine.draw_string(btn_play_x + 10, ctrl_y + 8, play_label, Color::WHITE, 1);
    if m_left && is_play_hover {
        state.toggle_play();
    }

    // Next Button
    let btn_next_x = btn_play_x + 118;
    let is_next_hover = mx >= btn_next_x && mx < btn_next_x + 50 && my >= ctrl_y && my < ctrl_y + 28;
    engine.fill_rounded_rect(btn_next_x, ctrl_y, 50, 28, 4, if is_next_hover { Color::rgb(37, 99, 235) } else { card_bg });
    engine.draw_rect(btn_next_x, ctrl_y, 50, 28, border_col);
    engine.draw_string(btn_next_x + 14, ctrl_y + 8, ">>|", text_col, 1);
    if m_left && is_next_hover {
        state.next_track();
    }

    // Volume Slider
    let vol_lbl_x = btn_next_x + 70;
    engine.draw_string(vol_lbl_x, ctrl_y + 8, "Ses:", muted_col, 1);
    let vol_x = vol_lbl_x + 36;
    let vol_w = 120;
    engine.fill_rounded_rect(vol_x, ctrl_y + 11, vol_w, 6, 2, card_bg);

    if m_left && mx >= vol_x && mx <= vol_x + vol_w && my >= ctrl_y && my <= ctrl_y + 28 {
        let v = ((mx - vol_x) * 100) / vol_w;
        state.volume = v.clamp(0, 100) as u8;
    }
    let vol_fill = ((vol_w * state.volume as usize) / 100).max(4);
    engine.fill_rounded_rect(vol_x, ctrl_y + 11, vol_fill, 6, 2, Color::rgb(59, 130, 246));
    engine.draw_string(vol_x + vol_w + 12, ctrl_y + 8, &format!("%{}", state.volume), text_col, 1);

    // 5. Playlist Drawer
    let list_y = ctrl_y + 40;
    engine.draw_string(ux + 20, list_y, "[ Calma Listesi (AC'97 Medya Kutusu) ]", Color::rgb(96, 165, 250), 1);

    for (i, t) in state.playlist.iter().enumerate() {
        let row_y = list_y + 20 + i * 26;
        if row_y + 24 > uy + wh {
            break;
        }

        let is_cur = i == state.track_index;
        let is_hover = mx >= ux + 20 && mx < ux + ww - 20 && my >= row_y && my < row_y + 24;

        if m_left && is_hover {
            state.track_index = i;
            state.progress_pct = 0;
            state.is_playing = true;
            crate::audio::play_startup_chime();
        }

        let r_bg = if is_cur {
            if dark_theme { Color::rgb(30, 58, 138) } else { Color::rgb(219, 234, 254) }
        } else if is_hover {
            card_bg
        } else {
            bg_col
        };

        engine.fill_rounded_rect(ux + 20, row_y, ww - 40, 24, 2, r_bg);

        let icon = if is_cur && state.is_playing { "▶" } else { "•" };
        engine.draw_string(ux + 28, row_y + 6, icon, if is_cur { Color::rgb(16, 185, 129) } else { muted_col }, 1);
        engine.draw_string(ux + 46, row_y + 6, t.title, text_col, 1);
        engine.draw_string(ux + 320, row_y + 6, t.artist, muted_col, 1);
        engine.draw_string(ux + ww - 80, row_y + 6, t.duration, muted_col, 1);
    }
}
