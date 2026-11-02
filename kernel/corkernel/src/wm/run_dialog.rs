//! CorOS Windows "Çalıştır" (Run Dialog - Win + R) Subsystem
//!
//! Replicates the authentic Windows Run Dialog:
//! - Position: Bottom-left above taskbar
//! - Classic prompt: "Windows, istediğiniz bir programı, klasörü veya belgeyi sizin için açar."
//! - Text input box with "Aç:" label
//! - [Tamam], [İptal], [Gözat...] buttons
//! - Executes apps, system utilities, and Ring 3 ELF binaries

use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;

pub struct RunDialog {
    pub is_open: bool,
    pub x: isize,
    pub y: isize,
    pub w: usize,
    pub h: usize,
    pub input: String,
    pub history: Vec<String>,
    pub cursor_blink: u64,
}

impl RunDialog {
    pub fn new() -> Self {
        Self {
            is_open: false,
            x: 24,
            y: 480,
            w: 380,
            h: 170,
            input: String::new(),
            history: Vec::new(),
            cursor_blink: 0,
        }
    }

    pub fn open(&mut self) {
        self.is_open = true;
        self.input.clear();
    }

    pub fn close(&mut self) {
        self.is_open = false;
    }

    pub fn toggle(&mut self) {
        if self.is_open {
            self.close();
        } else {
            self.open();
        }
    }

    /// Handles typing inside the Run Dialog. Returns `Some(command)` if Enter is pressed.
    pub fn handle_key(&mut self, ch: char) -> Option<String> {
        if !self.is_open {
            return None;
        }

        match ch {
            '\n' => {
                let cmd = String::from(self.input.trim());
                if !cmd.is_empty() {
                    self.history.push(cmd.clone());
                    self.close();
                    Some(cmd)
                } else {
                    None
                }
            }
            '\x1B' => {
                // Escape closes Run dialog
                self.close();
                None
            }
            '\x08' => {
                // Backspace
                self.input.pop();
                None
            }
            c if c >= ' ' && c <= '~' => {
                if self.input.len() < 40 {
                    self.input.push(c);
                }
                None
            }
            _ => None,
        }
    }

    /// Handles mouse clicks inside the Run dialog. Returns `Some(command)` if [Tamam] is clicked.
    pub fn handle_click(&mut self, mx: usize, my: usize) -> Option<String> {
        if !self.is_open {
            return None;
        }

        let wx = self.x as usize;
        let wy = self.y as usize;

        // Titlebar close [X]
        let close_x = wx + self.w - 32;
        let close_y = wy + 4;
        if mx >= close_x && mx < close_x + 28 && my >= close_y && my < close_y + 20 {
            self.close();
            crate::audio::play_click_sound();
            return None;
        }

        // Action Buttons at bottom
        let btn_y = wy + self.h - 38;
        let btn_h = 26;
        let ok_x = wx + self.w - 240;
        let cancel_x = wx + self.w - 160;
        let browse_x = wx + self.w - 80;

        // [Tamam] button
        if mx >= ok_x && mx < ok_x + 72 && my >= btn_y && my < btn_y + btn_h {
            let cmd = String::from(self.input.trim());
            if !cmd.is_empty() {
                self.history.push(cmd.clone());
                self.close();
                crate::audio::play_click_sound();
                return Some(cmd);
            }
        }

        // [İptal] button
        if mx >= cancel_x && mx < cancel_x + 72 && my >= btn_y && my < btn_y + btn_h {
            self.close();
            crate::audio::play_click_sound();
            return None;
        }

        // [Gözat...] button -> opens Dosya Gezgini
        if mx >= browse_x && mx < browse_x + 72 && my >= btn_y && my < btn_y + btn_h {
            self.close();
            crate::audio::play_click_sound();
            return Some(String::from("explorer"));
        }

        None
    }

    /// Renders the Windows Run Dialog
    pub fn render(&mut self, engine: &mut DisplayEngine, mx: usize, my: usize, palette: &ThemePalette) {
        if !self.is_open {
            return;
        }

        self.cursor_blink = self.cursor_blink.wrapping_add(1);

        let wx = self.x as usize;
        let wy = self.y as usize;
        let ww = self.w;
        let wh = self.h;

        // Soft drop shadow
        if wx >= 4 && wy >= 4 {
            engine.fill_rounded_rect(wx + 4, wy + 4, ww, wh, 8, palette.flyout_shadow);
        }

        // Card surface & border
        engine.fill_rounded_rect(wx, wy, ww, wh, 8, palette.card_bg);
        engine.draw_rect(wx, wy, ww, wh, palette.card_border);

        // 1. Title bar (Height: 28px)
        engine.fill_rounded_rect(wx + 1, wy + 1, ww - 2, 28, 6, palette.titlebar_bg_active);
        engine.draw_hline(wx, wy + 28, ww, palette.border_subtle);

        // Icon & Title
        engine.draw_string(wx + 10, wy + 8, "[>]", palette.accent_cyan, 1);
        engine.draw_string(wx + 32, wy + 8, "Calistir (Win + R)", palette.text_primary, 1);

        // Close button [X]
        let close_x = wx + ww - 30;
        let is_close_h = mx >= close_x && mx < close_x + 24 && my >= wy + 4 && my < wy + 24;
        let close_bg = if is_close_h { palette.accent_rose } else { palette.titlebar_bg_active };
        engine.fill_rounded_rect(close_x, wy + 5, 24, 18, 4, close_bg);
        engine.draw_string(close_x + 8, wy + 8, "x", palette.text_primary, 1);

        // 2. Body Text & Prompt Icon
        // Windows Run document icon
        engine.fill_rounded_rect(wx + 16, wy + 40, 32, 32, 6, Color::rgb(35, 45, 65));
        engine.draw_rect(wx + 16, wy + 40, 32, 32, palette.accent_cyan);
        engine.draw_string(wx + 24, wy + 50, "[R]", palette.accent_cyan, 1);

        // Description
        engine.draw_string(wx + 56, wy + 38, "CorOS bir programi, klasoru veya", palette.text_secondary, 1);
        engine.draw_string(wx + 56, wy + 52, "ELF binary dosyasini calistirir.", palette.text_secondary, 1);

        // 3. Input Row: "Aç:" [ Text Input Box ]
        engine.draw_string(wx + 18, wy + 84, "Ac:", palette.text_primary, 1);

        let input_x = wx + 54;
        let input_y = wy + 78;
        let input_w = ww - 72;
        let input_h = 24;

        engine.fill_rounded_rect(input_x, input_y, input_w, input_h, 4, Color::rgb(18, 18, 18));
        engine.draw_rect(input_x, input_y, input_w, input_h, palette.accent_cyan);

        // Render typed text
        if self.input.is_empty() {
            engine.draw_string(input_x + 8, input_y + 6, "komut yazin (orn: calc, term, HESAP.ELF)", palette.text_muted, 1);
        } else {
            engine.draw_string(input_x + 8, input_y + 6, &self.input, palette.text_primary, 1);
        }

        // Blinking text cursor
        if (self.cursor_blink / 20) % 2 == 0 {
            let cursor_x = input_x + 8 + self.input.len() * 6;
            engine.fill_rect(cursor_x, input_y + 4, 2, 14, palette.accent_cyan);
        }

        // 4. Buttons Row: [Tamam] [İptal] [Gözat...]
        let btn_y = wy + wh - 38;
        let btn_h = 24;
        let btn_w = 68;

        let ok_x = wx + ww - 232;
        let cancel_x = wx + ww - 156;
        let browse_x = wx + ww - 80;

        // [Tamam] button (Primary accent)
        let is_ok_h = mx >= ok_x && mx < ok_x + btn_w && my >= btn_y && my < btn_y + btn_h;
        let ok_bg = if is_ok_h { palette.accent_cyan } else { Color::rgb(0, 120, 212) };
        engine.fill_rounded_rect(ok_x, btn_y, btn_w, btn_h, 4, ok_bg);
        engine.draw_string(ok_x + 14, btn_y + 6, "Tamam", Color::WHITE, 1);

        // [İptal] button
        let is_cancel_h = mx >= cancel_x && mx < cancel_x + btn_w && my >= btn_y && my < btn_y + btn_h;
        let cancel_bg = if is_cancel_h { palette.item_hover_bg } else { Color::rgb(40, 40, 40) };
        engine.fill_rounded_rect(cancel_x, btn_y, btn_w, btn_h, 4, cancel_bg);
        engine.draw_rect(cancel_x, btn_y, btn_w, btn_h, palette.card_border);
        engine.draw_string(cancel_x + 18, btn_y + 6, "Iptal", palette.text_primary, 1);

        // [Gözat...] button
        let is_browse_h = mx >= browse_x && mx < browse_x + btn_w && my >= btn_y && my < btn_y + btn_h;
        let browse_bg = if is_browse_h { palette.item_hover_bg } else { Color::rgb(40, 40, 40) };
        engine.fill_rounded_rect(browse_x, btn_y, btn_w, btn_h, 4, browse_bg);
        engine.draw_rect(browse_x, btn_y, btn_w, btn_h, palette.card_border);
        engine.draw_string(browse_x + 12, btn_y + 6, "Gozat...", palette.text_primary, 1);
    }
}
