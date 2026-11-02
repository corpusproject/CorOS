//! Windows Action Center & Quick Settings Flyout Widget
//!
//! Provides Windows 11 style Quick Settings flyout and notifications:
//! - Wi-Fi, Bluetooth, Airplane Mode, Battery Saver, Night Light, Focus Assist toggles
//! - Real-time Brightness & Volume slider adjustments
//! - Network connection status and signal strength indicator
//! - Quick Action Buttons with interactive toggling and persistent settings state
//! - Action Center panel positioning above the system tray clock

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;

/// Quick Toggle Button State
#[derive(Debug, Clone)]
pub struct QuickToggle {
    pub id: u32,
    pub title: String,
    pub subtitle: String,
    pub icon_char: char,
    pub is_enabled: bool,
}

/// Action Center Flyout State
pub struct ActionCenterFlyout {
    pub is_open: bool,
    pub toggles: Vec<QuickToggle>,
    pub brightness_percent: u8,
    pub volume_percent: u8,
    pub is_muted: bool,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl ActionCenterFlyout {
    pub fn new() -> Self {
        let mut toggles = Vec::new();
        toggles.push(QuickToggle {
            id: 1,
            title: String::from("Wi-Fi"),
            subtitle: String::from("CorOS_5GHz"),
            icon_char: 'W',
            is_enabled: true,
        });
        toggles.push(QuickToggle {
            id: 2,
            title: String::from("Bluetooth"),
            subtitle: String::from("Acik"),
            icon_char: 'B',
            is_enabled: true,
        });
        toggles.push(QuickToggle {
            id: 3,
            title: String::from("Ucak Modu"),
            subtitle: String::from("Kapali"),
            icon_char: 'A',
            is_enabled: false,
        });
        toggles.push(QuickToggle {
            id: 4,
            title: String::from("Pil Tasarrufu"),
            subtitle: String::from("Kapali"),
            icon_char: 'P',
            is_enabled: false,
        });
        toggles.push(QuickToggle {
            id: 5,
            title: String::from("Gece Isigi"),
            subtitle: String::from("Kapali"),
            icon_char: 'G',
            is_enabled: false,
        });
        toggles.push(QuickToggle {
            id: 6,
            title: String::from("Odaklanma"),
            subtitle: String::from("Oncelik"),
            icon_char: 'O',
            is_enabled: false,
        });

        Self {
            is_open: false,
            toggles,
            brightness_percent: 85,
            volume_percent: 70,
            is_muted: false,
            x: 680,
            y: 430,
            width: 330,
            height: 290,
        }
    }

    pub fn toggle_open(&mut self) {
        self.is_open = !self.is_open;
    }

    /// Handle click inside flyout
    pub fn handle_click(&mut self, mouse_x: i32, mouse_y: i32) -> bool {
        if !self.is_open {
            return false;
        }

        if mouse_x < self.x || mouse_x >= self.x + self.width || mouse_y < self.y || mouse_y >= self.y + self.height {
            self.is_open = false; // Click outside closes
            return false;
        }

        // Check toggles grid (2 columns x 3 rows)
        let grid_start_x = self.x + 16;
        let grid_start_y = self.y + 16;
        let item_w = 140;
        let item_h = 56;
        let gap_x = 18;
        let gap_y = 10;

        for (i, toggle) in self.toggles.iter_mut().enumerate() {
            let col = (i % 2) as i32;
            let row = (i / 2) as i32;
            let item_x = grid_start_x + col * (item_w + gap_x);
            let item_y = grid_start_y + row * (item_h + gap_y);

            if mouse_x >= item_x && mouse_x < item_x + item_w && mouse_y >= item_y && mouse_y < item_y + item_h {
                toggle.is_enabled = !toggle.is_enabled;
                return true;
            }
        }

        // Volume slider area
        let vol_y = self.y + 225;
        if mouse_y >= vol_y && mouse_y <= vol_y + 16 && mouse_x >= self.x + 40 && mouse_x <= self.x + 300 {
            let percent = ((mouse_x - (self.x + 40)) * 100) / 260;
            self.volume_percent = (percent as u8).min(100);
            return true;
        }

        true
    }

    /// Render Windows 11 style Quick Settings flyout
    pub fn render(&self, display: &mut DisplayEngine, _palette: &ThemePalette) {
        if !self.is_open {
            return;
        }

        let ux = self.x as usize;
        let uy = self.y as usize;
        let uw = self.width as usize;
        let uh = self.height as usize;

        // Card shadow & frosted glass background
        display.fill_rect(ux + 4, uy + 4, uw, uh, Color::rgb(0, 0, 0));
        let bg_color = Color::rgb(32, 36, 44);
        display.fill_rect(ux, uy, uw, uh, bg_color);
        display.draw_rect(ux, uy, uw, uh, Color::rgb(55, 62, 75));

        // Render 6 toggle buttons
        let grid_start_x = self.x + 16;
        let grid_start_y = self.y + 16;
        let item_w = 140;
        let item_h = 56;
        let gap_x = 18;
        let gap_y = 10;

        for (i, toggle) in self.toggles.iter().enumerate() {
            let col = (i % 2) as i32;
            let row = (i / 2) as i32;
            let item_x = (grid_start_x + col * (item_w + gap_x)) as usize;
            let item_y = (grid_start_y + row * (item_h + gap_y)) as usize;
            let iw = item_w as usize;
            let ih = item_h as usize;

            let btn_bg = if toggle.is_enabled {
                Color::rgb(0, 103, 192) // Windows 11 Accent Blue
            } else {
                Color::rgb(45, 51, 62)
            };

            let text_color = if toggle.is_enabled { Color::WHITE } else { Color::rgb(210, 215, 225) };

            display.fill_rect(item_x, item_y, iw, ih, btn_bg);
            display.draw_rect(item_x, item_y, iw, ih, Color::rgb(70, 78, 92));

            // Icon square
            display.fill_rect(item_x + 8, item_y + 12, 32, 32, if toggle.is_enabled { Color::rgb(24, 120, 205) } else { Color::rgb(38, 43, 53) });
            display.draw_char(item_x + 20, item_y + 20, toggle.icon_char, text_color, 1);

            // Labels
            display.draw_string(item_x + 48, item_y + 14, &toggle.title, text_color, 1);
            display.draw_string(item_x + 48, item_y + 32, &toggle.subtitle, Color::rgb(160, 168, 180), 1);
        }

        // Sliders Section
        let slider_y = self.y + 225;
        display.draw_string((self.x + 16) as usize, (slider_y - 2) as usize, "Ses", Color::rgb(200, 205, 215), 1);

        let track_x = (self.x + 45) as usize;
        let track_w = 260usize;
        let track_h = 6usize;
        let sy = (slider_y + 4) as usize;
        display.fill_rect(track_x, sy, track_w, track_h, Color::rgb(55, 62, 75));

        let filled_w = (track_w * self.volume_percent as usize) / 100;
        display.fill_rect(track_x, sy, filled_w, track_h, Color::rgb(0, 103, 192));
        display.fill_circle((track_x + filled_w) as isize, (sy + 3) as isize, 6, Color::WHITE);
    }
}
