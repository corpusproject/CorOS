//! CorOS Sanal Masaüstleri (Virtual Desktops & Task View) Subsystem
//!
//! Provides full Windows 11 style multi-desktop workspace management:
//! - Multiple independent desktops: "Masaüstü 1", "Masaüstü 2", "Masaüstü 3"
//! - Shortcuts: Win + Ctrl + D (New Desktop), Win + Ctrl + Sol/Sağ Ok (Switch), Win + Tab (Task View)
//! - Window isolation per desktop: each desktop maintains its own active windows
//! - Sleek Task View top workspace switcher bar and taskbar indicator

use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;
use super::Window;

pub struct DesktopWorkspace {
    pub id: usize,
    pub name: String,
}

pub struct VirtualDesktopManager {
    pub workspaces: Vec<DesktopWorkspace>,
    pub active_idx: usize,
    pub task_view_open: bool,
    pub anim_offset_x: isize,
}

impl VirtualDesktopManager {
    pub fn new() -> Self {
        let mut workspaces = Vec::new();
        workspaces.push(DesktopWorkspace { id: 0, name: String::from("Masaustu 1") });
        workspaces.push(DesktopWorkspace { id: 1, name: String::from("Masaustu 2") });

        Self {
            workspaces,
            active_idx: 0,
            task_view_open: false,
            anim_offset_x: 0,
        }
    }

    pub fn current_desktop_id(&self) -> usize {
        self.workspaces.get(self.active_idx).map_or(0, |w| w.id)
    }

    pub fn current_desktop_name(&self) -> &str {
        self.workspaces.get(self.active_idx).map_or("Masaustu 1", |w| w.name.as_str())
    }

    pub fn switch_to(&mut self, idx: usize) {
        if idx < self.workspaces.len() && idx != self.active_idx {
            self.active_idx = idx;
            crate::audio::play_click_sound();
        }
    }

    pub fn desktop_count(&self) -> usize {
        self.workspaces.len()
    }

    pub fn close_task_view(&mut self) {
        self.task_view_open = false;
    }

    pub fn next(&mut self) {
        if !self.workspaces.is_empty() {
            let next_idx = (self.active_idx + 1) % self.workspaces.len();
            self.switch_to(next_idx);
        }
    }

    pub fn next_desktop(&mut self) {
        self.next();
    }

    pub fn prev(&mut self) {
        if !self.workspaces.is_empty() {
            let prev_idx = if self.active_idx == 0 { self.workspaces.len() - 1 } else { self.active_idx - 1 };
            self.switch_to(prev_idx);
        }
    }

    pub fn prev_desktop(&mut self) {
        self.prev();
    }

    pub fn add_desktop(&mut self) -> usize {
        if self.workspaces.len() < 4 {
            let new_id = self.workspaces.len();
            let name = alloc::format!("Masaustu {}", new_id + 1);
            self.workspaces.push(DesktopWorkspace { id: new_id, name });
            self.switch_to(new_id);
            crate::audio::play_click_sound();
            new_id
        } else {
            self.active_idx
        }
    }

    pub fn toggle_task_view(&mut self) {
        self.task_view_open = !self.task_view_open;
        crate::audio::play_click_sound();
    }

    /// Handles mouse clicks when Task View (Win + Tab / F3) is open. Returns Some(window_index) if window picked.
    pub fn handle_task_view_click(&mut self, mx: usize, my: usize, screen_w: usize, windows: &[Window]) -> Option<usize> {
        if !self.task_view_open {
            return None;
        }

        let bar_w = (self.workspaces.len() + 1) * 140 + 20;
        let bar_x = (screen_w.saturating_sub(bar_w)) / 2;
        let bar_y = 60;
        let card_w = 130;
        let card_h = 70;

        // Check desktop card clicks
        for (i, _) in self.workspaces.iter().enumerate() {
            let cx = bar_x + 10 + i * (card_w + 10);
            if mx >= cx && mx < cx + card_w && my >= bar_y + 10 && my < bar_y + 10 + card_h {
                self.switch_to(i);
                self.task_view_open = false;
                return Some(usize::MAX);
            }
        }

        // Check [+] Add Desktop button click
        let add_x = bar_x + 10 + self.workspaces.len() * (card_w + 10);
        if mx >= add_x && mx < add_x + card_w && my >= bar_y + 10 && my < bar_y + 10 + card_h {
            self.add_desktop();
            return Some(usize::MAX);
        }

        // Check window card clicks in grid (Mission Control window focus)
        let grid_y = bar_y + card_h + 40;
        let cur_id = self.current_desktop_id();
        let cur_windows: Vec<usize> = windows.iter()
            .enumerate()
            .filter(|(_, w)| (w.desktop_id == cur_id || w.desktop_id == usize::MAX) && w.is_open)
            .map(|(i, _)| i)
            .collect();

        for (idx, &win_idx) in cur_windows.iter().enumerate() {
            let wx = 32 + idx * 240;
            let wy = grid_y + 24;
            if wx + 220 < screen_w && mx >= wx && mx < wx + 220 && my >= wy && my < wy + 140 {
                self.task_view_open = false;
                return Some(win_idx);
            }
        }

        // Clicking outside closes Task View
        self.task_view_open = false;
        Some(usize::MAX)
    }

    /// Renders the Windows 11 Task View workspace overlay (`Win + Tab`)
    pub fn render_task_view(
        &self,
        engine: &mut DisplayEngine,
        screen_w: usize,
        screen_h: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
        windows: &[Window],
    ) {
        if !self.task_view_open {
            return;
        }

        // Semi-transparent dark frosted backdrop
        engine.fill_rect(0, 0, screen_w, screen_h.saturating_sub(48), Color::rgb(14, 18, 26));

        // Header Title
        engine.draw_string(32, 24, "Gorev Gorunumu (Win + Tab)", palette.text_primary, 1);
        engine.draw_string(230, 24, "| Sanal Masaustleri", palette.text_muted, 1);

        // Top Desktop Switcher Bar
        let card_w = 130;
        let card_h = 70;
        let total_items = self.workspaces.len() + 1; // plus [+] button
        let bar_w = total_items * (card_w + 10) + 10;
        let bar_x = (screen_w.saturating_sub(bar_w)) / 2;
        let bar_y = 60;

        // Container card
        engine.fill_rounded_rect(bar_x, bar_y, bar_w, card_h + 20, 8, palette.card_bg);
        engine.draw_rect(bar_x, bar_y, bar_w, card_h + 20, palette.card_border);

        // Render each Desktop Card
        for (i, ws) in self.workspaces.iter().enumerate() {
            let cx = bar_x + 10 + i * (card_w + 10);
            let cy = bar_y + 10;
            let is_active = i == self.active_idx;
            let is_h = mx >= cx && mx < cx + card_w && my >= cy && my < cy + card_h;

            let card_bg = if is_active {
                Color::rgb(28, 42, 64)
            } else if is_h {
                palette.item_hover_bg
            } else {
                Color::rgb(20, 24, 32)
            };

            let card_border = if is_active {
                palette.accent_cyan
            } else if is_h {
                palette.border_subtle
            } else {
                palette.card_border
            };

            engine.fill_rounded_rect(cx, cy, card_w, card_h, 6, card_bg);
            engine.draw_rect(cx, cy, card_w, card_h, card_border);

            // Mini desktop screen preview frame inside card
            engine.fill_rect(cx + 8, cy + 8, card_w - 16, 32, Color::rgb(12, 16, 22));
            engine.draw_rect(cx + 8, cy + 8, card_w - 16, 32, Color::rgb(35, 45, 60));

            // Small window blocks inside mini screen
            let win_count = windows.iter().filter(|w| w.desktop_id == ws.id && w.is_open).count();
            if win_count > 0 {
                engine.fill_rect(cx + 12, cy + 12, 40, 20, Color::rgb(45, 60, 85));
            }
            if win_count > 1 {
                engine.fill_rect(cx + 56, cy + 12, 40, 20, Color::rgb(35, 50, 75));
            }

            // Desktop label
            let text_col = if is_active { palette.accent_cyan } else { palette.text_primary };
            engine.draw_string(cx + 12, cy + 48, &ws.name, text_col, 1);
        }

        // Render [+] Yeni Masaüstü button
        let add_x = bar_x + 10 + self.workspaces.len() * (card_w + 10);
        let add_y = bar_y + 10;
        let is_add_h = mx >= add_x && mx < add_x + card_w && my >= add_y && my < add_y + card_h;
        let add_bg = if is_add_h { palette.item_hover_bg } else { Color::rgb(20, 24, 32) };
        engine.fill_rounded_rect(add_x, add_y, card_w, card_h, 6, add_bg);
        engine.draw_rect(add_x, add_y, card_w, card_h, palette.card_border);
        engine.draw_string(add_x + 36, add_y + 20, "[+]", palette.accent_cyan, 1);
        engine.draw_string(add_x + 14, add_y + 44, "Yeni Masaustu", palette.text_secondary, 1);

        // Window Overview Cards on active desktop
        let grid_y = bar_y + card_h + 40;
        engine.draw_string(32, grid_y, "Aktif Pencereler:", palette.text_secondary, 1);

        let cur_id = self.current_desktop_id();
        let cur_windows: Vec<&Window> = windows.iter()
            .filter(|w| (w.desktop_id == cur_id || w.desktop_id == usize::MAX) && w.is_open)
            .collect();

        if cur_windows.is_empty() {
            engine.draw_string(32, grid_y + 30, "Bu masaustunde acik pencere yok.", palette.text_muted, 1);
        } else {
            for (idx, win) in cur_windows.iter().enumerate() {
                let wx = 32 + idx * 240;
                let wy = grid_y + 24;
                if wx + 220 < screen_w {
                    engine.fill_rounded_rect(wx, wy, 220, 140, 6, palette.card_bg);
                    engine.draw_rect(wx, wy, 220, 140, palette.card_border);

                    // Window Title banner
                    engine.fill_rounded_rect(wx + 1, wy + 1, 218, 24, 6, palette.titlebar_bg_active);
                    engine.draw_string(wx + 8, wy + 6, win.title, palette.text_primary, 1);

                    // Inner representation
                    engine.fill_rect(wx + 8, wy + 32, 204, 98, Color::rgb(14, 14, 14));
                    engine.draw_string(wx + 20, wy + 70, win.title, palette.accent_cyan, 1);
                }
            }
        }
    }
}
