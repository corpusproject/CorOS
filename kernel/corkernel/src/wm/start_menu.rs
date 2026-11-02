//! CorOS Windows 11 Multi-Tabbed Start Menu Engine
//!
//! Provides an authentic, feature-rich Start Menu dashboard featuring:
//! - Multi-tab layout: [Sabitlenenler], [Hizli Araclar], [Son Dosyalar], [Sistem & Ring 3]
//! - Interactive real-time search filtering
//! - Quick user account and power controls
//! - Direct application launching and system actions

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;
use super::icons;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartMenuTab {
    Pinned,
    QuickTools,
    RecentFiles,
    SystemRing3,
}

#[derive(Clone, Debug)]
pub struct StartMenu {
    pub is_open: bool,
    pub active_tab: StartMenuTab,
    pub search_query: String,
    pub cursor_blink: u64,
}

impl StartMenu {
    pub fn new() -> Self {
        Self {
            is_open: false,
            active_tab: StartMenuTab::Pinned,
            search_query: String::new(),
            cursor_blink: 0,
        }
    }

    pub fn toggle(&mut self) {
        self.is_open = !self.is_open;
        if !self.is_open {
            self.search_query.clear();
        }
    }

    pub fn open(&mut self) {
        self.is_open = true;
    }

    pub fn close(&mut self) {
        self.is_open = false;
        self.search_query.clear();
    }

    pub fn tick(&mut self) {
        self.cursor_blink = self.cursor_blink.wrapping_add(1);
    }

    /// Renders the complete multi-tabbed Start Menu flyout card
    pub fn render(
        &self,
        engine: &mut DisplayEngine,
        screen_w: usize,
        screen_h: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        if !self.is_open {
            return;
        }

        let menu_w = 460;
        let menu_h = 470;
        let menu_x = (screen_w.saturating_sub(menu_w)) / 2;
        let menu_y = screen_h.saturating_sub(48 + menu_h + 10);

        // 1. Frosted Drop Shadow & Container Card
        if menu_x >= 4 && menu_y >= 4 {
            engine.fill_rounded_rect(menu_x + 4, menu_y + 4, menu_w, menu_h, 12, palette.flyout_shadow);
        }
        engine.fill_rounded_rect(menu_x, menu_y, menu_w, menu_h, 10, palette.card_bg);
        engine.draw_rect(menu_x, menu_y, menu_w, menu_h, palette.card_border);

        // 2. Interactive Search Box at Top
        let search_y = menu_y + 14;
        let search_box_border = if !self.search_query.is_empty() {
            palette.accent_cyan
        } else {
            palette.card_border
        };
        engine.fill_rounded_rect(menu_x + 20, search_y, menu_w - 40, 34, 6, palette.card_bg_secondary);
        engine.draw_rect(menu_x + 20, search_y, menu_w - 40, 34, search_box_border);

        // Search icon magnifying glass placeholder
        engine.draw_string(menu_x + 32, search_y + 11, "[?]", palette.text_muted, 1);

        if self.search_query.is_empty() {
            engine.draw_string(menu_x + 56, search_y + 11, "Uygulamalari, komutlari ve dosyalari arayin...", palette.text_muted, 1);
        } else {
            let cursor = if (self.cursor_blink / 20) % 2 == 0 { "|" } else { "" };
            let disp = format!("{}{}", self.search_query, cursor);
            engine.draw_string(menu_x + 56, search_y + 11, &disp, palette.text_primary, 1);
        }

        // 3. Navigation Tabs Bar: [Sabitlenenler] [Hizli Araclar] [Son Dosyalar] [Sistem & Ring 3]
        let tab_bar_y = search_y + 46;
        let tabs = [
            (StartMenuTab::Pinned, "Sabitlenenler", 100),
            (StartMenuTab::QuickTools, "Hizli Araclar", 96),
            (StartMenuTab::RecentFiles, "Son Dosyalar", 96),
            (StartMenuTab::SystemRing3, "Sistem & Ring3", 108),
        ];

        let mut tx = menu_x + 20;
        for &(tab_type, tab_label, tab_w) in &tabs {
            let is_sel = self.active_tab == tab_type;
            let is_h = mx >= tx && mx < tx + tab_w && my >= tab_bar_y && my < tab_bar_y + 24;

            if is_sel {
                engine.fill_rounded_rect(tx, tab_bar_y, tab_w, 24, 4, palette.card_bg_secondary);
                engine.draw_rect(tx, tab_bar_y, tab_w, 24, palette.accent_cyan);
                engine.draw_string(tx + 8, tab_bar_y + 6, tab_label, palette.accent_cyan, 1);
            } else {
                if is_h {
                    engine.fill_rounded_rect(tx, tab_bar_y, tab_w, 24, 4, palette.item_hover_bg);
                }
                engine.draw_string(tx + 8, tab_bar_y + 6, tab_label, palette.text_secondary, 1);
            }
            tx += tab_w + 6;
        }

        engine.draw_hline(menu_x + 20, tab_bar_y + 28, menu_w - 40, palette.card_border);

        // 4. Tab Body Content Area (Height: ~300px)
        let body_y = tab_bar_y + 36;

        match self.active_tab {
            StartMenuTab::Pinned => {
                self.render_pinned_tab(engine, menu_x, body_y, menu_w, mx, my, palette);
            }
            StartMenuTab::QuickTools => {
                self.render_quick_tools_tab(engine, menu_x, body_y, menu_w, mx, my, palette);
            }
            StartMenuTab::RecentFiles => {
                self.render_recent_files_tab(engine, menu_x, body_y, menu_w, mx, my, palette);
            }
            StartMenuTab::SystemRing3 => {
                self.render_system_ring3_tab(engine, menu_x, body_y, menu_w, mx, my, palette);
            }
        }

        // 5. Bottom User Account & Power Bar
        let foot_y = menu_y + menu_h - 48;
        engine.fill_rect(menu_x, foot_y, menu_w, 48, palette.card_bg_secondary);
        engine.draw_hline(menu_x, foot_y, menu_w, palette.card_border);

        // User Avatar with circular gradient
        engine.fill_circle((menu_x + 36) as isize, (foot_y + 24) as isize, 14, palette.accent_blue);
        engine.draw_string(menu_x + 32, foot_y + 19, "U", Color::WHITE, 1);
        engine.draw_string(menu_x + 58, foot_y + 13, "coros@silicon", palette.text_primary, 1);
        engine.draw_string(menu_x + 58, foot_y + 27, "Yerel Yonetici (Ring 0 / Ring 3)", palette.text_muted, 1);

        // Power Buttons: Restart [R] and Shutdown [P]
        let restart_x = menu_x + menu_w - 90;
        let is_rst_h = mx >= restart_x && mx < restart_x + 36 && my >= foot_y + 8 && my < foot_y + 40;
        if is_rst_h {
            engine.fill_rounded_rect(restart_x, foot_y + 8, 36, 32, 4, palette.item_hover_bg);
        }
        engine.draw_string(restart_x + 10, foot_y + 18, "[R]", palette.accent_cyan, 1);

        let power_x = menu_x + menu_w - 48;
        let is_pwr_h = mx >= power_x && mx < power_x + 36 && my >= foot_y + 8 && my < foot_y + 40;
        if is_pwr_h {
            engine.fill_rounded_rect(power_x, foot_y + 8, 36, 32, 4, Color::rgb(75, 20, 20));
        }
        engine.draw_string(power_x + 10, foot_y + 18, "[P]", palette.accent_rose, 1);
    }

    /// Renders Tab 1: Pinned Applications Grid (2 rows of 4)
    fn render_pinned_tab(
        &self,
        engine: &mut DisplayEngine,
        menu_x: usize,
        body_y: usize,
        menu_w: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        let all_apps: [(&str, &[u8], usize); 7] = [
            ("Dosya Gezgini", icons::ICON_FINDER_BMP, 0),
            ("Terminal", icons::ICON_TERMINAL_BMP, 1),
            ("Gorev Yoneticisi", icons::ICON_MONITOR_BMP, 2),
            ("3D Goruntuleyici", icons::ICON_CYBER3D_BMP, 3),
            ("Ayarlar & Tema", icons::ICON_SETTINGS_BMP, 4),
            ("CorOS Paint", icons::ICON_PAINT_BMP, 7),
            ("Not Defteri", icons::ICON_NOTEPAD_BMP, 5),
        ];

        let q = self.search_query.to_lowercase();
        let filtered: Vec<(&str, &[u8], usize)> = all_apps.iter()
            .filter(|(name, _, _)| q.is_empty() || name.to_lowercase().contains(&q))
            .copied()
            .collect();

        let col_w = (menu_w - 48) / 3;

        for (i, &(title, icon_bmp, _id)) in filtered.iter().take(6).enumerate() {
            let row = i / 3;
            let col = i % 3;
            let ax = menu_x + 24 + col * col_w;
            let ay = body_y + 8 + row * 84;

            let is_h = mx >= ax && mx < ax + col_w - 8 && my >= ay && my < ay + 76;
            if is_h {
                engine.fill_rounded_rect(ax, ay, col_w - 8, 76, 6, palette.item_hover_bg);
                engine.draw_rect(ax, ay, col_w - 8, 76, palette.border_subtle);
            }

            let icon_center_x = ax + (col_w - 8) / 2 - 24;
            engine.draw_bmp(icon_center_x, ay + 6, icon_bmp);

            let label_len = engine.string_width(title);
            let lx = ax + (col_w - 8).saturating_sub(label_len) / 2;
            let text_col = if is_h { palette.text_primary } else { palette.text_secondary };
            engine.draw_string(lx, ay + 58, title, text_col, 1);
        }

        // Hint bar at bottom of pinned tab
        let hint_y = body_y + 196;
        engine.fill_rounded_rect(menu_x + 24, hint_y, menu_w - 48, 48, 6, palette.card_bg_secondary);
        engine.draw_rect(menu_x + 24, hint_y, menu_w - 48, 48, palette.card_border);
        engine.draw_string(menu_x + 36, hint_y + 10, "Ipucu: Uygulamayi baslatmak icin simgeye tiklayin,", palette.accent_cyan, 1);
        engine.draw_string(menu_x + 36, hint_y + 26, "veya terminalde 'exec <uygulama>' komutunu kullanin.", palette.text_muted, 1);
    }

    /// Renders Tab 2: Quick Tools & Diagnostic Utilities
    fn render_quick_tools_tab(
        &self,
        engine: &mut DisplayEngine,
        menu_x: usize,
        body_y: usize,
        menu_w: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        let tools = [
            ("Geri Donusum Kutusu", "Kullanilmayan dosyalari temizle", "[TRASH]", 1),
            ("Intel Gigabit Ag Bilgisi", "IP: 10.0.2.15/24 DHCP yenile", "[NET]", 2),
            ("APIC Zamanlayici & Preemption", "4-Cekirdek gorev tablosunu ac", "[APIC]", 3),
            ("VFS /proc & /etc Modulu", "Sanal dosya sistemini denetle", "[VFS]", 4),
            ("Dinamik Cekirdek Modulleri", "lsmod / insmod surucu tablosu", "[KMOD]", 5),
            ("AC97 PCI Ses Testi", "Donanimsal tiklama sesini cal", "[AUDIO]", 6),
        ];

        let col_w = (menu_w - 48);

        for (i, &(title, desc, icon_tag, _id)) in tools.iter().enumerate() {
            let row_y = body_y + i * 44;
            let is_h = mx >= menu_x + 24 && mx < menu_x + 24 + col_w && my >= row_y && my < row_y + 38;

            if is_h {
                engine.fill_rounded_rect(menu_x + 24, row_y, col_w, 38, 4, palette.item_hover_bg);
                engine.draw_rect(menu_x + 24, row_y, col_w, 38, palette.border_subtle);
            } else {
                engine.fill_rounded_rect(menu_x + 24, row_y, col_w, 38, 4, palette.card_bg_secondary);
            }

            engine.draw_string(menu_x + 36, row_y + 12, icon_tag, palette.accent_cyan, 1);
            engine.draw_string(menu_x + 90, row_y + 6, title, palette.text_primary, 1);
            engine.draw_string(menu_x + 90, row_y + 20, desc, palette.text_muted, 1);
        }
    }

    /// Renders Tab 3: Recent Files & Standalone ELF Binaries
    fn render_recent_files_tab(
        &self,
        engine: &mut DisplayEngine,
        menu_x: usize,
        body_y: usize,
        menu_w: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        let recent = [
            ("HESAP.ELF", "242 Bayt", "Ring 3 Bilimsel Hesaplayici (ELF64)", "[ELF]", palette.accent_amber),
            ("APP.ELF", "239 Bayt", "Bagimsiz Kullanici Uygulamasi (ELF64)", "[ELF]", palette.accent_amber),
            ("README.TXT", "180 Bayt", "CorOS Hizli Kullanim Kilavuzu", "[TXT]", palette.text_primary),
            ("NOTLAR.TXT", "110 Bayt", "Kullanici Notlari (FAT32 Kalici)", "[TXT]", palette.text_primary),
            ("RESIM.PNG", "14 KB", "Paint 24-bit TrueColor Resmi", "[PNG]", palette.accent_cyan),
            ("BOOTX64.EFI", "64 KB", "UEFI 64-bit On-Yukleyici", "[EFI]", palette.accent_emerald),
        ];

        let col_w = menu_w - 48;

        for (i, &(name, size, desc, tag, tag_col)) in recent.iter().enumerate() {
            let row_y = body_y + i * 44;
            let is_h = mx >= menu_x + 24 && mx < menu_x + 24 + col_w && my >= row_y && my < row_y + 38;

            if is_h {
                engine.fill_rounded_rect(menu_x + 24, row_y, col_w, 38, 4, palette.item_hover_bg);
                engine.draw_rect(menu_x + 24, row_y, col_w, 38, palette.border_subtle);
            } else {
                engine.fill_rounded_rect(menu_x + 24, row_y, col_w, 38, 4, palette.card_bg_secondary);
            }

            engine.draw_string(menu_x + 36, row_y + 12, tag, tag_col, 1);
            engine.draw_string(menu_x + 84, row_y + 6, name, palette.text_primary, 1);
            engine.draw_string(menu_x + 84, row_y + 20, desc, palette.text_muted, 1);
            engine.draw_string(menu_x + col_w - 20, row_y + 12, size, palette.accent_cyan, 1);
        }
    }

    /// Renders Tab 4: System Telemetry & Ring 3 Security Subsystem
    fn render_system_ring3_tab(
        &self,
        engine: &mut DisplayEngine,
        menu_x: usize,
        body_y: usize,
        menu_w: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        let col_w = menu_w - 48;

        // 1. Hardware Specs Card
        engine.fill_rounded_rect(menu_x + 24, body_y, col_w, 90, 6, palette.card_bg_secondary);
        engine.draw_rect(menu_x + 24, body_y, col_w, 90, palette.card_border);

        engine.draw_string(menu_x + 36, body_y + 10, "CorOS Enterprise x86_64 SMP Kernel", palette.accent_cyan, 1);
        engine.draw_string(menu_x + 36, body_y + 28, "Islemci:  4-Cekirdek SMP @ 2.60 GHz (ACPI MADT OK)", palette.text_primary, 1);
        engine.draw_string(menu_x + 36, body_y + 44, "Bellek:    1024 MB RAM (14 MB Aktif Heap)", palette.text_secondary, 1);
        engine.draw_string(menu_x + 36, body_y + 60, "Depolama: AHCI SATA DMA (FAT32 ESP Bolumu)", palette.text_secondary, 1);
        engine.draw_string(menu_x + 36, body_y + 74, "Ekran:    1024x768 32bpp TrueColor @ 305 FPS", palette.accent_emerald, 1);

        // 2. Ring 3 Hardware Isolation Status Card
        let iso_y = body_y + 100;
        engine.fill_rounded_rect(menu_x + 24, iso_y, col_w, 80, 6, palette.card_bg_secondary);
        engine.draw_rect(menu_x + 24, iso_y, col_w, 80, palette.accent_emerald);

        engine.draw_string(menu_x + 36, iso_y + 10, "[ RING 3 DONANIMSAL IZOLASYON ETKIN ]", palette.accent_emerald, 1);
        engine.draw_string(menu_x + 36, iso_y + 28, "Kullanici Kod Segmenti : CS=0x1B (DPL 3 - Ring 3)", palette.text_primary, 1);
        engine.draw_string(menu_x + 36, iso_y + 44, "Kullanici Yigin Segmenti: SS=0x23 (DPL 3 - Ring 3)", palette.text_primary, 1);
        engine.draw_string(menu_x + 36, iso_y + 60, "Cekirdek Koruma (TSS)   : rsp0 Hardware Stack Trap OK", palette.accent_cyan, 1);

        // 3. Hardware Test Action Buttons
        let btn1_y = iso_y + 90;
        let is_btn1_h = mx >= menu_x + 24 && mx < menu_x + 24 + (col_w / 2 - 6) && my >= btn1_y && my < btn1_y + 32;
        let b1_bg = if is_btn1_h { palette.accent_blue } else { palette.card_bg_secondary };
        engine.fill_rounded_rect(menu_x + 24, btn1_y, col_w / 2 - 6, 32, 4, b1_bg);
        engine.draw_rect(menu_x + 24, btn1_y, col_w / 2 - 6, 32, palette.accent_blue);
        engine.draw_string(menu_x + 34, btn1_y + 9, "Ring 3 Testi Calistir", Color::WHITE, 1);

        let btn2_x = menu_x + 24 + col_w / 2 + 6;
        let is_btn2_h = mx >= btn2_x && mx < btn2_x + (col_w / 2 - 6) && my >= btn1_y && my < btn1_y + 32;
        let b2_bg = if is_btn2_h { palette.accent_rose } else { palette.card_bg_secondary };
        engine.fill_rounded_rect(btn2_x, btn1_y, col_w / 2 - 6, 32, 4, b2_bg);
        engine.draw_rect(btn2_x, btn1_y, col_w / 2 - 6, 32, palette.accent_rose);
        engine.draw_string(btn2_x + 24, btn1_y + 9, "Crash (#PF) Testi", Color::WHITE, 1);
    }
}
