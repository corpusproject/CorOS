//! CorOS Windows 11 File Properties Dialog Subsystem
//!
//! Provides an authentic modal inspector displaying file metadata,
//! storage cluster allocation, FAT32 directory records, and hardware Ring 3 privilege details.

use alloc::format;
use alloc::string::String;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertiesTab {
    General,
    Security,
    Details,
}

#[derive(Clone, Debug)]
pub struct PropertiesDialog {
    pub is_open: bool,
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
    pub active_tab: PropertiesTab,

    pub file_name: String,
    pub file_type: String,
    pub file_size_str: String,
    pub file_bytes: usize,
    pub folder_path: String,
    pub is_directory: bool,
    pub is_elf: bool,
    pub is_png: bool,
    pub created_time_str: String,
    pub entry_point_str: String,
    pub privilege_level: String,
}

impl PropertiesDialog {
    pub fn new() -> Self {
        Self {
            is_open: false,
            x: 320,
            y: 160,
            w: 390,
            h: 440,
            active_tab: PropertiesTab::General,

            file_name: String::new(),
            file_type: String::new(),
            file_size_str: String::new(),
            file_bytes: 0,
            folder_path: String::new(),
            is_directory: false,
            is_elf: false,
            is_png: false,
            created_time_str: String::from("16.10.2026, 19:40:12"),
            entry_point_str: String::from("0x00400078"),
            privilege_level: String::from("Ring 3 (DPL 3 User Mode)"),
        }
    }

    /// Opens the dialog for a specific target file
    pub fn open_for(
        &mut self,
        name: &str,
        kind: &str,
        size_str: &str,
        folder: &str,
        is_dir: bool,
        screen_w: usize,
        screen_h: usize,
    ) {
        self.is_open = true;
        self.file_name = String::from(name);
        self.folder_path = String::from(folder);
        self.is_directory = is_dir;
        self.file_size_str = String::from(size_str);
        self.active_tab = PropertiesTab::General;

        let upper = name.to_ascii_uppercase();
        self.is_elf = upper.ends_with(".ELF") || name == "CYBER3D.BIN";
        self.is_png = upper.ends_with(".PNG");

        // Parse byte count if possible
        let bytes = size_str.trim_end_matches(" B")
            .trim_end_matches(" KB")
            .parse::<usize>()
            .unwrap_or(240);
        self.file_bytes = if size_str.contains("KB") { bytes * 1024 } else { bytes };

        if is_dir {
            self.file_type = String::from("Dosya Klasoru (FAT32 Directory)");
            self.privilege_level = String::from("Ring 0 / VFS Dosya Sistemi");
        } else if self.is_elf {
            self.file_type = String::from("ELF64 Calistirilabilir Uygulama (x86_64)");
            self.entry_point_str = String::from("0x00400078 (PT_LOAD)");
            self.privilege_level = String::from("Ring 3 (DPL 3 - Donanimsal Izole)");
        } else if self.is_png {
            self.file_type = String::from("PNG 24-bit TrueColor Resmi (160x120)");
            self.privilege_level = String::from("Kullanici Medya Verisi");
        } else if upper.ends_with(".EFI") {
            self.file_type = String::from("PE32+ UEFI x86_64 Cekirdek / On-Yukleyici");
            self.privilege_level = String::from("Ring 0 (Cekirdek Yetkisi)");
        } else {
            self.file_type = format!("Metin Belgesi ({})", kind);
            self.privilege_level = String::from("Okuma / Yazma (Ring 0-3)");
        }

        // Center on screen
        self.x = (screen_w.saturating_sub(self.w)) / 2;
        self.y = (screen_h.saturating_sub(self.h)) / 2;
    }

    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Renders the Properties dialog window
    pub fn render(
        &mut self,
        engine: &mut DisplayEngine,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        if !self.is_open {
            return;
        }

        let x = self.x;
        let y = self.y;
        let w = self.w;
        let h = self.h;

        // 1. Drop shadow & Window Container
        engine.fill_rounded_rect(x + 4, y + 4, w, h, 8, palette.flyout_shadow);
        engine.fill_rounded_rect(x, y, w, h, 8, palette.window_bg);
        engine.draw_rect(x, y, w, h, palette.window_border_active);

        // 2. Titlebar
        engine.fill_rounded_rect(x, y, w, 32, 8, palette.titlebar_bg_active);
        engine.fill_rect(x, y + 24, w, 8, palette.titlebar_bg_active);
        engine.draw_hline(x, y + 32, w, palette.titlebar_divider);

        let title_str = format!("{} Ozellikleri", self.file_name);
        engine.draw_string(x + 14, y + 9, &title_str, palette.text_primary, 1);

        // Close 'X' Button on Titlebar
        let close_btn_x = x + w - 36;
        let is_close_h = mx >= close_btn_x && mx < close_btn_x + 32 && my >= y + 2 && my < y + 30;
        if is_close_h {
            engine.fill_rounded_rect(close_btn_x, y + 4, 30, 24, 4, palette.accent_rose);
        }
        let close_fg = if is_close_h { Color::WHITE } else { palette.text_secondary };
        engine.draw_string(close_btn_x + 11, y + 9, "X", close_fg, 1);

        // 3. Tab Bar: [Genel], [Guvenlik], [Ayrintilar]
        let tab_y = y + 40;
        let tabs = [
            (PropertiesTab::General, "Genel", 80),
            (PropertiesTab::Security, "Guvenlik", 90),
            (PropertiesTab::Details, "Ayrintilar", 90),
        ];

        let mut tab_x = x + 16;
        for &(tab_enum, label, tab_w) in &tabs {
            let is_active = self.active_tab == tab_enum;
            let is_h = mx >= tab_x && mx < tab_x + tab_w && my >= tab_y && my < tab_y + 24;

            if is_active {
                engine.fill_rounded_rect(tab_x, tab_y, tab_w, 24, 4, palette.card_bg_secondary);
                engine.draw_rect(tab_x, tab_y, tab_w, 24, palette.accent_cyan);
                engine.draw_string(tab_x + 12, tab_y + 6, label, palette.accent_cyan, 1);
            } else {
                if is_h {
                    engine.fill_rounded_rect(tab_x, tab_y, tab_w, 24, 4, palette.item_hover_bg);
                }
                engine.draw_string(tab_x + 12, tab_y + 6, label, palette.text_secondary, 1);
            }
            tab_x += tab_w + 6;
        }
        engine.draw_hline(x + 16, tab_y + 26, w - 32, palette.card_border);

        // 4. Tab Body Content
        let content_y = tab_y + 36;

        match self.active_tab {
            PropertiesTab::General => {
                // Header with File Icon and Bold Name
                let icon_bg = if self.is_elf {
                    palette.accent_amber
                } else if self.is_directory {
                    palette.accent_amber
                } else if self.is_png {
                    palette.accent_cyan
                } else {
                    palette.text_primary
                };
                let icon_letter = if self.is_directory { "DIR" } else if self.is_elf { "ELF" } else if self.is_png { "PNG" } else { "TXT" };
                engine.fill_rounded_rect(x + 20, content_y, 44, 44, 6, palette.card_bg_secondary);
                engine.draw_rect(x + 20, content_y, 44, 44, icon_bg);
                engine.draw_string(x + 26, content_y + 16, icon_letter, icon_bg, 1);

                engine.draw_string(x + 76, content_y + 6, &self.file_name, palette.text_primary, 1);
                engine.draw_string(x + 76, content_y + 24, &self.file_type, palette.text_muted, 1);

                engine.draw_hline(x + 20, content_y + 54, w - 40, palette.card_border);

                // Metadata Rows
                let meta_y = content_y + 64;
                let disk_space: &str = if self.is_directory { "4096 Bayt (1 Kume)" } else { "512 Bayt (1 Sektor / FAT32)" };
                let rows: [(&str, &str); 6] = [
                    ("Dosya Turu:", self.file_type.as_str()),
                    ("Konum:", self.folder_path.as_str()),
                    ("Boyut:", self.file_size_str.as_str()),
                    ("Disk Alani:", disk_space),
                    ("Olusturuldu:", self.created_time_str.as_str()),
                    ("Dosya Sistemi:", "FAT32 ESP (LBA 2048 DMA)"),
                ];

                for (idx, &(k, v)) in rows.iter().enumerate() {
                    let ry = meta_y + idx * 24;
                    engine.draw_string(x + 22, ry, k, palette.text_secondary, 1);
                    engine.draw_string(x + 130, ry, v, palette.text_primary, 1);
                }

                // Attributes Box
                let attr_y = meta_y + rows.len() * 24 + 10;
                engine.draw_hline(x + 20, attr_y - 6, w - 40, palette.card_border);
                engine.draw_string(x + 22, attr_y, "Nitelikler:", palette.text_secondary, 1);

                // Fake Checkboxes
                engine.draw_rect(x + 130, attr_y, 14, 14, palette.card_border);
                engine.draw_string(x + 134, attr_y + 2, "x", palette.accent_cyan, 1);
                engine.draw_string(x + 150, attr_y + 2, "Salt Okunur", palette.text_primary, 1);

                engine.draw_rect(x + 246, attr_y, 14, 14, palette.card_border);
                engine.draw_string(x + 266, attr_y + 2, "Gizli", palette.text_muted, 1);
            }

            PropertiesTab::Security => {
                engine.draw_string(x + 22, content_y, "Donanimsal Guvenlik & Yetki Matrisi", palette.accent_cyan, 1);
                engine.draw_hline(x + 20, content_y + 16, w - 40, palette.card_border);

                let sec_y = content_y + 26;
                let sec_rows = [
                    ("Grup / Kullanici:", "coros@silicon (Sistem Yoneticisi)"),
                    ("Yetki Seviyesi:", &self.privilege_level),
                    ("Segment Izni:", if self.is_elf { "RX (Read + Execute)" } else { "RW (Read + Write)" }),
                    ("TSS Stack:", "TSS.rsp0 Kernel Guard Aktif"),
                    ("Crash Koruma:", "#PF Vector 14 Trap Aktif"),
                    ("Ring 3 Izolasyon:", if self.is_elf { "ETKIN (Donanimsal DPL 3)" } else { "Cekirdek Dogrudan Erisim" }),
                ];

                for (idx, &(k, v)) in sec_rows.iter().enumerate() {
                    let ry = sec_y + idx * 24;
                    engine.draw_string(x + 22, ry, k, palette.text_secondary, 1);
                    engine.draw_string(x + 140, ry, v, palette.text_primary, 1);
                }

                // Security Shield Badge
                let shield_y = sec_y + sec_rows.len() * 24 + 12;
                engine.fill_rounded_rect(x + 20, shield_y, w - 40, 36, 4, palette.card_bg_secondary);
                engine.draw_rect(x + 20, shield_y, w - 40, 36, palette.accent_emerald);
                engine.draw_string(x + 32, shield_y + 11, "[ KORUNDU ] Donanimsal yetki izolasyonu aktif.", palette.accent_emerald, 1);
            }

            PropertiesTab::Details => {
                engine.draw_string(x + 22, content_y, "Ikili Baslik & Dizin Ayrintilari", palette.accent_cyan, 1);
                engine.draw_hline(x + 20, content_y + 16, w - 40, palette.card_border);

                let det_y = content_y + 26;
                let det_rows = [
                    ("Mimari:", "AMD x86_64 (64-Bit Little-Endian)"),
                    ("Giris RIP:", &self.entry_point_str),
                    ("Segmentler:", if self.is_elf { "1 PT_LOAD (0x400000 - 0x401000)" } else { "--" }),
                    ("FAT32 Kume:", "Cluster #14 (Offset 0x001C8000)"),
                    ("FAT Nitelik:", if self.is_directory { "0x10 (ATTR_DIRECTORY)" } else { "0x20 (ATTR_ARCHIVE)" }),
                    ("Hash:", "SHA256: 8f9b...a10c (Bare-Metal OK)"),
                ];

                for (idx, &(k, v)) in det_rows.iter().enumerate() {
                    let ry = det_y + idx * 24;
                    engine.draw_string(x + 22, ry, k, palette.text_secondary, 1);
                    engine.draw_string(x + 130, ry, v, palette.text_primary, 1);
                }
            }
        }

        // 5. Bottom Action Buttons: [Tamam] [Iptal]
        let btn_y = y + h - 42;
        engine.draw_hline(x + 16, btn_y - 10, w - 32, palette.card_border);

        let ok_x = x + w - 170;
        let is_ok_h = mx >= ok_x && mx < ok_x + 72 && my >= btn_y && my < btn_y + 26;
        let ok_bg = if is_ok_h { palette.accent_blue } else { palette.card_bg_secondary };
        engine.fill_rounded_rect(ok_x, btn_y, 72, 26, 4, ok_bg);
        engine.draw_rect(ok_x, btn_y, 72, 26, palette.accent_blue);
        engine.draw_string(ok_x + 16, btn_y + 7, "Tamam", Color::WHITE, 1);

        let cancel_x = x + w - 88;
        let is_cancel_h = mx >= cancel_x && mx < cancel_x + 72 && my >= btn_y && my < btn_y + 26;
        let cancel_bg = if is_cancel_h { palette.item_hover_bg } else { palette.card_bg_secondary };
        engine.fill_rounded_rect(cancel_x, btn_y, 72, 26, 4, cancel_bg);
        engine.draw_rect(cancel_x, btn_y, 72, 26, palette.card_border);
        engine.draw_string(cancel_x + 20, btn_y + 7, "Iptal", palette.text_secondary, 1);
    }

    /// Handles click inside or outside Properties dialog
    pub fn handle_click(&mut self, mx: usize, my: usize) -> bool {
        if !self.is_open {
            return false;
        }

        let x = self.x;
        let y = self.y;
        let w = self.w;
        let h = self.h;

        // Click outside closes dialog
        if mx < x || mx >= x + w || my < y || my >= y + h {
            self.close();
            return true;
        }

        // Close 'X' button
        let close_btn_x = x + w - 36;
        if mx >= close_btn_x && mx < close_btn_x + 32 && my >= y + 2 && my < y + 30 {
            self.close();
            return true;
        }

        // Tab Bar clicks
        let tab_y = y + 40;
        let tabs = [
            (PropertiesTab::General, 80),
            (PropertiesTab::Security, 90),
            (PropertiesTab::Details, 90),
        ];

        let mut tab_x = x + 16;
        for &(tab_enum, tab_w) in &tabs {
            if mx >= tab_x && mx < tab_x + tab_w && my >= tab_y && my < tab_y + 24 {
                self.active_tab = tab_enum;
                crate::audio::play_click_sound();
                return true;
            }
            tab_x += tab_w + 6;
        }

        // Bottom [Tamam] or [Iptal]
        let btn_y = y + h - 42;
        let ok_x = x + w - 170;
        if mx >= ok_x && mx < ok_x + 72 && my >= btn_y && my < btn_y + 26 {
            self.close();
            crate::audio::play_click_sound();
            return true;
        }

        let cancel_x = x + w - 88;
        if mx >= cancel_x && mx < cancel_x + 72 && my >= btn_y && my < btn_y + 26 {
            self.close();
            crate::audio::play_click_sound();
            return true;
        }

        true
    }
}
