//! CorOS Windows 11 Fluent File Explorer Context Menu Subsystem
//!
//! Replicates the authentic Windows 11 desktop context menu design:
//! - Top horizontal quick-action bar: [Kes], [Kopyala], [Yeniden adlandır], [Sil]
//! - Separator line
//! - Vertical action items with icons and right-aligned shortcuts:
//!   - Aç (Enter)
//!   - Hızlı erişime sabitle
//!   - Başlangıç'a sabitle
//!   - Ring 3 Modunda Çalıştır (F5) [for ELF files]
//!   - Terminalde Aç (Corpus Terminal)
//!   - Yol olarak kopyala (Ctrl+Shift+C)
//!   - Özellikler (Alt+Enter)
//!   - Daha fazla seçenek göster

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use super::theme::ThemePalette;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileContextAction {
    Open,
    Cut,
    Copy,
    Paste,
    Rename,
    Delete,
    PinQuickAccess,
    PinStart,
    OpenInTerminal,
    CopyPath,
    NewTextFile,
    RunRing3Elf,
    EditWithPaint,
    Properties,
    ShowMoreOptions,
}

#[derive(Clone, Debug)]
pub struct ContextMenuItem {
    pub action: FileContextAction,
    pub icon_tag: &'static str,
    pub label: &'static str,
    pub shortcut: &'static str,
    pub is_danger: bool,
    pub is_disabled: bool,
    pub is_separator_after: bool,
}

#[derive(Clone, Debug)]
pub struct TopStripButton {
    pub action: FileContextAction,
    pub icon_tag: &'static str,
    pub label: &'static str,
    pub is_disabled: bool,
    pub is_danger: bool,
}

#[derive(Clone, Debug)]
pub struct FileContextMenu {
    pub is_open: bool,
    pub x: usize,
    pub y: usize,
    pub target_file_idx: Option<usize>,
    pub target_file_name: String,
    pub is_blank_area: bool,
    pub has_clipboard_file: bool,
    pub is_target_dir: bool,
    pub is_target_elf: bool,
    pub is_target_png: bool,
    pub top_buttons: Vec<TopStripButton>,
    pub items: Vec<ContextMenuItem>,
    pub hovered_top_idx: Option<usize>,
    pub hovered_idx: Option<usize>,
}

impl FileContextMenu {
    pub fn new() -> Self {
        Self {
            is_open: false,
            x: 0,
            y: 0,
            target_file_idx: None,
            target_file_name: String::new(),
            is_blank_area: false,
            has_clipboard_file: false,
            is_target_dir: false,
            is_target_elf: false,
            is_target_png: false,
            top_buttons: Vec::new(),
            items: Vec::new(),
            hovered_top_idx: None,
            hovered_idx: None,
        }
    }

    /// Opens the context menu for a specific file or folder
    pub fn open_for_file(
        &mut self,
        x: usize,
        y: usize,
        file_idx: usize,
        file_name: &str,
        is_dir: bool,
        has_clipboard: bool,
    ) {
        self.is_open = true;
        self.x = x;
        self.y = y;
        self.target_file_idx = Some(file_idx);
        self.target_file_name = String::from(file_name);
        self.is_blank_area = false;
        self.has_clipboard_file = has_clipboard;
        self.is_target_dir = is_dir;
        self.is_target_elf = file_name.to_ascii_uppercase().ends_with(".ELF") || file_name == "CYBER3D.BIN";
        self.is_target_png = file_name.to_ascii_uppercase().ends_with(".PNG");
        self.hovered_top_idx = None;
        self.hovered_idx = None;

        self.rebuild_items();
    }

    /// Opens the context menu for blank/empty folder area
    pub fn open_for_blank_area(&mut self, x: usize, y: usize, has_clipboard: bool) {
        self.is_open = true;
        self.x = x;
        self.y = y;
        self.target_file_idx = None;
        self.target_file_name.clear();
        self.is_blank_area = true;
        self.has_clipboard_file = has_clipboard;
        self.is_target_dir = false;
        self.is_target_elf = false;
        self.is_target_png = false;
        self.hovered_top_idx = None;
        self.hovered_idx = None;

        self.rebuild_items();
    }

    /// Closes the context menu
    pub fn close(&mut self) {
        self.is_open = false;
        self.target_file_idx = None;
        self.hovered_top_idx = None;
        self.hovered_idx = None;
    }

    /// Rebuilds the action list dynamically based on target file properties
    fn rebuild_items(&mut self) {
        let mut top = Vec::new();
        let mut list = Vec::new();

        if self.is_blank_area {
            // Blank folder background menu
            list.push(ContextMenuItem {
                action: FileContextAction::Paste,
                icon_tag: "[V]",
                label: "Yapistir",
                shortcut: "Ctrl+V",
                is_danger: false,
                is_disabled: !self.has_clipboard_file,
                is_separator_after: false,
            });
            list.push(ContextMenuItem {
                action: FileContextAction::NewTextFile,
                icon_tag: "[+]",
                label: "Yeni Metin Belgesi",
                shortcut: "Ctrl+N",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });
            list.push(ContextMenuItem {
                action: FileContextAction::OpenInTerminal,
                icon_tag: "[>]",
                label: "Terminalde Ac (Corpus)",
                shortcut: "",
                is_danger: false,
                is_disabled: false,
                is_separator_after: true,
            });
            list.push(ContextMenuItem {
                action: FileContextAction::Properties,
                icon_tag: "[i]",
                label: "Klasor Ozellikleri",
                shortcut: "Alt+Enter",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });
        } else {
            // Top horizontal quick-action bar: [Kes], [Kopyala], [Yeniden adlandır], [Sil]
            top.push(TopStripButton {
                action: FileContextAction::Cut,
                icon_tag: "[X]",
                label: "Kes",
                is_disabled: self.is_target_dir,
                is_danger: false,
            });
            top.push(TopStripButton {
                action: FileContextAction::Copy,
                icon_tag: "[C]",
                label: "Kopyala",
                is_disabled: self.is_target_dir,
                is_danger: false,
            });
            top.push(TopStripButton {
                action: FileContextAction::Rename,
                icon_tag: "[A]",
                label: "Yeniden\nadlandir",
                is_disabled: self.target_file_name == "BOOTX64.EFI" || self.target_file_name == "CORKERNEL.EFI",
                is_danger: false,
            });
            top.push(TopStripButton {
                action: FileContextAction::Delete,
                icon_tag: "[D]",
                label: "Sil",
                is_disabled: self.is_target_dir || self.target_file_name == "BOOTX64.EFI" || self.target_file_name == "CORKERNEL.EFI",
                is_danger: true,
            });

            // 1. Aç (Open)
            list.push(ContextMenuItem {
                action: FileContextAction::Open,
                icon_tag: "[>]",
                label: if self.is_target_dir { "Klasoru Ac" } else { "Ac" },
                shortcut: "Enter",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });

            // 2. Hızlı erişime sabitle
            list.push(ContextMenuItem {
                action: FileContextAction::PinQuickAccess,
                icon_tag: "[*]",
                label: "Hizli erisime sabitle",
                shortcut: "",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });

            // 3. Başlangıç'a sabitle
            list.push(ContextMenuItem {
                action: FileContextAction::PinStart,
                icon_tag: "[^]",
                label: "Baslangic'a sabitle",
                shortcut: "",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });

            // 4. Ring 3 Executable (if ELF)
            if self.is_target_elf {
                list.push(ContextMenuItem {
                    action: FileContextAction::RunRing3Elf,
                    icon_tag: "[E]",
                    label: "Ring 3 Modunda Calistir",
                    shortcut: "F5",
                    is_danger: false,
                    is_disabled: false,
                    is_separator_after: false,
                });
            }

            // 5. Paint (if PNG)
            if self.is_target_png {
                list.push(ContextMenuItem {
                    action: FileContextAction::EditWithPaint,
                    icon_tag: "[P]",
                    label: "Paint ile Duzenle",
                    shortcut: "",
                    is_danger: false,
                    is_disabled: false,
                    is_separator_after: false,
                });
            }

            // 6. Yol olarak kopyala
            list.push(ContextMenuItem {
                action: FileContextAction::CopyPath,
                icon_tag: "[Y]",
                label: "Yol olarak kopyala",
                shortcut: "Ctrl+Shift+C",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });

            // 7. Özellikler
            list.push(ContextMenuItem {
                action: FileContextAction::Properties,
                icon_tag: "[i]",
                label: "Ozellikler",
                shortcut: "Alt+Enter",
                is_danger: false,
                is_disabled: false,
                is_separator_after: true,
            });

            // 8. Terminalde Aç (Corpus Terminal)
            list.push(ContextMenuItem {
                action: FileContextAction::OpenInTerminal,
                icon_tag: "[T]",
                label: "Terminalde Ac (Corpus)",
                shortcut: "",
                is_danger: false,
                is_disabled: false,
                is_separator_after: true,
            });

            // 9. Daha fazla seçenek göster
            list.push(ContextMenuItem {
                action: FileContextAction::ShowMoreOptions,
                icon_tag: "[+]",
                label: "Daha fazla secenek goster",
                shortcut: "",
                is_danger: false,
                is_disabled: false,
                is_separator_after: false,
            });
        }

        self.top_buttons = top;
        self.items = list;
    }

    /// Renders the context menu card onto the screen
    pub fn render(
        &mut self,
        engine: &mut DisplayEngine,
        screen_w: usize,
        screen_h: usize,
        mx: usize,
        my: usize,
        palette: &ThemePalette,
    ) {
        if !self.is_open || (self.items.is_empty() && self.top_buttons.is_empty()) {
            return;
        }

        let menu_w = 264;
        let top_strip_h = if self.top_buttons.is_empty() { 0 } else { 44 };
        let item_h = 26;
        let pad_y = 6;
        let mut total_h = pad_y * 2 + top_strip_h;
        for it in &self.items {
            total_h += item_h;
            if it.is_separator_after {
                total_h += 7;
            }
        }

        // Clamp menu coordinates so it doesn't overflow outside screen
        let cx = self.x.min(screen_w.saturating_sub(menu_w + 8));
        let cy = self.y.min(screen_h.saturating_sub(total_h + 48));

        // 1. Soft Shadow & Card Surface
        if cx >= 3 && cy >= 3 {
            engine.fill_rounded_rect(cx + 3, cy + 3, menu_w, total_h, 8, palette.flyout_shadow);
        }
        engine.fill_rounded_rect(cx, cy, menu_w, total_h, 6, palette.card_bg);
        engine.draw_rect(cx, cy, menu_w, total_h, palette.card_border);

        let mut cur_y = cy + pad_y;
        self.hovered_top_idx = None;
        self.hovered_idx = None;

        // 2. Render Top Quick-Action Strip (Kes, Kopyala, Yeniden adlandır, Sil)
        if !self.top_buttons.is_empty() {
            let num_btns = self.top_buttons.len();
            let btn_w = (menu_w - 12) / num_btns;

            for (idx, btn) in self.top_buttons.iter().enumerate() {
                let bx = cx + 6 + idx * btn_w;
                let by = cur_y;
                let is_h = mx >= bx && mx < bx + btn_w && my >= by && my < by + 36;

                if is_h && !btn.is_disabled {
                    self.hovered_top_idx = Some(idx);
                    let h_bg = if btn.is_danger {
                        Color::rgb(75, 20, 20)
                    } else {
                        palette.item_hover_bg
                    };
                    engine.fill_rounded_rect(bx + 1, by, btn_w - 2, 36, 4, h_bg);
                    engine.draw_rect(bx + 1, by, btn_w - 2, 36, palette.border_subtle);
                }

                let (icon_col, label_col) = if btn.is_disabled {
                    (palette.text_muted, palette.text_muted)
                } else if btn.is_danger {
                    (palette.accent_rose, palette.accent_rose)
                } else if is_h {
                    (palette.accent_cyan, palette.text_primary)
                } else {
                    (palette.accent_cyan, palette.text_secondary)
                };

                // Draw Icon centered
                let icon_w = engine.string_width(btn.icon_tag);
                let ix = bx + (btn_w.saturating_sub(icon_w)) / 2;
                engine.draw_string(ix, by + 4, btn.icon_tag, icon_col, 1);

                // Draw Subtitle Label
                if btn.label.contains('\n') {
                    let mut parts = btn.label.split('\n');
                    if let Some(p1) = parts.next() {
                        let w1 = engine.string_width(p1);
                        let l1 = bx + (btn_w.saturating_sub(w1)) / 2;
                        engine.draw_string(l1, by + 16, p1, label_col, 1);
                    }
                    if let Some(p2) = parts.next() {
                        let w2 = engine.string_width(p2);
                        let l2 = bx + (btn_w.saturating_sub(w2)) / 2;
                        engine.draw_string(l2, by + 26, p2, label_col, 1);
                    }
                } else {
                    let lbl_w = engine.string_width(btn.label);
                    let lx = bx + (btn_w.saturating_sub(lbl_w)) / 2;
                    engine.draw_string(lx, by + 20, btn.label, label_col, 1);
                }

                // Divider line between top strip buttons
                if idx + 1 < num_btns {
                    engine.draw_vline(bx + btn_w, by + 6, 26, palette.border_subtle);
                }
            }

            cur_y += 40;
            engine.draw_hline(cx + 8, cur_y + 2, menu_w - 16, palette.card_border);
            cur_y += 6;
        }

        // 3. Render Vertical Items List
        for (idx, item) in self.items.iter().enumerate() {
            let is_h = mx >= cx + 4 && mx < cx + menu_w - 4 && my >= cur_y && my < cur_y + item_h;
            if is_h && !item.is_disabled {
                self.hovered_idx = Some(idx);
                let h_bg = if item.is_danger {
                    Color::rgb(75, 20, 20)
                } else {
                    palette.item_hover_bg
                };
                engine.fill_rounded_rect(cx + 4, cur_y, menu_w - 8, item_h, 4, h_bg);
                engine.draw_rect(cx + 4, cur_y, menu_w - 8, item_h, palette.border_subtle);
            }

            let (icon_col, label_col, sc_col) = if item.is_disabled {
                (palette.text_muted, palette.text_muted, palette.text_muted)
            } else if item.is_danger {
                (palette.accent_rose, palette.accent_rose, palette.text_muted)
            } else if is_h {
                (palette.accent_cyan, palette.text_primary, palette.text_secondary)
            } else {
                (palette.accent_cyan, palette.text_primary, palette.text_muted)
            };

            // Draw Icon Tag
            engine.draw_string(cx + 12, cur_y + 6, item.icon_tag, icon_col, 1);

            // Draw Action Label
            engine.draw_string(cx + 38, cur_y + 6, item.label, label_col, 1);

            // Draw Shortcut text aligned to right
            if !item.shortcut.is_empty() {
                let sc_w = engine.string_width(item.shortcut);
                let sc_x = cx + menu_w - 14 - sc_w;
                engine.draw_string(sc_x, cur_y + 6, item.shortcut, sc_col, 1);
            }

            cur_y += item_h;

            // Draw divider line if needed
            if item.is_separator_after {
                engine.draw_hline(cx + 8, cur_y + 3, menu_w - 16, palette.card_border);
                cur_y += 7;
            }
        }
    }

    /// Handles click on context menu, returning the triggered action if any
    pub fn handle_click(&mut self, mx: usize, my: usize, screen_w: usize, screen_h: usize) -> Option<FileContextAction> {
        if !self.is_open || (self.items.is_empty() && self.top_buttons.is_empty()) {
            return None;
        }

        let menu_w = 264;
        let top_strip_h = if self.top_buttons.is_empty() { 0 } else { 44 };
        let item_h = 26;
        let pad_y = 6;
        let mut total_h = pad_y * 2 + top_strip_h;
        for it in &self.items {
            total_h += item_h;
            if it.is_separator_after {
                total_h += 7;
            }
        }

        let cx = self.x.min(screen_w.saturating_sub(menu_w + 8));
        let cy = self.y.min(screen_h.saturating_sub(total_h + 48));

        // Click outside closes the menu
        if !(mx >= cx && mx < cx + menu_w && my >= cy && my < cy + total_h) {
            self.close();
            return None;
        }

        let mut cur_y = cy + pad_y;

        // 1. Check click in top strip buttons
        if !self.top_buttons.is_empty() {
            let num_btns = self.top_buttons.len();
            let btn_w = (menu_w - 12) / num_btns;

            for (idx, btn) in self.top_buttons.iter().enumerate() {
                let bx = cx + 6 + idx * btn_w;
                let by = cur_y;
                let hit = mx >= bx && mx < bx + btn_w && my >= by && my < by + 36;
                if hit {
                    if !btn.is_disabled {
                        let act = btn.action;
                        self.close();
                        return Some(act);
                    } else {
                        return None;
                    }
                }
            }
            cur_y += 38 + 6;
        }

        // 2. Check click in vertical items list
        for item in &self.items {
            let hit = mx >= cx + 4 && mx < cx + menu_w - 4 && my >= cur_y && my < cur_y + item_h;
            if hit {
                if !item.is_disabled {
                    let act = item.action;
                    self.close();
                    return Some(act);
                } else {
                    return None;
                }
            }
            cur_y += item_h;
            if item.is_separator_after {
                cur_y += 7;
            }
        }

        None
    }
}
