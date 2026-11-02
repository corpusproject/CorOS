//! CorStore - Windows 11 Fluent App Store & Marketplace (`app_store.rs`)
//!
//! Bare-metal package installer & application catalog for CorOS.
//! Allows browsing, installing, and launching ELF64 applications and kernel modules.

use alloc::format;
use crate::display::{Color, DisplayEngine};

pub struct StoreApp {
    pub name: &'static str,
    pub category: &'static str,
    pub version: &'static str,
    pub size_str: &'static str,
    pub rating: u8, // 1..5 stars
    pub desc: &'static str,
    pub is_installed: bool,
    pub package_id: &'static str,
}

pub static STORE_CATALOG: [StoreApp; 6] = [
    StoreApp {
        name: "CorDoom 3D Retro",
        category: "Oyunlar",
        version: "v1.0.4",
        size_str: "2.4 MB",
        rating: 5,
        desc: "Bare-metal raycast 3D FPS motoru, akici 60 FPS",
        is_installed: true,
        package_id: "cordoom",
    },
    StoreApp {
        name: "CorOS Studio Code",
        category: "Gelistirici",
        version: "v1.2.0",
        size_str: "1.8 MB",
        rating: 5,
        desc: "C/Rust/Python syntax vurgulamali kod editoru",
        is_installed: true,
        package_id: "corcode",
    },
    StoreApp {
        name: "Ekran Alintisi Pro",
        category: "Araclar",
        version: "v1.1.0",
        size_str: "480 KB",
        rating: 4,
        desc: "Hizli ekran yakalama ve FAT32 PNG kayit araci",
        is_installed: true,
        package_id: "snipping",
    },
    StoreApp {
        name: "Medya Oynatici Fluent",
        category: "Medya",
        version: "v2.0.1",
        size_str: "850 KB",
        rating: 5,
        desc: "AC'97 44.1kHz spektrum gorsellestiricili calar",
        is_installed: true,
        package_id: "media",
    },
    StoreApp {
        name: "WireGuard VPN",
        category: "Ag & Guvenlik",
        version: "v0.9.8",
        size_str: "1.2 MB",
        rating: 5,
        desc: "Sifreli tunelleme ve peer-to-peer ag kalkani",
        is_installed: false,
        package_id: "wireguard",
    },
    StoreApp {
        name: "Wireshark Packet Sniffer",
        category: "Ag & Guvenlik",
        version: "v2.1.0",
        size_str: "3.1 MB",
        rating: 4,
        desc: "E1000 Gigabit paket analiz ve trafik filtreleme",
        is_installed: false,
        package_id: "wireshark",
    },
];

pub fn render_app_store(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    dark_theme: bool,
    selected_category: usize,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    let bg_col = if dark_theme { Color::rgb(18, 22, 32) } else { Color::rgb(245, 247, 250) };
    let card_bg = if dark_theme { Color::rgb(24, 30, 44) } else { Color::rgb(255, 255, 255) };
    let border_col = if dark_theme { Color::rgb(45, 55, 78) } else { Color::rgb(220, 228, 238) };
    let text_col = if dark_theme { Color::WHITE } else { Color::rgb(15, 23, 42) };
    let muted_col = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // 1. Top Header Banner
    let header_h = 56;
    let header_bg = if dark_theme { Color::rgb(12, 16, 25) } else { Color::rgb(235, 242, 250) };
    engine.fill_rect(ux, body_y, ww, header_h, header_bg);
    engine.draw_line(ux as isize, (body_y + header_h) as isize, (ux + ww) as isize, (body_y + header_h) as isize, border_col);

    engine.draw_string(ux + 20, body_y + 12, "CorStore - Windows 11 Fluent App Marketplace", text_col, 1);
    engine.draw_string(ux + 20, body_y + 32, "CorOS icin onayli 64-bit ikili uygulamalar ve suruculer", muted_col, 1);

    // 2. Categories Tab Bar
    let cat_y = body_y + header_h + 8;
    let categories = ["Hepsi", "Sistem", "Oyunlar", "Gelistirici", "Medya"];
    let mut cur_x = ux + 20;

    for (idx, cat) in categories.iter().enumerate() {
        let is_selected = idx == selected_category;
        let tab_w = engine.string_width(cat) + 20;

        let tab_bg = if is_selected {
            Color::rgb(0, 120, 212) // Windows 11 Accent Blue
        } else if dark_theme {
            Color::rgb(30, 38, 55)
        } else {
            Color::rgb(230, 236, 245)
        };

        let tab_fg = if is_selected { Color::WHITE } else { muted_col };

        engine.fill_rounded_rect(cur_x, cat_y, tab_w, 24, 4, tab_bg);
        engine.draw_string(cur_x + 10, cat_y + 5, cat, tab_fg, 1);

        cur_x += tab_w + 8;
    }

    // 3. Grid of Application Cards (2 columns)
    let grid_y = cat_y + 36;
    let card_w = (ww - 52) / 2;
    let card_h = 88;

    for (i, app) in STORE_CATALOG.iter().enumerate() {
        let col = i % 2;
        let row = i / 2;
        let cx = ux + 18 + col * (card_w + 16);
        let cy = grid_y + row * (card_h + 12);

        if cy + card_h > uy + wh {
            break;
        }

        let is_hover = mx >= cx && mx < cx + card_w && my >= cy && my < cy + card_h;
        let cur_card_bg = if is_hover {
            if dark_theme { Color::rgb(32, 42, 62) } else { Color::rgb(240, 246, 255) }
        } else {
            card_bg
        };

        engine.fill_rounded_rect(cx, cy, card_w, card_h, 6, cur_card_bg);
        engine.draw_rect(cx, cy, card_w, card_h, border_col);

        // App Icon Box (Letter badge)
        let icon_col = match app.category {
            "Oyunlar" => Color::rgb(245, 158, 11),
            "Gelistirici" => Color::rgb(59, 130, 246),
            "Medya" => Color::rgb(236, 72, 153),
            "Araclar" => Color::rgb(16, 185, 129),
            _ => Color::rgb(139, 92, 246),
        };
        engine.fill_rounded_rect(cx + 12, cy + 14, 38, 38, 6, icon_col);
        let initial = &app.name[0..1];
        engine.draw_string(cx + 26, cy + 24, initial, Color::WHITE, 1);

        // App Name, Version & Category
        engine.draw_string(cx + 58, cy + 12, app.name, text_col, 1);
        let meta = format!("{} • {} • {}", app.category, app.version, app.size_str);
        engine.draw_string(cx + 58, cy + 28, &meta, muted_col, 1);
        engine.draw_string(cx + 58, cy + 44, app.desc, muted_col, 1);

        // Action Button: [Baslat] or [Yukle]
        let btn_w = 70;
        let btn_h = 22;
        let btn_x = cx + card_w - btn_w - 12;
        let btn_y = cy + card_h - btn_h - 10;

        if app.is_installed {
            engine.fill_rounded_rect(btn_x, btn_y, btn_w, btn_h, 4, Color::rgb(16, 185, 129));
            engine.draw_string(btn_x + 14, btn_y + 4, "Baslat", Color::WHITE, 1);
        } else {
            engine.fill_rounded_rect(btn_x, btn_y, btn_w, btn_h, 4, Color::rgb(0, 120, 212));
            engine.draw_string(btn_x + 16, btn_y + 4, "Yukle", Color::WHITE, 1);
        }
    }
}
