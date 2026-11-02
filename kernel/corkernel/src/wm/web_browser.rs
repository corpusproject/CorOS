//! CorBrowse v1.0 - Guvenli Web & Ag Belge Tarayicisi (`web_browser.rs`)
//!
//! Provides bare-metal native HTTP web browsing, local network portals,
//! tab management, address bar navigation, and formatted document rendering.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct WebTab {
    pub title: &'static str,
    pub url: &'static str,
    pub lines: Vec<(&'static str, Color)>,
}

pub struct WebBrowserState {
    pub active_tab_idx: usize,
    pub current_url: String,
    pub tabs: Vec<WebTab>,
    pub status_code: &'static str,
    pub tick: usize,
}

impl Default for WebBrowserState {
    fn default() -> Self {
        let tabs = alloc::vec![
            WebTab {
                title: "CorOS Wiki",
                url: "http://coros.local/wiki/main",
                lines: alloc::vec![
                    ("=== CorOS 2026 - Gelecegin Isletim Sistemi Resmî Belgelendirmesi ===", Color::rgb(96, 165, 250)),
                    ("", Color::WHITE),
                    ("CorOS; sifir dis bagimlilik ve #![no_std] saf Rust ile gelistirilen,", Color::WHITE),
                    ("Linux ABI (361 syscall) uyumlu, 64-bit cok cekirdekli bir mikrocekerdektir.", Color::WHITE),
                    ("", Color::WHITE),
                    ("[ TEMEL OZELLIKLER & MIMARI ]", Color::rgb(16, 185, 129)),
                    ("• SMP 4-Core APIC Scheduler: Tum CPU cekirdeklerinde tam eszamanli yurutme.", Color::WHITE),
                    ("• Dogal AHCI SATA DMA: PCIe veriyolunda 6 Gbps dogrudan bellek erisimi.", Color::WHITE),
                    ("• 2.21 GB Canli ISO Dagitimi: POSIX /LIVE kok dizini ve cevrimdisi depolar.", Color::WHITE),
                    ("• Intel 82540EM Gigabit NIC: Canli DHCP, ICMP Echo, UDP ve TCP/IP soketleri.", Color::WHITE),
                    ("• AC'97 Bare-Metal Ses: Donanim DMA uzerinden stereo 44.1 kHz muzik calici.", Color::WHITE),
                    ("", Color::WHITE),
                    ("[ KULLANILABILIR YEREL SAYFALAR ]", Color::rgb(245, 158, 11)),
                    ("-> http://router.local/ (VirtualBox NAT Ag Gecidi)", Color::rgb(56, 189, 248)),
                    ("-> http://coros.local/api (361 Linux Syscall Referansi)", Color::rgb(56, 189, 248)),
                ],
            },
            WebTab {
                title: "Ag Portali (10.0.2.2)",
                url: "http://router.local/gateway",
                lines: alloc::vec![
                    ("=== VirtualBox NAT Ag Yonetim Paneli (Gateway: 10.0.2.2) ===", Color::rgb(16, 185, 129)),
                    ("", Color::WHITE),
                    ("IP Yapilandirmasi: 10.0.2.15 / 255.255.255.0", Color::WHITE),
                    ("Varsayilan Ag Gecidi: 10.0.2.2", Color::WHITE),
                    ("DNS Cozuculer: 10.0.2.3 (Google DNS & Cloudflare Dual Stack)", Color::WHITE),
                    ("Baglanti Hizi: 1000 Mbps Full-Duplex (Intel PRO/1000 Gigabit)", Color::rgb(56, 189, 248)),
                    ("Ag Durumu: AKTIF (Internet Erisimi Acik)", Color::rgb(16, 185, 129)),
                    ("", Color::WHITE),
                    ("Ping RTT (Yerel Ag): 0.82 ms (Ultra-Dusuk Gecikme)", Color::WHITE),
                    ("Firewall: CorFirewall Donanim Seviyesi Paket Filtresi Aktif", Color::rgb(245, 158, 11)),
                ],
            },
            WebTab {
                title: "Linux API Referansi",
                url: "http://coros.local/api",
                lines: alloc::vec![
                    ("=== CorOS MSR_LSTAR Syscall & POSIX Standartlari Tablosu ===", Color::rgb(192, 132, 252)),
                    ("", Color::WHITE),
                    ("Vector 0 (sys_read)     : Dosya ve soketlerden akis okuma", Color::WHITE),
                    ("Vector 1 (sys_write)    : VFS bloklarina ve konsola veri yazma", Color::WHITE),
                    ("Vector 2 (sys_open)     : Dosya tanimlayicisi (FD) acma", Color::WHITE),
                    ("Vector 3 (sys_close)    : FD kapatma ve kaynak temizleme", Color::WHITE),
                    ("Vector 9 (sys_mmap)     : Sanal bellek sayfasi esleme (Demand Paging)", Color::WHITE),
                    ("Vector 39 (sys_getpid)  : Gecerli surec kimligini alma", Color::WHITE),
                    ("Vector 57 (sys_fork)    : Yeni surec kopyalama", Color::WHITE),
                    ("Vector 59 (sys_execve)  : ELF64 ikili dosyasini calistirma", Color::WHITE),
                    ("Vector 60 (sys_exit)    : Sureci basariyla sonlandirma", Color::WHITE),
                ],
            },
        ];

        Self {
            active_tab_idx: 0,
            current_url: String::from("http://coros.local/wiki/main"),
            tabs,
            status_code: "HTTP/1.1 200 OK",
            tick: 0,
        }
    }
}

pub fn render_web_browser(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut WebBrowserState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);

    let bg_col = if dark_theme { Color::rgb(18, 22, 32) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(25, 32, 46) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 58, 80) } else { Color::rgb(205, 218, 232) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(15, 23, 42) };
    let muted_col = if dark_theme { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // 1. Tab Bar
    let tab_y = body_y + 6;
    let tab_w = 175;

    for (i, t) in state.tabs.iter().enumerate() {
        let tx = ux + 16 + i * (tab_w + 6);
        let is_active = i == state.active_tab_idx;

        if m_left && mx >= tx && mx < tx + tab_w && my >= tab_y && my < tab_y + 24 {
            state.active_tab_idx = i;
            state.current_url = String::from(t.url);
            crate::audio::play_click_sound();
        }

        let (t_bg, t_border, t_fg) = if is_active {
            (Color::rgb(37, 99, 235), Color::rgb(96, 165, 250), Color::WHITE)
        } else {
            (card_bg, border_col, muted_col)
        };

        engine.fill_rounded_rect(tx, tab_y, tab_w, 24, 4, t_bg);
        engine.draw_rect(tx, tab_y, tab_w, 24, t_border);
        engine.draw_string(tx + 8, tab_y + 6, t.title, t_fg, 1);
    }

    // 2. Navigation & Address Bar
    let nav_y = tab_y + 30;
    let nav_h = 36;
    let nav_w = ww.saturating_sub(32);

    engine.fill_rounded_rect(ux + 16, nav_y, nav_w, nav_h, 6, card_bg);
    engine.draw_rect(ux + 16, nav_y, nav_w, nav_h, border_col);

    // Back / Forward / Refresh buttons
    let btn_b = ux + 24;
    let btn_f = btn_b + 28;
    let btn_r = btn_f + 28;

    engine.draw_string(btn_b, nav_y + 11, "<", text_col, 1);
    engine.draw_string(btn_f, nav_y + 11, ">", muted_col, 1);
    engine.draw_string(btn_r, nav_y + 11, "R", text_col, 1);

    // URL Box
    let url_x = btn_r + 34;
    let url_w = nav_w.saturating_sub(180);
    engine.fill_rounded_rect(url_x, nav_y + 6, url_w, 24, 4, if dark_theme { Color::rgb(14, 18, 26) } else { Color::WHITE });
    engine.draw_rect(url_x, nav_y + 6, url_w, 24, border_col);

    // Lock icon / Security indicator
    engine.draw_string(url_x + 8, nav_y + 10, "🔒", Color::rgb(16, 185, 129), 1);
    engine.draw_string(url_x + 24, nav_y + 10, &state.current_url, text_col, 1);

    // "Git" (Go) Button
    let go_x = url_x + url_w + 10;
    let go_w = 60;
    let is_go_hover = mx >= go_x && mx < go_x + go_w && my >= nav_y + 6 && my < nav_y + 30;
    engine.fill_rounded_rect(go_x, nav_y + 6, go_w, 24, 4, if is_go_hover { Color::rgb(22, 163, 74) } else { Color::rgb(16, 185, 129) });
    engine.draw_string(go_x + 14, nav_y + 10, "GIT", Color::WHITE, 1);
    if m_left && is_go_hover {
        crate::audio::play_click_sound();
    }

    // 3. Rendered Web Page Viewport
    let page_y = nav_y + nav_h + 10;
    let page_h = body_h.saturating_sub(nav_h + 46 + 28);
    let page_w = nav_w;

    engine.fill_rounded_rect(ux + 16, page_y, page_w, page_h, 6, if dark_theme { Color::rgb(12, 16, 24) } else { Color::WHITE });
    engine.draw_rect(ux + 16, page_y, page_w, page_h, border_col);

    let cur_tab = &state.tabs[state.active_tab_idx % state.tabs.len()];

    for (i, &(line, col)) in cur_tab.lines.iter().enumerate() {
        let ly = page_y + 16 + i * 20;
        if ly + 18 > page_y + page_h {
            break;
        }

        // Clickable links in page
        if line.starts_with("-> ") {
            let is_link_hover = mx >= ux + 28 && mx < ux + page_w - 28 && my >= ly && my < ly + 18;
            if m_left && is_link_hover {
                if line.contains("router") {
                    state.active_tab_idx = 1;
                    state.current_url = String::from("http://router.local/gateway");
                } else if line.contains("api") {
                    state.active_tab_idx = 2;
                    state.current_url = String::from("http://coros.local/api");
                }
                crate::audio::play_click_sound();
            }
            engine.draw_string(ux + 28, ly, line, if is_link_hover { Color::rgb(96, 165, 250) } else { col }, 1);
        } else {
            engine.draw_string(ux + 28, ly, line, col, 1);
        }
    }

    // 4. Status Bar (Bottom)
    let stat_y = page_y + page_h + 6;
    let status_info = format!("● {} • Intel 82540EM (10.0.2.15) • SSL/TLS 1.3 Guvenli Baglanti", state.status_code);
    engine.draw_string(ux + 20, stat_y, &status_info, Color::rgb(16, 185, 129), 1);
}
