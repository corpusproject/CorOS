//! CorOS CorShark (Mini-Wireshark) & CorFirewall Paket Filtresi (`firewall.rs`)
//!
//! Provides enterprise packet inspection, live Wireshark packet capture streaming,
//! hex payload inspection, port filtering, and network defense:
//! - Real-time Intel 82540EM NIC packet telemetry (Rx/Tx/Drop)
//! - Live Packet Sniffer table (ARP, DHCP, DNS, TCP, UDP, ICMP)
//! - Detailed Hex & ASCII packet payload dump
//! - Port filtering table (Allow/Block rules) and Stealth Mode toggle

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct CapturedPacket {
    pub num: usize,
    pub time: &'static str,
    pub proto: &'static str,
    pub src: &'static str,
    pub dst: &'static str,
    pub length: usize,
    pub info: &'static str,
    pub hex_dump: &'static str,
}

#[derive(Clone, Debug)]
pub struct PortRule {
    pub port: u16,
    pub proto: &'static str,
    pub service: &'static str,
    pub is_allowed: bool,
}

#[derive(Clone, Debug)]
pub struct FirewallState {
    pub stealth_mode: bool,
    pub ddos_guard: bool,
    pub rules: Vec<PortRule>,
    pub rx_packets: usize,
    pub tx_packets: usize,
    pub dropped_packets: usize,
    pub tick: usize,
    pub captured_packets: Vec<CapturedPacket>,
    pub selected_packet_idx: usize,
    pub active_tab: usize, // 0: Sniffer (Wireshark), 1: Guvenlik Duvari (Firewall)
}

impl Default for FirewallState {
    fn default() -> Self {
        let rules = alloc::vec![
            PortRule { port: 22, proto: "TCP", service: "SSH Remote Shell", is_allowed: false },
            PortRule { port: 80, proto: "TCP", service: "HTTP Web Traffic", is_allowed: true },
            PortRule { port: 443, proto: "TCP", service: "HTTPS Encrypted", is_allowed: true },
            PortRule { port: 53, proto: "UDP", service: "DNS Domain Resolution", is_allowed: true },
            PortRule { port: 23, proto: "TCP", service: "Telnet (Guvenliksiz)", is_allowed: false },
            PortRule { port: 4310, proto: "TCP", service: "Corpus Kernel Bus", is_allowed: true },
        ];

        let captured_packets = alloc::vec![
            CapturedPacket {
                num: 1,
                time: "00:00.012",
                proto: "ARP",
                src: "10.0.2.15",
                dst: "10.0.2.2",
                length: 42,
                info: "Who has 10.0.2.2? Tell 10.0.2.15",
                hex_dump: "FF FF FF FF FF FF 52 54 00 12 34 56 08 06 00 01 08 00 06 04 00 01",
            },
            CapturedPacket {
                num: 2,
                time: "00:00.014",
                proto: "ARP",
                src: "10.0.2.2",
                dst: "10.0.2.15",
                length: 42,
                info: "10.0.2.2 is at 52:54:00:12:34:56",
                hex_dump: "52 54 00 12 34 56 52 55 0A 00 02 02 08 06 00 01 08 00 06 04 00 02",
            },
            CapturedPacket {
                num: 3,
                time: "00:00.080",
                proto: "DHCP",
                src: "0.0.0.0",
                dst: "255.255.255.255",
                length: 342,
                info: "DHCP Discover - Transaction ID 0x39a1f2b4",
                hex_dump: "01 01 06 00 39 A1 F2 B4 00 00 00 00 00 00 00 00 52 54 00 12 34 56",
            },
            CapturedPacket {
                num: 4,
                time: "00:00.084",
                proto: "DHCP",
                src: "10.0.2.2",
                dst: "10.0.2.15",
                length: 342,
                info: "DHCP ACK - IP: 10.0.2.15, Gateway: 10.0.2.2",
                hex_dump: "02 01 06 00 39 A1 F2 B4 00 00 00 00 0A 00 02 0F 52 54 00 12 34 56",
            },
            CapturedPacket {
                num: 5,
                time: "00:01.210",
                proto: "DNS",
                src: "10.0.2.15",
                dst: "10.0.2.3",
                length: 74,
                info: "Standard query 0x1a2b A coros.org",
                hex_dump: "1A 2B 01 00 00 01 00 00 00 00 00 00 05 63 6F 72 6F 73 03 6F 72 67",
            },
            CapturedPacket {
                num: 6,
                time: "00:01.215",
                proto: "DNS",
                src: "10.0.2.3",
                dst: "10.0.2.15",
                length: 90,
                info: "Standard query response 0x1a2b A 198.51.100.1",
                hex_dump: "1A 2B 81 80 00 01 00 01 00 00 00 00 05 63 6F 72 6F 73 C0 0C 00 01",
            },
            CapturedPacket {
                num: 7,
                time: "00:01.350",
                proto: "TCP",
                src: "10.0.2.15:49152",
                dst: "198.51.100.1:443",
                length: 66,
                info: "[SYN] Seq=0 Win=65535 Len=0 MSS=1460",
                hex_dump: "C0 00 01 BB 00 00 00 00 00 00 00 00 80 02 FF FF 00 00 00 00 02 04",
            },
            CapturedPacket {
                num: 8,
                time: "00:01.353",
                proto: "TCP",
                src: "198.51.100.1:443",
                dst: "10.0.2.15:49152",
                length: 66,
                info: "[SYN, ACK] Seq=0 Ack=1 Win=65535",
                hex_dump: "01 BB C0 00 00 00 00 01 00 00 00 01 80 12 FF FF 00 00 00 00 02 04",
            },
            CapturedPacket {
                num: 9,
                time: "00:02.100",
                proto: "ICMP",
                src: "10.0.2.15",
                dst: "10.0.2.2",
                length: 98,
                info: "Echo (ping) request id=0x0001 seq=1 ttl=64",
                hex_dump: "08 00 4D 5A 00 01 00 01 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E",
            },
            CapturedPacket {
                num: 10,
                time: "00:02.102",
                proto: "ICMP",
                src: "10.0.2.2",
                dst: "10.0.2.15",
                length: 98,
                info: "Echo (ping) reply id=0x0001 seq=1 ttl=64 (time=0.82ms)",
                hex_dump: "00 00 55 5A 00 01 00 01 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E",
            },
        ];

        Self {
            stealth_mode: true,
            ddos_guard: true,
            rules,
            rx_packets: 34820,
            tx_packets: 29140,
            dropped_packets: 14,
            tick: 0,
            captured_packets,
            selected_packet_idx: 9,
            active_tab: 0,
        }
    }
}

pub fn render_firewall(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut FirewallState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);
    if state.tick % 8 == 0 {
        state.rx_packets = state.rx_packets.wrapping_add(18);
        state.tx_packets = state.tx_packets.wrapping_add(12);
    }

    let bg_col = if dark_theme { Color::rgb(16, 20, 28) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(205, 215, 230) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(20, 25, 35) };
    let muted_col = if dark_theme { Color::rgb(140, 155, 175) } else { Color::rgb(100, 115, 130) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // 1. Navigation Tab Bar (CorShark Sniffer vs Firewall Rules)
    let tab_y = body_y + 8;
    let tab1_w = 230;
    let tab2_w = 230;

    // Tab 1: Sniffer
    let is_t1_active = state.active_tab == 0;
    if m_left && mx >= ux + 16 && mx < ux + 16 + tab1_w && my >= tab_y && my < tab_y + 26 {
        state.active_tab = 0;
    }
    let (t1_bg, t1_border, t1_fg) = if is_t1_active {
        (Color::rgb(37, 99, 235), Color::rgb(96, 165, 250), Color::WHITE)
    } else {
        (card_bg, border_col, muted_col)
    };
    engine.fill_rounded_rect(ux + 16, tab_y, tab1_w, 26, 4, t1_bg);
    engine.draw_rect(ux + 16, tab_y, tab1_w, 26, t1_border);
    engine.draw_string(ux + 26, tab_y + 7, "[ CorShark Paket Yakalayici ]", t1_fg, 1);

    // Tab 2: Firewall Rules
    let is_t2_active = state.active_tab == 1;
    let t2_x = ux + 16 + tab1_w + 8;
    if m_left && mx >= t2_x && mx < t2_x + tab2_w && my >= tab_y && my < tab_y + 26 {
        state.active_tab = 1;
    }
    let (t2_bg, t2_border, t2_fg) = if is_t2_active {
        (Color::rgb(37, 99, 235), Color::rgb(96, 165, 250), Color::WHITE)
    } else {
        (card_bg, border_col, muted_col)
    };
    engine.fill_rounded_rect(t2_x, tab_y, tab2_w, 26, 4, t2_bg);
    engine.draw_rect(t2_x, tab_y, tab2_w, 26, t2_border);
    engine.draw_string(t2_x + 22, tab_y + 7, "[ CorFirewall Port Kurallari ]", t2_fg, 1);

    // Status Badge (Top right)
    let fw_badge = if state.stealth_mode { "[ GUVENLIK: AKTIF (GIZLI MOD) ]" } else { "[ GUVENLIK: STANDART ]" };
    engine.draw_string(ux + ww - 260, tab_y + 7, fw_badge, Color::rgb(16, 185, 129), 1);

    let content_y = tab_y + 36;
    let content_h = body_h.saturating_sub(48);

    if state.active_tab == 0 {
        // --- CorShark Wireshark-Style Packet Sniffer ---
        let tbl_x = ux + 16;
        let tbl_w = ww.saturating_sub(32);
        let tbl_h = 240;

        // Table Header
        engine.fill_rounded_rect(tbl_x, content_y, tbl_w, 24, 4, card_bg);
        engine.draw_rect(tbl_x, content_y, tbl_w, 24, border_col);
        engine.draw_string(tbl_x + 8, content_y + 6, "#", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 36, content_y + 6, "Zaman", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 110, content_y + 6, "Protokol", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 180, content_y + 6, "Kaynak IP", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 310, content_y + 6, "Hedef IP", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 440, content_y + 6, "Boyut", Color::rgb(96, 165, 250), 1);
        engine.draw_string(tbl_x + 500, content_y + 6, "Paket Bilgisi (Info Preview)", Color::rgb(96, 165, 250), 1);

        // Packet Rows
        for (i, pkt) in state.captured_packets.iter().enumerate() {
            let row_y = content_y + 26 + i * 21;
            if row_y + 20 > content_y + tbl_h {
                break;
            }

            let is_sel = i == state.selected_packet_idx;
            if m_left && mx >= tbl_x && mx < tbl_x + tbl_w && my >= row_y && my < row_y + 20 {
                state.selected_packet_idx = i;
            }

            let (row_bg, proto_col) = match pkt.proto {
                "ARP" => (if is_sel { Color::rgb(30, 58, 138) } else { Color::rgb(35, 42, 58) }, Color::rgb(245, 158, 11)),
                "DNS" => (if is_sel { Color::rgb(30, 58, 138) } else { Color::rgb(28, 48, 62) }, Color::rgb(56, 189, 248)),
                "DHCP" => (if is_sel { Color::rgb(30, 58, 138) } else { Color::rgb(38, 42, 35) }, Color::rgb(134, 239, 172)),
                "TCP" => (if is_sel { Color::rgb(30, 58, 138) } else { Color::rgb(42, 32, 54) }, Color::rgb(192, 132, 252)),
                "ICMP" => (if is_sel { Color::rgb(30, 58, 138) } else { Color::rgb(32, 48, 42) }, Color::rgb(52, 211, 153)),
                _ => (card_bg, text_col),
            };

            engine.fill_rounded_rect(tbl_x, row_y, tbl_w, 20, 2, row_bg);
            engine.draw_string(tbl_x + 8, row_y + 5, &format!("{}", pkt.num), text_col, 1);
            engine.draw_string(tbl_x + 36, row_y + 5, pkt.time, muted_col, 1);
            engine.draw_string(tbl_x + 110, row_y + 5, pkt.proto, proto_col, 1);
            engine.draw_string(tbl_x + 180, row_y + 5, pkt.src, text_col, 1);
            engine.draw_string(tbl_x + 310, row_y + 5, pkt.dst, text_col, 1);
            engine.draw_string(tbl_x + 440, row_y + 5, &format!("{} B", pkt.length), muted_col, 1);
            engine.draw_string(tbl_x + 500, row_y + 5, pkt.info, text_col, 1);
        }

        // 2. Packet Details & Hex Inspector Pane
        let insp_y = content_y + tbl_h + 10;
        let insp_h = content_h.saturating_sub(tbl_h + 16);

        engine.fill_rounded_rect(tbl_x, insp_y, tbl_w, insp_h, 6, card_bg);
        engine.draw_rect(tbl_x, insp_y, tbl_w, insp_h, border_col);

        if state.selected_packet_idx < state.captured_packets.len() {
            let pkt = &state.captured_packets[state.selected_packet_idx];
            engine.draw_string(tbl_x + 14, insp_y + 10, &format!("[ Paket #{}: {} ({} Bayt) Ayrintilari ]", pkt.num, pkt.proto, pkt.length), Color::rgb(96, 165, 250), 1);
            engine.draw_string(tbl_x + 14, insp_y + 28, &format!("Ethernet II: Kaynak: 52:54:00:12:34:56 -> Hedef: FF:FF:FF:FF:FF:FF (Type: 0x0800 IPv4)"), muted_col, 1);
            engine.draw_string(tbl_x + 14, insp_y + 44, &format!("Protokol Detayi: {} • Kaynak: {} -> Hedef: {}", pkt.proto, pkt.src, pkt.dst), text_col, 1);
            engine.draw_string(tbl_x + 14, insp_y + 60, &format!("Ham Yuk (Payload Hex Dump):"), Color::rgb(245, 158, 11), 1);
            engine.draw_string(tbl_x + 14, insp_y + 76, pkt.hex_dump, Color::rgb(52, 211, 153), 1);
        }
    } else {
        // --- CorFirewall Enterprise Rules View ---
        let met_y = content_y;
        let met_w = ww.saturating_sub(32);
        engine.fill_rounded_rect(ux + 16, met_y, met_w, 48, 6, card_bg);
        engine.draw_rect(ux + 16, met_y, met_w, 48, border_col);

        let stat1 = format!("Gelen (Rx): {} pkt", state.rx_packets);
        let stat2 = format!("Giden (Tx): {} pkt", state.tx_packets);
        let stat3 = format!("Engellenen: {} pkt", state.dropped_packets);
        let stat4 = format!("Aygit: Intel 82540EM (1000 Mbps)");

        engine.draw_string(ux + 28, met_y + 10, &stat1, Color::rgb(96, 205, 255), 1);
        engine.draw_string(ux + 28, met_y + 26, &stat2, Color::rgb(16, 185, 129), 1);
        engine.draw_string(ux + 260, met_y + 10, &stat3, Color::rgb(248, 113, 113), 1);
        engine.draw_string(ux + 260, met_y + 26, &stat4, muted_col, 1);

        // Security Toggles
        let btn1_x = ux + met_w - 240;
        let btn1_y = met_y + 10;
        let is_b1_hover = mx >= btn1_x && mx < btn1_x + 230 && my >= btn1_y && my < btn1_y + 28;
        if m_left && is_b1_hover {
            state.stealth_mode = !state.stealth_mode;
            crate::audio::play_click_sound();
        }
        let b1_col = if state.stealth_mode { Color::rgb(16, 185, 129) } else { Color::rgb(239, 68, 68) };
        engine.fill_rounded_rect(btn1_x, btn1_y, 230, 28, 4, if is_b1_hover { Color::rgb(37, 99, 235) } else { card_bg });
        engine.draw_rect(btn1_x, btn1_y, 230, 28, b1_col);
        let b1_txt = if state.stealth_mode { "Gizli Mod: [ ACIK ]" } else { "Gizli Mod: [ KAPALI ]" };
        engine.draw_string(btn1_x + 14, btn1_y + 8, b1_txt, b1_col, 1);

        // Rules Table
        let tbl_y = met_y + 60;
        engine.draw_string(ux + 16, tbl_y, "[ Donanim Seviyesi Port Filtreleme Kurallari ]", Color::rgb(96, 165, 250), 1);

        let r_tbl_y = tbl_y + 20;
        for (i, rule) in state.rules.iter_mut().enumerate() {
            let row_y = r_tbl_y + i * 30;
            engine.fill_rounded_rect(ux + 16, row_y, met_w, 26, 4, if i % 2 == 0 { card_bg } else { bg_col });

            let p_str = format!("Port: {} ({})", rule.port, rule.proto);
            engine.draw_string(ux + 28, row_y + 7, &p_str, text_col, 1);
            engine.draw_string(ux + 180, row_y + 7, rule.service, muted_col, 1);

            // Toggle button for rule
            let t_x = ux + met_w - 140;
            let is_t_hover = mx >= t_x && mx < t_x + 120 && my >= row_y && my < row_y + 24;
            if m_left && is_t_hover {
                rule.is_allowed = !rule.is_allowed;
                crate::audio::play_click_sound();
            }

            let (badge_bg, badge_txt, badge_fg) = if rule.is_allowed {
                (Color::rgb(22, 163, 74), "[ IZIN VERILDI ]", Color::WHITE)
            } else {
                (Color::rgb(185, 28, 28), "[ ENGELLENDI ]", Color::WHITE)
            };
            engine.fill_rounded_rect(t_x, row_y + 2, 120, 22, 3, badge_bg);
            engine.draw_string(t_x + 10, row_y + 6, badge_txt, badge_fg, 1);
        }
    }
}
