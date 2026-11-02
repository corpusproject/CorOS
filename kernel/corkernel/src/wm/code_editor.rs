//! CorOS Studio Code - Bare-Metal Syntax Highlighting Code Editor (`code_editor.rs`)
//!
//! Full-featured developer editor with multi-language keyword highlighting,
//! line gutter, minimap, tabs, and status bar.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

pub struct CodeEditorState {
    pub active_tab: usize, // 0: main.rs, 1: kernel.c, 2: config.toml
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub lines: Vec<String>,
}

impl Default for CodeEditorState {
    fn default() -> Self {
        Self {
            active_tab: 0,
            cursor_line: 12,
            cursor_col: 4,
            lines: alloc::vec![
                String::from("// CorOS Kernel v0.1.0 - Main Entrypoint"),
                String::from("#![no_std]"),
                String::from("#![no_main]"),
                String::from(""),
                String::from("use corboot_info::BootInfo;"),
                String::from("use crate::display::DisplayEngine;"),
                String::from(""),
                String::from("/// Kernel main execution thread"),
                String::from("pub fn kernel_main(info: &BootInfo) -> ! {"),
                String::from("    let mut engine = DisplayEngine::init();"),
                String::from("    engine.clear(Color::rgb(18, 22, 32));"),
                String::from("    log_info(\"CorOS bare-metal desktop online.\");"),
                String::from("    loop {"),
                String::from("        engine.swap_buffers();"),
                String::from("    }"),
                String::from("}"),
            ],
        }
    }
}

pub fn render_code_editor(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    _mx: usize,
    _my: usize,
    dark_theme: bool,
    state: &CodeEditorState,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    let editor_bg = if dark_theme { Color::rgb(30, 30, 30) } else { Color::rgb(255, 255, 255) };
    let gutter_bg = if dark_theme { Color::rgb(37, 37, 38) } else { Color::rgb(243, 243, 243) };
    let gutter_fg = if dark_theme { Color::rgb(133, 133, 133) } else { Color::rgb(160, 160, 160) };
    let status_bg = Color::rgb(0, 122, 204); // VS Code Blue
    let border_col = if dark_theme { Color::rgb(45, 55, 72) } else { Color::rgb(220, 220, 220) };

    engine.fill_rect(ux, body_y, ww, body_h, editor_bg);

    // 1. Tab Bar
    let tab_h = 30;
    let tab_bar_bg = if dark_theme { Color::rgb(40, 40, 40) } else { Color::rgb(236, 236, 236) };
    engine.fill_rect(ux, body_y, ww, tab_h, tab_bar_bg);
    engine.draw_line(ux as isize, (body_y + tab_h) as isize, (ux + ww) as isize, (body_y + tab_h) as isize, border_col);

    let tabs = ["main.rs", "kernel.c", "config.toml"];
    let mut tab_x = ux;
    for (i, title) in tabs.iter().enumerate() {
        let is_active = i == state.active_tab;
        let tab_w = 110;

        let cur_tab_bg = if is_active { editor_bg } else { tab_bar_bg };
        let cur_tab_fg = if is_active { Color::WHITE } else { gutter_fg };

        engine.fill_rect(tab_x, body_y, tab_w, tab_h, cur_tab_bg);
        if is_active {
            engine.draw_line(tab_x as isize, body_y as isize, (tab_x + tab_w) as isize, body_y as isize, Color::rgb(0, 122, 204));
        }
        engine.draw_line((tab_x + tab_w) as isize, body_y as isize, (tab_x + tab_w) as isize, (body_y + tab_h) as isize, border_col);

        engine.draw_string(tab_x + 16, body_y + 8, title, cur_tab_fg, 1);
        tab_x += tab_w;
    }

    // 2. Line Numbers Gutter
    let gutter_w = 42;
    let status_h = 22;
    let content_y = body_y + tab_h;
    let content_h = body_h.saturating_sub(tab_h + status_h);

    engine.fill_rect(ux, content_y, gutter_w, content_h, gutter_bg);
    engine.draw_line((ux + gutter_w) as isize, content_y as isize, (ux + gutter_w) as isize, (content_y + content_h) as isize, border_col);

    // 3. Minimap sidebar (Right edge)
    let minimap_w = 50;
    let minimap_x = ux + ww - minimap_w;
    engine.fill_rect(minimap_x, content_y, minimap_w, content_h, gutter_bg);
    engine.draw_line(minimap_x as isize, content_y as isize, minimap_x as isize, (content_y + content_h) as isize, border_col);

    // 4. Code Lines with Full Syntax Highlighting
    let line_h = 16;
    for (idx, line) in state.lines.iter().enumerate() {
        let ly = content_y + 8 + idx * line_h;
        if ly + line_h > content_y + content_h {
            break;
        }

        // Line number in gutter
        let num_str = format!("{:2}", idx + 1);
        engine.draw_string(ux + 12, ly, &num_str, gutter_fg, 1);

        // Minimap micro-bar
        let mini_w = (line.len() * 2).min(minimap_w.saturating_sub(10));
        let mini_y = content_y + 8 + idx * 4;
        engine.fill_rect(minimap_x + 5, mini_y, mini_w, 2, Color::rgb(90, 105, 125));

        // Render syntax-highlighted tokens
        render_syntax_line(ux + gutter_w + 12, ly, line, engine);
    }

    // 5. Status Bar at Bottom
    let sb_y = uy + wh.saturating_sub(status_h);
    engine.fill_rect(ux, sb_y, ww, status_h, status_bg);
    engine.draw_string(ux + 12, sb_y + 5, "UTF-8", Color::WHITE, 1);
    engine.draw_string(ux + 70, sb_y + 5, "Rust", Color::WHITE, 1);
    let pos_str = format!("Ln {}, Col {}", state.cursor_line, state.cursor_col);
    engine.draw_string(ux + 130, sb_y + 5, &pos_str, Color::WHITE, 1);
    engine.draw_string(ux + 230, sb_y + 5, "Spaces: 4", Color::WHITE, 1);
    engine.draw_string(ux + ww - 100, sb_y + 5, "Git: main*", Color::WHITE, 1);
}

fn render_syntax_line(start_x: usize, y: usize, line: &str, engine: &mut DisplayEngine) {
    if line.trim_start().starts_with("//") || line.trim_start().starts_with("///") {
        // Comment: Slate Gray / Emerald Muted
        engine.draw_string(start_x, y, line, Color::rgb(106, 153, 85), 1);
        return;
    }

    let mut cx = start_x;
    let parts: Vec<&str> = line.split_inclusive(|c: char| !c.is_alphanumeric() && c != '_').collect();

    for token in parts {
        let trimmed = token.trim();
        let color = if is_rust_keyword(trimmed) {
            Color::rgb(86, 156, 214) // Blue / Cyan Keyword
        } else if is_rust_type(trimmed) {
            Color::rgb(78, 201, 176) // Teal Type
        } else if trimmed.starts_with('"') || trimmed.ends_with('"') {
            Color::rgb(206, 145, 120) // Orange String
        } else if trimmed.chars().all(|c| c.is_ascii_digit()) && !trimmed.is_empty() {
            Color::rgb(181, 206, 168) // Light Green Number
        } else if token.contains('(') {
            Color::rgb(220, 220, 170) // Yellow Function Call
        } else {
            Color::rgb(212, 212, 212) // Default Light Text
        };

        engine.draw_string(cx, y, token, color, 1);
        cx += engine.string_width(token);
    }
}

fn is_rust_keyword(w: &str) -> bool {
    matches!(w, "fn" | "let" | "mut" | "pub" | "struct" | "enum" | "match" | "if" | "else" | "return" | "loop" | "use" | "mod" | "impl" | "for" | "in" | "while" | "as")
}

fn is_rust_type(w: &str) -> bool {
    matches!(w, "BootInfo" | "DisplayEngine" | "Color" | "String" | "Vec" | "Option" | "Result" | "usize" | "u32" | "u64" | "i32" | "i64" | "bool" | "Self")
}
