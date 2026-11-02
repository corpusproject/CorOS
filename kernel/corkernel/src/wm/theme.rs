//! CorOS Windows 11 Fluent Theme & Color Engine
//!
//! Provides a deep, high-contrast Dark Mica & Slate color palette,
//! visual surface hierarchy, frosted glass styling, and UI layout constants.

use crate::display::{Color, DisplayEngine};

/// Comprehensive theme color palette tailored for professional high-contrast dark mode
#[derive(Clone, Copy, Debug)]
pub struct ThemePalette {
    // Desktop & Backdrop Surfaces
    pub desktop_bg: Color,
    pub taskbar_bg: Color,
    pub taskbar_border: Color,

    // Window Acrylic Surfaces
    pub window_bg: Color,
    pub window_border_active: Color,
    pub window_border_inactive: Color,
    pub titlebar_bg_active: Color,
    pub titlebar_bg_inactive: Color,
    pub titlebar_divider: Color,

    // Cards & Flyouts (Start Menu, Action Center, Context Menus)
    pub card_bg: Color,
    pub card_bg_secondary: Color,
    pub card_border: Color,
    pub flyout_shadow: Color,

    // Interactive States (Hover, Selected, Pressed)
    pub item_hover_bg: Color,
    pub item_selected_bg: Color,
    pub item_selected_border: Color,
    pub border_subtle: Color,

    // Text Hierarchy
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_muted: Color,
    pub text_accent: Color,

    // Vibrant Windows 11 Accents
    pub accent_blue: Color,
    pub accent_cyan: Color,
    pub accent_emerald: Color,
    pub accent_amber: Color,
    pub accent_purple: Color,
    pub accent_rose: Color,
}

impl ThemePalette {
    /// Deep Slate & Dark Mica Palette (High contrast, modern Windows 11 24H2 feel)
    pub const fn dark_mica() -> Self {
        Self {
            desktop_bg: Color::rgb(14, 17, 22),             // Deep Obsidian Slate
            taskbar_bg: Color::rgb(30, 30, 30),             // Windows 11 Dark Acrylic Taskbar
            taskbar_border: Color::rgb(48, 48, 48),         // Subtle Top Taskbar Border

            window_bg: Color::rgb(24, 24, 24),              // Windows 11 Dark Window Body
            window_border_active: Color::rgb(70, 70, 70),   // Elegant Sleek Window Border
            window_border_inactive: Color::rgb(40, 40, 40), // Inactive Window Border
            titlebar_bg_active: Color::rgb(32, 32, 32),     // Active Tab Bar Background
            titlebar_bg_inactive: Color::rgb(22, 22, 22),   // Inactive Titlebar
            titlebar_divider: Color::rgb(44, 44, 44),       // Titlebar Divider

            card_bg: Color::rgb(32, 32, 32),                // Card Container Surface
            card_bg_secondary: Color::rgb(40, 40, 40),      // Nested Card Background
            card_border: Color::rgb(54, 54, 54),            // Card Crisp Border
            flyout_shadow: Color::rgb(8, 8, 8),             // Soft Drop Shadow

            item_hover_bg: Color::rgb(46, 46, 46),          // Subtle Hover Tint
            item_selected_bg: Color::rgb(56, 56, 56),       // Selected Item Capsule
            item_selected_border: Color::rgb(0, 120, 212),  // Accent Border
            border_subtle: Color::rgb(50, 50, 50),          // Subtle Divider Border

            text_primary: Color::rgb(255, 255, 255),        // Crisp Pure White
            text_secondary: Color::rgb(204, 204, 204),      // Slate Silver
            text_muted: Color::rgb(140, 140, 140),          // Dim Cool Gray
            text_accent: Color::rgb(96, 205, 255),          // Windows 11 Cyan Accent Text

            accent_blue: Color::rgb(0, 120, 212),           // Microsoft Blue
            accent_cyan: Color::rgb(96, 205, 255),          // Windows 11 Light Cyan
            accent_emerald: Color::rgb(16, 185, 129),       // Emerald Green
            accent_amber: Color::rgb(245, 158, 11),         // Amber Gold
            accent_purple: Color::rgb(168, 85, 247),        // Royal Purple
            accent_rose: Color::rgb(239, 68, 68),           // Alert Red
        }
    }

    /// Modern Light Fluent Palette (Warm neutral tones with deep accents)
    pub const fn light_fluent() -> Self {
        Self {
            desktop_bg: Color::rgb(241, 245, 249),
            taskbar_bg: Color::rgb(248, 250, 252),
            taskbar_border: Color::rgb(218, 226, 236),

            window_bg: Color::rgb(255, 255, 255),
            window_border_active: Color::rgb(0, 120, 212),
            window_border_inactive: Color::rgb(203, 213, 225),
            titlebar_bg_active: Color::rgb(241, 245, 249),
            titlebar_bg_inactive: Color::rgb(248, 250, 252),
            titlebar_divider: Color::rgb(226, 232, 240),

            card_bg: Color::rgb(255, 255, 255),
            card_bg_secondary: Color::rgb(241, 245, 249),
            card_border: Color::rgb(203, 213, 225),
            flyout_shadow: Color::rgb(180, 190, 205),

            item_hover_bg: Color::rgb(238, 242, 246),
            item_selected_bg: Color::rgb(219, 234, 254),
            item_selected_border: Color::rgb(0, 120, 212),
            border_subtle: Color::rgb(226, 232, 240),

            text_primary: Color::rgb(15, 23, 42),
            text_secondary: Color::rgb(71, 85, 105),
            text_muted: Color::rgb(148, 163, 184),
            text_accent: Color::rgb(0, 120, 212),

            accent_blue: Color::rgb(0, 120, 212),
            accent_cyan: Color::rgb(14, 165, 233),
            accent_emerald: Color::rgb(16, 185, 129),
            accent_amber: Color::rgb(217, 119, 6),
            accent_purple: Color::rgb(147, 51, 234),
            accent_rose: Color::rgb(220, 38, 38),
        }
    }
}

/// Helper functions for drawing modern Windows 11 Fluent UI surfaces
pub struct ThemeRenderer;

impl ThemeRenderer {
    /// Draws a frosted acrylic flyout surface with drop-shadow effect
    pub fn draw_fluent_flyout(
        engine: &mut DisplayEngine,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        radius: usize,
        palette: &ThemePalette,
    ) {
        // 1. Soft Outer Drop Shadow (Simulated with 2 translucent layers)
        if x >= 4 && y >= 4 {
            engine.fill_rounded_rect(x + 3, y + 3, w, h, radius + 2, palette.flyout_shadow);
        }

        // 2. Main Card Surface
        engine.fill_rounded_rect(x, y, w, h, radius, palette.card_bg);

        // 3. Crisp Glass Border
        engine.draw_rect(x, y, w, h, palette.card_border);
    }

    /// Draws a modern interactive ribbon button with icon, label, and hover/click effects
    pub fn draw_ribbon_button(
        engine: &mut DisplayEngine,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        icon: &str,
        label: &str,
        is_hover: bool,
        is_active: bool,
        palette: &ThemePalette,
    ) {
        if is_active {
            engine.fill_rounded_rect(x, y, w, h, 4, palette.item_selected_bg);
            engine.draw_rect(x, y, w, h, palette.item_selected_border);
        } else if is_hover {
            engine.fill_rounded_rect(x, y, w, h, 4, palette.item_hover_bg);
            engine.draw_rect(x, y, w, h, palette.border_subtle);
        }

        let icon_col = if is_active {
            palette.accent_cyan
        } else if is_hover {
            palette.text_primary
        } else {
            palette.text_secondary
        };

        let label_col = if is_active {
            palette.text_primary
        } else if is_hover {
            palette.text_primary
        } else {
            palette.text_secondary
        };

        // Render Icon Tag and Text
        engine.draw_string(x + 6, y + (h.saturating_sub(12)) / 2, icon, icon_col, 1);
        let icon_w = engine.string_width(icon);
        engine.draw_string(x + 10 + icon_w, y + (h.saturating_sub(12)) / 2, label, label_col, 1);
    }

    /// Draws a modern badge with custom color and rounded pill border
    pub fn draw_badge(
        engine: &mut DisplayEngine,
        x: usize,
        y: usize,
        text: &str,
        bg_col: Color,
        fg_col: Color,
    ) {
        let text_w = engine.string_width(text);
        let badge_w = text_w + 12;
        let badge_h = 18;

        engine.fill_rounded_rect(x, y, badge_w, badge_h, 3, bg_col);
        engine.draw_rect(x, y, badge_w, badge_h, fg_col);
        engine.draw_string(x + 6, y + 4, text, fg_col, 1);
    }
}
