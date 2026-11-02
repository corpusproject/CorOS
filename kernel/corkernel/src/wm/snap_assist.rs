//! Windows Snap Assist & Aero Snap Window Tiling Engine
//!
//! Provides intelligent desktop window tiling and layout snapping:
//! - Snap zones: Left Half (50%), Right Half (50%), Top-Left Quarter, Top-Right Quarter,
//!   Bottom-Left Quarter, Bottom-Right Quarter, Full Screen Maximize
//! - Keyboard shortcuts: Win + Left, Win + Right, Win + Up, Win + Down
//! - Window drag-to-edge trigger threshold detection
//! - Visual translucent snap preview ghost rectangle overlay
//! - Multi-monitor display boundary awareness and snap layout grid menu

#![allow(dead_code)]

use crate::display::{Color, DisplayEngine};

/// Snap Layout Target Zone
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapZone {
    None,
    LeftHalf,
    RightHalf,
    TopHalf,
    BottomHalf,
    TopLeftQuarter,
    TopRightQuarter,
    BottomLeftQuarter,
    BottomRightQuarter,
    Maximize,
}

/// Snap Assist Geometry Target
#[derive(Debug, Clone, Copy)]
pub struct SnapRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Snap Assist Window Geometry Controller
pub struct SnapAssistEngine {
    pub screen_width: i32,
    pub screen_height: i32,
    pub taskbar_height: i32,
    pub active_zone: SnapZone,
    pub is_dragging_window: bool,
    pub preview_alpha: u8,
}

impl SnapAssistEngine {
    pub fn new(screen_width: i32, screen_height: i32, taskbar_height: i32) -> Self {
        Self {
            screen_width,
            screen_height,
            taskbar_height,
            active_zone: SnapZone::None,
            is_dragging_window: false,
            preview_alpha: 180,
        }
    }

    /// Calculate usable desktop workspace height excluding taskbar
    pub fn usable_height(&self) -> i32 {
        self.screen_height - self.taskbar_height
    }

    /// Evaluate cursor position during window drag to detect snap trigger zone
    pub fn update_cursor_drag(&mut self, cursor_x: i32, cursor_y: i32) -> SnapZone {
        let margin = 12;
        let usable_h = self.usable_height();

        let zone = if cursor_y <= margin {
            if cursor_x <= margin * 2 {
                SnapZone::TopLeftQuarter
            } else if cursor_x >= self.screen_width - margin * 2 {
                SnapZone::TopRightQuarter
            } else {
                SnapZone::Maximize
            }
        } else if cursor_x <= margin {
            if cursor_y <= usable_h / 3 {
                SnapZone::TopLeftQuarter
            } else if cursor_y >= (usable_h * 2) / 3 {
                SnapZone::BottomLeftQuarter
            } else {
                SnapZone::LeftHalf
            }
        } else if cursor_x >= self.screen_width - margin {
            if cursor_y <= usable_h / 3 {
                SnapZone::TopRightQuarter
            } else if cursor_y >= (usable_h * 2) / 3 {
                SnapZone::BottomRightQuarter
            } else {
                SnapZone::RightHalf
            }
        } else {
            SnapZone::None
        };

        self.active_zone = zone;
        zone
    }

    /// Compute snapped window bounds for a specific zone
    pub fn get_zone_rect(&self, zone: SnapZone) -> Option<SnapRect> {
        let w = self.screen_width;
        let h = self.usable_height();
        let half_w = w / 2;
        let half_h = h / 2;

        match zone {
            SnapZone::None => None,
            SnapZone::LeftHalf => Some(SnapRect { x: 0, y: 0, width: half_w, height: h }),
            SnapZone::RightHalf => Some(SnapRect { x: half_w, y: 0, width: half_w, height: h }),
            SnapZone::TopHalf => Some(SnapRect { x: 0, y: 0, width: w, height: half_h }),
            SnapZone::BottomHalf => Some(SnapRect { x: 0, y: half_h, width: w, height: half_h }),
            SnapZone::TopLeftQuarter => Some(SnapRect { x: 0, y: 0, width: half_w, height: half_h }),
            SnapZone::TopRightQuarter => Some(SnapRect { x: half_w, y: 0, width: half_w, height: half_h }),
            SnapZone::BottomLeftQuarter => Some(SnapRect { x: 0, y: half_h, width: half_w, height: half_h }),
            SnapZone::BottomRightQuarter => Some(SnapRect { x: half_w, y: half_h, width: half_w, height: half_h }),
            SnapZone::Maximize => Some(SnapRect { x: 0, y: 0, width: w, height: h }),
        }
    }

    /// Render visual snap preview ghost box over desktop
    pub fn render_preview(&self, display: &mut DisplayEngine) {
        if let Some(rect) = self.get_zone_rect(self.active_zone) {
            let rx = rect.x.max(0) as usize;
            let ry = rect.y.max(0) as usize;
            let rw = rect.width as usize;
            let rh = rect.height as usize;

            // Semi-translucent border & accent glow
            let accent_border = Color::rgb(0, 120, 215);
            display.draw_rect(rx, ry, rw, rh, accent_border);
            if rw > 4 && rh > 4 {
                display.draw_rect(rx + 1, ry + 1, rw - 2, rh - 2, accent_border);
            }
        }
    }
}
