//! Windows 11 Style Boot Splash Screen
//!
//! Renders an authentic Windows 11 boot sequence:
//! - Pure solid black background (#000000)
//! - Horizontally centered Fluent 3D Star logo (96x96 ARGB)
//! - Characteristic Windows 11 rotating circular progress dots below the logo
//! - CMOS RTC hardware-timed 2-second animation sequence transitioning smoothly into the desktop

use crate::display::{Color, DisplayEngine};
use crate::wm::icons::ICON_BOOT_STAR_BMP;

/// Renders a single antialiased glowing spinner dot
fn draw_spinner_dot(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    for dy in -3..=3 {
        for dx in -3..=3 {
            let d2 = dx * dx + dy * dy;
            let px = cx + dx;
            let py = cy + dy;
            if px >= 0 && (px as usize) < engine.width && py >= 0 && (py as usize) < engine.height {
                if d2 <= 3 {
                    engine.draw_pixel(px as usize, py as usize, Color::rgb(255, 255, 255));
                } else if d2 <= 9 {
                    engine.blend_pixel(px as usize, py as usize, Color::rgb(180, 215, 255), 140);
                }
            }
        }
    }
}

/// Plays the authentic Windows 11 boot splash animation before launching the desktop
pub fn show_boot_splash(engine: &mut DisplayEngine, _cpu_mhz: u64) {
    let sw = engine.width;
    let sh = engine.height;

    // Centered Star position
    let star_w = 96;
    let star_h = 96;
    let star_x = (sw.saturating_sub(star_w)) / 2;
    let star_y = (sh * 36) / 100;

    // Spinner center position (placed below the star like Windows)
    let spin_cx = (sw / 2) as isize;
    let spin_cy = (star_y + star_h + 84) as isize;

    // Hardware-timed 2 real seconds using CMOS RTC
    let mut last_sec = crate::time::read_rtc().second;
    let mut seconds_counted = 0u32;
    let mut frame = 0u32;

    while seconds_counted < 2 {
        let cur_sec = crate::time::read_rtc().second;
        if cur_sec != last_sec {
            last_sec = cur_sec;
            seconds_counted += 1;
        }

        // 1. Clear to deep pitch black (#000000)
        engine.fill_rect(0, 0, sw, sh, Color::rgb(0, 0, 0));

        // 2. Draw 96x96 Fluent 3D Star
        engine.draw_bmp(star_x, star_y, ICON_BOOT_STAR_BMP);

        // 3. Render 5 orbiting Windows progress dots with ease modulation
        let cycle_pos = ((frame % 60) * 256 / 60) as u8;
        for i in 0..5 {
            let offset = (i as u8).wrapping_mul(9);
            let u_dot = cycle_pos.wrapping_sub(offset);

            // Ease acceleration around the top
            let ease = (crate::cyberspace3d::sin(u_dot) * 22) >> 10;
            let angle = u_dot.wrapping_add(ease as u8);

            let sx = (crate::cyberspace3d::sin(angle) * 21) >> 10;
            let sy = (-crate::cyberspace3d::cos(angle) * 21) >> 10;

            let px = spin_cx + (sx as isize);
            let py = spin_cy + (sy as isize);
            draw_spinner_dot(engine, px, py);
        }

        // 4. Stream frame to VRAM
        engine.present();

        frame = frame.wrapping_add(1);
    }
}
