//! CorOS Desktop Emblems and Centered Wallpapers (Kali Dragon, CorOS Cyber Shield, etc.)

use crate::display::{Color, DisplayEngine};

pub fn render_kali_dragon(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    let col = Color::rgb(6, 12, 22);

    let draw_curve = |eng: &mut DisplayEngine, pts: &[(isize, isize, isize)]| {
        for i in 0..pts.len() {
            let (x1, y1, r1) = pts[i];
            eng.fill_circle(cx + x1, cy + y1, r1, col);
            if i + 1 < pts.len() {
                let (x2, y2, r2) = pts[i + 1];
                let steps = (((x2 - x1).abs() + (y2 - y1).abs()) * 2).max(1);
                for s in 1..steps {
                    let px = x1 + (x2 - x1) * s / steps;
                    let py = y1 + (y2 - y1) * s / steps;
                    let pr = r1 + (r2 - r1) * s / steps;
                    eng.fill_circle(cx + px, cy + py, pr, col);
                }
            }
        }
    };

    let body_pts: [(isize, isize, isize); 14] = [
        (24, -14, 4), (18, -4, 5), (8, 8, 5), (-4, 20, 6),
        (-16, 30, 6), (-24, 40, 6), (-22, 50, 6), (-12, 58, 6),
        (2, 60, 6), (16, 58, 5), (28, 54, 5), (38, 54, 4),
        (44, 60, 4), (48, 68, 3),
    ];
    draw_curve(engine, &body_pts);

    let neck_pts: [(isize, isize, isize); 5] = [
        (-12, -24, 5), (-2, -23, 5), (10, -20, 5), (20, -17, 4), (28, -14, 3),
    ];
    draw_curve(engine, &neck_pts);

    let head_snout: [(isize, isize, isize); 3] = [
        (28, -14, 3), (38, -10, 2), (46, -6, 1),
    ];
    draw_curve(engine, &head_snout);

    let head_jaw: [(isize, isize, isize); 3] = [
        (28, -11, 2), (36, -6, 2), (42, -5, 1),
    ];
    draw_curve(engine, &head_jaw);

    let horns: [(isize, isize, isize); 4] = [
        (12, -22, 3), (4, -28, 2), (-4, -32, 2), (-12, -35, 1),
    ];
    draw_curve(engine, &horns);

    engine.draw_line(cx + 26, cy - 15, cx + 30, cy - 13, Color::rgb(38, 152, 212));

    let wing_top: [(isize, isize, isize); 6] = [
        (-12, -24, 4), (-30, -38, 3), (-52, -48, 3), (-76, -54, 2), (-100, -55, 2), (-118, -52, 1),
    ];
    draw_curve(engine, &wing_top);

    let wing_mid: [(isize, isize, isize); 6] = [
        (-14, -22, 4), (-36, -29, 3), (-62, -34, 3), (-88, -36, 2), (-112, -34, 2), (-124, -30, 1),
    ];
    draw_curve(engine, &wing_mid);

    let wing_bot: [(isize, isize, isize); 6] = [
        (-16, -18, 4), (-38, -21, 3), (-64, -22, 3), (-88, -21, 2), (-108, -18, 2), (-118, -14, 1),
    ];
    draw_curve(engine, &wing_bot);

    let wing_base: [(isize, isize, isize); 4] = [
        (-12, -24, 4), (-16, -21, 4), (-18, -16, 4), (-8, -20, 5),
    ];
    draw_curve(engine, &wing_base);

    let tail_main: [(isize, isize, isize); 6] = [
        (48, 68, 3), (52, 80, 3), (55, 94, 2), (57, 108, 2), (58, 120, 1), (58, 126, 1),
    ];
    draw_curve(engine, &tail_main);

    let tail_fork: [(isize, isize, isize); 5] = [
        (48, 68, 3), (45, 80, 2), (42, 92, 2), (37, 104, 1), (34, 112, 1),
    ];
    draw_curve(engine, &tail_fork);
}

pub fn render_coros_cyber_shield(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    let border_col = Color::CYAN;
    let inner_col = Color::rgb(14, 20, 36);
    let accent_col = Color::rgb(168, 85, 247);
    let glow_col = Color::rgb(37, 99, 235);

    let pts = [
        (cx, cy - 35),
        (cx + 45, cy - 40),
        (cx + 55, cy - 10),
        (cx + 40, cy + 25),
        (cx, cy + 60),
        (cx - 40, cy + 25),
        (cx - 55, cy - 10),
        (cx - 45, cy - 40),
    ];

    for i in 0..pts.len() {
        let (x1, y1) = pts[i];
        let (x2, y2) = pts[(i + 1) % pts.len()];
        engine.draw_line(x1, y1, x2, y2, border_col);
        engine.draw_line(x1 + (cx - x1).signum(), y1 + (cy - y1).signum(), x2 + (cx - x2).signum(), y2 + (cy - y2).signum(), glow_col);
    }

    for dy in -32..=52 {
        let half_w = match dy {
            -32..= -10 => 40 + (dy + 32) / 2,
            -9..= 25 => 50 - (dy + 10) / 3,
            _ => 38 - (dy - 25),
        };
        let half_w = half_w.max(2);
        engine.draw_hline((cx - half_w) as usize, (cy + dy) as usize, (2 * half_w) as usize, inner_col);
    }

    engine.fill_circle(cx, cy + 5, 14, accent_col);
    engine.fill_circle(cx, cy + 5, 9, inner_col);
    engine.fill_rect((cx + 2) as usize, (cy - 1) as usize, 12, 12, inner_col);
    engine.fill_circle(cx + 3, cy + 5, 4, Color::CYAN);

    engine.draw_hline((cx - 105) as usize, (cy - 10) as usize, 50, Color::CYAN);
    engine.fill_circle(cx - 105, cy - 10, 3, Color::CYAN);
    engine.draw_line(cx - 80, cy - 10, cx - 95, cy - 25, Color::CYAN);
    engine.fill_circle(cx - 95, cy - 25, 2, accent_col);

    engine.draw_hline((cx + 55) as usize, (cy - 10) as usize, 50, Color::CYAN);
    engine.fill_circle(cx + 105, cy - 10, 3, Color::CYAN);
    engine.draw_line(cx + 80, cy - 10, cx + 95, cy - 25, Color::CYAN);
    engine.fill_circle(cx + 95, cy - 25, 2, accent_col);

    engine.draw_string((cx - 24) as usize, (cy + 24) as usize, "COROS", Color::WHITE, 1);
    engine.draw_string((cx - 30) as usize, (cy + 34) as usize, "SILICON", Color::CYAN, 1);
}

pub fn render_cosmic_pulsar(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    engine.fill_circle(cx, cy, 14, Color::rgb(99, 102, 241));
    engine.fill_circle(cx, cy, 8, Color::rgb(199, 210, 254));
    engine.fill_circle(cx, cy, 4, Color::WHITE);
    for len in 1..=45 {
        let col = Color::rgb(129, 140, 248);
        if cx - len >= 0 { engine.draw_pixel((cx - len) as usize, cy as usize, col); }
        if cx + len >= 0 { engine.draw_pixel((cx + len) as usize, cy as usize, col); }
        if cy - len >= 0 { engine.draw_pixel(cx as usize, (cy - len) as usize, col); }
        if cy + len >= 0 { engine.draw_pixel(cx as usize, (cy + len) as usize, col); }
    }
    engine.draw_string((cx - 40) as usize, (cy + 30) as usize, "DEEP SPACE", Color::rgb(199, 210, 254), 1);
}

pub fn render_modern_ring(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    engine.fill_circle(cx, cy, 32, Color::rgb(35, 45, 65));
    engine.fill_circle(cx, cy, 26, Color::rgb(18, 26, 40));
    engine.draw_line(cx - 20, cy, cx + 20, cy, Color::rgb(71, 85, 105));
    engine.draw_string((cx - 24) as usize, (cy - 12) as usize, "CorOS", Color::WHITE, 1);
    engine.draw_string((cx - 20) as usize, (cy + 4) as usize, "SLATE", Color::rgb(148, 163, 184), 1);
}

pub fn render_matrix_shield(engine: &mut DisplayEngine, cx: isize, cy: isize) {
    if cx >= 36 && cy >= 36 {
        engine.draw_rect((cx - 36) as usize, (cy - 36) as usize, 72, 72, Color::EMERALD);
        engine.draw_rect((cx - 32) as usize, (cy - 32) as usize, 64, 64, Color::rgb(5, 150, 105));
        engine.draw_string((cx - 18) as usize, (cy - 12) as usize, ">_OS", Color::EMERALD, 1);
        engine.draw_string((cx - 28) as usize, (cy + 6) as usize, "ROOT #1", Color::rgb(110, 231, 183), 1);
    }
}
