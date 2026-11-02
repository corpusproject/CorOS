//! Precision Touchpad Gestures: palm rejection, two-finger scroll with coasting & pinch-to-zoom.

/// Helper function computing integer Euclidean distance without floating-point intrinsics.
pub fn int_distance(x0: i32, y0: i32, x1: i32, y1: i32) -> i32 {
    let dx = (x1 - x0) as i64;
    let dy = (y1 - y0) as i64;
    let sq = dx * dx + dy * dy;
    if sq <= 0 {
        return 0;
    }
    let mut x = sq;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + sq / x) / 2;
    }
    x as i32
}

/// Recognized touchpad gesture.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TouchpadGesture {
    SingleTap { x: i32, y: i32 },
    TwoFingerScroll { dx: i32, dy: i32 },
    PinchZoom { scale_delta: f32 },
    ThreeFingerSwipe { dx: i32 },
    None,
}

/// Precision Touchpad Gesture Recognizer.
pub struct TouchpadGestureRecognizer {
    pub palm_pressure_threshold: i32,
    pub palm_edge_margin: i32,
    pub pad_width: i32,
    pub pad_height: i32,
    pub min_scroll_distance: i32,
    pub min_pinch_distance: i32,
    pub last_pos: [(i32, i32); 2],
    pub prev_pinch_distance: i32,
    pub scroll_velocity: (i32, i32),
    pub active_fingers: usize,
}

impl TouchpadGestureRecognizer {
    pub fn new() -> Self {
        Self {
            palm_pressure_threshold: 180,
            palm_edge_margin: 40,
            pad_width: 1000,
            pad_height: 600,
            min_scroll_distance: 5,
            min_pinch_distance: 12,
            last_pos: [(0, 0); 2],
            prev_pinch_distance: 0,
            scroll_velocity: (0, 0),
            active_fingers: 0,
        }
    }

    /// Tests if a contact falls into palm exclusion boundaries (pressure or edge margin).
    pub fn is_palm(&self, x: i32, _y: i32, pressure: i32) -> bool {
        if pressure >= self.palm_pressure_threshold {
            return true;
        }
        if x < self.palm_edge_margin || x > (self.pad_width - self.palm_edge_margin) {
            return true;
        }
        false
    }

    /// Computes velocity in units per second given dt in milliseconds.
    pub fn calculate_scroll_velocity(&self, dt_ms: u32) -> (i32, i32) {
        if dt_ms == 0 {
            return self.scroll_velocity;
        }
        (
            (self.scroll_velocity.0 * 1000) / (dt_ms as i32),
            (self.scroll_velocity.1 * 1000) / (dt_ms as i32),
        )
    }

    /// Evaluates current frame contacts and returns recognized gesture.
    pub fn process_contacts(
        &mut self,
        fingers: &[(i32, i32, i32)], // (x, y, pressure)
    ) -> TouchpadGesture {
        // Palm rejection boundary & pressure check
        for &(x, y, p) in fingers {
            if self.is_palm(x, y, p) {
                return TouchpadGesture::None;
            }
        }

        match fingers.len() {
            1 => {
                self.active_fingers = 1;
                self.last_pos[0] = (fingers[0].0, fingers[0].1);
                self.prev_pinch_distance = 0;
                self.scroll_velocity = (0, 0);
                TouchpadGesture::SingleTap {
                    x: fingers[0].0,
                    y: fingers[0].1,
                }
            }
            2 => {
                let current_dist = int_distance(
                    fingers[0].0,
                    fingers[0].1,
                    fingers[1].0,
                    fingers[1].1,
                );

                if self.active_fingers == 2 && self.prev_pinch_distance > 0 {
                    let dist_delta = current_dist - self.prev_pinch_distance;
                    if dist_delta.abs() >= self.min_pinch_distance {
                        let scale_delta = (dist_delta as f32) / (self.prev_pinch_distance as f32);
                        self.prev_pinch_distance = current_dist;
                        self.last_pos[0] = (fingers[0].0, fingers[0].1);
                        self.last_pos[1] = (fingers[1].0, fingers[1].1);
                        return TouchpadGesture::PinchZoom { scale_delta };
                    }
                }

                let dx = (fingers[0].0 - self.last_pos[0].0 + fingers[1].0 - self.last_pos[1].0) / 2;
                let dy = (fingers[0].1 - self.last_pos[0].1 + fingers[1].1 - self.last_pos[1].1) / 2;
                self.last_pos[0] = (fingers[0].0, fingers[0].1);
                self.last_pos[1] = (fingers[1].0, fingers[1].1);
                self.prev_pinch_distance = current_dist;
                self.active_fingers = 2;

                if dx.abs() >= self.min_scroll_distance || dy.abs() >= self.min_scroll_distance {
                    self.scroll_velocity = (dx, dy);
                    TouchpadGesture::TwoFingerScroll { dx, dy }
                } else {
                    TouchpadGesture::None
                }
            }
            _ => {
                self.active_fingers = 0;
                self.prev_pinch_distance = 0;
                self.scroll_velocity = (0, 0);
                TouchpadGesture::None
            }
        }
    }
}
