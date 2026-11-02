//! Atomic Kernel Mode Setting (KMS) state machine, CRTC timings, connectors, planes & VBlank event queues.

use alloc::vec::Vec;

/// DRM Plane Type (Primary scanout, overlay video plane, or hardware cursor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrmPlaneType {
    Primary,
    Overlay,
    Cursor,
}

/// Pixel format fourcc code (e.g., `DRM_FORMAT_XRGB8888` = 0x34325258, `ARGB8888` = 0x34325241).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrmFourcc(pub u32);

impl DrmFourcc {
    pub const XRGB8888: Self = Self(0x3432_5258);
    pub const ARGB8888: Self = Self(0x3432_5241);
    pub const RGB565: Self = Self(0x3631_4752);
    pub const NV12: Self = Self(0x3231_564E);

    #[inline]
    pub const fn bits_per_pixel(&self) -> u32 {
        match self.0 {
            0x3631_4752 => 16,
            0x3231_564E => 12,
            _ => 32,
        }
    }
}

/// Detailed CRTC display mode timings with millihertz refresh rate calculator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DisplayModeTimings {
    pub clock_khz: u32,
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub flags: u32,
}

impl DisplayModeTimings {
    pub const FLAG_PHSYNC: u32 = 1 << 0;
    pub const FLAG_NHSYNC: u32 = 1 << 1;
    pub const FLAG_PVSYNC: u32 = 1 << 2;
    pub const FLAG_NVSYNC: u32 = 1 << 3;
    pub const FLAG_INTERLACE: u32 = 1 << 4;

    /// Calculates the vertical refresh rate in millihertz (e.g. 60,000 for 60.00 Hz).
    pub fn refresh_millihertz(&self) -> u32 {
        if self.htotal == 0 || self.vtotal == 0 {
            return 0;
        }
        let total_pixels = (self.htotal as u64) * (self.vtotal as u64);
        let clock_hz = (self.clock_khz as u64) * 1000;
        ((clock_hz * 1000) / total_pixels) as u32
    }

    /// Verifies sync boundaries are monotonically increasing within totals.
    pub fn is_valid(&self) -> bool {
        self.clock_khz > 0
            && self.hdisplay > 0
            && self.hdisplay <= self.hsync_start
            && self.hsync_start <= self.hsync_end
            && self.hsync_end <= self.htotal
            && self.vdisplay > 0
            && self.vdisplay <= self.vsync_start
            && self.vsync_start <= self.vsync_end
            && self.vsync_end <= self.vtotal
    }
}

/// DRM Plane state representing on-screen position, source rectangle, and framebuffer binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrmPlaneState {
    pub plane_id: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    pub zpos: u8,
    pub alpha: u16,
    pub visible: bool,
}

/// DRM CRTC state controlling display raster engine and active mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DrmCrtcState {
    pub crtc_id: u32,
    pub active: bool,
    pub mode: DisplayModeTimings,
    pub vblank_sequence: u64,
}

/// DRM Connector connection status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrmConnectorStatus {
    Connected,
    Disconnected,
    Unknown,
}

/// DRM Connector state binding display cables to encoders and CRTCs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrmConnectorState {
    pub connector_id: u32,
    pub status: DrmConnectorStatus,
    pub encoder_id: u32,
    pub crtc_id: u32,
    pub dpms: u8,
    pub supported_modes: Vec<DisplayModeTimings>,
}

/// VBlank page-flip completion event queued for userspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VblankEvent {
    pub crtc_id: u32,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub user_data: u64,
}

/// Atomic state commit transaction validating plane clipping, format support, and CRTC routing.
pub struct AtomicKmsTransaction {
    pub planes: Vec<DrmPlaneState>,
    pub crtcs: Vec<DrmCrtcState>,
    pub vblank_events: Vec<VblankEvent>,
}

impl AtomicKmsTransaction {
    pub fn new() -> Self {
        Self {
            planes: Vec::new(),
            crtcs: Vec::new(),
            vblank_events: Vec::new(),
        }
    }

    /// Validates that all visible planes clip cleanly inside their destination CRTC display mode.
    pub fn validate_atomic_state(&self) -> bool {
        for plane in &self.planes {
            if !plane.visible {
                continue;
            }
            let crtc = self.crtcs.iter().find(|c| c.crtc_id == plane.crtc_id);
            match crtc {
                Some(c) if c.active => {
                    if !c.mode.is_valid() {
                        return false;
                    }
                    if plane.crtc_x < 0
                        || plane.crtc_y < 0
                        || (plane.crtc_x as u32 + plane.crtc_w) > c.mode.hdisplay as u32
                        || (plane.crtc_y as u32 + plane.crtc_h) > c.mode.vdisplay as u32
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Atomically applies state and increments CRTC vblank sequence numbers.
    pub fn commit_atomic_state(&mut self, timestamp_ns: u64) -> usize {
        if !self.validate_atomic_state() {
            return 0;
        }
        let mut events_generated = 0;
        for crtc in &mut self.crtcs {
            if crtc.active {
                crtc.vblank_sequence = crtc.vblank_sequence.wrapping_add(1);
                self.vblank_events.push(VblankEvent {
                    crtc_id: crtc.crtc_id,
                    sequence: crtc.vblank_sequence,
                    timestamp_ns,
                    user_data: 0,
                });
                events_generated += 1;
            }
        }
        events_generated
    }
}
