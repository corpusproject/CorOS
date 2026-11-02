//! CorOS DRM/KMS Graphics & Compositor Subsystem Bridge (`drm_kms_bridge.rs`)
//!
//! Integrates:
//! - `cordrm::kms_atomic::{DisplayModeTimings, DrmFourcc, DrmPlaneType}`
//! - `cordrm::gem_prime::{GemManager, GemBufferObject}`
//! - `cordrm::damage_compositor::{CompositorSurface, DamageRect}`

extern crate alloc;

use alloc::vec::Vec;
use crate::sync::SpinLock;
use cordrm::damage_compositor::{CompositorSurface, DamageRect};
use cordrm::gem_prime::GemManager;
use cordrm::kms_atomic::DisplayModeTimings;

pub struct DrmKmsBridge {
    gem_manager: SpinLock<Option<GemManager>>,
    current_mode: SpinLock<DisplayModeTimings>,
    damage_surface: SpinLock<Option<CompositorSurface>>,
}

unsafe impl Send for DrmKmsBridge {}
unsafe impl Sync for DrmKmsBridge {}

impl DrmKmsBridge {
    pub const fn uninit() -> Self {
        Self {
            gem_manager: SpinLock::new(None),
            current_mode: SpinLock::new(DisplayModeTimings {
                clock_khz: 148_500,
                hdisplay: 1920,
                hsync_start: 2008,
                hsync_end: 2052,
                htotal: 2200,
                vdisplay: 1080,
                vsync_start: 1084,
                vsync_end: 1089,
                vtotal: 1125,
                flags: DisplayModeTimings::FLAG_PHSYNC | DisplayModeTimings::FLAG_PVSYNC,
            }),
            damage_surface: SpinLock::new(None),
        }
    }

    /// Initializes GEM allocator and display surface tracking.
    pub fn initialize(&self) {
        let mut gem = self.gem_manager.lock_irqsave();
        if gem.is_none() {
            *gem = Some(GemManager::new());
        }
        drop(gem);

        let mut ds = self.damage_surface.lock_irqsave();
        if ds.is_none() {
            *ds = Some(CompositorSurface::new(1, 0, 0, 1920, 1080, 0));
        }
    }

    /// Allocates a hardware scanout dumb buffer via GEM.
    pub fn create_dumb_buffer(&self, width: u32, height: u32, bpp: u8) -> u32 {
        self.initialize();
        let mut gem = self.gem_manager.lock_irqsave();
        if let Some(ref mut mgr) = *gem {
            mgr.allocate_dumb(width, height, bpp, 0x1000)
        } else {
            0
        }
    }

    /// Exports a GEM buffer as a PRIME DMA-BUF file descriptor token.
    pub fn export_prime_dma_buf(&self, handle: u32) -> Option<i32> {
        self.initialize();
        let mut gem = self.gem_manager.lock_irqsave();
        gem.as_mut().and_then(|mgr| mgr.export_prime_dma_buf(handle))
    }

    /// Imports a PRIME DMA-BUF file descriptor token back into a GEM buffer handle.
    pub fn import_prime_dma_buf(&self, fd: i32) -> Option<u32> {
        self.initialize();
        let mut gem = self.gem_manager.lock_irqsave();
        gem.as_mut().and_then(|mgr| mgr.import_prime_dma_buf(fd))
    }

    /// Sets the active atomic KMS display timing mode.
    pub fn set_mode(&self, mode: DisplayModeTimings) {
        *self.current_mode.lock_irqsave() = mode;
    }

    /// Retrieves the current active display timings.
    pub fn current_mode(&self) -> DisplayModeTimings {
        *self.current_mode.lock_irqsave()
    }

    /// Marks a bounding box region dirty for partial compositing.
    pub fn add_damage_rect(&self, x: i32, y: i32, width: u32, height: u32) {
        self.initialize();
        let mut ds = self.damage_surface.lock_irqsave();
        if let Some(ref mut surf) = *ds {
            surf.damage_list.push(DamageRect::new(x, y, width, height));
        }
    }

    /// Consumes and clears all accumulated dirty damage rectangles.
    pub fn drain_damage_rects(&self) -> Vec<DamageRect> {
        self.initialize();
        let mut ds = self.damage_surface.lock_irqsave();
        if let Some(ref mut surf) = *ds {
            core::mem::take(&mut surf.damage_list)
        } else {
            Vec::new()
        }
    }
}

pub static GLOBAL_DRM_KMS_BRIDGE: DrmKmsBridge = DrmKmsBridge::uninit();
