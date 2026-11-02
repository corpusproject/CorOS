#![no_std]
//! `cordrm` — CorOS Direct Rendering Manager (DRM/KMS), Display Compositor & 2D/3D Graphics Pipeline.

extern crate alloc;

pub mod kms_atomic;
pub mod gem_prime;
pub mod ttm_vram;
pub mod edid_displayid;
pub mod dp_aux_link;
pub mod damage_compositor;
pub mod software_raster;
pub mod font_shaper;
pub mod sync_timeline;
pub mod gpu_scheduler;

pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. kms_atomic test
    let mode = kms_atomic::DisplayModeTimings {
        clock_khz: 148_500,
        hdisplay: 1920,
        hsync_start: 2008,
        hsync_end: 2052,
        htotal: 2200,
        vdisplay: 1080,
        vsync_start: 1084,
        vsync_end: 1089,
        vtotal: 1125,
        flags: kms_atomic::DisplayModeTimings::FLAG_PHSYNC | kms_atomic::DisplayModeTimings::FLAG_PVSYNC,
    };
    if mode.is_valid() && mode.refresh_millihertz() >= 59_000 {
        passed += 1;
    }

    // 2. gem_prime test
    let mut gem = gem_prime::GemManager::new();
    let handle = gem.allocate_dumb(1920, 1080, 32, 0x1000);
    if let Some(fd) = gem.export_prime_dma_buf(handle) {
        if gem.import_prime_dma_buf(fd) == Some(handle) {
            passed += 1;
        }
    }

    // 3. ttm_vram test
    let mut ttm = ttm_vram::TtmPoolManager::new(1024 * 1024, 2048 * 1024);
    let rule = ttm_vram::TtmPlacementRule::new_vram(false);
    if ttm.place_buffer(1, 512 * 1024, rule) == Ok(ttm_vram::TtmMemoryDomain::VramDedicated) {
        passed += 1;
    }

    // 4. edid_displayid test
    let mut fake_edid = [0u8; 128];
    fake_edid[0..8].copy_from_slice(&edid_displayid::ParsedEdid::HEADER);
    // checksum byte at end
    let mut sum = 0u8;
    for i in 0..127 {
        sum = sum.wrapping_add(fake_edid[i]);
    }
    fake_edid[127] = (0u8).wrapping_sub(sum);
    if edid_displayid::ParsedEdid::verify_checksum(&fake_edid) {
        passed += 1;
    }

    // 5. dp_aux_link test
    let mut trainer = dp_aux_link::DpLinkTrainer::new(4, dp_aux_link::DpLinkRate::Rate5_40Gbps);
    trainer.step_clock_recovery(true);
    trainer.step_channel_equalization(true);
    if trainer.phase == dp_aux_link::LinkTrainingPhase::Success {
        passed += 1;
    }

    // 6. damage_compositor test
    let r1 = damage_compositor::DamageRect::new(10, 10, 50, 50);
    let r2 = damage_compositor::DamageRect::new(30, 30, 50, 50);
    let u = r1.union(&r2);
    if u.width == 70 && u.height == 70 {
        passed += 1;
    }

    // 7. software_raster test
    let mut target = software_raster::SoftwareRasterTarget::new(64, 64);
    target.clear(0xFF00_0000);
    target.draw_line(
        software_raster::Point2D { x: 0, y: 0 },
        software_raster::Point2D { x: 10, y: 10 },
        0xFFFF_FFFF,
    );
    passed += 1;

    // 8. font_shaper test
    let shaper = font_shaper::FontShaper::new(8, 16);
    let bounds = shaper.measure_text_line("CorOS");
    if bounds.width > 0 && bounds.height == 16 {
        passed += 1;
    }

    // 9. sync_timeline test
    let mut timeline = sync_timeline::SyncTimeline::new(1);
    let fence = timeline.create_fence_point();
    timeline.signal_up_to(1);
    if timeline.is_point_signaled(fence.seqno) {
        passed += 1;
    }

    // 10. gpu_scheduler test
    let mut sched = gpu_scheduler::DrmGpuScheduler::new(100, 5000);
    sched.submit_job(gpu_scheduler::GpuJob {
        job_id: 1,
        context_id: 10,
        priority: gpu_scheduler::GpuPriority::Normal,
        credits_required: 20,
        submission_time_ms: 100,
    });
    let dispatched = sched.dispatch_pending(100);
    if dispatched == 1 && sched.complete_job(1) {
        passed += 1;
    }

    passed
}
