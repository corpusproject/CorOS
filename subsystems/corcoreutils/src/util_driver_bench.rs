//! CorOS Userland Coreutil: `driver-bench`
//! Hardware subsystem benchmark calculator & report formatter measuring:
//! - Storage IOPS and sequential MiB/s throughput (AHCI DMA / NVMe)
//! - Physical RAM / L3 cache memory copy bandwidth (GiB/s)
//! - UEFI GOP / PCIe Write-Combining framebuffer presentation rate (FPS & frame time in microseconds)

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug)]
pub struct StorageBenchSample {
    pub driver_name: &'static str,
    pub block_size_bytes: u32,
    pub blocks_transferred: u64,
    pub elapsed_microseconds: u64,
}

impl StorageBenchSample {
    pub const fn total_bytes(&self) -> u64 {
        self.blocks_transferred * (self.block_size_bytes as u64)
    }

    /// Computes I/O operations per second (`IOPS`).
    pub const fn compute_iops(&self) -> u64 {
        if self.elapsed_microseconds == 0 {
            0
        } else {
            (self.blocks_transferred * 1_000_000) / self.elapsed_microseconds
        }
    }

    /// Computes throughput in MiB/s (`1024 * 1024` bytes per second).
    pub const fn compute_throughput_mib_s(&self) -> u64 {
        if self.elapsed_microseconds == 0 {
            0
        } else {
            (self.total_bytes() * 1_000_000) / (self.elapsed_microseconds * 1024 * 1024)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryBenchSample {
    pub profile_name: &'static str,
    pub bytes_copied: u64,
    pub elapsed_microseconds: u64,
}

impl MemoryBenchSample {
    /// Computes memory bandwidth in tenths of GiB/s (e.g., `245` = `24.5 GiB/s`).
    pub const fn compute_gib_s_tenths(&self) -> u64 {
        if self.elapsed_microseconds == 0 {
            0
        } else {
            let mib_s = (self.bytes_copied * 1_000_000) / (self.elapsed_microseconds * 1024 * 1024);
            (mib_s * 10) / 1024
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FramebufferBenchSample {
    pub resolution_width: u32,
    pub resolution_height: u32,
    pub bpp: u32,
    pub frames_rendered: u64,
    pub elapsed_microseconds: u64,
}

impl FramebufferBenchSample {
    pub const fn average_fps(&self) -> u64 {
        if self.elapsed_microseconds == 0 {
            0
        } else {
            (self.frames_rendered * 1_000_000) / self.elapsed_microseconds
        }
    }

    pub const fn avg_frame_time_us(&self) -> u64 {
        if self.frames_rendered == 0 {
            0
        } else {
            self.elapsed_microseconds / self.frames_rendered
        }
    }

    /// Computes PCIe VRAM burst bandwidth in MiB/s.
    pub const fn vram_bandwidth_mib_s(&self) -> u64 {
        if self.elapsed_microseconds == 0 {
            0
        } else {
            let bytes_per_frame =
                (self.resolution_width as u64) * (self.resolution_height as u64) * ((self.bpp / 8) as u64);
            let total_bytes = bytes_per_frame * self.frames_rendered;
            (total_bytes * 1_000_000) / (self.elapsed_microseconds * 1024 * 1024)
        }
    }
}

/// Formats a comprehensive hardware driver benchmark report combining Storage, RAM, and Framebuffer telemetry.
pub fn format_driver_bench_report(
    storage: &StorageBenchSample,
    memory: &MemoryBenchSample,
    fb: &FramebufferBenchSample,
) -> String {
    let mut out = String::new();
    out.push_str("=== CorOS Hardware Driver Benchmark Suite ===\n");
    out.push_str(&format!(
        "[STORAGE] {}: {} B blocks, {} IOPS, {} MiB/s\n",
        storage.driver_name,
        storage.block_size_bytes,
        storage.compute_iops(),
        storage.compute_throughput_mib_s()
    ));

    let gib_tenths = memory.compute_gib_s_tenths();
    out.push_str(&format!(
        "[MEMORY ] {}: {}.{} GiB/s\n",
        memory.profile_name,
        gib_tenths / 10,
        gib_tenths % 10
    ));

    out.push_str(&format!(
        "[DISPLAY] {}x{}x{}: {} FPS ({} us/frame, {} MiB/s VRAM burst)\n",
        fb.resolution_width,
        fb.resolution_height,
        fb.bpp,
        fb.average_fps(),
        fb.avg_frame_time_us(),
        fb.vram_bandwidth_mib_s()
    ));

    out
}

pub fn verify_util_driver_bench() -> u32 {
    let mut passed = 0u32;

    let st = StorageBenchSample {
        driver_name: "AHCI SATA DMA",
        block_size_bytes: 4096,
        blocks_transferred: 65536, // 256 MiB
        elapsed_microseconds: 500_000, // 0.5 s -> 512 MiB/s, 131072 IOPS
    };
    if st.compute_iops() == 131_072 && st.compute_throughput_mib_s() == 512 {
        passed += 1;
    }

    let mem = MemoryBenchSample {
        profile_name: "SSE2 Non-Temporal 64B Cacheline Copy",
        bytes_copied: 2 * 1024 * 1024 * 1024, // 2 GiB
        elapsed_microseconds: 100_000,         // 0.1 s -> 20.0 GiB/s
    };
    if mem.compute_gib_s_tenths() == 200 {
        passed += 1;
    }

    let fb = FramebufferBenchSample {
        resolution_width: 1920,
        resolution_height: 1080,
        bpp: 32,
        frames_rendered: 200,
        elapsed_microseconds: 1_000_000, // 200 FPS, 5000 us/frame
    };
    if fb.average_fps() == 200 && fb.avg_frame_time_us() == 5000 {
        passed += 1;
    }

    let report = format_driver_bench_report(&st, &mem, &fb);
    if report.contains("131072 IOPS, 512 MiB/s")
        && report.contains("20.0 GiB/s")
        && report.contains("1920x1080x32: 200 FPS (5000 us/frame")
    {
        passed += 1;
    }

    passed
}
