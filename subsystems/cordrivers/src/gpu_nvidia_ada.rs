//! CorOS Hardware Driver Module: `gpu_nvidia_ada`
//!
//! NVIDIA Ada Lovelace / Ampere / Turing GPU Architecture (`PMC`, `PFIFO`, `PBUS`,
//! `PRAMIN`, `NVDisplay`) BAR0 MMIO register blocks, `NVC0`+ Pushbuffer Method Header
//! encoder (`INCR`, `NON_INCR`, `IMM`), NVDisplay Scanout Head raster timing configuration,
//! and BAR1 VRAM Page Table / Aperture allocator.

/// NVIDIA BAR0 Top-Level MMIO Register Sub-Engine Offsets.
pub mod nv_bar0_regs {
    /// Master Control (`PMC_BOOT_0`: Chipset/Architecture ID).
    pub const PMC_BOOT_0: usize = 0x000000;
    /// Master Enable bitmask (`PMC_ENABLE`: PFIFO, PGRAPH, PDISPLAY, etc.).
    pub const PMC_ENABLE: usize = 0x000200;
    /// Bus Control (`PBUS`).
    pub const PBUS_BASE: usize = 0x001000;
    /// Host FIFO & Channel DMA Engine (`PFIFO`).
    pub const PFIFO_BASE: usize = 0x002000;
    /// Timer (`PTIMER` nanosecond clock `TIME_0` / `TIME_1`).
    pub const PTIMER_TIME_0: usize = 0x009400;
    pub const PTIMER_TIME_1: usize = 0x009410;
    /// Framebuffer / Memory Controller (`PFB_CSTATUS` VRAM size in MiB).
    pub const PFB_CSTATUS: usize = 0x10020C;
    /// Graphics / Compute Engine (`PGRAPH`).
    pub const PGRAPH_BASE: usize = 0x400000;
    /// NVDisplay Engine (`PDISPLAY` / Core Channel).
    pub const PDISPLAY_BASE: usize = 0x610000;
    /// BAR0 PRAMIN Window (1 MiB sliding window into VRAM at `0x700000`).
    pub const PRAMIN_BASE: usize = 0x700000;
}

/// NVIDIA GPU Architecture family decoded from `PMC_BOOT_0[28:20]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvidiaArchGeneration {
    Kepler,
    Maxwell,
    Pascal,
    Volta,
    Turing,
    Ampere,
    AdaLovelace,
    Blackwell,
    Unknown(u16),
}

/// Decodes `PMC_BOOT_0` into `(architecture_generation, chip_code)`.
pub const fn decode_pmc_boot_0(boot0: u32) -> (NvidiaArchGeneration, u16) {
    let arch_id = ((boot0 >> 20) & 0x1FF) as u16;
    let chip_id = ((boot0 >> 20) & 0xFF) as u16;
    let gen = match arch_id & 0x1F0 {
        0x0E0 | 0x0F0 | 0x100 => NvidiaArchGeneration::Kepler,
        0x110 | 0x120 => NvidiaArchGeneration::Maxwell,
        0x130 => NvidiaArchGeneration::Pascal,
        0x140 => NvidiaArchGeneration::Volta,
        0x160 => NvidiaArchGeneration::Turing,
        0x170 => NvidiaArchGeneration::Ampere,
        0x190 => NvidiaArchGeneration::AdaLovelace,
        0x1B0 => NvidiaArchGeneration::Blackwell,
        _ => NvidiaArchGeneration::Unknown(arch_id),
    };
    (gen, chip_id)
}

/// NVIDIA Fermi/Kepler/Maxwell/Pascal/Turing/Ampere/Ada (`NVC0`+) Pushbuffer Method Addressing Mode (`bits 31:29`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvPushMethodType {
    /// Incrementing method (`0b001`): writes `count` DWORDs to `method, method+4, ...`.
    Increasing = 1,
    /// Non-incrementing method (`0b011`): writes `count` DWORDs repeatedly to the same `method`.
    NonIncreasing = 3,
    /// Immediate 13-bit data (`0b100`): embeds 13-bit payload directly in `bits 28:16` with 0 trailing DWORDs.
    Immediate13Bit = 4,
    /// Increment-once method (`0b101`): writes first DWORD to `method`, remaining DWORDs to `method+4`.
    IncreaseOnce = 5,
}

/// Encodes a 32-bit `NVC0`+ Pushbuffer Method Header:
/// `[31:29] = mode | [28:16] = count_or_imm13 | [15:13] = subchannel | [11:0] = (method_byte_offset >> 2)`.
#[inline]
pub const fn encode_nv_push_header(
    mode: NvPushMethodType,
    subchannel: u8,
    method_byte_offset: u16,
    count_or_imm: u16,
) -> u32 {
    let mode_bits = (mode as u32) << 29;
    let count_bits = ((count_or_imm & 0x1FFF) as u32) << 16;
    let subch_bits = ((subchannel & 0x07) as u32) << 13;
    let mthd_dword = ((method_byte_offset >> 2) & 0x0FFF) as u32;
    mode_bits | count_bits | subch_bits | mthd_dword
}

/// Decodes a 32-bit `NVC0`+ Pushbuffer Method Header into `(mode_raw, subchannel, method_byte_offset, count_or_imm)`.
#[inline]
pub const fn decode_nv_push_header(hdr: u32) -> (u8, u8, u16, u16) {
    let mode = ((hdr >> 29) & 0x07) as u8;
    let count_or_imm = ((hdr >> 16) & 0x1FFF) as u16;
    let subchannel = ((hdr >> 13) & 0x07) as u8;
    let method_byte_offset = ((hdr & 0x0FFF) as u16) << 2;
    (mode, subchannel, method_byte_offset, count_or_imm)
}

/// NVDisplay Scanout Head Timing & Core Channel Surface Descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvDisplayHeadConfig {
    pub head_index: u8,
    pub raster_size: u32,
    pub raster_sync_end: u32,
    pub raster_blank_end: u32,
    pub raster_blank_start: u32,
    pub surface_offset_256b: u32,
    pub pitch_blocks: u32,
    pub pixel_clock_khz: u32,
}

impl NvDisplayHeadConfig {
    #[inline]
    const fn pack_xy(x: u16, y: u16) -> u32 {
        ((y as u32) << 16) | (x as u32)
    }

    /// Computes NVDisplay Core Channel raster parameters for `head_index` (`0..=3`).
    pub const fn compute(
        head_index: u8,
        h_active: u16,
        h_sync_start: u16,
        h_sync_end: u16,
        h_total: u16,
        v_active: u16,
        v_sync_start: u16,
        v_sync_end: u16,
        v_total: u16,
        pixel_clock_khz: u32,
        vram_surface_offset: u64,
        pitch_bytes: u32,
    ) -> Self {
        let h_sync_width = h_sync_end.saturating_sub(h_sync_start);
        let v_sync_width = v_sync_end.saturating_sub(v_sync_start);
        let h_back_porch_end = h_total.saturating_sub(h_sync_start);
        let v_back_porch_end = v_total.saturating_sub(v_sync_start);
        let h_blank_start = h_back_porch_end.saturating_add(h_active);
        let v_blank_start = v_back_porch_end.saturating_add(v_active);

        Self {
            head_index: head_index & 0x03,
            raster_size: Self::pack_xy(h_total, v_total),
            raster_sync_end: Self::pack_xy(
                h_sync_width.saturating_sub(1),
                v_sync_width.saturating_sub(1),
            ),
            raster_blank_end: Self::pack_xy(h_back_porch_end, v_back_porch_end),
            raster_blank_start: Self::pack_xy(h_blank_start, v_blank_start),
            surface_offset_256b: (vram_surface_offset >> 8) as u32,
            pitch_blocks: pitch_bytes / 64,
            pixel_clock_khz,
        }
    }
}

/// BAR1 VRAM Linear Aperture Allocator (64 KiB large-page granularity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvBar1ApertureManager {
    pub bar1_phys_base: u64,
    pub total_vram_bytes: u64,
    pub next_free_offset: u64,
    pub active_allocations: u32,
}

impl NvBar1ApertureManager {
    pub const PAGE_GRANULARITY: u64 = 64 * 1024; // 64 KiB NVIDIA big-page alignment

    #[inline]
    pub const fn new(bar1_phys_base: u64, total_vram_bytes: u64) -> Self {
        Self {
            bar1_phys_base,
            total_vram_bytes,
            next_free_offset: 0,
            active_allocations: 0,
        }
    }

    /// Allocates a 64 KiB-aligned VRAM region in BAR1 and returns `(vram_offset, cpu_bar1_phys_addr)`.
    pub fn alloc_vram_64k(&mut self, size_bytes: u64) -> Option<(u64, u64)> {
        if size_bytes == 0 {
            return None;
        }
        let aligned_size =
            (size_bytes + (Self::PAGE_GRANULARITY - 1)) & !(Self::PAGE_GRANULARITY - 1);
        if self.next_free_offset + aligned_size > self.total_vram_bytes {
            return None;
        }
        let vram_off = self.next_free_offset;
        self.next_free_offset += aligned_size;
        self.active_allocations += 1;
        Some((vram_off, self.bar1_phys_base + vram_off))
    }
}

/// Self-test for `gpu_nvidia_ada` PMC_BOOT_0 architecture decoding, NVC0 pushbuffer method headers,
/// NVDisplay Head raster calculation, and BAR1 64 KiB VRAM allocation.
pub fn verify_driver_module_gpu_nvidia_ada() -> u32 {
    let mut passed = 0u32;

    // 1. Verify PMC_BOOT_0 decoding for AD102 (Ada Lovelace `0x192000A1`)
    let (arch, chip) = decode_pmc_boot_0(0x1920_00A1);
    if arch == NvidiaArchGeneration::AdaLovelace && chip == 0x92 {
        passed += 1;
    }

    // 2. Verify NVC0+ Pushbuffer Increasing Method Header roundtrip
    let hdr = encode_nv_push_header(NvPushMethodType::Increasing, 0, 0x0840, 4);
    let (mode, subch, mthd, cnt) = decode_nv_push_header(hdr);
    if mode == 1 && subch == 0 && mthd == 0x0840 && cnt == 4 {
        passed += 1;
    }

    // 3. Verify NVDisplay Head 0 raster timing for 1920x1080
    let head = NvDisplayHeadConfig::compute(
        0,
        1920,
        2008,
        2052,
        2200,
        1080,
        1084,
        1089,
        1125,
        148_500,
        0x0040_0000,
        1920 * 4,
    );
    if head.raster_size == ((1125u32 << 16) | 2200)
        && head.surface_offset_256b == 0x0000_4000
        && head.pitch_blocks == 120
    {
        passed += 1;
    }

    // 4. Verify BAR1 64 KiB VRAM aperture allocation
    let mut bar1 = NvBar1ApertureManager::new(0x0000_0002_0000_0000, 256 * 1024 * 1024);
    let a1 = bar1.alloc_vram_64k(1920 * 1080 * 4); // ~8.29 MiB -> rounds up to 8320 KiB (`0x82_0000`)
    let a2 = bar1.alloc_vram_64k(4096); // -> rounds up to 64 KiB (`0x1_0000`)
    if a1 == Some((0, 0x0000_0002_0000_0000))
        && a2 == Some((0x0082_0000, 0x0000_0002_0082_0000))
        && bar1.active_allocations == 2
    {
        passed += 1;
    }

    passed
}
