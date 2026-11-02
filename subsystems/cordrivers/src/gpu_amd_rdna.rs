//! CorOS Hardware Driver Module: `gpu_amd_rdna`
//!
//! AMD RDNA / RDNA2 / RDNA3 Display Core Next (`DCN`) CRTC timing generator
//! (`OTG_H_TOTAL`, `OTG_H_BLANK_START_END`, `OTG_V_TOTAL`, `OTG_CONTROL`),
//! Primary Hubp Surface Flip controller (`DCSURF_PRIMARY_SURFACE_ADDRESS`),
//! GFX10/GFX11 Command Processor `PM4` Type-3 Packet builder (`SET_UCONFIG_REG`,
//! `WRITE_DATA`, `RELEASE_MEM`, `DRAW_INDEX_AUTO`, `INDIRECT_BUFFER`), and GFX Ring state.

/// AMD DCN (Display Core Next) OTG & HUBP MMIO Register offsets (DWORD-indexed / byte offsets).
pub mod amd_dcn_regs {
    pub const OTG0_CONTROL: u32 = 0x50C0;
    pub const OTG0_H_TOTAL: u32 = 0x50C4;
    pub const OTG0_H_BLANK_START_END: u32 = 0x50C8;
    pub const OTG0_H_SYNC_A: u32 = 0x50CC;
    pub const OTG0_V_TOTAL: u32 = 0x50D8;
    pub const OTG0_V_BLANK_START_END: u32 = 0x50DC;
    pub const OTG0_V_SYNC_A: u32 = 0x50E0;
    pub const DCSURF_SURFACE_CONFIG: u32 = 0x4500;
    pub const DCSURF_ADDR_CONFIG: u32 = 0x4504;
    pub const DCSURF_TILING_CONFIG: u32 = 0x4508;
    pub const DCSURF_PRI_VIEWPORT_DIMENSION: u32 = 0x4514;
    pub const DCSURF_PRIMARY_SURFACE_ADDRESS: u32 = 0x4528;
    pub const DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x452C;
    pub const DCSURF_FLIP_CONTROL: u32 = 0x4510;
}

/// AMD GFX Command Processor PM4 Type-3 Packet IT_OPCODE definitions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pm4Opcode {
    Nop = 0x10,
    SetBase = 0x11,
    ClearState = 0x12,
    IndexBufferSize = 0x13,
    DispatchDirect = 0x15,
    IndexType = 0x2A,
    DrawIndex2 = 0x27,
    DrawIndexAuto = 0x2D,
    WaitRegMem = 0x3C,
    WriteData = 0x37,
    IndirectBuffer = 0x3F,
    AcquireMem = 0x58,
    ReleaseMem = 0x49,
    SetConfigReg = 0x68,
    SetContextReg = 0x69,
    SetShReg = 0x76,
    SetUconfigReg = 0x79,
}

/// AMD DCN Surface Pixel Format (`SURFACE_PIXEL_FORMAT`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcnSurfacePixelFormat {
    GrphArgb1555 = 1,
    GrphRgb565 = 2,
    GrphArgb8888 = 8,
    GrphArgb2101010 = 10,
    GrphFp16 = 22,
}

/// AMD RDNA2/RDNA3 Swizzle Mode (`SW_MODE`) for 2D surfaces.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdnaSwizzleMode {
    SwLinear = 0x00,
    Sw4kbS = 0x01,
    Sw4kbD = 0x02,
    Sw64kbS = 0x09,
    Sw64kbD = 0x0A,
    Sw64kbRX = 0x19,
}

/// Builds a 32-bit PM4 Type-3 Packet Header:
/// `[31:30] = 3 (Type 3) | [29:16] = (num_extra_dwords - 1) | [15:8] = it_opcode | [0] = predicate`.
#[inline]
pub const fn encode_pm4_type3_header(
    opcode: Pm4Opcode,
    payload_dword_count: u16,
    predicate: bool,
) -> u32 {
    let count_field = (payload_dword_count.saturating_sub(1) & 0x3FFF) as u32;
    let pred_bit = if predicate { 1u32 } else { 0 };
    (3u32 << 30) | (count_field << 16) | ((opcode as u32) << 8) | pred_bit
}

/// Decodes a 32-bit PM4 Type-3 header into `(it_opcode, payload_dword_count)` if `header[31:30] == 3`.
#[inline]
pub const fn decode_pm4_type3_header(header: u32) -> Option<(u8, u16)> {
    if (header >> 30) != 3 {
        return None;
    }
    let count = (((header >> 16) & 0x3FFF) as u16) + 1;
    let op = ((header >> 8) & 0xFF) as u8;
    Some((op, count))
}

/// Builds a 4-DWORD PM4 `WRITE_DATA` packet that writes a 32-bit `value` to a 64-bit GPU virtual address `dst_gpu_va`.
#[inline]
pub const fn build_pm4_write_data_dword(dst_gpu_va: u64, value: u32) -> [u32; 5] {
    let hdr = encode_pm4_type3_header(Pm4Opcode::WriteData, 4, false);
    // Control DWORD: DST_SEL = 5 (Memory), WR_CONFIRM = 1 (bit 20), ENGINE_SEL = 0 (ME)
    let ctrl = (5u32 << 8) | (1u32 << 20);
    [
        hdr,
        ctrl,
        (dst_gpu_va & 0xFFFF_FFFF) as u32,
        (dst_gpu_va >> 32) as u32,
        value,
    ]
}

/// Builds a 3-DWORD PM4 `SET_UCONFIG_REG` packet writing a single 32-bit register at `mmio_byte_offset`.
#[inline]
pub const fn build_pm4_set_uconfig_reg(mmio_byte_offset: u32, reg_value: u32) -> [u32; 3] {
    const UCONFIG_SPACE_START_DWORD: u32 = 0xC000;
    let dword_idx = (mmio_byte_offset >> 2).saturating_sub(UCONFIG_SPACE_START_DWORD);
    [
        encode_pm4_type3_header(Pm4Opcode::SetUconfigReg, 2, false),
        dword_idx & 0xFFFF,
        reg_value,
    ]
}

/// AMD DCN CRTC Timing & Primary Surface Flip state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RdnaDcnScanoutState {
    pub otg_h_total: u32,
    pub otg_h_blank_start_end: u32,
    pub otg_v_total: u32,
    pub otg_v_blank_start_end: u32,
    pub viewport_dimension: u32,
    pub surface_config: u32,
    pub tiling_config: u32,
    pub surface_addr_low: u32,
    pub surface_addr_high: u32,
    pub vsync_flip_pending: bool,
    pub flip_count: u64,
}

impl RdnaDcnScanoutState {
    /// Configures DCN OTG timings and primary HUBP surface format for a given display resolution and 256B-aligned VRAM address.
    pub const fn new_mode(
        h_active: u16,
        h_total: u16,
        v_active: u16,
        v_total: u16,
        format: DcnSurfacePixelFormat,
        swizzle: RdnaSwizzleMode,
        vram_surface_phys: u64,
    ) -> Self {
        let h_blank_start = h_active;
        let h_blank_end = h_total.saturating_sub(h_active);
        let v_blank_start = v_active;
        let v_blank_end = v_total.saturating_sub(v_active);
        let aligned_addr = vram_surface_phys & !0xFFu64;

        Self {
            otg_h_total: (h_total.saturating_sub(1)) as u32,
            otg_h_blank_start_end: ((h_blank_end as u32) << 16) | (h_blank_start as u32),
            otg_v_total: (v_total.saturating_sub(1)) as u32,
            otg_v_blank_start_end: ((v_blank_end as u32) << 16) | (v_blank_start as u32),
            viewport_dimension: (((v_active as u32) & 0x3FFF) << 16) | ((h_active as u32) & 0x3FFF),
            surface_config: format as u32,
            tiling_config: (swizzle as u32) & 0x1F,
            surface_addr_low: (aligned_addr >> 8) as u32, // DCN stores bits [39:8] in PRIMARY_SURFACE_ADDRESS
            surface_addr_high: (aligned_addr >> 40) as u32,
            vsync_flip_pending: false,
            flip_count: 0,
        }
    }

    /// Programs a page flip to a new 256-byte aligned VRAM surface address.
    pub fn flip_surface(&mut self, new_vram_surface_phys: u64, immediate_hblank_flip: bool) {
        let aligned = new_vram_surface_phys & !0xFFu64;
        self.surface_addr_low = (aligned >> 8) as u32;
        self.surface_addr_high = (aligned >> 40) as u32;
        self.vsync_flip_pending = !immediate_hblank_flip;
        self.flip_count += 1;
    }
}

/// Self-test for `gpu_amd_rdna` PM4 Type-3 packet encoding/decoding and DCN OTG/HUBP scanout state.
pub fn verify_driver_module_gpu_amd_rdna() -> u32 {
    let mut passed = 0u32;

    // 1. Verify PM4 Type-3 packet header roundtrip encoding/decoding
    let hdr = encode_pm4_type3_header(Pm4Opcode::DrawIndexAuto, 2, false);
    if decode_pm4_type3_header(hdr) == Some((Pm4Opcode::DrawIndexAuto as u8, 2)) {
        passed += 1;
    }

    // 2. Verify PM4 WRITE_DATA 5-DWORD packet generation
    let pkt = build_pm4_write_data_dword(0x0000_0080_1000_2000, 0xCAFE_BABE);
    if pkt[2] == 0x1000_2000 && pkt[3] == 0x0000_0080 && pkt[4] == 0xCAFE_BABE {
        passed += 1;
    }

    // 3. Verify DCN 2560x1440 OTG timing and 256B-aligned surface address shift (`addr >> 8`)
    let mut scanout = RdnaDcnScanoutState::new_mode(
        2560,
        2720,
        1440,
        1481,
        DcnSurfacePixelFormat::GrphArgb8888,
        RdnaSwizzleMode::Sw64kbRX,
        0x0000_0001_0040_0000,
    );
    if scanout.otg_h_total == 2719
        && scanout.otg_v_total == 1480
        && scanout.surface_addr_low == 0x0100_4000
    {
        passed += 1;
    }

    // 4. Verify DCN surface flip updates address registers and increments flip counter
    scanout.flip_surface(0x0000_0001_0200_0000, false);
    if scanout.surface_addr_low == 0x0102_0000
        && scanout.vsync_flip_pending
        && scanout.flip_count == 1
    {
        passed += 1;
    }

    passed
}
