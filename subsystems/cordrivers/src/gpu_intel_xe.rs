//! CorOS Hardware Driver Module: `gpu_intel_xe`
//!
//! Intel Iris Xe / UHD Graphics (Gen11 / Gen12 / Xe-LP) Display Engine MMIO registers
//! (`PIPECONF`, `HTOTAL`, `HBLANK`, `HSYNC`, `VTOTAL`, `VBLANK`, `VSYNC`, `DSPCNTR`,
//! `DSPSTRIDE`, `DSPSURF`), GMBUS I2C EDID 1.4 controller & 128-byte EDID block parser,
//! and Hardware Cursor Plane state machine.

/// Intel Display Engine Pipe A Timing & Plane MMIO Register Offsets.
pub mod xe_display_regs {
    /// Pipe A Horizontal Total (`[28:16] = HTotal - 1`, `[12:0] = HActive - 1`).
    pub const HTOTAL_A: usize = 0x60000;
    /// Pipe A Horizontal Blank (`[28:16] = HBlankEnd - 1`, `[12:0] = HBlankStart - 1`).
    pub const HBLANK_A: usize = 0x60004;
    /// Pipe A Horizontal Sync (`[28:16] = HSyncEnd - 1`, `[12:0] = HSyncStart - 1`).
    pub const HSYNC_A: usize = 0x60008;
    /// Pipe A Vertical Total (`[28:16] = VTotal - 1`, `[12:0] = VActive - 1`).
    pub const VTOTAL_A: usize = 0x6000C;
    /// Pipe A Vertical Blank.
    pub const VBLANK_A: usize = 0x60010;
    /// Pipe A Vertical Sync.
    pub const VSYNC_A: usize = 0x60014;
    /// Pipe A Source Image Size (`[28:16] = Width - 1`, `[12:0] = Height - 1`).
    pub const PIPESRC_A: usize = 0x6001C;
    /// Pipe A Configuration (`Bit 31 = Enable`, `Bit 30 = State`).
    pub const PIPECONF_A: usize = 0x70008;
    /// Primary Plane A Control (`DSPCNTR_A`).
    pub const DSPCNTR_A: usize = 0x70180;
    /// Primary Plane A Linear Offset (`DSPLINOFF_A`).
    pub const DSPLINOFF_A: usize = 0x70184;
    /// Primary Plane A Stride (`DSPSTRIDE_A`, in bytes or 64-byte tiles).
    pub const DSPSTRIDE_A: usize = 0x70188;
    /// Primary Plane A Surface Base Address (`DSPSURF_A`, 4 KiB aligned GGTT offset; writing triggers flip).
    pub const DSPSURF_A: usize = 0x7019C;
    /// Cursor A Control (`CURACNTR`).
    pub const CURACNTR: usize = 0x70080;
    /// Cursor A Base Address (`CURABASE`).
    pub const CURABASE: usize = 0x70084;
    /// Cursor A Position (`CURAPOS`).
    pub const CURAPOS: usize = 0x70088;
    /// GMBUS0 — Clock/Port Select (`0xC5100`).
    pub const GMBUS0: usize = 0xC5100;
    /// GMBUS1 — Command/Status (`0xC5104`).
    pub const GMBUS1: usize = 0xC5104;
    /// GMBUS2 — Status (`0xC5108`).
    pub const GMBUS2: usize = 0xC5108;
    /// GMBUS3 — 4-byte Data Buffer (`0xC510C`).
    pub const GMBUS3: usize = 0xC510C;
}

/// Intel Primary Plane Pixel Format codes (`DSPCNTR[27:24]`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XePlanePixelFormat {
    Indexed8Bpp = 0b0010,
    Rgb565 = 0b0101,
    Bgrx8888 = 0b0110,
    Bgra8888 = 0b0111,
    Rgbx1010102 = 0b1000,
    Rgba1010102 = 0b1001,
    Rgbx8888 = 0b1110,
    Rgba8888 = 0b1111,
}

/// Complete Display Pipe Timing & Primary Plane Register Configuration for an Intel Xe CRTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XePipeTimingRegisters {
    pub htotal: u32,
    pub hblank: u32,
    pub hsync: u32,
    pub vtotal: u32,
    pub vblank: u32,
    pub vsync: u32,
    pub pipesrc: u32,
    pub pipeconf: u32,
    pub dspcntr: u32,
    pub dspstride: u32,
    pub dspsurf: u32,
}

impl XePipeTimingRegisters {
    #[inline]
    const fn pack_timing_pair(low: u16, high: u16) -> u32 {
        (((high.saturating_sub(1) & 0x1FFF) as u32) << 16)
            | ((low.saturating_sub(1) & 0x1FFF) as u32)
    }

    /// Computes the exact Intel Display Pipe register values for a progressive display mode
    /// and a linear 4 KiB-aligned GGTT surface base address.
    pub const fn compute_mode(
        hactive: u16,
        hsync_start: u16,
        hsync_end: u16,
        htotal: u16,
        vactive: u16,
        vsync_start: u16,
        vsync_end: u16,
        vtotal: u16,
        format: XePlanePixelFormat,
        pitch_bytes: u32,
        ggtt_surface_addr: u32,
    ) -> Self {
        let dspcntr = (1u32 << 31) // Plane Enable
            | ((format as u32) << 24); // Pixel Format (Linear tiling = bit 10 clear)

        Self {
            htotal: Self::pack_timing_pair(hactive, htotal),
            hblank: Self::pack_timing_pair(hactive, htotal),
            hsync: Self::pack_timing_pair(hsync_start, hsync_end),
            vtotal: Self::pack_timing_pair(vactive, vtotal),
            vblank: Self::pack_timing_pair(vactive, vtotal),
            vsync: Self::pack_timing_pair(vsync_start, vsync_end),
            pipesrc: (((hactive.saturating_sub(1) as u32) & 0x1FFF) << 16)
                | ((vactive.saturating_sub(1) as u32) & 0x1FFF),
            pipeconf: 1u32 << 31, // Pipe Enable
            dspcntr,
            dspstride: pitch_bytes & !0x3F, // 64-byte aligned linear stride
            dspsurf: ggtt_surface_addr & !0xFFF, // 4 KiB aligned GGTT offset
        }
    }
}

#[inline]
const fn encode_cursor_axis(v: i16) -> u32 {
    if v < 0 {
        (1u32 << 15) | ((-v as u32) & 0x1FFF)
    } else {
        (v as u32) & 0x1FFF
    }
}

/// Encodes the `CURAPOS` (Hardware Cursor Position) register with sign-magnitude coordinates.
#[inline]
pub const fn encode_cursor_position(x: i16, y: i16) -> u32 {
    (encode_cursor_axis(y) << 16) | encode_cursor_axis(x)
}

/// Encodes the `GMBUS1` register command to perform an I2C EDID read transaction on 7-bit slave `0x50`.
#[inline]
pub const fn encode_gmbus1_edid_read(start_offset: u8, byte_count: u16) -> u32 {
    let sw_rdy = 1u32 << 30;
    let wait_state = 1u32 << 25;
    let index_enable = 1u32 << 27;
    let total_bytes = ((byte_count & 0x01FF) as u32) << 16;
    let index_reg = (start_offset as u32) << 8;
    let slave_addr_read = (0x50u32 << 1) | 0x01; // 7-bit 0x50 + Read bit 0 = 0xA1
    sw_rdy | index_enable | wait_state | total_bytes | index_reg | slave_addr_read
}

/// Decoded native timing from a 128-byte VESA EDID 1.4 block (`Detailed Timing Descriptor #1` at byte `54..72`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdidNativeTiming {
    pub manufacturer_id: [u8; 3],
    pub product_code: u16,
    pub pixel_clock_khz: u32,
    pub h_active: u16,
    pub h_blanking: u16,
    pub v_active: u16,
    pub v_blanking: u16,
}

impl EdidNativeTiming {
    /// Validates the 8-byte EDID magic header (`00 FF FF FF FF FF FF 00`), verifies the modulo-256
    /// checksum, and decodes Detailed Timing Descriptor #1.
    pub fn parse_edid_block(edid: &[u8; 128]) -> Option<Self> {
        const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        if edid[0..8] != EDID_HEADER {
            return None;
        }
        let mut sum = 0u8;
        let mut i = 0;
        while i < 128 {
            sum = sum.wrapping_add(edid[i]);
            i += 1;
        }
        if sum != 0 {
            return None;
        }

        // Compressed 3-letter PnP Manufacturer ID at bytes 8..10 (big-endian)
        let mfg_raw = u16::from_be_bytes([edid[8], edid[9]]);
        let manufacturer_id = [
            b'@' + (((mfg_raw >> 10) & 0x1F) as u8),
            b'@' + (((mfg_raw >> 5) & 0x1F) as u8),
            b'@' + ((mfg_raw & 0x1F) as u8),
        ];
        let product_code = u16::from_le_bytes([edid[10], edid[11]]);

        // Detailed Timing Descriptor #1 at offset 54
        let pclk_10khz = u16::from_le_bytes([edid[54], edid[55]]) as u32;
        if pclk_10khz == 0 {
            return None;
        }
        let h_active = (edid[56] as u16) | (((edid[58] >> 4) as u16) << 8);
        let h_blanking = (edid[57] as u16) | (((edid[58] & 0x0F) as u16) << 8);
        let v_active = (edid[59] as u16) | (((edid[61] >> 4) as u16) << 8);
        let v_blanking = (edid[60] as u16) | (((edid[61] & 0x0F) as u16) << 8);

        Some(Self {
            manufacturer_id,
            product_code,
            pixel_clock_khz: pclk_10khz * 10,
            h_active,
            h_blanking,
            v_active,
            v_blanking,
        })
    }
}

/// Self-test for `gpu_intel_xe` Pipe A mode timing registers, GMBUS EDID command encoding, and EDID 1.4 parsing.
pub fn verify_driver_module_gpu_intel_xe() -> u32 {
    let mut passed = 0u32;

    // 1. Verify 1920x1080@60Hz CEA-861 Pipe A register calculation
    let regs = XePipeTimingRegisters::compute_mode(
        1920,
        2008,
        2052,
        2200,
        1080,
        1084,
        1089,
        1125,
        XePlanePixelFormat::Bgrx8888,
        1920 * 4,
        0x0020_0000,
    );
    if (regs.htotal & 0x1FFF) == 1919
        && ((regs.htotal >> 16) & 0x1FFF) == 2199
        && (regs.vtotal & 0x1FFF) == 1079
        && regs.dspstride == 7680
        && regs.dspsurf == 0x0020_0000
    {
        passed += 1;
    }

    // 2. Verify Hardware Cursor negative-coordinate sign-magnitude encoding
    let pos = encode_cursor_position(-16, 240);
    if (pos & 0xFFFF) == (0x8000 | 16) && (pos >> 16) == 240 {
        passed += 1;
    }

    // 3. Verify GMBUS1 EDID 128-byte I2C read command encoding
    let gmbus1 = encode_gmbus1_edid_read(0, 128);
    if (gmbus1 & 0xFF) == 0xA1 && ((gmbus1 >> 16) & 0x1FF) == 128 {
        passed += 1;
    }

    // 4. Verify EDID 1.4 block checksum and Detailed Timing Descriptor #1 parser (1920x1080, 148.5 MHz)
    let mut edid = [0u8; 128];
    edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // PnP ID "INT" -> ('I'-'@')=9, ('N'-'@')=14, ('T'-'@')=20 -> (9<<10)|(14<<5)|20 = 0x25D4
    edid[8..10].copy_from_slice(&0x25D4u16.to_be_bytes());
    edid[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
    // Pixel clock 148.5 MHz = 14850 * 10 kHz = 0x3A02
    edid[54..56].copy_from_slice(&14850u16.to_le_bytes());
    // HActive = 1920 (0x780), HBlank = 280 (0x118)
    edid[56] = 0x80;
    edid[57] = 0x18;
    edid[58] = 0x71;
    // VActive = 1080 (0x438), VBlank = 45 (0x02D)
    edid[59] = 0x38;
    edid[60] = 0x2D;
    edid[61] = 0x40;

    let mut sum = 0u8;
    for b in &edid[0..127] {
        sum = sum.wrapping_add(*b);
    }
    edid[127] = 0u8.wrapping_sub(sum);

    if let Some(parsed) = EdidNativeTiming::parse_edid_block(&edid) {
        if parsed.manufacturer_id == *b"INT"
            && parsed.pixel_clock_khz == 148_500
            && parsed.h_active == 1920
            && parsed.v_active == 1080
        {
            passed += 1;
        }
    }

    passed
}
