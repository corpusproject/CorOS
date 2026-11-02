//! Intel High Definition Audio (Intel HDA / Azalia) Controller Driver for CorOS.
//! 100% in-house implementation supporting MMIO registers, CORB/RIRB DMA command rings,
//! Codec discovery, and PCM audio stream buffer descriptor lists (BDL).

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// -----------------------------------------------------------------------------
// Intel HDA Controller MMIO Registers (Base Offset)
// -----------------------------------------------------------------------------
pub const HDA_REG_GCAP: usize     = 0x00; // Global Capabilities (16-bit)
pub const HDA_REG_VMIN: usize     = 0x02; // Minor Version (8-bit)
pub const HDA_REG_VMAJ: usize     = 0x03; // Major Version (8-bit)
pub const HDA_REG_OUTPAY: usize   = 0x04; // Output Payload Capability (16-bit)
pub const HDA_REG_INPAY: usize    = 0x06; // Input Payload Capability (16-bit)
pub const HDA_REG_GCTL: usize     = 0x08; // Global Control (32-bit)
pub const HDA_REG_WAKEEN: usize   = 0x0C; // Wake Enable (16-bit)
pub const HDA_REG_STATESTS: usize = 0x0E; // State Change Status (16-bit)
pub const HDA_REG_GSTS: usize     = 0x10; // Global Status (16-bit)
pub const HDA_REG_INTCTL: usize   = 0x20; // Interrupt Control (32-bit)
pub const HDA_REG_INTSTS: usize   = 0x24; // Interrupt Status (32-bit)

// CORB Registers (Command Outbound Ring Buffer)
pub const HDA_REG_CORBLBASE: usize = 0x40; // CORB Lower Base Address (32-bit)
pub const HDA_REG_CORBUBASE: usize = 0x44; // CORB Upper Base Address (32-bit)
pub const HDA_REG_CORBWP: usize    = 0x48; // CORB Write Pointer (16-bit)
pub const HDA_REG_CORBRP: usize    = 0x4A; // CORB Read Pointer (16-bit)
pub const HDA_REG_CORBCTL: usize   = 0x4C; // CORB Control (8-bit)
pub const HDA_REG_CORBSTS: usize   = 0x4D; // CORB Status (8-bit)
pub const HDA_REG_CORBSIZE: usize  = 0x4E; // CORB Size (8-bit)

// RIRB Registers (Response Inbound Ring Buffer)
pub const HDA_REG_RIRBLBASE: usize = 0x50; // RIRB Lower Base Address (32-bit)
pub const HDA_REG_RIRBUBASE: usize = 0x54; // RIRB Upper Base Address (32-bit)
pub const HDA_REG_RIRBWP: usize    = 0x58; // RIRB Write Pointer (16-bit)
pub const HDA_REG_RINTCNT: usize   = 0x5A; // Response Interrupt Count (16-bit)
pub const HDA_REG_RIRBCTL: usize   = 0x5C; // RIRB Control (8-bit)
pub const HDA_REG_RIRBSTS: usize   = 0x5D; // RIRB Status (8-bit)
pub const HDA_REG_RIRBSIZE: usize  = 0x5E; // RIRB Size (8-bit)

// Output Stream 0 Registers (Offset 0x100)
pub const HDA_SD0_CTL: usize       = 0x100; // Stream Descriptor 0 Control (24-bit)
pub const HDA_SD0_STS: usize       = 0x103; // Stream Descriptor 0 Status (8-bit)
pub const HDA_SD0_LPIB: usize      = 0x104; // Link Position in Buffer (32-bit)
pub const HDA_SD0_CBL: usize       = 0x108; // Cyclic Buffer Length (32-bit)
pub const HDA_SD0_LVI: usize       = 0x10C; // Last Valid Index (16-bit)
pub const HDA_SD0_FIFOS: usize     = 0x110; // FIFO Size (16-bit)
pub const HDA_SD0_FMT: usize       = 0x112; // Stream Format (16-bit)
pub const HDA_SD0_BDPL: usize      = 0x118; // BDL Pointer Lower (32-bit)
pub const HDA_SD0_BDPU: usize      = 0x11C; // BDL Pointer Upper (32-bit)

// Buffer Descriptor List (BDL) Entry - 16 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct HdaBdlEntry {
    pub addr_low: u32,
    pub addr_high: u32,
    pub length: u32,
    pub flags: u32, // Bit 0 = Interrupt on Completion (IOC)
}

// -----------------------------------------------------------------------------
// Intel HDA Device Controller
// -----------------------------------------------------------------------------
pub struct HdaController {
    pub mmio_base: usize,
    pub corb_entries: Vec<u32>, // 256 entries x 4 bytes = 1024 bytes
    pub rirb_entries: Vec<u64>, // 256 entries x 8 bytes = 2048 bytes
    pub bdl_entries: Vec<HdaBdlEntry>,
    pub pcm_buffer: Vec<u8>,
    pub corb_wp: u16,
    pub rirb_rp: u16,
    pub codec_mask: u16,
}

impl HdaController {
    pub unsafe fn init(mmio_base: usize) -> Result<Self, &'static str> {
        // 1. Reset Controller: clear CRST bit in GCTL
        let mut gctl = read_volatile((mmio_base + HDA_REG_GCTL) as *const u32);
        gctl &= !1; // Clear CRST
        write_volatile((mmio_base + HDA_REG_GCTL) as *mut u32, gctl);

        // Wait for CRST to become 0
        let mut timeout = 100_000;
        while (read_volatile((mmio_base + HDA_REG_GCTL) as *const u32) & 1) != 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("Intel HDA controller enter reset timeout");
            }
        }

        // 2. Bring controller out of reset: set CRST bit
        write_volatile((mmio_base + HDA_REG_GCTL) as *mut u32, 1);
        timeout = 100_000;
        while (read_volatile((mmio_base + HDA_REG_GCTL) as *const u32) & 1) == 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("Intel HDA controller leave reset timeout");
            }
        }

        // Wait 521 microseconds for codecs to assert STATESTS
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }

        let codec_mask = read_volatile((mmio_base + HDA_REG_STATESTS) as *const u16);

        // 3. Initialize CORB (256 entries = 1024 bytes)
        let mut corb_entries = Vec::with_capacity(256);
        corb_entries.resize(256, 0);

        // Stop CORB DMA
        write_volatile((mmio_base + HDA_REG_CORBCTL) as *mut u8, 0);

        // Set Base addresses
        let corb_phys = corb_entries.as_ptr() as u64;
        write_volatile((mmio_base + HDA_REG_CORBLBASE) as *mut u32, corb_phys as u32);
        write_volatile((mmio_base + HDA_REG_CORBUBASE) as *mut u32, (corb_phys >> 32) as u32);

        // Set size: 256 entries (size capability bit 2: 0b10)
        write_volatile((mmio_base + HDA_REG_CORBSIZE) as *mut u8, 0x02);

        // Reset CORB read pointer
        write_volatile((mmio_base + HDA_REG_CORBRP) as *mut u16, 0x8000);
        while (read_volatile((mmio_base + HDA_REG_CORBRP) as *const u16) & 0x8000) == 0 {}
        write_volatile((mmio_base + HDA_REG_CORBRP) as *mut u16, 0x0000);

        // Reset CORB write pointer
        write_volatile((mmio_base + HDA_REG_CORBWP) as *mut u16, 0x0000);

        // Start CORB DMA
        write_volatile((mmio_base + HDA_REG_CORBCTL) as *mut u8, 0x02);

        // 4. Initialize RIRB (256 entries = 2048 bytes)
        let mut rirb_entries = Vec::with_capacity(256);
        rirb_entries.resize(256, 0);

        write_volatile((mmio_base + HDA_REG_RIRBCTL) as *mut u8, 0);
        let rirb_phys = rirb_entries.as_ptr() as u64;
        write_volatile((mmio_base + HDA_REG_RIRBLBASE) as *mut u32, rirb_phys as u32);
        write_volatile((mmio_base + HDA_REG_RIRBUBASE) as *mut u32, (rirb_phys >> 32) as u32);
        write_volatile((mmio_base + HDA_REG_RIRBSIZE) as *mut u8, 0x02);

        // Reset RIRB write pointer
        write_volatile((mmio_base + HDA_REG_RIRBWP) as *mut u16, 0x8000);
        // Set Response Interrupt Count to 1
        write_volatile((mmio_base + HDA_REG_RINTCNT) as *mut u16, 1);
        // Start RIRB DMA
        write_volatile((mmio_base + HDA_REG_RIRBCTL) as *mut u8, 0x02);

        // 5. Initialize BDL and PCM audio stream buffer
        let mut bdl_entries = Vec::with_capacity(2);
        let mut pcm_buffer = Vec::with_capacity(65536);
        pcm_buffer.resize(65536, 0);

        let buf_phys = pcm_buffer.as_ptr() as u64;
        bdl_entries.push(HdaBdlEntry {
            addr_low: buf_phys as u32,
            addr_high: (buf_phys >> 32) as u32,
            length: 32768,
            flags: 1, // IOC
        });
        bdl_entries.push(HdaBdlEntry {
            addr_low: (buf_phys + 32768) as u32,
            addr_high: ((buf_phys + 32768) >> 32) as u32,
            length: 32768,
            flags: 1,
        });

        Ok(Self {
            mmio_base,
            corb_entries,
            rirb_entries,
            bdl_entries,
            pcm_buffer,
            corb_wp: 0,
            rirb_rp: 0,
            codec_mask,
        })
    }

    /// Send a 32-bit Codec Verb and wait for 64-bit Response via CORB/RIRB.
    pub unsafe fn send_verb(&mut self, cad: u8, nid: u8, verb: u32) -> Result<u64, &'static str> {
        let command = ((cad as u32) << 28) | ((nid as u32) << 20) | (verb & 0x000FFFFF);

        self.corb_wp = (self.corb_wp + 1) % 256;
        self.corb_entries[self.corb_wp as usize] = command;

        // Update CORB Write Pointer register
        write_volatile((self.mmio_base + HDA_REG_CORBWP) as *mut u16, self.corb_wp);

        // Wait for RIRB Write Pointer to advance
        let mut timeout = 100_000;
        loop {
            let rirb_wp = read_volatile((self.mmio_base + HDA_REG_RIRBWP) as *const u16) & 0xFF;
            if rirb_wp != self.rirb_rp {
                self.rirb_rp = (self.rirb_rp + 1) % 256;
                let resp = self.rirb_entries[self.rirb_rp as usize];
                return Ok(resp);
            }
            timeout -= 1;
            if timeout == 0 {
                return Err("Intel HDA Codec Verb response timeout");
            }
        }
    }

    /// Configure Stream 0 for 44.1 kHz, 16-bit, 2 channels PCM audio.
    pub unsafe fn setup_output_stream(&mut self) {
        let bdl_phys = self.bdl_entries.as_ptr() as u64;

        // Reset stream
        write_volatile((self.mmio_base + HDA_SD0_CTL) as *mut u32, 1);
        while (read_volatile((self.mmio_base + HDA_SD0_CTL) as *const u32) & 1) == 0 {}
        write_volatile((self.mmio_base + HDA_SD0_CTL) as *mut u32, 0);
        while (read_volatile((self.mmio_base + HDA_SD0_CTL) as *const u32) & 1) != 0 {}

        // Set BDL pointer
        write_volatile((self.mmio_base + HDA_SD0_BDPL) as *mut u32, bdl_phys as u32);
        write_volatile((self.mmio_base + HDA_SD0_BDPU) as *mut u32, (bdl_phys >> 32) as u32);

        // Cyclic Buffer Length = 65536 bytes
        write_volatile((self.mmio_base + HDA_SD0_CBL) as *mut u32, 65536);
        // Last Valid Index = 1 (2 buffers: 0 and 1)
        write_volatile((self.mmio_base + HDA_SD0_LVI) as *mut u16, 1);

        // Format: 44.1 kHz, 16-bit, 2 channels:
        // Bit 14 (Base 44.1k = 1), Bits 6:4 (16-bit = 001), Bits 3:0 (2 channels = 0001)
        let fmt: u16 = (1 << 14) | (1 << 4) | 1;
        write_volatile((self.mmio_base + HDA_SD0_FMT) as *mut u16, fmt);

        // Enable DMA and Stream 1 tag
        let ctl: u32 = (1 << 20) | (1 << 4) | (1 << 2) | (1 << 1);
        write_volatile((self.mmio_base + HDA_SD0_CTL) as *mut u32, ctl);
    }
}
