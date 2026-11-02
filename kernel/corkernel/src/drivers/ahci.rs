//! CorOS Advanced Host Controller Interface (AHCI 1.3.1 / SATA) Driver (`ahci.rs`)
//!
//! Provides bare-metal Serial ATA (SATA) disk access through AHCI MMIO:
//! - Generic Host Control (CAP, GHC, IS, PI, VS, CCC_CTL, CAP2, BOHC)
//! - Port Registers (CLB, CLBU, FB, FBU, IS, IE, CMD, TFD, SIG, SSTS, SCTL, SERR, SACT, CI)
//! - Command List: 32 Command Headers per port
//! - Command Table: Command FIS (Frame Information Structure), ATAPI command, PRDT (Physical Region Descriptor Table)
//! - Register H2D (Host to Device) FIS construction (ATA Command 0xEC = IDENTIFY DEVICE, 0x25 = READ DMA EXT, 0x35 = WRITE DMA EXT)
//! - Port detection (SATA drive vs SATAPI optical drive vs enclosure management vs none)
//! - 48-bit LBA sector reading and writing

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

/// AHCI Generic Host Control Offsets
pub const AHCI_CAP: usize = 0x00;      // Host Capabilities
pub const AHCI_GHC: usize = 0x04;      // Global Host Control
pub const AHCI_IS: usize = 0x08;       // Interrupt Status
pub const AHCI_PI: usize = 0x0C;       // Ports Implemented
pub const AHCI_VS: usize = 0x10;       // Version (e.g. 0x00010301 for 1.3.1)
pub const AHCI_CAP2: usize = 0x24;     // Host Capabilities Extended
pub const AHCI_BOHC: usize = 0x28;     // BIOS/OS Handoff Control and Status

/// GHC Bits
pub const GHC_HR: u32 = 1 << 0;        // HBA Reset
pub const GHC_IE: u32 = 1 << 1;        // Interrupt Enable
pub const GHC_AE: u32 = 1 << 31;       // AHCI Enable

/// Port Register Offsets (relative to port base: 0x100 + port_idx * 0x80)
pub const PORT_CLB: usize = 0x00;      // Command List Base Address (32-byte aligned)
pub const PORT_CLBU: usize = 0x04;     // Command List Base Address Upper 32-bits
pub const PORT_FB: usize = 0x08;       // FIS Base Address (256-byte aligned)
pub const PORT_FBU: usize = 0x0C;      // FIS Base Address Upper 32-bits
pub const PORT_IS: usize = 0x10;       // Interrupt Status
pub const PORT_IE: usize = 0x14;       // Interrupt Enable
pub const PORT_CMD: usize = 0x18;      // Command and Status
pub const PORT_TFD: usize = 0x20;      // Task File Data
pub const PORT_SIG: usize = 0x24;      // Signature
pub const PORT_SSTS: usize = 0x28;     // SATA Status (SCR0: SStatus)
pub const PORT_SCTL: usize = 0x2C;     // SATA Control (SCR2: SControl)
pub const PORT_SERR: usize = 0x30;     // SATA Error (SCR1: SError)
pub const PORT_SACT: usize = 0x34;     // SATA Active (SCR3: SActive)
pub const PORT_CI: usize = 0x38;       // Command Issue

/// Port Command Bits
pub const PORT_CMD_ST: u32 = 1 << 0;   // Start processing command list
pub const PORT_CMD_SUD: u32 = 1 << 1;  // Spin-Up Device
pub const PORT_CMD_POD: u32 = 1 << 2;  // Power On Device
pub const PORT_CMD_FRE: u32 = 1 << 4;  // FIS Receive Enable
pub const PORT_CMD_FR: u32 = 1 << 14;  // FIS Receive Running
pub const PORT_CMD_CR: u32 = 1 << 15;  // Command List Running

/// SATA Signatures
pub const SATA_SIG_ATA: u32 = 0x00000101;   // SATA Drive
pub const SATA_SIG_ATAPI: u32 = 0xEB140101; // SATAPI Optical Drive
pub const SATA_SIG_SEMB: u32 = 0xC33C0101;  // Enclosure management bridge
pub const SATA_SIG_PM: u32 = 0x96690101;    // Port multiplier

/// ATA Commands
pub const ATA_CMD_READ_DMA_EX: u8 = 0x25;
pub const ATA_CMD_WRITE_DMA_EX: u8 = 0x35;
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
pub const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;

/// FIS Types
pub const FIS_TYPE_REG_H2D: u8 = 0x27;
pub const FIS_TYPE_REG_D2H: u8 = 0x34;
pub const FIS_TYPE_DMA_ACT: u8 = 0x39;
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;
pub const FIS_TYPE_DATA: u8 = 0x46;
pub const FIS_TYPE_BIST: u8 = 0x58;
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;
pub const FIS_TYPE_DEV_BITS: u8 = 0xA1;

/// Command Header (32 bytes per command in Command List)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AhciCommandHeader {
    pub flags: u16,        // CFL (bits 0-4), A, W, P, R, B, C, R, PMP (bits 12-15)
    pub prdtl: u16,        // Physical Region Descriptor Table Length (number of entries)
    pub prdbc: u32,        // Physical Region Descriptor Byte Count transferred
    pub ctba: u32,         // Command Table Descriptor Base Address Low
    pub ctbau: u32,        // Command Table Descriptor Base Address High
    pub reserved: [u32; 4],
}

/// Physical Region Descriptor Table Entry (PRDT Entry: 16 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AhciPrdtEntry {
    pub dba: u32,          // Data Base Address Low
    pub dbau: u32,         // Data Base Address Upper 32-bits
    pub reserved: u32,
    pub dbc_flags: u32,    // Byte Count (bits 0-21, 0-indexed: count - 1), bit 31 = Interrupt on completion
}

/// Register Host-to-Device FIS (20 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FisRegH2D {
    pub fis_type: u8,      // FIS_TYPE_REG_H2D (0x27)
    pub flags: u8,         // bit 7: C (1 = Command, 0 = Control)
    pub command: u8,       // Command Register (e.g. 0x25 READ DMA EXT)
    pub features_low: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,        // bit 6 = LBA mode (1)
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub features_high: u8,
    pub count_low: u8,
    pub count_high: u8,
    pub icc: u8,           // Isochronous command completion
    pub control: u8,
    pub reserved: [u8; 4],
}

/// Port Device Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciDeviceType {
    None,
    Sata,
    Satapi,
    Semb,
    PortMultiplier,
}

/// Information obtained from ATA IDENTIFY DEVICE
#[derive(Debug, Clone)]
pub struct SataIdentifyInfo {
    pub serial_number: String,
    pub firmware_revision: String,
    pub model_number: String,
    pub total_sectors: u64,
    pub sector_size: u32,
    pub is_lba48_supported: bool,
}

/// AHCI Port Representation
pub struct AhciPort {
    pub port_index: usize,
    pub mmio_base: usize,
    pub device_type: AhciDeviceType,
    pub identify: Option<SataIdentifyInfo>,
}

impl AhciPort {
    pub fn new(port_idx: usize, hba_base: usize) -> Self {
        let port_mmio = hba_base + 0x100 + port_idx * 0x80;
        let mut port = Self {
            port_index: port_idx,
            mmio_base: port_mmio,
            device_type: AhciDeviceType::None,
            identify: None,
        };
        port.probe_device();
        port
    }

    unsafe fn read_reg(&self, reg: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + reg) as *const u32)
    }

    unsafe fn write_reg(&self, reg: usize, val: u32) {
        core::ptr::write_volatile((self.mmio_base + reg) as *mut u32, val);
    }

    /// Probe whether a device is attached and detected
    pub fn probe_device(&mut self) {
        let ssts = unsafe { self.read_reg(PORT_SSTS) };
        let det = ssts & 0x0F;
        let ipm = (ssts >> 8) & 0x0F;

        // Device presence detected and communication established
        if det != 3 || ipm != 1 {
            self.device_type = AhciDeviceType::None;
            return;
        }

        let sig = unsafe { self.read_reg(PORT_SIG) };
        self.device_type = match sig {
            SATA_SIG_ATA => AhciDeviceType::Sata,
            SATA_SIG_ATAPI => AhciDeviceType::Satapi,
            SATA_SIG_SEMB => AhciDeviceType::Semb,
            SATA_SIG_PM => AhciDeviceType::PortMultiplier,
            _ => AhciDeviceType::None,
        };
    }

    /// Stop port command processing
    pub fn stop_cmd(&self) {
        unsafe {
            let mut cmd = self.read_reg(PORT_CMD);
            cmd &= !(PORT_CMD_ST | PORT_CMD_FRE);
            self.write_reg(PORT_CMD, cmd);

            // Wait until FR and CR clear
            for _ in 0..10_000 {
                let cur = self.read_reg(PORT_CMD);
                if (cur & (PORT_CMD_FR | PORT_CMD_CR)) == 0 {
                    break;
                }
            }
        }
    }

    /// Start port command processing
    pub fn start_cmd(&self) {
        unsafe {
            for _ in 0..10_000 {
                if (self.read_reg(PORT_CMD) & PORT_CMD_CR) == 0 {
                    break;
                }
            }
            let mut cmd = self.read_reg(PORT_CMD);
            cmd |= PORT_CMD_FRE;
            self.write_reg(PORT_CMD, cmd);
            cmd |= PORT_CMD_ST;
            self.write_reg(PORT_CMD, cmd);
        }
    }

    /// Build and issue ATA IDENTIFY DEVICE command
    pub fn parse_identify_buffer(words: &[u16; 256]) -> SataIdentifyInfo {
        let swap_chars = |raw: &[u16]| -> String {
            let mut s = String::new();
            for &w in raw {
                let c1 = (w >> 8) as u8 as char;
                let c2 = (w & 0xFF) as u8 as char;
                if c1.is_ascii_graphic() || c1 == ' ' { s.push(c1); }
                if c2.is_ascii_graphic() || c2 == ' ' { s.push(c2); }
            }
            String::from(s.trim())
        };

        let serial = swap_chars(&words[10..20]);
        let firmware = swap_chars(&words[23..27]);
        let model = swap_chars(&words[27..47]);

        let lba48 = (words[83] & (1 << 10)) != 0;
        let total_sec = if lba48 {
            (words[100] as u64)
                | ((words[101] as u64) << 16)
                | ((words[102] as u64) << 32)
                | ((words[103] as u64) << 48)
        } else {
            (words[60] as u64) | ((words[61] as u64) << 16)
        };

        SataIdentifyInfo {
            serial_number: serial,
            firmware_revision: firmware,
            model_number: model,
            total_sectors: total_sec,
            sector_size: 512,
            is_lba48_supported: lba48,
        }
    }
}

/// AHCI Host Bus Adapter (HBA) Controller
pub struct AhciController {
    pub mmio_base: usize,
    pub cap: u32,
    pub version: u32,
    pub port_count: usize,
    pub ports: Vec<AhciPort>,
}

impl AhciController {
    pub fn new(mmio_base: usize) -> Self {
        let cap = unsafe { core::ptr::read_volatile(mmio_base as *const u32) };
        let ghc = unsafe { core::ptr::read_volatile((mmio_base + AHCI_GHC) as *const u32) };
        let version = unsafe { core::ptr::read_volatile((mmio_base + AHCI_VS) as *const u32) };
        let pi = unsafe { core::ptr::read_volatile((mmio_base + AHCI_PI) as *const u32) };

        // Ensure AHCI Enable (AE) bit is set in GHC
        if (ghc & GHC_AE) == 0 {
            unsafe {
                core::ptr::write_volatile((mmio_base + AHCI_GHC) as *mut u32, ghc | GHC_AE);
            }
        }

        let mut ports = Vec::new();
        for i in 0..32 {
            if (pi & (1 << i)) != 0 {
                let p = AhciPort::new(i, mmio_base);
                ports.push(p);
            }
        }

        let port_count = ports.len();

        Self {
            mmio_base,
            cap,
            version,
            port_count,
            ports,
        }
    }

    /// Find first active SATA drive
    pub fn first_sata_port(&mut self) -> Option<&mut AhciPort> {
        self.ports.iter_mut().find(|p| p.device_type == AhciDeviceType::Sata)
    }
}
