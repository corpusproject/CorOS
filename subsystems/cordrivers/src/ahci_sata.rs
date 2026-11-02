//! CorOS Hardware Driver Module: `ahci_sata`
//!
//! Serial ATA AHCI 1.3.1 Host Bus Adapter (HBA) Generic Host Control registers,
//! Port register layout (`PxCLB`, `PxFB`, `PxIS`, `PxCI`, `PxSSTS`, `PxCMD`),
//! SATA Frame Information Structures (`FisRegH2D` `0x27`, `FisRegD2H` `0x34`),
//! `AhciCommandHeader`, `AhciPrdtEntry`, and LBA48 DMA command builders.

/// AHCI HBA Generic Host Control MMIO offsets (BAR5 / ABAR `0x00..0x2B`).
pub mod ahci_hba_regs {
    pub const CAP: usize = 0x00;
    pub const GHC: usize = 0x04;
    pub const IS: usize = 0x08;
    pub const PI: usize = 0x0C;
    pub const VS: usize = 0x10;
    pub const CCC_CTL: usize = 0x14;
    pub const CCC_PORTS: usize = 0x18;
    pub const EM_LOC: usize = 0x1C;
    pub const EM_CTL: usize = 0x20;
    pub const CAP2: usize = 0x24;
    pub const BOHC: usize = 0x28;
    pub const PORT_BASE: usize = 0x100;
    pub const PORT_STRIDE: usize = 0x80;
}

/// AHCI Per-Port Register offsets relative to `0x100 + port * 0x80`.
pub mod ahci_port_regs {
    pub const PX_CLB: usize = 0x00;
    pub const PX_CLBU: usize = 0x04;
    pub const PX_FB: usize = 0x08;
    pub const PX_FBU: usize = 0x0C;
    pub const PX_IS: usize = 0x10;
    pub const PX_IE: usize = 0x14;
    pub const PX_CMD: usize = 0x18;
    pub const PX_TFD: usize = 0x20;
    pub const PX_SIG: usize = 0x24;
    pub const PX_SSTS: usize = 0x28;
    pub const PX_SCTL: usize = 0x2C;
    pub const PX_SERR: usize = 0x30;
    pub const PX_SACT: usize = 0x34;
    pub const PX_CI: usize = 0x38;
    pub const PX_SNTF: usize = 0x3C;
    pub const PX_FBS: usize = 0x40;
}

/// Port Command and Status (`PxCMD`) bitflags.
pub mod px_cmd_flags {
    pub const ST: u32 = 1 << 0;
    pub const SUD: u32 = 1 << 1;
    pub const POD: u32 = 1 << 2;
    pub const FRE: u32 = 1 << 4;
    pub const FR: u32 = 1 << 14;
    pub const CR: u32 = 1 << 15;
}

/// Known SATA device signatures in `PxSIG`.
pub mod sata_signatures {
    pub const SATA_ATA_DISK: u32 = 0x0000_0101;
    pub const SATA_ATAPI_OPTICAL: u32 = 0xEB14_0101;
    pub const SATA_SEMB: u32 = 0xC33C_0101;
    pub const SATA_PORT_MULTIPLIER: u32 = 0x9669_0101;
}

/// ATA Command Set opcodes used over SATA Register H2D FIS.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaCommand {
    ReadDmaExt = 0x25,
    WriteDmaExt = 0x35,
    ReadFpdmaQueued = 0x60,
    WriteFpdmaQueued = 0x61,
    Packet = 0xA0,
    IdentifyDevice = 0xEC,
    FlushCacheExt = 0xEA,
    DataSetManagement = 0x06,
}

/// SATA FIS Type codes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SataFisType {
    RegH2D = 0x27,
    RegD2H = 0x34,
    DmaActivate = 0x39,
    DmaSetup = 0x41,
    Data = 0x46,
    BistActivate = 0x58,
    PioSetup = 0x5F,
    SetDeviceBits = 0xA1,
}

/// 20-byte Host-to-Device Register FIS (`FisRegH2D`, FIS Type `0x27`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FisRegH2D {
    pub fis_type: u8,
    /// Bit 7 = `C` (1 = Command register update, 0 = Device Control update); Bits `3:0` = Port Multiplier.
    pub pm_and_c: u8,
    pub command: u8,
    pub feature_low: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub feature_high: u8,
    pub count_low: u8,
    pub count_high: u8,
    pub icc: u8,
    pub control: u8,
    pub rsvd: [u8; 4],
}

impl FisRegH2D {
    /// Builds an LBA48 `READ DMA EXT` (`0x25`) or `WRITE DMA EXT` (`0x35`) Register H2D FIS.
    #[inline]
    pub const fn lba48_dma(command: AtaCommand, lba: u64, sector_count: u16) -> Self {
        Self {
            fis_type: SataFisType::RegH2D as u8,
            pm_and_c: 0x80, // C = 1 (Command)
            command: command as u8,
            feature_low: 0,
            lba0: (lba & 0xFF) as u8,
            lba1: ((lba >> 8) & 0xFF) as u8,
            lba2: ((lba >> 16) & 0xFF) as u8,
            device: 1 << 6, // LBA mode enabled
            lba3: ((lba >> 24) & 0xFF) as u8,
            lba4: ((lba >> 32) & 0xFF) as u8,
            lba5: ((lba >> 40) & 0xFF) as u8,
            feature_high: 0,
            count_low: (sector_count & 0xFF) as u8,
            count_high: ((sector_count >> 8) & 0xFF) as u8,
            icc: 0,
            control: 0,
            rsvd: [0; 4],
        }
    }

    /// Builds an `IDENTIFY DEVICE` (`0xEC`) Register H2D FIS.
    #[inline]
    pub const fn identify_device() -> Self {
        Self {
            fis_type: SataFisType::RegH2D as u8,
            pm_and_c: 0x80,
            command: AtaCommand::IdentifyDevice as u8,
            feature_low: 0,
            lba0: 0,
            lba1: 0,
            lba2: 0,
            device: 0,
            lba3: 0,
            lba4: 0,
            lba5: 0,
            feature_high: 0,
            count_low: 0,
            count_high: 0,
            icc: 0,
            control: 0,
            rsvd: [0; 4],
        }
    }
}

/// 20-byte Device-to-Host Register FIS (`FisRegD2H`, FIS Type `0x34`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FisRegD2H {
    pub fis_type: u8,
    pub pm_and_interrupt: u8,
    pub status: u8,
    pub error: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub rsvd0: u8,
    pub count_low: u8,
    pub count_high: u8,
    pub rsvd1: [u8; 6],
}

impl FisRegD2H {
    #[inline]
    pub const fn decoded_lba48(&self) -> u64 {
        (self.lba0 as u64)
            | ((self.lba1 as u64) << 8)
            | ((self.lba2 as u64) << 16)
            | ((self.lba3 as u64) << 24)
            | ((self.lba4 as u64) << 32)
            | ((self.lba5 as u64) << 40)
    }
}

/// 32-byte AHCI Command Header entry in the Port Command List (up to 32 slots per port).
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AhciCommandHeader {
    /// Bits `4:0` = Command FIS Length in DWORDs (`CFL`, `5` for 20-byte `FisRegH2D`),
    /// Bit `5` = ATAPI (`A`), Bit `6` = Write (`W`), Bit `7` = Prefetchable (`P`),
    /// Bit `10` = Clear Busy upon R_OK (`C`).
    pub flags: u16,
    /// Physical Region Descriptor Table Length (`PRDT` entry count).
    pub prdtl: u16,
    /// Physical Region Descriptor Byte Count Transferred (`PRD` byte counter updated by HBA).
    pub prdbc: u32,
    /// Command Table Descriptor Base Address (128-byte aligned physical address).
    pub ctba: u64,
    pub rsvd: [u32; 4],
}

impl AhciCommandHeader {
    #[inline]
    pub const fn new_dma(ctba_phys: u64, prdtl: u16, is_write: bool) -> Self {
        let cfl_dwords = 5u16; // 20 bytes / 4 = 5 DWORDs
        let write_bit = if is_write { 1u16 << 6 } else { 0 };
        let clear_busy = 1u16 << 10;
        Self {
            flags: cfl_dwords | write_bit | clear_busy,
            prdtl,
            prdbc: 0,
            ctba: ctba_phys & !0x7Fu64,
            rsvd: [0; 4],
        }
    }
}

/// 16-byte AHCI Physical Region Descriptor Table (`PRDT`) entry (up to 4 MiB per entry).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AhciPrdtEntry {
    /// Data Base Address (2-byte aligned physical address).
    pub dba: u64,
    pub rsvd: u32,
    /// Bit 31 = Interrupt on Completion (`I`); Bits `21:0` = Data Byte Count minus 1 (`DBC`).
    pub dbc_and_ioc: u32,
}

impl AhciPrdtEntry {
    pub const MAX_BYTES_PER_PRDT: u32 = 4 * 1024 * 1024;

    #[inline]
    pub const fn new(phys_addr: u64, byte_count: u32, interrupt_on_completion: bool) -> Self {
        let clamped = if byte_count > Self::MAX_BYTES_PER_PRDT {
            Self::MAX_BYTES_PER_PRDT
        } else if byte_count == 0 {
            1
        } else {
            byte_count
        };
        let dbc = (clamped - 1) & 0x003F_FFFF;
        let ioc = if interrupt_on_completion {
            1u32 << 31
        } else {
            0
        };
        Self {
            dba: phys_addr & !1u64,
            rsvd: 0,
            dbc_and_ioc: ioc | dbc,
        }
    }

    #[inline]
    pub const fn byte_count(&self) -> u32 {
        (self.dbc_and_ioc & 0x003F_FFFF) + 1
    }
}

/// Decoded SATA Port Status (`PxSSTS`) register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SataLinkStatus {
    pub det: u8,
    pub spd_gen: u8,
    pub ipm: u8,
}

impl SataLinkStatus {
    #[inline]
    pub const fn from_pxssts(ssts: u32) -> Self {
        Self {
            det: (ssts & 0x0F) as u8,
            spd_gen: ((ssts >> 4) & 0x0F) as u8,
            ipm: ((ssts >> 8) & 0x0F) as u8,
        }
    }

    /// Returns `true` if a device is present and PHY communication is established (`DET == 3`, `IPM == 1`).
    #[inline]
    pub const fn is_active_link(&self) -> bool {
        self.det == 0x03 && self.ipm == 0x01
    }

    /// Returns the negotiated SATA link speed in Mbit/s (`1500` for Gen1, `3000` for Gen2, `6000` for Gen3).
    #[inline]
    pub const fn link_rate_mbps(&self) -> u32 {
        match self.spd_gen {
            1 => 1500,
            2 => 3000,
            3 => 6000,
            _ => 0,
        }
    }
}

/// Self-test for `ahci_sata` FIS builders, command headers, PRDT entries, and SATA link state decoding.
pub fn verify_driver_module_ahci_sata() -> u32 {
    let mut passed = 0u32;

    // 1. Verify structure sizes match AHCI 1.3.1 specification
    if core::mem::size_of::<FisRegH2D>() == 20
        && core::mem::size_of::<FisRegD2H>() == 20
        && core::mem::size_of::<AhciCommandHeader>() == 32
        && core::mem::size_of::<AhciPrdtEntry>() == 16
    {
        passed += 1;
    }

    // 2. Verify LBA48 READ DMA EXT FIS encoding for high 48-bit LBA
    let lba: u64 = 0x1234_5678_9ABC;
    let fis = FisRegH2D::lba48_dma(AtaCommand::ReadDmaExt, lba, 0x0100);
    if fis.fis_type == 0x27
        && fis.command == 0x25
        && fis.lba0 == 0xBC
        && fis.lba5 == 0x12
        && fis.count_high == 0x01
    {
        passed += 1;
    }

    // 3. Verify Command Header & PRDT entry construction
    let cmd_hdr = AhciCommandHeader::new_dma(0x4000_0180, 2, true);
    let prdt = AhciPrdtEntry::new(0x8000_0000, 65536, true);
    if (cmd_hdr.flags & 0x1F) == 5
        && (cmd_hdr.flags & (1 << 6)) != 0
        && prdt.byte_count() == 65536
        && (prdt.dbc_and_ioc & (1 << 31)) != 0
    {
        passed += 1;
    }

    // 4. Verify SATA Gen3 link status decoding
    let link = SataLinkStatus::from_pxssts(0x0000_0133); // IPM=1, SPD=3 (Gen3), DET=3
    if link.is_active_link() && link.link_rate_mbps() == 6000 {
        passed += 1;
    }

    passed
}
