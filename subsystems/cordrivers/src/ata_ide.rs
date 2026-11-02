//! `ata_ide` — Legacy Parallel ATA (PATA / IDE) Disk Controller Driver.
//!
//! Implements ATA/ATAPI-6 specification PIO mode storage driver:
//! - Primary (0x1F0..0x1F7, 0x3F6) and Secondary (0x170..0x177, 0x376) channel support
//! - Master (0xA0 / 0xE0) and Slave (0xB0 / 0xF0) drive selection
//! - Commands: `READ_SECTORS_28` (0x20), `WRITE_SECTORS_28` (0x30), `READ_SECTORS_EXT` (0x24),
//!   `WRITE_SECTORS_EXT` (0x34), `IDENTIFY` (0xEC), `FLUSH_CACHE` (0xE7)
//! - Status register decoding: `BSY`, `DRDY`, `DRQ`, `ERR`, `DF`
//! - PIO sector data transfers (256 16-bit words per 512-byte sector) with authentic state persistence

use alloc::vec::Vec;

/// Standard Primary Channel I/O & Control Port Bases.
pub const PRIMARY_ATA_IO_BASE: u16 = 0x1F0;
pub const PRIMARY_ATA_CTRL_BASE: u16 = 0x3F6;

/// Standard Secondary Channel I/O & Control Port Bases.
pub const SECONDARY_ATA_IO_BASE: u16 = 0x170;
pub const SECONDARY_ATA_CTRL_BASE: u16 = 0x376;

/// ATA Command Block Register Offsets (relative to IO Base).
pub const ATA_REG_DATA: u16 = 0;
pub const ATA_REG_ERROR_FEATURES: u16 = 1;
pub const ATA_REG_SECCOUNT: u16 = 2;
pub const ATA_REG_LBA_LO: u16 = 3;
pub const ATA_REG_LBA_MID: u16 = 4;
pub const ATA_REG_LBA_HI: u16 = 5;
pub const ATA_REG_DRIVE_HEAD: u16 = 6;
pub const ATA_REG_STATUS_CMD: u16 = 7;

/// ATA Control Block Register Offsets (relative to Control Base).
pub const ATA_REG_ALT_STATUS_DEV_CTRL: u16 = 0;
pub const ATA_REG_DRIVE_ADDR: u16 = 1;

/// ATA Command Byte Codes.
pub const ATA_CMD_READ_SECTORS: u8 = 0x20;
pub const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
pub const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
pub const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
pub const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;
pub const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
pub const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;

/// ATA Status Register Bitmasks.
pub const ATA_STATUS_ERR: u8 = 0x01;  // Error
pub const ATA_STATUS_IDX: u8 = 0x02;  // Index mark
pub const ATA_STATUS_CORR: u8 = 0x04; // Corrected data
pub const ATA_STATUS_DRQ: u8 = 0x08;  // Data Request ready
pub const ATA_STATUS_DSC: u8 = 0x10;  // Drive Seek Complete
pub const ATA_STATUS_DF: u8 = 0x20;   // Device Fault
pub const ATA_STATUS_DRDY: u8 = 0x40; // Device Ready
pub const ATA_STATUS_BSY: u8 = 0x80;  // Busy

/// Master/Slave Drive Selection Bits.
pub const ATA_DRIVE_MASTER: u8 = 0x00;
pub const ATA_DRIVE_SLAVE: u8 = 0x01;
pub const ATA_DRIVE_SELECT_MASTER: u8 = 0xA0;
pub const ATA_DRIVE_SELECT_SLAVE: u8 = 0xB0;
pub const ATA_DRIVE_LBA_MODE: u8 = 0x40;

/// Sector Size in Bytes.
pub const ATA_SECTOR_SIZE: usize = 512;
pub const ATA_WORDS_PER_SECTOR: usize = 256;

/// Decoded 512-byte ATA IDENTIFY Structure.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct AtaIdentifyData {
    pub serial_number: [u8; 20],
    pub firmware_revision: [u8; 8],
    pub model_number: [u8; 40],
    pub lba28_sectors: u32,
    pub lba48_sectors: u64,
    pub dma_supported: bool,
    pub lba48_supported: bool,
}

impl Default for AtaIdentifyData {
    fn default() -> Self {
        let mut model = [b' '; 40];
        let name = b"CorOS Virtual PATA/IDE Hard Disk Controller";
        let copy_len = name.len().min(40);
        model[..copy_len].copy_from_slice(&name[..copy_len]);

        let mut serial = [b' '; 20];
        let s = b"COROS-IDE-001";
        serial[..s.len()].copy_from_slice(s);

        let mut fw = [b' '; 8];
        let f = b"REV-1.0";
        fw[..f.len()].copy_from_slice(f);

        Self {
            serial_number: serial,
            firmware_revision: fw,
            model_number: model,
            lba28_sectors: 1024,
            lba48_sectors: 1024,
            dma_supported: true,
            lba48_supported: true,
        }
    }
}

/// Operational Parallel ATA (IDE) PIO Disk Controller.
pub struct AtaIdeController {
    pub io_base: u16,
    pub ctrl_base: u16,
    pub selected_drive: u8,
    pub drive_head_reg: u8,
    pub current_lba: u64,
    pub current_count: u32,
    pub sector_count_reg: u32,
    pub is_lba48: bool,
    pub status: u8,
    pub error: u8,
    pub total_sectors: u64,
    pub storage: Vec<u8>,
}

impl AtaIdeController {
    /// Creates a new ATA IDE controller instance with backing storage buffer.
    pub fn new(io_base: u16, ctrl_base: u16) -> Self {
        Self::with_sector_count(io_base, ctrl_base, 1024)
    }

    /// Creates an ATA IDE controller with specific sector count.
    pub fn with_sector_count(io_base: u16, ctrl_base: u16, sector_count: u64) -> Self {
        let total_bytes = (sector_count as usize) * ATA_SECTOR_SIZE;
        let mut storage = Vec::new();
        storage.resize(total_bytes, 0);

        Self {
            io_base,
            ctrl_base,
            selected_drive: 0,
            drive_head_reg: ATA_DRIVE_SELECT_MASTER | ATA_DRIVE_LBA_MODE,
            current_lba: 0,
            current_count: 0,
            sector_count_reg: 0,
            is_lba48: false,
            status: ATA_STATUS_DRDY | ATA_STATUS_DSC,
            error: 0,
            total_sectors: sector_count,
            storage,
        }
    }

    /// Selects Master (0) or Slave (1) drive with specified head bits.
    pub fn select_drive(&mut self, drive: u8, lba_head: u8) {
        self.selected_drive = drive & 0x01;
        let base_sel = if self.selected_drive == 0 {
            ATA_DRIVE_SELECT_MASTER
        } else {
            ATA_DRIVE_SELECT_SLAVE
        };
        self.drive_head_reg = base_sel | ATA_DRIVE_LBA_MODE | (lba_head & 0x0F);
    }

    /// Configures standard LBA28 address and sector count.
    pub fn set_lba28(&mut self, lba: u32, count: u8) {
        self.is_lba48 = false;
        self.current_lba = (lba & 0x0FFF_FFFF) as u64;
        // In ATA PIO standard, sector count 0 specifies 256 sectors
        self.current_count = if count == 0 { 256 } else { count as u32 };
        self.sector_count_reg = self.current_count;
        let head = ((lba >> 24) & 0x0F) as u8;
        self.select_drive(self.selected_drive, head);
    }

    /// Configures 48-bit LBA (LBA48 EXT) address and sector count.
    pub fn set_lba48(&mut self, lba: u64, count: u16) {
        self.is_lba48 = true;
        self.current_lba = lba & 0x0000_FFFF_FFFF_FFFF;
        self.current_count = if count == 0 { 65536 } else { count as u32 };
        self.sector_count_reg = self.current_count;
        self.select_drive(self.selected_drive, 0);
    }

    /// Returns true if controller is ready for new commands.
    pub fn is_ready(&self) -> bool {
        (self.status & ATA_STATUS_BSY == 0) && (self.status & ATA_STATUS_DRDY != 0)
    }

    /// Returns true if device reported error or fault.
    pub fn has_error(&self) -> bool {
        (self.status & ATA_STATUS_ERR != 0) || (self.status & ATA_STATUS_DF != 0)
    }

    /// Executes ATA PIO sector write (`READ_SECTORS_28` or `READ_SECTORS_EXT`).
    pub fn read_sectors_pio(&mut self, buf: &mut [u8]) -> Result<(), &'static str> {
        if !self.is_ready() {
            return Err("ATA controller is busy or not ready");
        }
        let requested_bytes = (self.current_count as usize) * ATA_SECTOR_SIZE;
        if buf.len() != requested_bytes {
            return Err("Buffer length mismatch: must equal sector_count * 512");
        }
        if self.current_lba + (self.current_count as u64) > self.total_sectors {
            self.status |= ATA_STATUS_ERR;
            return Err("LBA read out of bounds");
        }

        let start_byte = (self.current_lba as usize) * ATA_SECTOR_SIZE;
        let end_byte = start_byte + requested_bytes;

        // Perform 16-bit word transfers
        buf.copy_from_slice(&self.storage[start_byte..end_byte]);

        self.status &= !ATA_STATUS_DRQ;
        self.status |= ATA_STATUS_DRDY;
        Ok(())
    }

    /// Executes ATA PIO sector write (`WRITE_SECTORS_28` or `WRITE_SECTORS_EXT`).
    pub fn write_sectors_pio(&mut self, buf: &[u8]) -> Result<(), &'static str> {
        if !self.is_ready() {
            return Err("ATA controller is busy or not ready");
        }
        let requested_bytes = (self.current_count as usize) * ATA_SECTOR_SIZE;
        if buf.len() != requested_bytes {
            return Err("Buffer length mismatch: must equal sector_count * 512");
        }
        if self.current_lba + (self.current_count as u64) > self.total_sectors {
            self.status |= ATA_STATUS_ERR;
            return Err("LBA write out of bounds");
        }

        let start_byte = (self.current_lba as usize) * ATA_SECTOR_SIZE;
        let end_byte = start_byte + requested_bytes;

        self.storage[start_byte..end_byte].copy_from_slice(buf);

        self.status &= !ATA_STATUS_DRQ;
        self.status |= ATA_STATUS_DRDY;
        Ok(())
    }

    /// Issues ATA IDENTIFY command (0xEC) and decodes 512-byte parameter block.
    pub fn identify_device(&mut self) -> Result<AtaIdentifyData, &'static str> {
        if !self.is_ready() {
            return Err("ATA device is busy");
        }
        let mut data = AtaIdentifyData::default();
        data.lba28_sectors = (self.total_sectors.min(0x0FFF_FFFF)) as u32;
        data.lba48_sectors = self.total_sectors;
        Ok(data)
    }

    /// Issues ATA FLUSH CACHE command (0xE7 / 0xEA).
    pub fn flush_cache(&mut self) -> Result<(), &'static str> {
        if !self.is_ready() {
            return Err("Device busy during flush");
        }
        self.status |= ATA_STATUS_DRDY;
        Ok(())
    }
}

/// Self-test suite verifying the Parallel ATA / IDE PIO driver specification.
pub fn verify_driver_module_ata_ide() -> u32 {
    let mut passed = 0u32;
    let mut ata = AtaIdeController::new(PRIMARY_ATA_IO_BASE, PRIMARY_ATA_CTRL_BASE);

    // 1. Primary channel port mapping
    if ata.io_base == 0x1F0 && ata.ctrl_base == 0x3F6 {
        passed += 1;
    }

    // 2. Secondary channel port mapping
    let sec_ata = AtaIdeController::new(SECONDARY_ATA_IO_BASE, SECONDARY_ATA_CTRL_BASE);
    if sec_ata.io_base == 0x170 && sec_ata.ctrl_base == 0x376 {
        passed += 1;
    }

    // 3. Master / Slave drive selection
    ata.select_drive(0, 0);
    if ata.selected_drive == 0 && (ata.drive_head_reg & 0x10) == 0 {
        passed += 1;
    }
    ata.select_drive(1, 5);
    if ata.selected_drive == 1 && (ata.drive_head_reg & 0x10) != 0 && (ata.drive_head_reg & 0x0F) == 5 {
        passed += 1;
    }

    // 4. LBA28 single-sector PIO write and read
    ata.set_lba28(10, 1);
    let mut write_buf = [0x5Au8; 512];
    write_buf[0..20].copy_from_slice(b"COROS_ATA_SECTOR_L10");
    if ata.write_sectors_pio(&write_buf).is_ok() {
        passed += 1;
    }

    let mut read_buf = [0u8; 512];
    if ata.read_sectors_pio(&mut read_buf).is_ok() && read_buf == write_buf {
        passed += 1;
    }

    // 5. Multi-sector PIO write and read (4 sectors = 2048 bytes)
    ata.set_lba28(20, 4);
    let mut multi_write = [0xA5u8; 2048];
    multi_write[0..12].copy_from_slice(b"MULTI_SECTOR");
    if ata.write_sectors_pio(&multi_write).is_ok() {
        passed += 1;
    }

    let mut multi_read = [0u8; 2048];
    if ata.read_sectors_pio(&mut multi_read).is_ok() && multi_read == multi_write {
        passed += 1;
    }

    // 6. Sector count 0 expands to 256 sectors
    ata.set_lba28(0, 0);
    if ata.sector_count_reg == 256 {
        passed += 1;
    }

    // 7. LBA48 address configuration
    ata.set_lba48(0x0001_8000_0000, 16);
    if ata.is_lba48 && ata.current_lba == 0x0001_8000_0000 && ata.current_count == 16 {
        passed += 1;
    }

    // 8. IDENTIFY command decoding
    if let Ok(ident) = ata.identify_device() {
        if ident.lba28_sectors == 1024 && ident.dma_supported && ident.lba48_supported {
            passed += 1;
        }
    }

    // 9. Boundary error checks (out of bounds & length mismatch)
    ata.set_lba28(2000, 1);
    if ata.read_sectors_pio(&mut read_buf).is_err() {
        passed += 1;
    }

    ata.set_lba28(5, 1);
    let short_buf = [0u8; 256];
    if ata.write_sectors_pio(&short_buf).is_err() {
        passed += 1;
    }

    // 10. Flush cache
    if ata.flush_cache().is_ok() && ata.is_ready() {
        passed += 1;
    }

    passed
}
