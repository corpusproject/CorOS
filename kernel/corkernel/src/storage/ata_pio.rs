//! Pure bare-metal ATA / IDE PIO storage driver.
//! 100% in-house CorOS implementation with zero external crates.

use super::{BlockDevice, StorageError};
use crate::arch::x86_64::cpu;

pub const PRIMARY_ATA_IO_BASE: u16 = 0x1F0;
pub const PRIMARY_ATA_CTRL_BASE: u16 = 0x3F6;

pub const ATA_CMD_READ_PIO_EXT: u8 = 0x24;
pub const ATA_CMD_WRITE_PIO_EXT: u8 = 0x34;
pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;

pub const ATA_STATUS_BSY: u8 = 0x80;
pub const ATA_STATUS_DRDY: u8 = 0x40;
pub const ATA_STATUS_DF: u8 = 0x20;
pub const ATA_STATUS_DRQ: u8 = 0x08;
pub const ATA_STATUS_ERR: u8 = 0x01;

pub struct AtaPioDisk {
    pub io_base: u16,
    pub ctrl_base: u16,
    pub is_slave: bool,
    pub total_sectors: u64,
}

impl AtaPioDisk {
    pub fn new(io_base: u16, ctrl_base: u16, is_slave: bool) -> Self {
        Self {
            io_base,
            ctrl_base,
            is_slave,
            total_sectors: 131072, // 64 MB default (can be updated via identify)
        }
    }

    /// Probes and initializes the ATA drive
    pub unsafe fn probe(&mut self) -> Result<(), StorageError> {
        let drive_sel = if self.is_slave { 0xB0 } else { 0xA0 };
        cpu::out8(self.io_base + 6, drive_sel);
        for _ in 0..10 {
            cpu::in8(self.ctrl_base); // 400ns delay
        }

        // Send IDENTIFY command
        cpu::out8(self.io_base + 2, 0);
        cpu::out8(self.io_base + 3, 0);
        cpu::out8(self.io_base + 4, 0);
        cpu::out8(self.io_base + 5, 0);
        cpu::out8(self.io_base + 7, ATA_CMD_IDENTIFY);

        let status = cpu::in8(self.io_base + 7);
        if status == 0 || status == 0xFF {
            return Err(StorageError::DeviceNotFound);
        }

        // Wait until BSY clears
        self.wait_not_busy()?;

        let status = cpu::in8(self.io_base + 7);
        if (status & ATA_STATUS_ERR) != 0 {
            return Err(StorageError::DeviceFault);
        }

        self.wait_drq()?;

        // Read 256 words of IDENTIFY data
        let mut id_buf = [0u16; 256];
        for word in id_buf.iter_mut() {
            *word = cpu::in16(self.io_base);
        }

        // Words 100-103: Total user addressable 48-bit sectors
        let sectors_48 = (id_buf[100] as u64)
            | ((id_buf[101] as u64) << 16)
            | ((id_buf[102] as u64) << 32)
            | ((id_buf[103] as u64) << 48);

        if sectors_48 > 0 {
            self.total_sectors = sectors_48;
        } else {
            // Words 60-61: 28-bit LBA sectors
            let sectors_28 = (id_buf[60] as u64) | ((id_buf[61] as u64) << 16);
            if sectors_28 > 0 {
                self.total_sectors = sectors_28;
            }
        }

        Ok(())
    }

    unsafe fn wait_not_busy(&self) -> Result<u8, StorageError> {
        for _ in 0..500_000 {
            let status = cpu::in8(self.io_base + 7);
            if (status & ATA_STATUS_BSY) == 0 {
                return Ok(status);
            }
            cpu::pause();
        }
        Err(StorageError::Timeout)
    }

    unsafe fn wait_drq(&self) -> Result<u8, StorageError> {
        for _ in 0..500_000 {
            let status = cpu::in8(self.io_base + 7);
            if (status & ATA_STATUS_BSY) == 0 && (status & ATA_STATUS_DRQ) != 0 {
                return Ok(status);
            }
            if (status & (ATA_STATUS_ERR | ATA_STATUS_DF)) != 0 {
                return Err(StorageError::DeviceFault);
            }
            cpu::pause();
        }
        Err(StorageError::Timeout)
    }

    unsafe fn read_single_sector_lba48(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), StorageError> {
        self.wait_not_busy()?;

        let drive_sel = if self.is_slave { 0x50 } else { 0x40 };
        cpu::out8(self.io_base + 6, drive_sel);

        // High bytes of sector count and LBA
        cpu::out8(self.io_base + 2, 0); // Count high
        cpu::out8(self.io_base + 3, ((lba >> 24) & 0xFF) as u8);
        cpu::out8(self.io_base + 4, ((lba >> 32) & 0xFF) as u8);
        cpu::out8(self.io_base + 5, ((lba >> 40) & 0xFF) as u8);

        // Low bytes of sector count and LBA
        cpu::out8(self.io_base + 2, 1); // Count low = 1 sector
        cpu::out8(self.io_base + 3, (lba & 0xFF) as u8);
        cpu::out8(self.io_base + 4, ((lba >> 8) & 0xFF) as u8);
        cpu::out8(self.io_base + 5, ((lba >> 16) & 0xFF) as u8);

        cpu::out8(self.io_base + 7, ATA_CMD_READ_PIO_EXT);

        self.wait_drq()?;

        for i in 0..256 {
            let word = cpu::in16(self.io_base);
            buf[i * 2] = (word & 0xFF) as u8;
            buf[i * 2 + 1] = ((word >> 8) & 0xFF) as u8;
        }

        Ok(())
    }

    unsafe fn write_single_sector_lba48(&self, lba: u64, buf: &[u8; 512]) -> Result<(), StorageError> {
        self.wait_not_busy()?;

        let drive_sel = if self.is_slave { 0x50 } else { 0x40 };
        cpu::out8(self.io_base + 6, drive_sel);

        // High bytes
        cpu::out8(self.io_base + 2, 0);
        cpu::out8(self.io_base + 3, ((lba >> 24) & 0xFF) as u8);
        cpu::out8(self.io_base + 4, ((lba >> 32) & 0xFF) as u8);
        cpu::out8(self.io_base + 5, ((lba >> 40) & 0xFF) as u8);

        // Low bytes
        cpu::out8(self.io_base + 2, 1);
        cpu::out8(self.io_base + 3, (lba & 0xFF) as u8);
        cpu::out8(self.io_base + 4, ((lba >> 8) & 0xFF) as u8);
        cpu::out8(self.io_base + 5, ((lba >> 16) & 0xFF) as u8);

        cpu::out8(self.io_base + 7, ATA_CMD_WRITE_PIO_EXT);

        self.wait_drq()?;

        for i in 0..256 {
            let word = (buf[i * 2] as u16) | ((buf[i * 2 + 1] as u16) << 8);
            cpu::out16(self.io_base, word);
        }

        // Flush cache to ensure durability
        cpu::out8(self.io_base + 7, ATA_CMD_FLUSH_EXT);
        self.wait_not_busy()?;

        Ok(())
    }
}

impl BlockDevice for AtaPioDisk {
    fn read_sectors(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        if buf.len() < (count as usize) * 512 {
            return Err(StorageError::BufferTooSmall);
        }

        let mut sec_buf = [0u8; 512];
        for i in 0..count {
            unsafe {
                self.read_single_sector_lba48(lba + i as u64, &mut sec_buf)?;
            }
            let offset = (i as usize) * 512;
            buf[offset..offset + 512].copy_from_slice(&sec_buf);
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), StorageError> {
        if buf.len() < (count as usize) * 512 {
            return Err(StorageError::BufferTooSmall);
        }

        let mut sec_buf = [0u8; 512];
        for i in 0..count {
            let offset = (i as usize) * 512;
            sec_buf.copy_from_slice(&buf[offset..offset + 512]);
            unsafe {
                self.write_single_sector_lba48(lba + i as u64, &sec_buf)?;
            }
        }
        Ok(())
    }

    fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    fn device_name(&self) -> &str {
        "ATA IDE (PIO LBA48)"
    }
}
