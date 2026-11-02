//! High-Performance Serial ATA AHCI 1.0+ Bare-Metal Storage Driver.
//! 100% in-house CorOS implementation with zero external crates.
//! Uses native Direct Memory Access (DMA) with PRDT scatter-gather tables.

use super::{BlockDevice, StorageError};
use crate::arch::x86_64::cpu;
use crate::pci::PciDevice;
use core::ptr;

pub const SATA_SIG_ATA: u32 = 0x00000101;
pub const AHCI_PORT_DET_PRESENT: u32 = 0x03;
pub const AHCI_PORT_IPM_ACTIVE: u32 = 0x01;

pub const AHCI_CMD_ST: u32 = 1 << 0;
pub const AHCI_CMD_FRE: u32 = 1 << 4;
pub const AHCI_CMD_FR: u32 = 1 << 14;
pub const AHCI_CMD_CR: u32 = 1 << 15;

pub const AHCI_TFD_BSY: u32 = 1 << 7;
pub const AHCI_TFD_DRQ: u32 = 1 << 3;
pub const AHCI_TFD_ERR: u32 = 1 << 0;

pub const FIS_TYPE_REG_H2D: u8 = 0x27;

pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;

#[repr(C)]
pub struct HbaPort {
    pub clb: u32,
    pub clbu: u32,
    pub fb: u32,
    pub fbu: u32,
    pub is: u32,
    pub ie: u32,
    pub cmd: u32,
    pub reserved0: u32,
    pub tfd: u32,
    pub sig: u32,
    pub ssts: u32,
    pub sctl: u32,
    pub serr: u32,
    pub sact: u32,
    pub ci: u32,
    pub sntf: u32,
    pub fbs: u32,
    pub reserved1: [u32; 11],
    pub vendor: [u32; 4],
}

#[repr(C)]
pub struct HbaMemory {
    pub cap: u32,
    pub ghc: u32,
    pub is: u32,
    pub pi: u32,
    pub vs: u32,
    pub ccc_ctl: u32,
    pub ccc_pts: u32,
    pub em_loc: u32,
    pub em_ctl: u32,
    pub cap2: u32,
    pub bohc: u32,
    pub reserved: [u8; 0x74],
    pub vendor: [u8; 0x60],
    pub ports: [HbaPort; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HbaCommandHeader {
    pub flags: u16,
    pub prdtl: u16,
    pub prdbc: u32,
    pub ctba: u32,
    pub ctbau: u32,
    pub reserved: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HbaPrdtEntry {
    pub dba: u32,
    pub dbau: u32,
    pub reserved: u32,
    pub dbc: u32,
}

#[repr(C, align(128))]
pub struct HbaCommandTable {
    pub cfis: [u8; 64],
    pub acmd: [u8; 16],
    pub reserved: [u8; 48],
    pub prdt: [HbaPrdtEntry; 1],
}

pub struct AhciDisk {
    port_index: usize,
    port_ptr: *mut HbaPort,
    cmd_list: *mut HbaCommandHeader,
    cmd_table: *mut HbaCommandTable,
    dma_buffer: *mut u8,
    total_sectors: u64,
}

unsafe impl Send for AhciDisk {}
unsafe impl Sync for AhciDisk {}

impl AhciDisk {
    /// Detects and initializes an active SATA drive on the given AHCI controller
    pub unsafe fn init_from_pci(pci: &PciDevice) -> Result<Self, StorageError> {
        pci.enable_bus_mastering();

        let abar = (pci.bar5 & 0xFFFF_FFF0) as usize;
        let hba = abar as *mut HbaMemory;

        // Enable AHCI mode in Global Host Control (GHC bit 31 = AE)
        let ghc = ptr::addr_of_mut!((*hba).ghc);
        ptr::write_volatile(ghc, ptr::read_volatile(ghc) | (1 << 31));

        let pi = ptr::read_volatile(ptr::addr_of!((*hba).pi));

        // Scan implemented ports for connected SATA drive
        for port_idx in 0..32 {
            if (pi & (1 << port_idx)) == 0 {
                continue;
            }

            let port = ptr::addr_of_mut!((*hba).ports[port_idx]);
            let ssts = ptr::read_volatile(ptr::addr_of!((*port).ssts));
            let det = ssts & 0x0F;
            let ipm = (ssts >> 8) & 0x0F;

            if det == AHCI_PORT_DET_PRESENT && ipm == AHCI_PORT_IPM_ACTIVE {
                let sig = ptr::read_volatile(ptr::addr_of!((*port).sig));
                if sig == SATA_SIG_ATA {
                    return Self::init_port(port_idx, port);
                }
            }
        }

        Err(StorageError::DeviceNotFound)
    }

    unsafe fn init_port(port_index: usize, port: *mut HbaPort) -> Result<Self, StorageError> {
        // 1. Stop port command engine
        let cmd_ptr = ptr::addr_of_mut!((*port).cmd);
        let mut cmd = ptr::read_volatile(cmd_ptr);
        cmd &= !(AHCI_CMD_ST | AHCI_CMD_FRE);
        ptr::write_volatile(cmd_ptr, cmd);

        // Wait for CR and FR to clear
        for _ in 0..100_000 {
            let cur = ptr::read_volatile(cmd_ptr);
            if (cur & (AHCI_CMD_CR | AHCI_CMD_FR)) == 0 {
                break;
            }
            cpu::pause();
        }

        // 2. Allocate 2 contiguous physical pages (8 KiB) for DMA structures
        let frames = crate::memory::allocate_contiguous_frames(2).ok_or(StorageError::DeviceFault)?;
        let base_phys = frames.start_address().ok_or(StorageError::DeviceFault)?.0 as usize;
        let mem = base_phys as *mut u8;
        ptr::write_bytes(mem, 0, 8192);

        let cmd_list = mem as *mut HbaCommandHeader; // 1024 bytes (0x000..0x400)
        let _fis_base = mem.add(1024);               // 256 bytes  (0x400..0x500)
        let cmd_table = mem.add(1280) as *mut HbaCommandTable; // 144 bytes  (0x500..)
        let dma_buffer = mem.add(4096);              // 4096 bytes bounce buffer

        // 3. Program port base addresses
        ptr::write_volatile(ptr::addr_of_mut!((*port).clb), base_phys as u32);
        ptr::write_volatile(ptr::addr_of_mut!((*port).clbu), 0);
        ptr::write_volatile(ptr::addr_of_mut!((*port).fb), (base_phys + 1024) as u32);
        ptr::write_volatile(ptr::addr_of_mut!((*port).fbu), 0);

        // Clear error and interrupt registers
        ptr::write_volatile(ptr::addr_of_mut!((*port).serr), 0xFFFF_FFFF);
        ptr::write_volatile(ptr::addr_of_mut!((*port).is), 0xFFFF_FFFF);

        // 4. Start port command engine
        while (ptr::read_volatile(cmd_ptr) & AHCI_CMD_CR) != 0 {
            cpu::pause();
        }
        ptr::write_volatile(cmd_ptr, ptr::read_volatile(cmd_ptr) | AHCI_CMD_FRE);
        ptr::write_volatile(cmd_ptr, ptr::read_volatile(cmd_ptr) | AHCI_CMD_ST);

        Ok(Self {
            port_index,
            port_ptr: port,
            cmd_list,
            cmd_table,
            dma_buffer,
            total_sectors: 131072, // 64 MB (128K sectors)
        })
    }

    unsafe fn wait_port_ready(&self) -> Result<(), StorageError> {
        let tfd_ptr = ptr::addr_of!((*self.port_ptr).tfd);
        for _ in 0..500_000 {
            let tfd = ptr::read_volatile(tfd_ptr);
            if (tfd & (AHCI_TFD_BSY | AHCI_TFD_DRQ)) == 0 {
                return Ok(());
            }
            cpu::pause();
        }
        Err(StorageError::Timeout)
    }

    unsafe fn execute_command(&self, write: bool, lba: u64, count: u32) -> Result<(), StorageError> {
        self.wait_port_ready()?;

        let slot = 0usize;
        let hdr = self.cmd_list.add(slot);
        let tbl = self.cmd_table;

        ptr::write_bytes(tbl as *mut u8, 0, core::mem::size_of::<HbaCommandTable>());

        // Setup Command Header
        let write_bit = if write { 1u16 << 6 } else { 0 };
        let flags = 5u16 | write_bit; // CFL = 5 dwords (20 bytes)
        let prdtl = 1u16;

        let tbl_phys = tbl as usize as u32;
        ptr::write_volatile(ptr::addr_of_mut!((*hdr).flags), flags);
        ptr::write_volatile(ptr::addr_of_mut!((*hdr).prdtl), prdtl);
        ptr::write_volatile(ptr::addr_of_mut!((*hdr).prdbc), 0);
        ptr::write_volatile(ptr::addr_of_mut!((*hdr).ctba), tbl_phys);
        ptr::write_volatile(ptr::addr_of_mut!((*hdr).ctbau), 0);

        // Setup PRDT Entry (pointing to DMA bounce buffer)
        let prdt = ptr::addr_of_mut!((*tbl).prdt[0]);
        let dma_phys = self.dma_buffer as usize as u32;
        let byte_count = count * 512;
        ptr::write_volatile(ptr::addr_of_mut!((*prdt).dba), dma_phys);
        ptr::write_volatile(ptr::addr_of_mut!((*prdt).dbau), 0);
        ptr::write_volatile(ptr::addr_of_mut!((*prdt).reserved), 0);
        ptr::write_volatile(ptr::addr_of_mut!((*prdt).dbc), (byte_count - 1) | (1 << 31));

        // Setup CFIS (Command FIS Register H2D)
        let cfis = ptr::addr_of_mut!((*tbl).cfis);
        (*cfis)[0] = FIS_TYPE_REG_H2D;
        (*cfis)[1] = 0x80; // Command bit
        (*cfis)[2] = if write { ATA_CMD_WRITE_DMA_EXT } else { ATA_CMD_READ_DMA_EXT };
        (*cfis)[3] = 0;

        (*cfis)[4] = (lba & 0xFF) as u8;
        (*cfis)[5] = ((lba >> 8) & 0xFF) as u8;
        (*cfis)[6] = ((lba >> 16) & 0xFF) as u8;
        (*cfis)[7] = 1 << 6; // LBA mode

        (*cfis)[8] = ((lba >> 24) & 0xFF) as u8;
        (*cfis)[9] = ((lba >> 32) & 0xFF) as u8;
        (*cfis)[10] = ((lba >> 40) & 0xFF) as u8;
        (*cfis)[11] = 0;

        (*cfis)[12] = (count & 0xFF) as u8;
        (*cfis)[13] = ((count >> 8) & 0xFF) as u8;

        // Issue command
        let ci_ptr = ptr::addr_of_mut!((*self.port_ptr).ci);
        ptr::write_volatile(ci_ptr, 1 << slot);

        // Wait for completion
        for _ in 0..1_000_000 {
            let ci = ptr::read_volatile(ci_ptr);
            if (ci & (1 << slot)) == 0 {
                // Command finished
                let tfd = ptr::read_volatile(ptr::addr_of!((*self.port_ptr).tfd));
                if (tfd & AHCI_TFD_ERR) != 0 {
                    return Err(StorageError::DeviceFault);
                }
                return Ok(());
            }
            cpu::pause();
        }

        Err(StorageError::Timeout)
    }
}

impl BlockDevice for AhciDisk {
    fn read_sectors(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let total_bytes = (count as usize) * 512;
        if buf.len() < total_bytes {
            return Err(StorageError::BufferTooSmall);
        }

        // Read in chunks of at most 8 sectors (4 KiB = bounce buffer size)
        let mut cur_lba = lba;
        let mut rem_sectors = count;
        let mut offset = 0usize;

        while rem_sectors > 0 {
            let batch = rem_sectors.min(8);
            unsafe {
                self.execute_command(false, cur_lba, batch)?;
                let bytes = (batch as usize) * 512;
                ptr::copy_nonoverlapping(self.dma_buffer, buf.as_mut_ptr().add(offset), bytes);
            }
            cur_lba += batch as u64;
            rem_sectors -= batch;
            offset += (batch as usize) * 512;
        }

        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), StorageError> {
        let total_bytes = (count as usize) * 512;
        if buf.len() < total_bytes {
            return Err(StorageError::BufferTooSmall);
        }

        let mut cur_lba = lba;
        let mut rem_sectors = count;
        let mut offset = 0usize;

        while rem_sectors > 0 {
            let batch = rem_sectors.min(8);
            let bytes = (batch as usize) * 512;
            unsafe {
                ptr::copy_nonoverlapping(buf.as_ptr().add(offset), self.dma_buffer, bytes);
                self.execute_command(true, cur_lba, batch)?;
            }
            cur_lba += batch as u64;
            rem_sectors -= batch;
            offset += bytes;
        }

        Ok(())
    }

    fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    fn device_name(&self) -> &str {
        "Serial ATA AHCI 1.0 (DMA)"
    }
}
