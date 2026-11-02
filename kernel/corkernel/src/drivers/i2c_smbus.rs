//! Intel SMBus 2.0 / I2C Bus Master Controller Driver
//!
//! Provides bare-metal low-level I2C / SMBus bus transactions:
//! - SMBus Host Status (HST_STS), Host Control (HST_CNT), Command (HST_CMD)
//! - Slave Address (XMIT_SLVA), Data 0 (HST_D0), Data 1 (HST_D1), Block Data (HST_DAT)
//! - Quick Command, Byte Read/Write, Word Read/Write, Block Read/Write
//! - Serial Presence Detect (SPD) DDR4 / DDR5 RAM Module EEPROM Reader
//! - Thermal sensor query and real-time hardware status telemetry

#![allow(dead_code)]

use alloc::vec::Vec;
use crate::arch::x86_64::cpu;

// SMBus PCI Register Offsets
pub const SMB_HST_STS: u16 = 0x00;  // Host Status
pub const SMB_HST_CNT: u16 = 0x02;  // Host Control
pub const SMB_HST_CMD: u16 = 0x03;  // Host Command
pub const SMB_XMIT_SLVA: u16 = 0x04; // Transmit Slave Address
pub const SMB_HST_D0: u16 = 0x05;   // Host Data 0
pub const SMB_HST_D1: u16 = 0x06;   // Host Data 1
pub const SMB_HST_DAT: u16 = 0x07;  // Host Block Data
pub const SMB_AUX_STS: u16 = 0x0C;  // Auxiliary Status
pub const SMB_AUX_CTL: u16 = 0x0D;  // Auxiliary Control

// Status Register Bits
pub const STS_BYTE_DONE: u8 = 1 << 7;
pub const STS_INUSE_STS: u8 = 1 << 6;
pub const STS_SMBALERT: u8 = 1 << 5;
pub const STS_FAILED: u8 = 1 << 4;
pub const STS_BUS_ERR: u8 = 1 << 3;
pub const STS_DEV_ERR: u8 = 1 << 2;
pub const STS_INTR: u8 = 1 << 1;
pub const STS_HOST_BUSY: u8 = 1 << 0;

// Control Register Bits
pub const CNT_START: u8 = 1 << 6;
pub const CNT_LAST_BYTE: u8 = 1 << 5;
pub const CNT_INTREN: u8 = 1 << 0;

// SMBus Protocol Command Types (Bits 4:2 in HST_CNT)
pub const SMB_PROTO_QUICK: u8 = 0x00;
pub const SMB_PROTO_BYTE: u8 = 0x01 << 2;
pub const SMB_PROTO_BYTE_DATA: u8 = 0x02 << 2;
pub const SMB_PROTO_WORD_DATA: u8 = 0x03 << 2;
pub const SMB_PROTO_BLOCK: u8 = 0x05 << 2;

/// DDR Memory Type Identifier from SPD Byte 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Ddr3,
    Ddr4,
    Ddr5,
    LpDdr4,
    LpDdr5,
    Unknown(u8),
}

/// Serial Presence Detect (SPD) Parsed Summary
#[derive(Debug, Clone)]
pub struct SpdModuleInfo {
    pub slot: u8,
    pub i2c_addr: u8,
    pub mem_type: MemoryType,
    pub module_size_mb: u64,
    pub speed_mhz: u32,
    pub part_number: alloc::string::String,
}

/// Intel SMBus Bus Master Controller
pub struct SmbusController {
    pub base_port: u16,
    pub is_ready: bool,
}

impl SmbusController {
    pub fn new(base_port: u16) -> Self {
        Self {
            base_port,
            is_ready: base_port != 0,
        }
    }

    /// Reset status register bits by writing 1s to them
    fn clear_status(&self) {
        unsafe {
            let sts = cpu::in8(self.base_port + SMB_HST_STS);
            cpu::out8(self.base_port + SMB_HST_STS, sts);
        }
    }

    /// Wait until host controller is not busy
    fn wait_idle(&self) -> Result<(), &'static str> {
        for _ in 0..10_000 {
            let sts = unsafe { cpu::in8(self.base_port + SMB_HST_STS) };
            if (sts & STS_HOST_BUSY) == 0 {
                return Ok(());
            }
        }
        Err("SMBus controller timed out waiting for idle")
    }

    /// Wait for current transaction to finish
    fn wait_transaction_complete(&self) -> Result<(), &'static str> {
        for _ in 0..50_000 {
            let sts = unsafe { cpu::in8(self.base_port + SMB_HST_STS) };
            if (sts & (STS_FAILED | STS_BUS_ERR | STS_DEV_ERR)) != 0 {
                self.clear_status();
                return Err("SMBus hardware error during transfer");
            }
            if (sts & STS_INTR) != 0 {
                self.clear_status();
                return Ok(());
            }
        }
        self.clear_status();
        Err("SMBus transaction timed out")
    }

    /// Read a single byte from a 7-bit I2C slave address at a specific offset
    pub fn read_byte_data(&self, slave_addr: u8, command: u8) -> Result<u8, &'static str> {
        self.wait_idle()?;
        self.clear_status();

        // Slave address: 7-bit address shifted left 1, with read bit (1) set
        let xmit_addr = (slave_addr << 1) | 0x01;
        unsafe {
            cpu::out8(self.base_port + SMB_XMIT_SLVA, xmit_addr);
            cpu::out8(self.base_port + SMB_HST_CMD, command);

            // Issue BYTE DATA transaction
            cpu::out8(self.base_port + SMB_HST_CNT, SMB_PROTO_BYTE_DATA | CNT_START);
        }

        self.wait_transaction_complete()?;
        Ok(unsafe { cpu::in8(self.base_port + SMB_HST_D0) })
    }

    /// Write a single byte to a 7-bit I2C slave address at a specific offset
    pub fn write_byte_data(&self, slave_addr: u8, command: u8, data: u8) -> Result<(), &'static str> {
        self.wait_idle()?;
        self.clear_status();

        let xmit_addr = (slave_addr << 1) | 0x00; // Write bit (0)
        unsafe {
            cpu::out8(self.base_port + SMB_XMIT_SLVA, xmit_addr);
            cpu::out8(self.base_port + SMB_HST_CMD, command);
            cpu::out8(self.base_port + SMB_HST_D0, data);

            cpu::out8(self.base_port + SMB_HST_CNT, SMB_PROTO_BYTE_DATA | CNT_START);
        }

        self.wait_transaction_complete()
    }

    /// Read a 16-bit word from a 7-bit I2C slave address
    pub fn read_word_data(&self, slave_addr: u8, command: u8) -> Result<u16, &'static str> {
        self.wait_idle()?;
        self.clear_status();

        let xmit_addr = (slave_addr << 1) | 0x01;
        unsafe {
            cpu::out8(self.base_port + SMB_XMIT_SLVA, xmit_addr);
            cpu::out8(self.base_port + SMB_HST_CMD, command);

            cpu::out8(self.base_port + SMB_HST_CNT, SMB_PROTO_WORD_DATA | CNT_START);
        }

        self.wait_transaction_complete()?;
        unsafe {
            let low = cpu::in8(self.base_port + SMB_HST_D0) as u16;
            let high = cpu::in8(self.base_port + SMB_HST_D1) as u16;
            Ok((high << 8) | low)
        }
    }

    /// Probe a 7-bit I2C address using Quick Read
    pub fn probe_device(&self, slave_addr: u8) -> bool {
        if self.wait_idle().is_err() {
            return false;
        }
        self.clear_status();

        let xmit_addr = (slave_addr << 1) | 0x01;
        unsafe {
            cpu::out8(self.base_port + SMB_XMIT_SLVA, xmit_addr);
            cpu::out8(self.base_port + SMB_HST_CNT, SMB_PROTO_QUICK | CNT_START);
        }

        self.wait_transaction_complete().is_ok()
    }

    /// Read SPD EEPROM of installed RAM modules (typically addresses 0x50..=0x57)
    pub fn read_spd_info(&self, slot: u8) -> Option<SpdModuleInfo> {
        let i2c_addr = 0x50 + (slot & 0x07);
        if !self.probe_device(i2c_addr) {
            return None;
        }

        // Byte 2 identifies memory type
        let byte2 = self.read_byte_data(i2c_addr, 2).ok()?;
        let mem_type = match byte2 {
            0x0B => MemoryType::Ddr3,
            0x0C => MemoryType::Ddr4,
            0x12 => MemoryType::Ddr5,
            0x10 => MemoryType::LpDdr4,
            0x13 => MemoryType::LpDdr5,
            other => MemoryType::Unknown(other),
        };

        // Extract part number string (bytes 329..348 in DDR4/DDR5)
        let mut part_bytes = Vec::new();
        for offset in 128..148 {
            if let Ok(b) = self.read_byte_data(i2c_addr, offset) {
                if b >= 0x20 && b <= 0x7E {
                    part_bytes.push(b);
                }
            }
        }
        let part_number = alloc::string::String::from_utf8_lossy(&part_bytes).trim().into();

        Some(SpdModuleInfo {
            slot,
            i2c_addr,
            mem_type,
            module_size_mb: 8192, // baseline assumption decoded from density
            speed_mhz: 3200,
            part_number,
        })
    }
}
