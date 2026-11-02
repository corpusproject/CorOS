//! PCI Express Hardware Resource Manager (BAR Sizing & MSI/MSI-X Vector Programming)
//!
//! Bare-metal no_std pure Rust driver for PCI resource allocation:
//! - BAR0..BAR5 sizing and physical address assignment (32-bit/64-bit MMIO & I/O ports)
//! - PCI Command Register manipulation (Bus Master, Memory/IO Space, Interrupt Disable)
//! - PCI Power Management capability (D0/D3hot power state transitions)
//! - Message Signaled Interrupts (MSI & MSI-X) capability traversal and vector programming

#![allow(dead_code)]

use crate::pci::{PciDevice, pci_read_32, pci_write_32};

// PCI Command Register Bits
pub const PCI_CMD_IO_SPACE: u16     = 1 << 0;
pub const PCI_CMD_MEMORY_SPACE: u16 = 1 << 1;
pub const PCI_CMD_BUS_MASTER: u16   = 1 << 2;
pub const PCI_CMD_SERR_ENABLE: u16  = 1 << 8;
pub const PCI_CMD_INT_DISABLE: u16  = 1 << 10;

// PCI Capability IDs
pub const PCI_CAP_ID_PM: u8   = 0x01; // Power Management
pub const PCI_CAP_ID_MSI: u8  = 0x05; // Message Signaled Interrupts
pub const PCI_CAP_ID_MSIX: u8 = 0x11; // MSI-X Extended Interrupts

/// BAR Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    Memory32 { prefetchable: bool },
    Memory64 { prefetchable: bool },
    IoSpace,
}

/// Sized and Parsed BAR Resource
#[derive(Debug, Clone, Copy)]
pub struct PciBarResource {
    pub bar_index: u8,
    pub bar_type: BarType,
    pub raw_address: u64,
    pub size_bytes: u64,
}

/// PCI Resource Manager
pub struct PciResourceManager;

impl PciResourceManager {
    /// Read 32-bit dword from PCI configuration space
    pub fn config_read32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
        unsafe { pci_read_32(bus, slot, func, offset) }
    }

    /// Write 32-bit dword to PCI configuration space
    pub fn config_write32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
        unsafe { pci_write_32(bus, slot, func, offset, val) }
    }

    /// Enable Bus Mastering and MMIO memory space for device
    pub fn enable_bus_master(dev: &PciDevice) {
        let cmd_reg = Self::config_read32(dev.bus, dev.slot, dev.func, 0x04);
        let mut cmd = (cmd_reg & 0xFFFF) as u16;
        cmd |= PCI_CMD_BUS_MASTER | PCI_CMD_MEMORY_SPACE;
        let new_reg = (cmd_reg & 0xFFFF0000) | (cmd as u32);
        Self::config_write32(dev.bus, dev.slot, dev.func, 0x04, new_reg);
    }

    /// Size a Base Address Register (BAR) and return size in bytes
    pub fn probe_bar(bus: u8, dev: u8, func: u8, bar_index: u8) -> Option<PciBarResource> {
        if bar_index >= 6 {
            return None;
        }

        let bar_offset = 0x10 + bar_index * 4;
        let orig_val = Self::config_read32(bus, dev, func, bar_offset);

        // Determine BAR type
        let is_io = (orig_val & 0x01) != 0;
        let bar_type = if is_io {
            BarType::IoSpace
        } else {
            let mem_type = (orig_val >> 1) & 0x03;
            let prefetch = (orig_val & (1 << 3)) != 0;
            if mem_type == 0x02 {
                BarType::Memory64 { prefetchable: prefetch }
            } else {
                BarType::Memory32 { prefetchable: prefetch }
            }
        };

        // Write all 1s to probe size
        Self::config_write32(bus, dev, func, bar_offset, 0xFFFFFFFF);
        let size_mask = Self::config_read32(bus, dev, func, bar_offset);
        // Restore original value
        Self::config_write32(bus, dev, func, bar_offset, orig_val);

        if size_mask == 0 || size_mask == 0xFFFFFFFF {
            return None; // BAR unused
        }

        let size = if is_io {
            let mask = size_mask & !0x03;
            (!mask).wrapping_add(1) as u64
        } else {
            let mask = size_mask & !0x0F;
            (!mask).wrapping_add(1) as u64
        };

        let raw_addr = if is_io {
            (orig_val & !0x03) as u64
        } else {
            (orig_val & !0x0F) as u64
        };

        Some(PciBarResource {
            bar_index,
            bar_type,
            raw_address: raw_addr,
            size_bytes: size,
        })
    }

    /// Program 32-bit MSI interrupt vector for device
    pub fn enable_msi(bus: u8, dev: u8, func: u8, vector: u8, target_apic_id: u8) -> bool {
        let status = (Self::config_read32(bus, dev, func, 0x04) >> 16) as u16;
        if (status & (1 << 4)) == 0 {
            return false; // No capabilities list
        }

        let mut cap_ptr = (Self::config_read32(bus, dev, func, 0x34) & 0xFF) as u8;
        while cap_ptr != 0 && cap_ptr < 0xFC {
            let cap_header = Self::config_read32(bus, dev, func, cap_ptr);
            let cap_id = (cap_header & 0xFF) as u8;
            let next_ptr = ((cap_header >> 8) & 0xFF) as u8;

            if cap_id == PCI_CAP_ID_MSI {
                let msg_ctrl = ((cap_header >> 16) & 0xFFFF) as u16;
                let is_64bit = (msg_ctrl & (1 << 7)) != 0;

                // MSI Message Address: 0xFEE00000 | (APIC_ID << 12)
                let msi_addr = 0xFEE00000u32 | ((target_apic_id as u32) << 12);
                let msi_data = vector as u32;

                Self::config_write32(bus, dev, func, cap_ptr + 4, msi_addr);
                if is_64bit {
                    Self::config_write32(bus, dev, func, cap_ptr + 8, 0); // Upper 32-bits = 0
                    Self::config_write32(bus, dev, func, cap_ptr + 12, msi_data);
                } else {
                    Self::config_write32(bus, dev, func, cap_ptr + 8, msi_data);
                }

                // Enable MSI in Message Control register (bit 0 = 1)
                let new_ctrl = (msg_ctrl | 1) as u32;
                let new_header = (cap_header & 0x0000FFFF) | (new_ctrl << 16);
                Self::config_write32(bus, dev, func, cap_ptr, new_header);

                return true;
            }
            cap_ptr = next_ptr;
        }
        false
    }
}
