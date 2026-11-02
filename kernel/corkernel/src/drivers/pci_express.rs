//! CorOS PCI Express (PCIe) & MSI/MSI-X Bus Subsystem (`pci_express.rs`)
//!
//! Provides advanced PCI Express root complex access:
//! - Enhanced Configuration Access Mechanism (ECAM / MMCONFIG via ACPI MCFG table)
//! - 4096-byte extended configuration space per function
//! - Standard PCI Express Capability Structure (PCIe Link Speed, Link Width, Slot Control)
//! - Message Signaled Interrupts (MSI: 32-bit & 64-bit Address, Data, Mask bits, Pending bits)
//! - Extended Message Signaled Interrupts (MSI-X: Table BAR, Table Offset, PBA BAR, PBA Offset)
//! - Advanced Error Reporting (AER: Correctable & Uncorrectable Error Status Registers)

extern crate alloc;

use alloc::vec::Vec;

pub const PCI_CAP_ID_PM: u8 = 0x01;    // Power Management
pub const PCI_CAP_ID_MSI: u8 = 0x05;   // Message Signaled Interrupts
pub const PCI_CAP_ID_PCIE: u8 = 0x10;  // PCI Express Capability
pub const PCI_CAP_ID_MSIX: u8 = 0x11;  // MSI-X

/// PCI Express Extended Capability IDs (offset >= 0x100)
pub const PCIE_EXT_CAP_AER: u16 = 0x0001; // Advanced Error Reporting
pub const PCIE_EXT_CAP_VC: u16 = 0x0002;  // Virtual Channel
pub const PCIE_EXT_CAP_DSN: u16 = 0x0003; // Device Serial Number
pub const PCIE_EXT_CAP_SRIOV: u16 = 0x0010; // Single Root I/O Virtualization

/// MSI Control Register Bits
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;
pub const MSI_CTRL_64BIT: u16 = 1 << 7;
pub const MSI_CTRL_PER_VECTOR_MASK: u16 = 1 << 8;

/// MSI-X Control Register Bits
pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;
pub const MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;

/// PCIe Link Speeds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieLinkSpeed {
    Unknown,
    Gen1_2_5GTs,
    Gen2_5_0GTs,
    Gen3_8_0GTs,
    Gen4_16_0GTs,
    Gen5_32_0GTs,
}

/// PCIe Link Width
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieLinkWidth {
    Unknown,
    X1,
    X2,
    X4,
    X8,
    X12,
    X16,
    X32,
}

/// Decoded PCIe Device Profile
#[derive(Debug, Clone)]
pub struct PcieDeviceInfo {
    pub seg: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub link_speed: PcieLinkSpeed,
    pub link_width: PcieLinkWidth,
    pub msi_offset: Option<u8>,
    pub msix_offset: Option<u8>,
    pub pcie_cap_offset: Option<u8>,
}

/// MSI-X Table Entry (16 bytes in MMIO BAR)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_control: u32, // bit 0 = Mask
}

/// PCIe ECAM Manager
pub struct PcieEcamManager {
    pub mmconfig_base: usize,
    pub start_bus: u8,
    pub end_bus: u8,
    pub devices: Vec<PcieDeviceInfo>,
}

impl PcieEcamManager {
    pub fn new(mmconfig_base: usize, start_bus: u8, end_bus: u8) -> Self {
        let mut mgr = Self {
            mmconfig_base,
            start_bus,
            end_bus,
            devices: Vec::new(),
        };
        mgr.scan_bus();
        mgr
    }

    /// Calculate ECAM physical address for specific B/D/F/Register
    pub fn ecam_addr(&self, bus: u8, dev: u8, func: u8, reg: u16) -> usize {
        self.mmconfig_base
            + (((bus as usize) - (self.start_bus as usize)) << 20)
            + ((dev as usize) << 15)
            + ((func as usize) << 12)
            + (reg as usize)
    }

    pub unsafe fn read_config_u32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32 {
        let addr = self.ecam_addr(bus, dev, func, reg);
        core::ptr::read_volatile(addr as *const u32)
    }

    pub unsafe fn write_config_u32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32) {
        let addr = self.ecam_addr(bus, dev, func, reg);
        core::ptr::write_volatile(addr as *mut u32, val);
    }

    pub unsafe fn read_config_u16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16 {
        let addr = self.ecam_addr(bus, dev, func, reg);
        core::ptr::read_volatile(addr as *const u16)
    }

    pub unsafe fn write_config_u16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16) {
        let addr = self.ecam_addr(bus, dev, func, reg);
        core::ptr::write_volatile(addr as *mut u16, val);
    }

    /// Enumerate all PCIe buses and functions
    pub fn scan_bus(&mut self) {
        self.devices.clear();

        for bus in self.start_bus..=self.end_bus {
            for dev in 0..32 {
                // Read vendor ID of function 0
                let id = unsafe { self.read_config_u32(bus, dev, 0, 0) };
                let vendor = (id & 0xFFFF) as u16;
                if vendor == 0xFFFF || vendor == 0x0000 {
                    continue;
                }

                // Check header type to see if it's multi-function
                let hdr = unsafe { self.read_config_u32(bus, dev, 0, 0x0C) };
                let is_multi_function = ((hdr >> 16) & 0x80) != 0;
                let max_funcs = if is_multi_function { 8 } else { 1 };

                for func in 0..max_funcs {
                    let func_id = unsafe { self.read_config_u32(bus, dev, func, 0) };
                    let func_vendor = (func_id & 0xFFFF) as u16;
                    if func_vendor == 0xFFFF || func_vendor == 0x0000 {
                        continue;
                    }
                    let func_device = ((func_id >> 16) & 0xFFFF) as u16;

                    let class_reg = unsafe { self.read_config_u32(bus, dev, func, 0x08) };
                    let rev = (class_reg & 0xFF) as u8;
                    let prog_if = ((class_reg >> 8) & 0xFF) as u8;
                    let sub = ((class_reg >> 16) & 0xFF) as u8;
                    let class = ((class_reg >> 24) & 0xFF) as u8;

                    // Walk standard capability linked list (offset 0x34)
                    let mut cap_ptr = (unsafe { self.read_config_u32(bus, dev, func, 0x34) } & 0xFF) as u8;
                    let mut msi_off = None;
                    let mut msix_off = None;
                    let mut pcie_off = None;

                    while cap_ptr >= 0x40 && cap_ptr <= 0xFC {
                        let cap_hdr = unsafe { self.read_config_u16(bus, dev, func, cap_ptr as u16) };
                        let cap_id = (cap_hdr & 0xFF) as u8;
                        let next = ((cap_hdr >> 8) & 0xFF) as u8;

                        match cap_id {
                            PCI_CAP_ID_MSI => msi_off = Some(cap_ptr),
                            PCI_CAP_ID_MSIX => msix_off = Some(cap_ptr),
                            PCI_CAP_ID_PCIE => pcie_off = Some(cap_ptr),
                            _ => {}
                        }

                        if next == cap_ptr || next == 0 {
                            break;
                        }
                        cap_ptr = next;
                    }

                    // Query Link status if PCIe capability is present
                    let (speed, width) = if let Some(poff) = pcie_off {
                        let link_stat = unsafe { self.read_config_u16(bus, dev, func, (poff + 0x12) as u16) };
                        let s_code = (link_stat & 0x0F) as u8;
                        let w_code = ((link_stat >> 4) & 0x3F) as u8;

                        let spd = match s_code {
                            1 => PcieLinkSpeed::Gen1_2_5GTs,
                            2 => PcieLinkSpeed::Gen2_5_0GTs,
                            3 => PcieLinkSpeed::Gen3_8_0GTs,
                            4 => PcieLinkSpeed::Gen4_16_0GTs,
                            5 => PcieLinkSpeed::Gen5_32_0GTs,
                            _ => PcieLinkSpeed::Unknown,
                        };

                        let wd = match w_code {
                            1 => PcieLinkWidth::X1,
                            2 => PcieLinkWidth::X2,
                            4 => PcieLinkWidth::X4,
                            8 => PcieLinkWidth::X8,
                            12 => PcieLinkWidth::X12,
                            16 => PcieLinkWidth::X16,
                            32 => PcieLinkWidth::X32,
                            _ => PcieLinkWidth::Unknown,
                        };

                        (spd, wd)
                    } else {
                        (PcieLinkSpeed::Unknown, PcieLinkWidth::Unknown)
                    };

                    self.devices.push(PcieDeviceInfo {
                        seg: 0,
                        bus,
                        device: dev,
                        function: func,
                        vendor_id: func_vendor,
                        device_id: func_device,
                        class_code: class,
                        subclass: sub,
                        prog_if,
                        revision: rev,
                        link_speed: speed,
                        link_width: width,
                        msi_offset: msi_off,
                        msix_offset: msix_off,
                        pcie_cap_offset: pcie_off,
                    });
                }
            }
        }
    }

    /// Enable 64-bit MSI for a device
    pub fn enable_msi(&self, dev: &PcieDeviceInfo, target_cpu_lapic_id: u8, vector: u8) -> bool {
        let msi_off = match dev.msi_offset {
            Some(o) => o as u16,
            None => return false,
        };

        unsafe {
            let ctrl = self.read_config_u16(dev.bus, dev.device, dev.function, msi_off + 2);
            let is_64bit = (ctrl & MSI_CTRL_64BIT) != 0;

            // Target LAPIC address: 0xFEE00000 | (lapic_id << 12)
            let msg_addr = 0xFEE00000u32 | ((target_cpu_lapic_id as u32) << 12);
            let msg_data = vector as u32;

            self.write_config_u32(dev.bus, dev.device, dev.function, msi_off + 4, msg_addr);

            if is_64bit {
                self.write_config_u32(dev.bus, dev.device, dev.function, msi_off + 8, 0); // High 32 bits = 0
                self.write_config_u16(dev.bus, dev.device, dev.function, msi_off + 12, msg_data as u16);
            } else {
                self.write_config_u16(dev.bus, dev.device, dev.function, msi_off + 8, msg_data as u16);
            }

            // Set MSI Enable bit
            self.write_config_u16(dev.bus, dev.device, dev.function, msi_off + 2, ctrl | MSI_CTRL_ENABLE);
        }

        true
    }
}
