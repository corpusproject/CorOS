//! Pure bare-metal PCI Configuration Space scanner and device manager.
//! 100% in-house CorOS implementation via standard x86_64 I/O ports 0xCF8 and 0xCFC.

use alloc::vec::Vec;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

// PCI Device Class Codes
pub const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
pub const PCI_SUBCLASS_IDE: u8 = 0x01;
pub const PCI_SUBCLASS_SATA: u8 = 0x06;
pub const PCI_SUBCLASS_NVME: u8 = 0x08;

pub const PCI_PROG_IF_AHCI: u8 = 0x01;
pub const PCI_PROG_IF_NVME: u8 = 0x02;

#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bar0: u32,
    pub bar1: u32,
    pub bar2: u32,
    pub bar3: u32,
    pub bar4: u32,
    pub bar5: u32,
}

impl PciDevice {
    /// Enables PCI Memory Space and Bus Mastering (required for AHCI DMA)
    pub unsafe fn enable_bus_mastering(&self) {
        let cmd = pci_read_16(self.bus, self.slot, self.func, 0x04);
        // Bit 0: I/O Space, Bit 1: Memory Space, Bit 2: Bus Master
        pci_write_16(self.bus, self.slot, self.func, 0x04, cmd | 0x0007);
    }

    pub fn is_ahci_controller(&self) -> bool {
        self.class_code == PCI_CLASS_MASS_STORAGE
            && self.subclass == PCI_SUBCLASS_SATA
            && self.prog_if == PCI_PROG_IF_AHCI
    }

    pub fn is_ide_controller(&self) -> bool {
        self.class_code == PCI_CLASS_MASS_STORAGE && self.subclass == PCI_SUBCLASS_IDE
    }

    pub fn is_nvme_controller(&self) -> bool {
        self.class_code == PCI_CLASS_MASS_STORAGE && self.subclass == PCI_SUBCLASS_NVME
    }

    pub fn is_ac97_audio(&self) -> bool {
        // Class 0x04 (Multimedia), Subclass 0x01 (Audio controller) or Intel AC'97 Vendor/Device 0x8086:0x2415
        (self.class_code == 0x04 && self.subclass == 0x01)
            || (self.vendor_id == 0x8086 && (self.device_id == 0x2415 || self.device_id == 0x2425))
    }

    pub fn is_e1000_ethernet(&self) -> bool {
        // Intel Vendor 0x8086, Device 0x100E (82540EM), 0x1004, 0x100F, etc.
        self.vendor_id == 0x8086 && (self.device_id == 0x100E || self.device_id == 0x1004 || self.device_id == 0x100F)
    }

    pub fn is_usb_controller(&self) -> bool {
        // Class 0x0C (Serial Bus), Subclass 0x03 (USB Controller)
        self.class_code == 0x0C && self.subclass == 0x03
    }

    pub fn is_xhci(&self) -> bool {
        self.is_usb_controller() && self.prog_if == 0x30 // USB 3.0 xHCI
    }

    pub fn is_ehci(&self) -> bool {
        self.is_usb_controller() && self.prog_if == 0x20 // USB 2.0 EHCI
    }
}

/// Reads a 32-bit dword from PCI configuration space
pub unsafe fn pci_read_32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    crate::arch::x86_64::cpu::out32(PCI_CONFIG_ADDRESS, address);
    crate::arch::x86_64::cpu::in32(PCI_CONFIG_DATA)
}

/// Writes a 32-bit dword to PCI configuration space
pub unsafe fn pci_write_32(bus: u8, slot: u8, func: u8, offset: u8, value: u32) {
    let address = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    crate::arch::x86_64::cpu::out32(PCI_CONFIG_ADDRESS, address);
    crate::arch::x86_64::cpu::out32(PCI_CONFIG_DATA, value);
}

/// Reads a 16-bit word from PCI configuration space
pub unsafe fn pci_read_16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    let dword = pci_read_32(bus, slot, func, offset);
    ((dword >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Writes a 16-bit word to PCI configuration space
pub unsafe fn pci_write_16(bus: u8, slot: u8, func: u8, offset: u8, value: u16) {
    let shift = (offset & 2) * 8;
    let mask = !(0xFFFFu32 << shift);
    let current = pci_read_32(bus, slot, func, offset);
    let new_val = (current & mask) | ((value as u32) << shift);
    pci_write_32(bus, slot, func, offset, new_val);
}

/// Reads an 8-bit byte from PCI configuration space
pub unsafe fn pci_read_8(bus: u8, slot: u8, func: u8, offset: u8) -> u8 {
    let dword = pci_read_32(bus, slot, func, offset);
    ((dword >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Scans the PCI buses for all connected devices
pub unsafe fn scan_pci() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for bus in 0..=8 {
        for slot in 0..32 {
            let vendor_id = pci_read_16(bus, slot, 0, 0x00);
            if vendor_id == 0xFFFF {
                continue;
            }
            let header_type = pci_read_8(bus, slot, 0, 0x0E);
            let max_func = if (header_type & 0x80) != 0 { 8 } else { 1 };
            for func in 0..max_func {
                let v_id = pci_read_16(bus, slot, func, 0x00);
                if v_id == 0xFFFF {
                    continue;
                }
                let device_id = pci_read_16(bus, slot, func, 0x02);
                let class_code = pci_read_8(bus, slot, func, 0x0B);
                let subclass = pci_read_8(bus, slot, func, 0x0A);
                let prog_if = pci_read_8(bus, slot, func, 0x09);
                let bar0 = pci_read_32(bus, slot, func, 0x10);
                let bar1 = pci_read_32(bus, slot, func, 0x14);
                let bar2 = pci_read_32(bus, slot, func, 0x18);
                let bar3 = pci_read_32(bus, slot, func, 0x1C);
                let bar4 = pci_read_32(bus, slot, func, 0x20);
                let bar5 = pci_read_32(bus, slot, func, 0x24);

                devices.push(PciDevice {
                    bus,
                    slot,
                    func,
                    vendor_id: v_id,
                    device_id,
                    class_code,
                    subclass,
                    prog_if,
                    bar0,
                    bar1,
                    bar2,
                    bar3,
                    bar4,
                    bar5,
                });
            }
        }
    }
    devices
}
