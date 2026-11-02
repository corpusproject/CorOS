//! Universal Motherboard Chipset & Root Complex Subsystem
//!
//! Bare-metal no_std pure Rust driver for PC motherboard chipsets:
//! - Intel PCH Chipsets: 700-series (Z790/B760), 600-series (Z690/B660/H610), 500/400/300-series, Q35/440FX
//! - AMD Chipsets: AM5 (X670E/B650/A620 - Promontory 21), AM4 (X570/B550/B450 - Bixby), Threadripper
//! - ACPI MCFG PCIe Enhanced Configuration Access Mechanism (ECAM) for multi-segment PCI routing
//! - SMBus / I2C Host Controller identification for DDR4/DDR5 SPD memory telemetry

#![allow(dead_code)]

use alloc::string::String;
use crate::pci::PciDevice;

/// Motherboard Chipset Generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotherboardChipset {
    // Intel
    IntelSeries700, // Z790, B760, H770
    IntelSeries600, // Z690, B660, H610
    IntelSeries500, // Z590, B560
    IntelSeries300_400, // Z490, Z390, B360
    IntelQ35or440Fx, // Virtual / Legacy
    IntelOther(u16),

    // AMD
    AmdAm5Promontory21, // X670E, X670, B650E, B650, A620
    AmdAm4Series500,    // X570, B550, A520
    AmdAm4Series300_400,// X470, B450, A320
    AmdThreadripperTrx, // TRX40, WRX80
    AmdOther(u16),

    GenericUnknown,
}

/// PCIe ECAM Memory Map Entry (from ACPI MCFG Table)
#[derive(Debug, Clone, Copy)]
pub struct PcieEcamSegment {
    pub base_address: u64,
    pub pci_segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// Universal Motherboard Controller Profile
pub struct MotherboardProfile {
    pub name: String,
    pub chipset: MotherboardChipset,
    pub vendor_name: String,
    pub host_bridge_dev: u16,
    pub has_smbus: bool,
    pub ecam_segments: [Option<PcieEcamSegment>; 4],
}

impl MotherboardProfile {
    /// Probe the motherboard chipset by examining the PCI Host Bridge (Bus 0, Slot 0, Func 0)
    pub fn probe_from_pci(devices: &[PciDevice]) -> Self {
        let mut host_bridge = None;
        let mut has_smbus = false;

        for dev in devices {
            // Bus 0, Slot 0, Func 0 is universally the Host Bridge / Memory Controller Hub
            if dev.bus == 0 && dev.slot == 0 && dev.func == 0 {
                host_bridge = Some((dev.vendor_id, dev.device_id));
            }
            // Class 0x0C, Subclass 0x05 is SMBus Controller
            if dev.class_code == 0x0C && dev.subclass == 0x05 {
                has_smbus = true;
            }
        }

        let (vendor, dev_id) = host_bridge.unwrap_or((0x8086, 0x1237));
        Self::identify_chipset(vendor, dev_id, has_smbus)
    }

    fn identify_chipset(vendor: u16, dev_id: u16, has_smbus: bool) -> Self {
        let (name, chipset, vendor_name) = match vendor {
            0x8086 => match dev_id {
                0x7A00..=0x7A27 | 0xA700..=0xA71F => (
                    "Intel 700-Series Platform Controller Hub (Z790 / B760)",
                    MotherboardChipset::IntelSeries700,
                    "Intel Corporation",
                ),
                0x4600..=0x464F => (
                    "Intel 600-Series Platform Controller Hub (Z690 / B660 / H610)",
                    MotherboardChipset::IntelSeries600,
                    "Intel Corporation",
                ),
                0x4380..=0x43EF => (
                    "Intel 500-Series Platform Controller Hub (Z590 / B560)",
                    MotherboardChipset::IntelSeries500,
                    "Intel Corporation",
                ),
                0x1237 => (
                    "Intel 440FX PCI Host Bridge (QEMU / Standard PC)",
                    MotherboardChipset::IntelQ35or440Fx,
                    "Intel Corporation",
                ),
                0x29C0 => (
                    "Intel Q35 Express Chipset Host Bridge",
                    MotherboardChipset::IntelQ35or440Fx,
                    "Intel Corporation",
                ),
                other => (
                    "Intel Desktop/Server Host Bridge",
                    MotherboardChipset::IntelOther(other),
                    "Intel Corporation",
                ),
            },
            0x1022 => match dev_id {
                0x14D8..=0x14E4 => (
                    "AMD Socket AM5 Promontory 21 Chipset (X670E / B650 / A620)",
                    MotherboardChipset::AmdAm5Promontory21,
                    "Advanced Micro Devices (AMD)",
                ),
                0x1480..=0x1487 => (
                    "AMD Socket AM4 500-Series Chipset (X570 / B550 / A520)",
                    MotherboardChipset::AmdAm4Series500,
                    "Advanced Micro Devices (AMD)",
                ),
                0x1450..=0x1457 => (
                    "AMD Socket AM4 300/400-Series Chipset (X470 / B450 / A320)",
                    MotherboardChipset::AmdAm4Series300_400,
                    "Advanced Micro Devices (AMD)",
                ),
                other => (
                    "AMD Ryzen Root Complex Host Bridge",
                    MotherboardChipset::AmdOther(other),
                    "Advanced Micro Devices (AMD)",
                ),
            },
            _ => (
                "Generic x86_64 Motherboard Host Bridge",
                MotherboardChipset::GenericUnknown,
                "Standard Motherboard Vendor",
            ),
        };

        Self {
            name: String::from(name),
            chipset,
            vendor_name: String::from(vendor_name),
            host_bridge_dev: dev_id,
            has_smbus,
            ecam_segments: [None; 4],
        }
    }

    /// Add an ECAM base address mapping from ACPI MCFG
    pub fn add_ecam_segment(&mut self, segment: PcieEcamSegment) {
        for slot in self.ecam_segments.iter_mut() {
            if slot.is_none() {
                *slot = Some(segment);
                break;
            }
        }
    }

    /// Calculate physical MMIO address for PCIe ECAM config space
    pub fn get_ecam_address(&self, bus: u8, slot: u8, func: u8, offset: u16) -> Option<u64> {
        let seg = self.ecam_segments[0]?;
        if bus >= seg.start_bus && bus <= seg.end_bus {
            let bus_off = (bus - seg.start_bus) as u64;
            let addr = seg.base_address
                + (bus_off << 20)
                + ((slot as u64) << 15)
                + ((func as u64) << 12)
                + (offset as u64);
            Some(addr)
        } else {
            None
        }
    }
}
