//! AMD Ryzen/EPYC, Radeon Graphics & Promontory Chipset Hardware Registry.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

use alloc::vec::Vec;

/// AMD PCI Vendor ID (0x1002 for ATI/Radeon GPU, 0x1022 for AMD CPU/SoC/Chipset).
pub const PCI_VENDOR_AMD_GFX: u16 = 0x1002;
pub const PCI_VENDOR_AMD_CPU: u16 = 0x1022;

/// AMD Architecture Family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmdArchGeneration {
    Zen1SummitRidge,
    Zen2MatisseRome,
    Zen3VermeerMilan,
    Zen4RaphaelGenoa,
    Zen5GraniteRidgeTurin,
    Rdna1Navi10,
    Rdna2Navi20,
    Rdna3Navi30,
    Rdna3_5StrixPoint,
    CdnaComputeArcturus,
    PromontoryChipset,
}

/// AMD Driver Category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmdDriverCategory {
    RootComplexHostBridge,
    DataFabricInternalBridge,
    RadeonDiscreteGpuEngine,
    RadeonIntegratedGpuEngine,
    PromontoryPcieBridge,
    PromontoryAhciSata,
    PromontoryXhciUsb,
    AudioCoProcessorAcp,
    PlatformSecurityProcessorPsp,
    CryptographyCcpEngine,
}

/// Detailed AMD Device entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdPciDeviceEntry {
    pub vendor_id: u16,
    pub device_id: u16,
    pub generation: AmdArchGeneration,
    pub category: AmdDriverCategory,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bar0_min_size: u32,
    pub bar2_aperture_size: u64,
    pub codename: &'static str,
    pub commercial_name: &'static str,
}

/// Curated authentic table of AMD Ryzen, EPYC and Radeon devices.
pub static AMD_HARDWARE_CATALOG: &[AmdPciDeviceEntry] = &[
    // --- Zen 4 / Zen 5 Desktop & Server Bridges ---
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x14D8,
        generation: AmdArchGeneration::Zen4RaphaelGenoa,
        category: AmdDriverCategory::RootComplexHostBridge,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0,
        bar2_aperture_size: 0,
        codename: "Raphael AM5",
        commercial_name: "AMD Ryzen 7000/8000/9000 Series Host Bridge",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x14E0,
        generation: AmdArchGeneration::Zen4RaphaelGenoa,
        category: AmdDriverCategory::DataFabricInternalBridge,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0,
        bar2_aperture_size: 0,
        codename: "Raphael DF",
        commercial_name: "AMD Data Fabric Function 0 (DRAM Channels & Infinity Fabric)",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x1649,
        generation: AmdArchGeneration::Zen4RaphaelGenoa,
        category: AmdDriverCategory::PlatformSecurityProcessorPsp,
        class_code: 0x10,
        subclass: 0x80,
        prog_if: 0x00,
        bar0_min_size: 0x100000,
        bar2_aperture_size: 0,
        codename: "PSP 3.0",
        commercial_name: "AMD Platform Security Processor (PSP/CCP Cryptographic Coprocessor)",
    },

    // --- Promontory Chipsets: X670E, B650, X570, B550 ---
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x43F4,
        generation: AmdArchGeneration::PromontoryChipset,
        category: AmdDriverCategory::PromontoryXhciUsb,
        class_code: 0x0C,
        subclass: 0x03,
        prog_if: 0x30,
        bar0_min_size: 0x10000,
        bar2_aperture_size: 0,
        codename: "Promontory 21 (PROM21)",
        commercial_name: "AMD 600/800 Series Chipset USB 3.2 xHCI Host Controller",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x43F5,
        generation: AmdArchGeneration::PromontoryChipset,
        category: AmdDriverCategory::PromontoryAhciSata,
        class_code: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
        bar0_min_size: 0x1000,
        bar2_aperture_size: 0,
        codename: "Promontory 21 SATA",
        commercial_name: "AMD 600/800 Series Chipset SATA AHCI Controller",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_CPU,
        device_id: 0x43EC,
        generation: AmdArchGeneration::PromontoryChipset,
        category: AmdDriverCategory::PromontoryPcieBridge,
        class_code: 0x06,
        subclass: 0x04,
        prog_if: 0x00,
        bar0_min_size: 0,
        bar2_aperture_size: 0,
        codename: "Promontory 21 Downstream",
        commercial_name: "AMD 600 Series PCI Express Upstream/Downstream Switch Port",
    },

    // --- RDNA3 Discrete Graphics (Navi 31, Navi 32, Navi 33) ---
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x744C,
        generation: AmdArchGeneration::Rdna3Navi30,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000, // 256 MiB BAR0 (re-sizable BAR)
        bar2_aperture_size: 0x400000000, // 16 GiB VRAM physical aperture
        codename: "Navi 31 XTX",
        commercial_name: "AMD Radeon RX 7900 XTX 24GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x7448,
        generation: AmdArchGeneration::Rdna3Navi30,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x500000000, // 20 GiB VRAM
        codename: "Navi 31 XT",
        commercial_name: "AMD Radeon RX 7900 XT 20GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x747E,
        generation: AmdArchGeneration::Rdna3Navi30,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x400000000,
        codename: "Navi 32 XT",
        commercial_name: "AMD Radeon RX 7800 XT 16GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x7480,
        generation: AmdArchGeneration::Rdna3Navi30,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x300000000, // 12 GiB VRAM
        codename: "Navi 32 XL",
        commercial_name: "AMD Radeon RX 7700 XT 12GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x7422,
        generation: AmdArchGeneration::Rdna3Navi30,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x200000000, // 8 GiB VRAM
        codename: "Navi 33 XT",
        commercial_name: "AMD Radeon RX 7600 XT 8GB/16GB",
    },

    // --- RDNA2 Discrete Graphics (Navi 21, Navi 22, Navi 23) ---
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x73BF,
        generation: AmdArchGeneration::Rdna2Navi20,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x400000000,
        codename: "Navi 21 XT",
        commercial_name: "AMD Radeon RX 6900 XT / 6950 XT 16GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x73DF,
        generation: AmdArchGeneration::Rdna2Navi20,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x300000000,
        codename: "Navi 22 XT",
        commercial_name: "AMD Radeon RX 6700 XT / 6750 XT 12GB",
    },
    AmdPciDeviceEntry {
        vendor_id: PCI_VENDOR_AMD_GFX,
        device_id: 0x73FF,
        generation: AmdArchGeneration::Rdna2Navi20,
        category: AmdDriverCategory::RadeonDiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x10000000,
        bar2_aperture_size: 0x200000000,
        codename: "Navi 23 XT",
        commercial_name: "AMD Radeon RX 6600 XT 8GB",
    },
];

/// Finds an AMD device by vendor and device ID.
pub fn lookup_amd_device(vendor_id: u16, device_id: u16) -> Option<&'static AmdPciDeviceEntry> {
    AMD_HARDWARE_CATALOG
        .iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
}

/// Lists all AMD discrete and integrated GPU entries.
pub fn list_radeon_gpus() -> Vec<&'static AmdPciDeviceEntry> {
    AMD_HARDWARE_CATALOG
        .iter()
        .filter(|d| {
            d.category == AmdDriverCategory::RadeonDiscreteGpuEngine
                || d.category == AmdDriverCategory::RadeonIntegratedGpuEngine
        })
        .collect()
}
