//! Intel PCI/PCIe Hardware Identification, Device Families, Capabilities & MMIO Layouts.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

use alloc::vec::Vec;

/// Intel PCI Vendor ID (0x8086).
pub const PCI_VENDOR_INTEL: u16 = 0x8086;

/// Hardware Architecture Family / Generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelArchGeneration {
    NehalemWestmere,
    SandyBridgeIvyBridge,
    HaswellBroadwell,
    SkylakeKabyLakeCoffeeLake,
    CometLakeRocketLake,
    IceLakeTigerLake,
    AlderLakeRaptorLake,
    MeteorLakeArrowLake,
    XeonScalablePurley,
    XeonScalableWhitley,
    XeonScalableEagleStream,
    DiscreteArcGraphics,
    GenericLegacy,
}

/// Specialized driver binding category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelDriverCategory {
    HostBridgeDramController,
    PchLpcIsaBridge,
    PchSataAhciController,
    PchPcieRootPort,
    PchSmbusController,
    PchSpiFlashController,
    PchHdaSoundController,
    PchXhciUsbController,
    PchCnviWirelessController,
    GigabitEthernetController,
    MultiGigEthernetController,
    TenGigabitEthernetController,
    HighSpeedNvmeController,
    IntegratedGpuEngine,
    DiscreteGpuEngine,
    ThunderboltController,
    ManagementEngineHeci,
    SerialIoI2cController,
    SerialIoUartController,
    SerialIoSpiController,
}

/// Detailed Intel PCI/PCIe device specification entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntelPciDeviceEntry {
    pub device_id: u16,
    pub generation: IntelArchGeneration,
    pub category: IntelDriverCategory,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bar0_min_size: u32,
    pub required_quirks: u32,
    pub codename: &'static str,
    pub commercial_name: &'static str,
}

pub mod intel_quirks {
    pub const QUIRK_NO_MSI: u32 = 1 << 0;
    pub const QUIRK_64BIT_DMA_BUG: u32 = 1 << 1;
    pub const QUIRK_SATA_AHCI_FORCE_ST: u32 = 1 << 2;
    pub const QUIRK_IGPU_OPREGION_VBT: u32 = 1 << 3;
    pub const QUIRK_XHCI_DISABLE_STREAMS: u32 = 1 << 4;
    pub const QUIRK_I225_PHY_RESET: u32 = 1 << 5;
    pub const QUIRK_ARC_BAR1_REBAR_MANDATORY: u32 = 1 << 6;
}

/// Curated authentic table of Intel PCI devices across Desktop, Mobile and Workstation platforms.
pub static INTEL_HARDWARE_CATALOG: &[IntelPciDeviceEntry] = &[
    // --- Alder Lake & Raptor Lake (12th/13th/14th Gen Core) ---
    IntelPciDeviceEntry {
        device_id: 0x4660,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::HostBridgeDramController,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0,
        required_quirks: 0,
        codename: "Alder Lake-S",
        commercial_name: "12th Gen Core Processor Host Bridge/DRAM Registers",
    },
    IntelPciDeviceEntry {
        device_id: 0x4680,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::IntegratedGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x1000000, // 16 MiB MMIO
        required_quirks: intel_quirks::QUIRK_IGPU_OPREGION_VBT,
        codename: "Alder Lake-S GT1",
        commercial_name: "Intel UHD Graphics 770",
    },
    IntelPciDeviceEntry {
        device_id: 0xA780,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::IntegratedGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x1000000,
        required_quirks: intel_quirks::QUIRK_IGPU_OPREGION_VBT,
        codename: "Raptor Lake-S GT1",
        commercial_name: "Intel UHD Graphics 770 (13th/14th Gen)",
    },
    IntelPciDeviceEntry {
        device_id: 0x7A04,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchLpcIsaBridge,
        class_code: 0x06,
        subclass: 0x01,
        prog_if: 0x00,
        bar0_min_size: 0,
        required_quirks: 0,
        codename: "Z790 PCH",
        commercial_name: "Intel Z790 Chipset LPC/eSPI Controller",
    },
    IntelPciDeviceEntry {
        device_id: 0x7A08,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchLpcIsaBridge,
        class_code: 0x06,
        subclass: 0x01,
        prog_if: 0x00,
        bar0_min_size: 0,
        required_quirks: 0,
        codename: "B760 PCH",
        commercial_name: "Intel B760 Chipset LPC/eSPI Controller",
    },
    IntelPciDeviceEntry {
        device_id: 0x7A60,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchXhciUsbController,
        class_code: 0x0C,
        subclass: 0x03,
        prog_if: 0x30,
        bar0_min_size: 0x10000, // 64 KiB MMIO
        required_quirks: 0,
        codename: "Raptor Lake PCH xHCI",
        commercial_name: "Intel 700 Series Chipset USB 3.2 Gen 2x2 Controller",
    },
    IntelPciDeviceEntry {
        device_id: 0x7A50,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchHdaSoundController,
        class_code: 0x04,
        subclass: 0x03,
        prog_if: 0x00,
        bar0_min_size: 0x4000, // 16 KiB MMIO
        required_quirks: 0,
        codename: "Raptor Lake PCH cAVS",
        commercial_name: "Intel High Definition Audio / Smart Sound Technology",
    },
    IntelPciDeviceEntry {
        device_id: 0x7A62,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchSataAhciController,
        class_code: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
        bar0_min_size: 0x2000,
        required_quirks: intel_quirks::QUIRK_SATA_AHCI_FORCE_ST,
        codename: "Raptor Lake PCH SATA",
        commercial_name: "Intel 700 Series Chipset SATA AHCI Controller",
    },

    // --- Discrete GPU Families: Arc Alchemist & Battlemage ---
    IntelPciDeviceEntry {
        device_id: 0x5690,
        generation: IntelArchGeneration::DiscreteArcGraphics,
        category: IntelDriverCategory::DiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x2000000, // 32 MiB GTT/Control
        required_quirks: intel_quirks::QUIRK_ARC_BAR1_REBAR_MANDATORY,
        codename: "Alchemist ACM-G10",
        commercial_name: "Intel Arc A770 Graphics 16GB",
    },
    IntelPciDeviceEntry {
        device_id: 0x5691,
        generation: IntelArchGeneration::DiscreteArcGraphics,
        category: IntelDriverCategory::DiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x2000000,
        required_quirks: intel_quirks::QUIRK_ARC_BAR1_REBAR_MANDATORY,
        codename: "Alchemist ACM-G10",
        commercial_name: "Intel Arc A750 Graphics 8GB",
    },
    IntelPciDeviceEntry {
        device_id: 0x5692,
        generation: IntelArchGeneration::DiscreteArcGraphics,
        category: IntelDriverCategory::DiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x2000000,
        required_quirks: intel_quirks::QUIRK_ARC_BAR1_REBAR_MANDATORY,
        codename: "Alchemist ACM-G10",
        commercial_name: "Intel Arc A580 Graphics",
    },
    IntelPciDeviceEntry {
        device_id: 0x56A5,
        generation: IntelArchGeneration::DiscreteArcGraphics,
        category: IntelDriverCategory::DiscreteGpuEngine,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x1000000,
        required_quirks: intel_quirks::QUIRK_ARC_BAR1_REBAR_MANDATORY,
        codename: "Alchemist ACM-G11",
        commercial_name: "Intel Arc A380 Graphics",
    },

    // --- High-Performance Ethernet PHYs (1GbE, 2.5GbE, 10GbE, 100GbE) ---
    IntelPciDeviceEntry {
        device_id: 0x1539,
        generation: IntelArchGeneration::GenericLegacy,
        category: IntelDriverCategory::GigabitEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x20000, // 128 KiB
        required_quirks: 0,
        codename: "Powerville",
        commercial_name: "Intel I211 Gigabit Network Connection",
    },
    IntelPciDeviceEntry {
        device_id: 0x1533,
        generation: IntelArchGeneration::GenericLegacy,
        category: IntelDriverCategory::GigabitEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x20000,
        required_quirks: 0,
        codename: "Springville",
        commercial_name: "Intel I210 Gigabit Network Connection",
    },
    IntelPciDeviceEntry {
        device_id: 0x15F3,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::MultiGigEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x100000, // 1 MiB
        required_quirks: intel_quirks::QUIRK_I225_PHY_RESET,
        codename: "Foxville",
        commercial_name: "Intel Ethernet Controller I225-V (2.5GbE)",
    },
    IntelPciDeviceEntry {
        device_id: 0x125B,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::MultiGigEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x100000,
        required_quirks: 0,
        codename: "Foxville-LM",
        commercial_name: "Intel Ethernet Controller I225-LM (2.5GbE Enterprise)",
    },
    IntelPciDeviceEntry {
        device_id: 0x125C,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::MultiGigEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x100000,
        required_quirks: 0,
        codename: "Bartonville",
        commercial_name: "Intel Ethernet Controller I226-V (2.5GbE Rev 2)",
    },
    IntelPciDeviceEntry {
        device_id: 0x1563,
        generation: IntelArchGeneration::XeonScalablePurley,
        category: IntelDriverCategory::TenGigabitEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x400000, // 4 MiB
        required_quirks: 0,
        codename: "Sageville",
        commercial_name: "Intel Ethernet Controller X550 10GBASE-T",
    },
    IntelPciDeviceEntry {
        device_id: 0x1592,
        generation: IntelArchGeneration::XeonScalableEagleStream,
        category: IntelDriverCategory::TenGigabitEthernetController,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        bar0_min_size: 0x800000, // 8 MiB
        required_quirks: 0,
        codename: "Columbiaville",
        commercial_name: "Intel Ethernet Controller E810-C for QSFP28 100GbE",
    },

    // --- Wi-Fi 6 / 6E / 7 Wireless Adapters (CNVi & PCIe discrete) ---
    IntelPciDeviceEntry {
        device_id: 0x2723,
        generation: IntelArchGeneration::IceLakeTigerLake,
        category: IntelDriverCategory::PchCnviWirelessController,
        class_code: 0x02,
        subclass: 0x80,
        prog_if: 0x00,
        bar0_min_size: 0x4000,
        required_quirks: 0,
        codename: "Cyclone Peak",
        commercial_name: "Intel Wi-Fi 6 AX200 160MHz",
    },
    IntelPciDeviceEntry {
        device_id: 0x2725,
        generation: IntelArchGeneration::AlderLakeRaptorLake,
        category: IntelDriverCategory::PchCnviWirelessController,
        class_code: 0x02,
        subclass: 0x80,
        prog_if: 0x00,
        bar0_min_size: 0x4000,
        required_quirks: 0,
        codename: "Typhoon Peak",
        commercial_name: "Intel Wi-Fi 6E AX210 160MHz (6GHz Band)",
    },
    IntelPciDeviceEntry {
        device_id: 0x7E40,
        generation: IntelArchGeneration::MeteorLakeArrowLake,
        category: IntelDriverCategory::PchCnviWirelessController,
        class_code: 0x02,
        subclass: 0x80,
        prog_if: 0x00,
        bar0_min_size: 0x8000,
        required_quirks: 0,
        codename: "Gale Peak",
        commercial_name: "Intel Wi-Fi 7 BE200 320MHz MLO (Ultra-High Throughput)",
    },
];

/// Searches the catalog by device ID.
pub fn lookup_intel_device(device_id: u16) -> Option<&'static IntelPciDeviceEntry> {
    INTEL_HARDWARE_CATALOG.iter().find(|d| d.device_id == device_id)
}

/// Returns all entries matching a specific driver category.
pub fn find_by_category(category: IntelDriverCategory) -> Vec<&'static IntelPciDeviceEntry> {
    INTEL_HARDWARE_CATALOG.iter().filter(|d| d.category == category).collect()
}
