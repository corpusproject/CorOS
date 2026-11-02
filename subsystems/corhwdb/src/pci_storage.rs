//! NVMe SSD, AHCI Host Controllers & Storage Bridge Hardware Registry.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

pub const PCI_VENDOR_SAMSUNG: u16 = 0x144D;
pub const PCI_VENDOR_WESTERN_DIGITAL: u16 = 0x15B7;
pub const PCI_VENDOR_KIOXIA: u16 = 0x1E0F;
pub const PCI_VENDOR_SOLIDIGM_SK_HYNIX: u16 = 0x0274;
pub const PCI_VENDOR_MICRON_CRUCIAL: u16 = 0x1344;
pub const PCI_VENDOR_PHISON: u16 = 0x1987;
pub const PCI_VENDOR_SILICON_MOTION: u16 = 0x126F;
pub const PCI_VENDOR_ASMEDIA: u16 = 0x1B21;

/// NVMe / Storage Controller Class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageControllerType {
    NvmePcieGen3,
    NvmePcieGen4,
    NvmePcieGen5,
    AhciSataGen3,
    UsbXhciHostController,
    PcieSataBridge,
}

/// NVMe Quirk Flags required for hardware errata workarounds.
pub mod nvme_quirks {
    pub const QUIRK_NO_DEEPEST_PS: u32 = 1 << 0;
    pub const QUIRK_IGNORE_DEV_SUBNQN: u32 = 1 << 1;
    pub const QUIRK_DISABLE_WRITE_ZEROES: u32 = 1 << 2;
    pub const QUIRK_DELAY_BEFORE_CHK_RDY: u32 = 1 << 3;
    pub const QUIRK_128K_MAX_SEGMENT: u32 = 1 << 4;
}

/// Storage Device Descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageDeviceEntry {
    pub vendor_id: u16,
    pub device_id: u16,
    pub controller_type: StorageControllerType,
    pub quirks: u32,
    pub max_io_queues: u16,
    pub controller_name: &'static str,
    pub drive_model: &'static str,
}

/// Catalog of authentic NVMe and Storage Controller chips.
pub static STORAGE_HARDWARE_CATALOG: &[StorageDeviceEntry] = &[
    // --- Samsung Electronics (970 EVO, 980 PRO, 990 PRO) ---
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SAMSUNG,
        device_id: 0xA808,
        controller_type: StorageControllerType::NvmePcieGen3,
        quirks: 0,
        max_io_queues: 32,
        controller_name: "Samsung Phoenix Controller",
        drive_model: "Samsung SSD 970 EVO / 970 EVO Plus / 970 PRO M.2 NVMe",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SAMSUNG,
        device_id: 0xA80A,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: nvme_quirks::QUIRK_NO_DEEPEST_PS,
        max_io_queues: 128,
        controller_name: "Samsung Elpis Controller (8nm)",
        drive_model: "Samsung SSD 980 PRO PCIe 4.0 NVMe M.2 SSD",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SAMSUNG,
        device_id: 0xA80C,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 128,
        controller_name: "Samsung Pascal Controller (8nm)",
        drive_model: "Samsung SSD 990 PRO PCIe 4.0 NVMe M.2 SSD (7450 MB/s)",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SAMSUNG,
        device_id: 0xA80E,
        controller_type: StorageControllerType::NvmePcieGen5,
        quirks: 0,
        max_io_queues: 256,
        controller_name: "Samsung Piccolo Controller (5nm)",
        drive_model: "Samsung SSD 990 EVO Plus / Enterprise PM1743 PCIe 5.0",
    },

    // --- Western Digital / SanDisk (WD Black SN850X, SN770) ---
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_WESTERN_DIGITAL,
        device_id: 0x5011,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 64,
        controller_name: "WD Black G2 Controller",
        drive_model: "WD_BLACK SN850 NVMe SSD",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_WESTERN_DIGITAL,
        device_id: 0x5017,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 128,
        controller_name: "WD Black 20-82-20035-B1",
        drive_model: "WD_BLACK SN850X NVMe SSD 7300 MB/s",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_WESTERN_DIGITAL,
        device_id: 0x5018,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 64,
        controller_name: "SanDisk DRAM-less Controller",
        drive_model: "WD_BLACK SN770 NVMe SSD",
    },

    // --- Solidigm / SK Hynix (Platinum P41, Gold P31) ---
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SOLIDIGM_SK_HYNIX,
        device_id: 0x1533,
        controller_type: StorageControllerType::NvmePcieGen3,
        quirks: 0,
        max_io_queues: 32,
        controller_name: "SK hynix Cepheus Controller",
        drive_model: "SK hynix Gold P31 M.2 NVMe SSD",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_SOLIDIGM_SK_HYNIX,
        device_id: 0x17A3,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 128,
        controller_name: "SK hynix Aries Controller",
        drive_model: "SK hynix Platinum P41 / Solidigm P44 Pro PCIe 4.0 SSD",
    },

    // --- Micron / Crucial (T700, T500, P5 Plus) ---
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_MICRON_CRUCIAL,
        device_id: 0x5411,
        controller_type: StorageControllerType::NvmePcieGen4,
        quirks: 0,
        max_io_queues: 64,
        controller_name: "Phison PS5018-E18 (Crucial custom)",
        drive_model: "Crucial P5 Plus PCIe 4.0 3D NAND NVMe SSD",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_MICRON_CRUCIAL,
        device_id: 0x5415,
        controller_type: StorageControllerType::NvmePcieGen5,
        quirks: nvme_quirks::QUIRK_DELAY_BEFORE_CHK_RDY,
        max_io_queues: 256,
        controller_name: "Phison PS5026-E26",
        drive_model: "Crucial T700 / T705 PCIe 5.0 NVMe SSD (12,400 MB/s)",
    },

    // --- ASMedia USB 3.2 xHCI & PCIe-to-SATA Bridges ---
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_ASMEDIA,
        device_id: 0x1062,
        controller_type: StorageControllerType::PcieSataBridge,
        quirks: 0,
        max_io_queues: 1,
        controller_name: "ASM1062",
        drive_model: "ASMedia ASM1062 Serial ATA AHCI 2-Port Controller",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_ASMEDIA,
        device_id: 0x1166,
        controller_type: StorageControllerType::PcieSataBridge,
        quirks: 0,
        max_io_queues: 1,
        controller_name: "ASM1166",
        drive_model: "ASMedia ASM1166 PCIe Gen3 x2 to 6-Port SATA 6Gb/s AHCI Controller",
    },
    StorageDeviceEntry {
        vendor_id: PCI_VENDOR_ASMEDIA,
        device_id: 0x3242,
        controller_type: StorageControllerType::UsbXhciHostController,
        quirks: 0,
        max_io_queues: 8,
        controller_name: "ASM3242",
        drive_model: "ASMedia ASM3242 USB 3.2 Gen 2x2 (20Gbps) Host Controller",
    },
];

/// Looks up storage entry by vendor and device ID.
pub fn lookup_storage_device(vendor_id: u16, device_id: u16) -> Option<&'static StorageDeviceEntry> {
    STORAGE_HARDWARE_CATALOG
        .iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
}
