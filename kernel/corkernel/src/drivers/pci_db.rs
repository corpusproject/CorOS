//! PCI Vendor & Device Identification Database
//!
//! Maps 16-bit PCI Vendor IDs and Device IDs to authentic hardware vendor
//! names, device names, and functional device categories.

#[derive(Clone, Copy, Debug)]
pub struct PciDeviceInfo {
    pub vendor_name: &'static str,
    pub device_name: &'static str,
    pub category: &'static str,
}

struct PciEntry {
    vendor_id: u16,
    device_id: u16,
    vendor_name: &'static str,
    device_name: &'static str,
    category: &'static str,
}

const PCI_DATABASE: &[PciEntry] = &[
    // --- Intel Corporation (0x8086) ---
    PciEntry { vendor_id: 0x8086, device_id: 0x100E, vendor_name: "Intel Corporation", device_name: "82540EM Gigabit Ethernet Controller", category: "Network Controller" },
    PciEntry { vendor_id: 0x8086, device_id: 0x100F, vendor_name: "Intel Corporation", device_name: "82545EM Gigabit Ethernet Controller (Copper)", category: "Network Controller" },
    PciEntry { vendor_id: 0x8086, device_id: 0x10D3, vendor_name: "Intel Corporation", device_name: "82574L Gigabit Network Connection", category: "Network Controller" },
    PciEntry { vendor_id: 0x8086, device_id: 0x1539, vendor_name: "Intel Corporation", device_name: "I211 Gigabit Network Connection", category: "Network Controller" },
    PciEntry { vendor_id: 0x8086, device_id: 0x15F3, vendor_name: "Intel Corporation", device_name: "Ethernet Controller I225-V (2.5 Gbps)", category: "Network Controller" },
    PciEntry { vendor_id: 0x8086, device_id: 0x2415, vendor_name: "Intel Corporation", device_name: "82801AA AC'97 Audio Controller", category: "Multimedia Audio" },
    PciEntry { vendor_id: 0x8086, device_id: 0x24C5, vendor_name: "Intel Corporation", device_name: "82801DB/DBL/DBM (ICH4/ICH4-M) AC'97 Audio", category: "Multimedia Audio" },
    PciEntry { vendor_id: 0x8086, device_id: 0x2668, vendor_name: "Intel Corporation", device_name: "82801FB/FBM/FR/FW/FRW (ICH6) HD Audio", category: "High Definition Audio" },
    PciEntry { vendor_id: 0x8086, device_id: 0x2829, vendor_name: "Intel Corporation", device_name: "82801HM/HEM (ICH8M/ICH8M-E) SATA Controller [AHCI]", category: "Mass Storage SATA" },
    PciEntry { vendor_id: 0x8086, device_id: 0x2922, vendor_name: "Intel Corporation", device_name: "82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA Controller [AHCI]", category: "Mass Storage SATA" },
    PciEntry { vendor_id: 0x8086, device_id: 0x1237, vendor_name: "Intel Corporation", device_name: "440FX - 82441FX PMC [Natoma]", category: "Host Bridge" },
    PciEntry { vendor_id: 0x8086, device_id: 0x7000, vendor_name: "Intel Corporation", device_name: "82371SB PIIX3 ISA [Natoma/Triton II]", category: "ISA Bridge" },
    PciEntry { vendor_id: 0x8086, device_id: 0x7010, vendor_name: "Intel Corporation", device_name: "82371SB PIIX3 IDE [Natoma/Triton II]", category: "IDE Storage" },
    PciEntry { vendor_id: 0x8086, device_id: 0x7113, vendor_name: "Intel Corporation", device_name: "82371AB/EB/MB PIIX4 ACPI", category: "Bridge Power" },
    PciEntry { vendor_id: 0x8086, device_id: 0x29C0, vendor_name: "Intel Corporation", device_name: "82G33/G31/P35/P31 Express DRAM Controller", category: "Host Bridge" },
    PciEntry { vendor_id: 0x8086, device_id: 0x0100, vendor_name: "Intel Corporation", device_name: "2nd Generation Core Processor DRAM Controller", category: "Host Bridge" },
    PciEntry { vendor_id: 0x8086, device_id: 0x0116, vendor_name: "Intel Corporation", device_name: "2nd Generation Core Processor HD Graphics 3000", category: "VGA Display" },
    PciEntry { vendor_id: 0x8086, device_id: 0x0412, vendor_name: "Intel Corporation", device_name: "HD Graphics 4600 (Haswell Desktop)", category: "VGA Display" },
    PciEntry { vendor_id: 0x8086, device_id: 0x3E92, vendor_name: "Intel Corporation", device_name: "CoffeeLake-S GT2 [UHD Graphics 630]", category: "VGA Display" },
    PciEntry { vendor_id: 0x8086, device_id: 0x4680, vendor_name: "Intel Corporation", device_name: "Alder Lake-S GT1 [UHD Graphics 770]", category: "VGA Display" },
    PciEntry { vendor_id: 0x8086, device_id: 0xF1A8, vendor_name: "Intel Corporation", device_name: "SSD 660p Series NVMe PCIe SSD", category: "Non-Volatile Memory (NVMe)" },

    // --- Advanced Micro Devices (AMD) (0x1022 / 0x1002) ---
    PciEntry { vendor_id: 0x1022, device_id: 0x2000, vendor_name: "AMD Inc.", device_name: "79c970 [PCnet32 LANCE] Ethernet", category: "Network Controller" },
    PciEntry { vendor_id: 0x1022, device_id: 0x7901, vendor_name: "AMD Inc.", device_name: "FCH SATA Controller [AHCI mode]", category: "Mass Storage SATA" },
    PciEntry { vendor_id: 0x1022, device_id: 0x1450, vendor_name: "AMD Inc.", device_name: "Zeppelin/Raven/Raven2 PCIe Root Complex", category: "Host Bridge" },
    PciEntry { vendor_id: 0x1022, device_id: 0x1480, vendor_name: "AMD Inc.", device_name: "Starship/Matisse Root Complex (Ryzen 3000/5000)", category: "Host Bridge" },
    PciEntry { vendor_id: 0x1022, device_id: 0x1576, vendor_name: "AMD Inc.", device_name: "Family 17h/19h HD Audio Controller", category: "High Definition Audio" },
    PciEntry { vendor_id: 0x1002, device_id: 0x73FF, vendor_name: "AMD / ATI", device_name: "Navi 23 [Radeon RX 6600 / 6600 XT]", category: "VGA Display" },
    PciEntry { vendor_id: 0x1002, device_id: 0x744C, vendor_name: "AMD / ATI", device_name: "Navi 33 [Radeon RX 7600]", category: "VGA Display" },

    // --- NVIDIA Corporation (0x10DE) ---
    PciEntry { vendor_id: 0x10DE, device_id: 0x1C82, vendor_name: "NVIDIA Corporation", device_name: "GP107 [GeForce GTX 1050 Ti]", category: "3D VGA Controller" },
    PciEntry { vendor_id: 0x10DE, device_id: 0x2182, vendor_name: "NVIDIA Corporation", device_name: "TU116 [GeForce GTX 1660 Ti]", category: "3D VGA Controller" },
    PciEntry { vendor_id: 0x10DE, device_id: 0x2484, vendor_name: "NVIDIA Corporation", device_name: "GA104 [GeForce RTX 3070]", category: "3D VGA Controller" },
    PciEntry { vendor_id: 0x10DE, device_id: 0x2704, vendor_name: "NVIDIA Corporation", device_name: "AD103 [GeForce RTX 4080]", category: "3D VGA Controller" },

    // --- Realtek Semiconductor (0x10EC) ---
    PciEntry { vendor_id: 0x10EC, device_id: 0x8139, vendor_name: "Realtek Semiconductor", device_name: "RTL-8100/8101L/8139 PCI Fast Ethernet Adapter", category: "Network Controller" },
    PciEntry { vendor_id: 0x10EC, device_id: 0x8168, vendor_name: "Realtek Semiconductor", device_name: "RTL8111/8168/8411 PCI Express Gigabit Ethernet", category: "Network Controller" },
    PciEntry { vendor_id: 0x10EC, device_id: 0x8125, vendor_name: "Realtek Semiconductor", device_name: "RTL8125 2.5GbE Controller", category: "Network Controller" },
    PciEntry { vendor_id: 0x10EC, device_id: 0x0887, vendor_name: "Realtek Semiconductor", device_name: "ALC887-VD High Definition Audio Codec", category: "Multimedia Audio" },
    PciEntry { vendor_id: 0x10EC, device_id: 0x0892, vendor_name: "Realtek Semiconductor", device_name: "ALC892 High Definition Audio Codec", category: "Multimedia Audio" },

    // --- Red Hat, Inc. / QEMU VirtIO (0x1AF4) ---
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1000, vendor_name: "Red Hat, Inc.", device_name: "Virtio Network Device (Legacy)", category: "Network Virtualization" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1001, vendor_name: "Red Hat, Inc.", device_name: "Virtio Block Device (Legacy)", category: "Mass Storage Virtualization" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1002, vendor_name: "Red Hat, Inc.", device_name: "Virtio Memory Balloon Device", category: "Memory Management" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1003, vendor_name: "Red Hat, Inc.", device_name: "Virtio Console Device", category: "Communication Controller" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1004, vendor_name: "Red Hat, Inc.", device_name: "Virtio SCSI Device", category: "SCSI Storage" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1005, vendor_name: "Red Hat, Inc.", device_name: "Virtio RNG (Random Number Generator)", category: "Hardware Security" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1041, vendor_name: "Red Hat, Inc.", device_name: "Virtio Network Device (Modern)", category: "Network Virtualization" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1042, vendor_name: "Red Hat, Inc.", device_name: "Virtio Block Device (Modern)", category: "Mass Storage Virtualization" },
    PciEntry { vendor_id: 0x1AF4, device_id: 0x1050, vendor_name: "Red Hat, Inc.", device_name: "Virtio GPU Device (Modern 2D/3D)", category: "VGA Display" },

    // --- VMware / Oracle VirtualBox (0x15AD / 0x80EE) ---
    PciEntry { vendor_id: 0x15AD, device_id: 0x0405, vendor_name: "VMware", device_name: "SVGA II Adapter", category: "VGA Display" },
    PciEntry { vendor_id: 0x15AD, device_id: 0x0740, vendor_name: "VMware", device_name: "Virtual Machine Interface (VMMDev)", category: "Virtualization Bridge" },
    PciEntry { vendor_id: 0x80EE, device_id: 0xBEEF, vendor_name: "Oracle VirtualBox", device_name: "VirtualBox Graphics Adapter", category: "VGA Display" },
    PciEntry { vendor_id: 0x80EE, device_id: 0xCAFE, vendor_name: "Oracle VirtualBox", device_name: "VirtualBox Guest Integration Device", category: "Virtualization Integration" },

    // --- Samsung Electronics (NVMe) (0x144D) ---
    PciEntry { vendor_id: 0x144D, device_id: 0xA808, vendor_name: "Samsung Electronics", device_name: "NVMe SSD Controller 970 EVO / PRO", category: "Non-Volatile Memory (NVMe)" },
    PciEntry { vendor_id: 0x144D, device_id: 0xA80A, vendor_name: "Samsung Electronics", device_name: "NVMe SSD Controller 980 PRO", category: "Non-Volatile Memory (NVMe)" },
];

pub fn lookup_pci_device(vendor_id: u16, device_id: u16) -> PciDeviceInfo {
    for entry in PCI_DATABASE {
        if entry.vendor_id == vendor_id && entry.device_id == device_id {
            return PciDeviceInfo {
                vendor_name: entry.vendor_name,
                device_name: entry.device_name,
                category: entry.category,
            };
        }
    }

    let vendor_name = match vendor_id {
        0x8086 => "Intel Corporation",
        0x1002 | 0x1022 => "Advanced Micro Devices (AMD)",
        0x10DE => "NVIDIA Corporation",
        0x10EC => "Realtek Semiconductor",
        0x14E4 => "Broadcom Corporation",
        0x168C => "Qualcomm Atheros",
        0x1B36 => "Red Hat / QEMU",
        0x1AF4 => "VirtIO Consortium",
        0x15AD => "VMware Inc.",
        0x80EE => "Oracle VirtualBox",
        0x144D => "Samsung Electronics",
        _ => "Bilinmeyen Uretici (Unknown Vendor)",
    };

    PciDeviceInfo {
        vendor_name,
        device_name: "Standart PCI Aygiti (Generic Device)",
        category: "PCI Cevre Birimi (Peripheral)",
    }
}
