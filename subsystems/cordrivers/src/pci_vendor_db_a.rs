//! CorOS Hardware Driver Module: `pci_vendor_db_a`
//!
//! Curated PCI/PCIe Hardware Identification Database — Table A:
//! Intel Corporation (`0x8086`) Host Bridges, LPC/eSPI Chipsets, AHCI SATA Controllers,
//! Optane/Data Center NVMe SSDs, xHCI USB 3.x Host Controllers, HD Audio (`Azalia` / `Smart Sound`),
//! Ethernet Controllers (`e1000`, `igb`, `ixgbe`, `i225`/`i226`, `Wi-Fi 6E/7`), and
//! Integrated/Discrete GPUs (`HD/UHD Graphics`, `Iris Xe`, `Arc Alchemist`).

/// PCI Vendor ID for Intel Corporation.
pub const PCI_VENDOR_INTEL: u16 = 0x8086;

/// Functional Driver Category for binding an appropriate CorOS kernel subsystem driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelDriverBinding {
    HostBridgeDram,
    LpcIsaBridge,
    AhciSataStorage,
    NvmeSsdStorage,
    XhciUsbController,
    SmbusController,
    HdaAudioController,
    GigabitEthernetE1000,
    MultiGigabitEthernetIgc,
    TenGigabitEthernetIxgbe,
    WirelessAxBeWifi,
    IntegratedXeGraphics,
    DiscreteArcGraphics,
    MeHeciManagement,
}

/// Curated entry in the Intel PCI Device Database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntelPciDeviceRecord {
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub binding: IntelDriverBinding,
    pub model_name: &'static str,
}

/// Authentic Intel (`0x8086`) PCI/PCIe Hardware Device Table across Desktop, Server, and Mobile generations.
pub static INTEL_PCI_DEVICE_TABLE: &[IntelPciDeviceRecord] = &[
    // Host Bridges & DRAM Controllers
    IntelPciDeviceRecord {
        device_id: 0x1237,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::HostBridgeDram,
        model_name: "Intel 440FX 82441FX PMC [Natoma] Host Bridge",
    },
    IntelPciDeviceRecord {
        device_id: 0x29C0,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::HostBridgeDram,
        model_name: "Intel 82G33/G31/P35/P31 Express DRAM Controller (Q35)",
    },
    IntelPciDeviceRecord {
        device_id: 0x4660,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::HostBridgeDram,
        model_name: "Intel 12th Gen Core Alder Lake-S Host Bridge/DRAM Registers",
    },
    IntelPciDeviceRecord {
        device_id: 0xA700,
        class_code: 0x06,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::HostBridgeDram,
        model_name: "Intel 13th/14th Gen Core Raptor Lake-S Host Bridge/DRAM Controller",
    },
    // LPC / ISA / SMBus Chipset Controllers
    IntelPciDeviceRecord {
        device_id: 0x7000,
        class_code: 0x06,
        subclass: 0x01,
        prog_if: 0x00,
        binding: IntelDriverBinding::LpcIsaBridge,
        model_name: "Intel 82371SB PIIX3 ISA Bridge",
    },
    IntelPciDeviceRecord {
        device_id: 0x2918,
        class_code: 0x06,
        subclass: 0x01,
        prog_if: 0x00,
        binding: IntelDriverBinding::LpcIsaBridge,
        model_name: "Intel 82801IB (ICH9) LPC Interface Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0x7A84,
        class_code: 0x06,
        subclass: 0x01,
        prog_if: 0x00,
        binding: IntelDriverBinding::LpcIsaBridge,
        model_name: "Intel Z690 Chipset eSPI/LPC Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0x2930,
        class_code: 0x0C,
        subclass: 0x05,
        prog_if: 0x00,
        binding: IntelDriverBinding::SmbusController,
        model_name: "Intel 82801I (ICH9 Family) SMBus Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0x7A23,
        class_code: 0x0C,
        subclass: 0x05,
        prog_if: 0x00,
        binding: IntelDriverBinding::SmbusController,
        model_name: "Intel Alder Lake-S PCH SMBus Controller",
    },
    // AHCI SATA Storage Controllers
    IntelPciDeviceRecord {
        device_id: 0x2922,
        class_code: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
        binding: IntelDriverBinding::AhciSataStorage,
        model_name: "Intel 82801IR/IO/IH (ICH9R/DO/DH) 6-port SATA Controller [AHCI]",
    },
    IntelPciDeviceRecord {
        device_id: 0xA102,
        class_code: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
        binding: IntelDriverBinding::AhciSataStorage,
        model_name: "Intel 100 Series / C230 Chipset Sunrise Point-H SATA [AHCI]",
    },
    IntelPciDeviceRecord {
        device_id: 0x7AE2,
        class_code: 0x01,
        subclass: 0x06,
        prog_if: 0x01,
        binding: IntelDriverBinding::AhciSataStorage,
        model_name: "Intel Alder Lake-S PCH SATA Controller [AHCI]",
    },
    // NVMe Solid State Drives
    IntelPciDeviceRecord {
        device_id: 0x0953,
        class_code: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
        binding: IntelDriverBinding::NvmeSsdStorage,
        model_name: "Intel PCIe Data Center SSD DC P3700 / P4510 [NVMe]",
    },
    IntelPciDeviceRecord {
        device_id: 0xF1A8,
        class_code: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
        binding: IntelDriverBinding::NvmeSsdStorage,
        model_name: "Intel SSD 660p / 670p Series [NVMe]",
    },
    IntelPciDeviceRecord {
        device_id: 0x2701,
        class_code: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
        binding: IntelDriverBinding::NvmeSsdStorage,
        model_name: "Intel Optane SSD 900P / 905P Series [NVMe]",
    },
    // xHCI USB 3.0 / 3.1 / 3.2 Host Controllers
    IntelPciDeviceRecord {
        device_id: 0x8CB1,
        class_code: 0x0C,
        subclass: 0x03,
        prog_if: 0x30,
        binding: IntelDriverBinding::XhciUsbController,
        model_name: "Intel 9 Series Chipset Wildcat Point USB xHCI Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0xA36D,
        class_code: 0x0C,
        subclass: 0x03,
        prog_if: 0x30,
        binding: IntelDriverBinding::XhciUsbController,
        model_name: "Intel Cannon Lake PCH USB 3.1 xHCI Host Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0x7AE0,
        class_code: 0x0C,
        subclass: 0x03,
        prog_if: 0x30,
        binding: IntelDriverBinding::XhciUsbController,
        model_name: "Intel Alder Lake-S PCH USB 3.2 Gen 2x2 xHCI Controller",
    },
    // High Definition Audio Controllers
    IntelPciDeviceRecord {
        device_id: 0x2668,
        class_code: 0x04,
        subclass: 0x03,
        prog_if: 0x00,
        binding: IntelDriverBinding::HdaAudioController,
        model_name: "Intel 82801FB/FBM/FR/FW/FRW (ICH6 Family) High Definition Audio",
    },
    IntelPciDeviceRecord {
        device_id: 0x293E,
        class_code: 0x04,
        subclass: 0x03,
        prog_if: 0x00,
        binding: IntelDriverBinding::HdaAudioController,
        model_name: "Intel 82801I (ICH9 Family) HD Audio Controller",
    },
    IntelPciDeviceRecord {
        device_id: 0x7AD0,
        class_code: 0x04,
        subclass: 0x03,
        prog_if: 0x80,
        binding: IntelDriverBinding::HdaAudioController,
        model_name: "Intel Alder Lake-S HD Audio / Smart Sound Technology (SST)",
    },
    // Gigabit, 2.5GbE, 10GbE & Wireless Network Controllers
    IntelPciDeviceRecord {
        device_id: 0x100E,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::GigabitEthernetE1000,
        model_name: "Intel 82540EM Gigabit Ethernet Controller (PRO/1000 MT)",
    },
    IntelPciDeviceRecord {
        device_id: 0x10D3,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::GigabitEthernetE1000,
        model_name: "Intel 82574L Gigabit Network Connection (e1000e)",
    },
    IntelPciDeviceRecord {
        device_id: 0x1533,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::GigabitEthernetE1000,
        model_name: "Intel I210 Gigabit Network Connection (igb)",
    },
    IntelPciDeviceRecord {
        device_id: 0x15F3,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::MultiGigabitEthernetIgc,
        model_name: "Intel Ethernet Controller I225-V 2.5GbE (igc)",
    },
    IntelPciDeviceRecord {
        device_id: 0x125C,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::MultiGigabitEthernetIgc,
        model_name: "Intel Ethernet Controller I226-V 2.5GbE (igc)",
    },
    IntelPciDeviceRecord {
        device_id: 0x10FB,
        class_code: 0x02,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::TenGigabitEthernetIxgbe,
        model_name: "Intel 82599ES 10-Gigabit SFI/SFP+ Network Connection (ixgbe)",
    },
    IntelPciDeviceRecord {
        device_id: 0x2725,
        class_code: 0x02,
        subclass: 0x80,
        prog_if: 0x00,
        binding: IntelDriverBinding::WirelessAxBeWifi,
        model_name: "Intel Wi-Fi 6E AX210/AX1675 160MHz Wireless Network Adapter",
    },
    // Integrated UHD / Iris Xe & Discrete Arc GPUs
    IntelPciDeviceRecord {
        device_id: 0x3E92,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::IntegratedXeGraphics,
        model_name: "Intel CoffeeLake-S GT2 [UHD Graphics 630]",
    },
    IntelPciDeviceRecord {
        device_id: 0x9A49,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::IntegratedXeGraphics,
        model_name: "Intel TigerLake-LP GT2 [Iris Xe Graphics]",
    },
    IntelPciDeviceRecord {
        device_id: 0x4680,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::IntegratedXeGraphics,
        model_name: "Intel AlderLake-S GT1 [UHD Graphics 770]",
    },
    IntelPciDeviceRecord {
        device_id: 0x56A0,
        class_code: 0x03,
        subclass: 0x00,
        prog_if: 0x00,
        binding: IntelDriverBinding::DiscreteArcGraphics,
        model_name: "Intel DG2 [Arc A770 16GB Graphics]",
    },
];

/// Looks up an Intel (`0x8086`) PCI device record by 16-bit `device_id`.
pub fn lookup_intel_device(device_id: u16) -> Option<&'static IntelPciDeviceRecord> {
    let mut i = 0;
    while i < INTEL_PCI_DEVICE_TABLE.len() {
        if INTEL_PCI_DEVICE_TABLE[i].device_id == device_id {
            return Some(&INTEL_PCI_DEVICE_TABLE[i]);
        }
        i += 1;
    }
    None
}

/// Decodes a standard PCI Base Class / Subclass / Prog-IF triple into a human-readable description.
pub const fn decode_pci_class_name(class_code: u8, subclass: u8, prog_if: u8) -> &'static str {
    match (class_code, subclass, prog_if) {
        (0x01, 0x01, _) => "IDE Mass Storage Controller",
        (0x01, 0x06, 0x01) => "Serial ATA Controller (AHCI 1.0)",
        (0x01, 0x08, 0x02) => "Non-Volatile Memory Controller (NVMe)",
        (0x02, 0x00, _) => "Ethernet Network Controller",
        (0x02, 0x80, _) => "802.11 Wireless Network Controller",
        (0x03, 0x00, _) => "VGA-Compatible Display Controller",
        (0x03, 0x02, _) => "3D Graphics Accelerator",
        (0x04, 0x01, _) => "Multimedia Audio Controller (AC'97)",
        (0x04, 0x03, _) => "High Definition Audio (Azalia) Controller",
        (0x06, 0x00, _) => "PCI Host / DRAM Bridge",
        (0x06, 0x01, _) => "PCI-to-ISA / LPC Bridge",
        (0x06, 0x04, _) => "PCI-to-PCI Express Root Port / Bridge",
        (0x0C, 0x03, 0x30) => "USB 3.x eXtensible Host Controller (xHCI)",
        (0x0C, 0x05, _) => "System Management Bus (SMBus) Controller",
        _ => "Generic PCI/PCIe Peripheral",
    }
}

/// Self-test for `pci_vendor_db_a` Intel PCI device ID lookups, uniqueness verification, and class decoding.
pub fn verify_driver_module_pci_vendor_db_a() -> u32 {
    let mut passed = 0u32;

    // 1. Verify lookup of classic QEMU/VirtualBox Intel 82540EM (0x100E) and ICH9 AHCI (0x2922)
    if let (Some(e1000), Some(ahci)) = (lookup_intel_device(0x100E), lookup_intel_device(0x2922)) {
        if e1000.binding == IntelDriverBinding::GigabitEthernetE1000
            && ahci.binding == IntelDriverBinding::AhciSataStorage
        {
            passed += 1;
        }
    }

    // 2. Verify lookup of Intel Iris Xe (0x9A49) and Arc A770 (0x56A0)
    if let (Some(xe), Some(arc)) = (lookup_intel_device(0x9A49), lookup_intel_device(0x56A0)) {
        if xe.binding == IntelDriverBinding::IntegratedXeGraphics
            && arc.binding == IntelDriverBinding::DiscreteArcGraphics
        {
            passed += 1;
        }
    }

    // 3. Verify every entry in INTEL_PCI_DEVICE_TABLE has a unique device_id
    let mut all_unique = true;
    for i in 0..INTEL_PCI_DEVICE_TABLE.len() {
        for j in (i + 1)..INTEL_PCI_DEVICE_TABLE.len() {
            if INTEL_PCI_DEVICE_TABLE[i].device_id == INTEL_PCI_DEVICE_TABLE[j].device_id {
                all_unique = false;
            }
        }
    }
    if all_unique && INTEL_PCI_DEVICE_TABLE.len() >= 30 {
        passed += 1;
    }

    // 4. Verify PCI Class Code decoder
    if decode_pci_class_name(0x01, 0x08, 0x02) == "Non-Volatile Memory Controller (NVMe)"
        && decode_pci_class_name(0x0C, 0x03, 0x30) == "USB 3.x eXtensible Host Controller (xHCI)"
    {
        passed += 1;
    }

    passed
}
