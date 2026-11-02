//! CorOS Hardware Driver Module: `pci_vendor_db_b`
//!
//! Curated PCI/PCIe Hardware Identification Database — Table B:
//! - AMD / ATI Technologies (`0x1002`): Radeon Polaris, Vega, RDNA, RDNA2, RDNA3 GPUs & HDMI Audio
//! - Advanced Micro Devices (`0x1022`): Zen 2/3/4/5 Root Complex, IOMMU, FCH SATA, xHCI, CCP, Audio
//! - Realtek Semiconductor (`0x10EC`): RTL8139, RTL8169, RTL8168/8111, RTL8125 2.5GbE, RTL8852 Wi-Fi, RTS5229 NVMe
//! - Broadcom / LSI (`0x14E4`): NetXtreme BCM5720, BCM57416 10GbE, BCM43602/4378 Wi-Fi
//! - Qualcomm / Atheros (`0x168C`): AR9285, AR9380, QCA9880, QCA6174, QCNFA765 Wi-Fi 6E

/// PCI Vendor IDs covered by Database B.
pub mod vendor_ids_b {
    pub const AMD_ATI_GPU: u16 = 0x1002;
    pub const AMD_CPU_FCH: u16 = 0x1022;
    pub const REALTEK: u16 = 0x10EC;
    pub const BROADCOM: u16 = 0x14E4;
    pub const QUALCOMM_ATHEROS: u16 = 0x168C;
}

/// Driver Subsystem family for Table B devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorBDriverFamily {
    AmdRdnaDisplayGpu,
    AmdHdmiDisplayAudio,
    AmdZenHostBridgeIommu,
    AmdFchSataAhci,
    AmdFchUsbXhci,
    AmdCryptographicCoprocessor,
    RealtekPciEthernet,
    RealtekWirelessLan,
    RealtekNvmeOrCardReader,
    BroadcomNetXtremeEthernet,
    BroadcomWirelessLan,
    AtherosWirelessLan,
}

/// Curated PCI Device Record in Table B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VendorBPciDeviceRecord {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub family: VendorBDriverFamily,
    pub model_name: &'static str,
}

/// Curated Hardware Device Table for AMD (`0x1002`, `0x1022`), Realtek (`0x10EC`),
/// Broadcom (`0x14E4`), and Qualcomm/Atheros (`0x168C`).
pub static VENDOR_B_PCI_DEVICE_TABLE: &[VendorBPciDeviceRecord] = &[
    // AMD / ATI Radeon GPUs (0x1002)
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x67DF,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Ellesmere [Radeon RX 470/480/570/580/590]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x731F,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 10 [Radeon RX 5700 / 5700 XT]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x73BF,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 21 [Radeon RX 6800/6800 XT / 6900 XT]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x73DF,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 22 [Radeon RX 6700 XT / 6750 XT]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x73FF,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 23 [Radeon RX 6600 / 6600 XT / 6650 XT]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x744C,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 31 [Radeon RX 7900 XT / 7900 XTX]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0x747E,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdRdnaDisplayGpu,
        model_name: "AMD Navi 32 [Radeon RX 7700 XT / 7800 XT]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1002,
        device_id: 0xAB28,
        class_code: 0x04,
        subclass: 0x03,
        family: VendorBDriverFamily::AmdHdmiDisplayAudio,
        model_name: "AMD Navi 21/23 HDMI/DP Audio Controller",
    },
    // AMD Zen SoC, IOMMU, FCH SATA & USB (0x1022)
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x1480,
        class_code: 0x06,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdZenHostBridgeIommu,
        model_name: "AMD Starship/Matisse (Zen 2/3) Root Complex",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x1482,
        class_code: 0x08,
        subclass: 0x06,
        family: VendorBDriverFamily::AmdZenHostBridgeIommu,
        model_name: "AMD Starship/Matisse (Zen 2/3) IOMMU (AMD-Vi)",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x14D8,
        class_code: 0x06,
        subclass: 0x00,
        family: VendorBDriverFamily::AmdZenHostBridgeIommu,
        model_name: "AMD Raphael/Granite Ridge (Zen 4/5) Root Complex",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x7901,
        class_code: 0x01,
        subclass: 0x06,
        family: VendorBDriverFamily::AmdFchSataAhci,
        model_name: "AMD FCH SATA Controller [AHCI Mode]",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x149C,
        class_code: 0x0C,
        subclass: 0x03,
        family: VendorBDriverFamily::AmdFchUsbXhci,
        model_name: "AMD Matisse USB 3.0 xHCI Host Controller",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x1022,
        device_id: 0x1486,
        class_code: 0x10,
        subclass: 0x80,
        family: VendorBDriverFamily::AmdCryptographicCoprocessor,
        model_name: "AMD Starship/Matisse Cryptographic Coprocessor (PSP/CCP)",
    },
    // Realtek Semiconductor (0x10EC)
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8139,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::RealtekPciEthernet,
        model_name: "Realtek RTL-8100/8101L/8139 PCI Fast Ethernet Adapter",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8168,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::RealtekPciEthernet,
        model_name: "Realtek RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8169,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::RealtekPciEthernet,
        model_name: "Realtek RTL8169 PCI Gigabit Ethernet Controller",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8125,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::RealtekPciEthernet,
        model_name: "Realtek RTL8125 2.5GbE PCIe Network Controller",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8126,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::RealtekPciEthernet,
        model_name: "Realtek RTL8126 5GbE PCIe Network Controller",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x8852,
        class_code: 0x02,
        subclass: 0x80,
        family: VendorBDriverFamily::RealtekWirelessLan,
        model_name: "Realtek RTL8852AE / RTL8852BE 802.11ax PCIe Wi-Fi 6 Adapter",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x10EC,
        device_id: 0x5765,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorBDriverFamily::RealtekNvmeOrCardReader,
        model_name: "Realtek RTS5765DL NVMe SSD Controller",
    },
    // Broadcom Inc. (0x14E4)
    VendorBPciDeviceRecord {
        vendor_id: 0x14E4,
        device_id: 0x165F,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::BroadcomNetXtremeEthernet,
        model_name: "Broadcom NetXtreme BCM5720 Dual-Port Gigabit Ethernet PCIe",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x14E4,
        device_id: 0x16D8,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorBDriverFamily::BroadcomNetXtremeEthernet,
        model_name: "Broadcom BCM57416 NetXtreme-E Dual-Media 10G RDMA Ethernet",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x14E4,
        device_id: 0x43BA,
        class_code: 0x02,
        subclass: 0x80,
        family: VendorBDriverFamily::BroadcomWirelessLan,
        model_name: "Broadcom BCM43602 802.11ac Wireless LAN SoC",
    },
    // Qualcomm / Atheros (0x168C)
    VendorBPciDeviceRecord {
        vendor_id: 0x168C,
        device_id: 0x002B,
        class_code: 0x02,
        subclass: 0x80,
        family: VendorBDriverFamily::AtherosWirelessLan,
        model_name: "Qualcomm Atheros AR9285 Wireless Network Adapter (PCI-Express)",
    },
    VendorBPciDeviceRecord {
        vendor_id: 0x168C,
        device_id: 0x003E,
        class_code: 0x02,
        subclass: 0x80,
        family: VendorBDriverFamily::AtherosWirelessLan,
        model_name: "Qualcomm Atheros QCA6174 802.11ac Wireless Network Adapter",
    },
];

/// Looks up a PCI device in Database B by `(vendor_id, device_id)`.
pub fn lookup_vendor_b_device(
    vendor_id: u16,
    device_id: u16,
) -> Option<&'static VendorBPciDeviceRecord> {
    let mut i = 0;
    while i < VENDOR_B_PCI_DEVICE_TABLE.len() {
        let entry = &VENDOR_B_PCI_DEVICE_TABLE[i];
        if entry.vendor_id == vendor_id && entry.device_id == device_id {
            return Some(entry);
        }
        i += 1;
    }
    None
}

/// Returns the canonical vendor name for Vendor IDs in Database B.
pub const fn vendor_b_name(vendor_id: u16) -> Option<&'static str> {
    match vendor_id {
        vendor_ids_b::AMD_ATI_GPU => Some("Advanced Micro Devices, Inc. [AMD/ATI]"),
        vendor_ids_b::AMD_CPU_FCH => Some("Advanced Micro Devices, Inc. [AMD]"),
        vendor_ids_b::REALTEK => Some("Realtek Semiconductor Co., Ltd."),
        vendor_ids_b::BROADCOM => Some("Broadcom Inc. and Subsidiaries"),
        vendor_ids_b::QUALCOMM_ATHEROS => Some("Qualcomm Atheros"),
        _ => None,
    }
}

/// Self-test for `pci_vendor_db_b` AMD/Realtek/Broadcom/Atheros lookups and `(vendor_id, device_id)` uniqueness.
pub fn verify_driver_module_pci_vendor_db_b() -> u32 {
    let mut passed = 0u32;

    // 1. Verify AMD Radeon RX 7900 XTX (`0x1002:0x744C`) and AMD Zen IOMMU (`0x1022:0x1482`)
    if let (Some(gpu), Some(iommu)) = (
        lookup_vendor_b_device(0x1002, 0x744C),
        lookup_vendor_b_device(0x1022, 0x1482),
    ) {
        if gpu.family == VendorBDriverFamily::AmdRdnaDisplayGpu
            && iommu.family == VendorBDriverFamily::AmdZenHostBridgeIommu
        {
            passed += 1;
        }
    }

    // 2. Verify Realtek RTL8168 (`0x10EC:0x8168`) and RTL8125 2.5GbE (`0x10EC:0x8125`)
    if let (Some(r8168), Some(r8125)) = (
        lookup_vendor_b_device(0x10EC, 0x8168),
        lookup_vendor_b_device(0x10EC, 0x8125),
    ) {
        if r8168.family == VendorBDriverFamily::RealtekPciEthernet
            && r8125.family == VendorBDriverFamily::RealtekPciEthernet
        {
            passed += 1;
        }
    }

    // 3. Verify Broadcom NetXtreme (`0x14E4:0x165F`) and Atheros QCA6174 (`0x168C:0x003E`)
    if lookup_vendor_b_device(0x14E4, 0x165F).is_some()
        && lookup_vendor_b_device(0x168C, 0x003E).is_some()
        && vendor_b_name(0x10EC) == Some("Realtek Semiconductor Co., Ltd.")
    {
        passed += 1;
    }

    // 4. Verify all `(vendor_id, device_id)` pairs in VENDOR_B_PCI_DEVICE_TABLE are strictly distinct
    let mut all_unique = true;
    for i in 0..VENDOR_B_PCI_DEVICE_TABLE.len() {
        for j in (i + 1)..VENDOR_B_PCI_DEVICE_TABLE.len() {
            if VENDOR_B_PCI_DEVICE_TABLE[i].vendor_id == VENDOR_B_PCI_DEVICE_TABLE[j].vendor_id
                && VENDOR_B_PCI_DEVICE_TABLE[i].device_id == VENDOR_B_PCI_DEVICE_TABLE[j].device_id
            {
                all_unique = false;
            }
        }
    }
    if all_unique && VENDOR_B_PCI_DEVICE_TABLE.len() >= 25 {
        passed += 1;
    }

    passed
}
