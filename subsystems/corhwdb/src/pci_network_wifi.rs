//! `pci_network_wifi` — Wi-Fi 5 / Wi-Fi 6 / Wi-Fi 6E / Wi-Fi 7 PCI Wireless Controllers.
//! Detailed registry of Intel, Realtek, MediaTek, Qualcomm, and Broadcom WLAN NICs.

pub const PCI_VENDOR_INTEL: u16 = 0x8086;
pub const PCI_VENDOR_REALTEK: u16 = 0x10EC;
pub const PCI_VENDOR_MEDIATEK: u16 = 0x14C3;
pub const PCI_VENDOR_QUALCOMM: u16 = 0x17CB;
pub const PCI_VENDOR_BROADCOM: u16 = 0x14E4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum WifiGeneration {
    Wifi5_802_11ac,
    Wifi6_802_11ax,
    Wifi6E_802_11ax_6GHz,
    Wifi7_802_11be,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WifiMimoConfig {
    Mimo1x1,
    Mimo2x2,
    Mimo3x3,
    Mimo4x4,
}

pub struct WifiDeviceDescriptor {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subvendor_id: u16,
    pub subdevice_id: u16,
    pub generation: WifiGeneration,
    pub mimo: WifiMimoConfig,
    pub max_bandwidth_mhz: u16,
    pub peak_phy_rate_mbps: u32,
    pub bluetooth_integrated: bool,
    pub bluetooth_version: &'static str,
    pub commercial_name: &'static str,
    pub driver_binding: &'static str,
}

pub static WIFI_NIC_CATALOG: &[WifiDeviceDescriptor] = &[
    // --- Intel Wi-Fi 7 ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x272b,
        subvendor_id: 0x8086,
        subdevice_id: 0x00F0,
        generation: WifiGeneration::Wifi7_802_11be,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 320,
        peak_phy_rate_mbps: 5764,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.4",
        commercial_name: "Intel Wi-Fi 7 BE200 320MHz",
        driver_binding: "iwlwifi_be",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x272c,
        subvendor_id: 0x8086,
        subdevice_id: 0x00F4,
        generation: WifiGeneration::Wifi7_802_11be,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 320,
        peak_phy_rate_mbps: 5764,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.4",
        commercial_name: "Killer Wi-Fi 7 BE1750x Gaming Adapter",
        driver_binding: "iwlwifi_be",
    },

    // --- Intel Wi-Fi 6E ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x2725,
        subvendor_id: 0x8086,
        subdevice_id: 0x0090,
        generation: WifiGeneration::Wifi6E_802_11ax_6GHz,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.3",
        commercial_name: "Intel Wi-Fi 6E AX210 160MHz",
        driver_binding: "iwlwifi_ax",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x51F0,
        subvendor_id: 0x8086,
        subdevice_id: 0x0094,
        generation: WifiGeneration::Wifi6E_802_11ax_6GHz,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.3",
        commercial_name: "Intel Wi-Fi 6E AX211 CNVio2",
        driver_binding: "iwlwifi_cnvi",
    },

    // --- Intel Wi-Fi 6 ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x2723,
        subvendor_id: 0x8086,
        subdevice_id: 0x0080,
        generation: WifiGeneration::Wifi6_802_11ax,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.2",
        commercial_name: "Intel Wi-Fi 6 AX200",
        driver_binding: "iwlwifi_ax",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_INTEL,
        device_id: 0x31DC,
        subvendor_id: 0x8086,
        subdevice_id: 0x0030,
        generation: WifiGeneration::Wifi5_802_11ac,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 1733,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.1",
        commercial_name: "Intel Wireless-AC 9560",
        driver_binding: "iwlwifi_ac",
    },

    // --- MediaTek Wi-Fi 6 / 6E / 7 ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x7921,
        subvendor_id: 0x14C3,
        subdevice_id: 0x7921,
        generation: WifiGeneration::Wifi6_802_11ax,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 80,
        peak_phy_rate_mbps: 1201,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.2",
        commercial_name: "MediaTek MT7921 Wi-Fi 6 Wireless",
        driver_binding: "mt7921e",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x7922,
        subvendor_id: 0x14C3,
        subdevice_id: 0x0616,
        generation: WifiGeneration::Wifi6E_802_11ax_6GHz,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.3",
        commercial_name: "AMD RZ616 (MediaTek MT7922) Wi-Fi 6E",
        driver_binding: "mt7921e",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x7925,
        subvendor_id: 0x14C3,
        subdevice_id: 0x7925,
        generation: WifiGeneration::Wifi7_802_11be,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2882,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.4",
        commercial_name: "MediaTek MT7925 Wi-Fi 7 Wireless",
        driver_binding: "mt7925e",
    },

    // --- Realtek Wi-Fi 5 / 6 / 6E ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0xC821,
        subvendor_id: 0x10EC,
        subdevice_id: 0xC821,
        generation: WifiGeneration::Wifi5_802_11ac,
        mimo: WifiMimoConfig::Mimo1x1,
        max_bandwidth_mhz: 80,
        peak_phy_rate_mbps: 433,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 4.2",
        commercial_name: "Realtek RTL8821CE 802.11ac PCIe Adapter",
        driver_binding: "rtw88_8821ce",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0xC822,
        subvendor_id: 0x10EC,
        subdevice_id: 0xC822,
        generation: WifiGeneration::Wifi5_802_11ac,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 80,
        peak_phy_rate_mbps: 867,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.0",
        commercial_name: "Realtek RTL8822CE 802.11ac PCIe Adapter",
        driver_binding: "rtw88_8822ce",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0x8852,
        subvendor_id: 0x10EC,
        subdevice_id: 0x8852,
        generation: WifiGeneration::Wifi6_802_11ax,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 80,
        peak_phy_rate_mbps: 1201,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.2",
        commercial_name: "Realtek RTL8852AE Wi-Fi 6 PCIe Adapter",
        driver_binding: "rtw89_8852ae",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0xB852,
        subvendor_id: 0x10EC,
        subdevice_id: 0xB852,
        generation: WifiGeneration::Wifi6_802_11ax,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.2",
        commercial_name: "Realtek RTL8852BE Wi-Fi 6 PCIe Adapter",
        driver_binding: "rtw89_8852be",
    },

    // --- Qualcomm FastConnect ---
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_QUALCOMM,
        device_id: 0x1103,
        subvendor_id: 0x17CB,
        subdevice_id: 0x0001,
        generation: WifiGeneration::Wifi6E_802_11ax_6GHz,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 160,
        peak_phy_rate_mbps: 2402,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.3",
        commercial_name: "Qualcomm FastConnect 6900 (WCN6856)",
        driver_binding: "ath11k_pci",
    },
    WifiDeviceDescriptor {
        vendor_id: PCI_VENDOR_QUALCOMM,
        device_id: 0x1107,
        subvendor_id: 0x17CB,
        subdevice_id: 0x0002,
        generation: WifiGeneration::Wifi7_802_11be,
        mimo: WifiMimoConfig::Mimo2x2,
        max_bandwidth_mhz: 320,
        peak_phy_rate_mbps: 5800,
        bluetooth_integrated: true,
        bluetooth_version: "Bluetooth 5.4",
        commercial_name: "Qualcomm FastConnect 7800 (WCN7850)",
        driver_binding: "ath12k_pci",
    },
];

pub fn lookup_wifi_nic(vendor: u16, device: u16) -> Option<&'static WifiDeviceDescriptor> {
    WIFI_NIC_CATALOG.iter().find(|w| w.vendor_id == vendor && w.device_id == device)
}
