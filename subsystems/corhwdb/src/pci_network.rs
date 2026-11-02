//! Realtek, Broadcom, Qualcomm, MediaTek & Marvell Network Hardware Registry.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

use alloc::vec::Vec;

pub const PCI_VENDOR_REALTEK: u16 = 0x10EC;
pub const PCI_VENDOR_BROADCOM: u16 = 0x14E4;
pub const PCI_VENDOR_QUALCOMM_ATHEROS: u16 = 0x168C;
pub const PCI_VENDOR_QUALCOMM: u16 = 0x17CB;
pub const PCI_VENDOR_MEDIATEK: u16 = 0x14C3;
pub const PCI_VENDOR_MARVELL: u16 = 0x11AB;
pub const PCI_VENDOR_AQUANTIA: u16 = 0x1D6A;

/// Network Controller Medium Type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkPhyMedium {
    Ethernet100BaseTx,
    Ethernet1000BaseT,
    Ethernet2500BaseT,
    Ethernet5000BaseT,
    Ethernet10GBaseT,
    Ethernet25GBaseR,
    Wifi4_80211n,
    Wifi5_80211ac,
    Wifi6_80211ax,
    Wifi7_80211be,
}

/// Network Driver Descriptor Entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkDeviceEntry {
    pub vendor_id: u16,
    pub device_id: u16,
    pub medium: NetworkPhyMedium,
    pub default_rx_ring_size: u16,
    pub default_tx_ring_size: u16,
    pub max_mtu_bytes: u16,
    pub hardware_tso_support: bool,
    pub hardware_csum_support: bool,
    pub chip_name: &'static str,
    pub commercial_name: &'static str,
}

/// Realtek, Broadcom, Qualcomm, MediaTek Network Card Catalog.
pub static NETWORK_HARDWARE_CATALOG: &[NetworkDeviceEntry] = &[
    // --- Realtek Semiconductor (RTL8111, RTL8168, RTL8125, RTL8126) ---
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0x8168,
        medium: NetworkPhyMedium::Ethernet1000BaseT,
        default_rx_ring_size: 256,
        default_tx_ring_size: 256,
        max_mtu_bytes: 9000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "RTL8168/8111",
        commercial_name: "Realtek RTL8111/8168/8411 PCI Express Gigabit Ethernet",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0x8125,
        medium: NetworkPhyMedium::Ethernet2500BaseT,
        default_rx_ring_size: 1024,
        default_tx_ring_size: 1024,
        max_mtu_bytes: 9000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "RTL8125B",
        commercial_name: "Realtek RTL8125 2.5GbE Gaming Ethernet Controller",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0x8126,
        medium: NetworkPhyMedium::Ethernet5000BaseT,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 16000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "RTL8126",
        commercial_name: "Realtek RTL8126 5GbE PCIe Network Connection",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0xC821,
        medium: NetworkPhyMedium::Wifi5_80211ac,
        default_rx_ring_size: 512,
        default_tx_ring_size: 512,
        max_mtu_bytes: 1500,
        hardware_tso_support: false,
        hardware_csum_support: true,
        chip_name: "RTL8821CE",
        commercial_name: "Realtek RTL8821CE 802.11ac PCIe Wireless Network Adapter",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0xC822,
        medium: NetworkPhyMedium::Wifi5_80211ac,
        default_rx_ring_size: 512,
        default_tx_ring_size: 512,
        max_mtu_bytes: 1500,
        hardware_tso_support: false,
        hardware_csum_support: true,
        chip_name: "RTL8822CE",
        commercial_name: "Realtek RTL8822CE 802.11ac 2x2 Wi-Fi + Bluetooth M.2",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_REALTEK,
        device_id: 0x8852,
        medium: NetworkPhyMedium::Wifi6_80211ax,
        default_rx_ring_size: 1024,
        default_tx_ring_size: 1024,
        max_mtu_bytes: 1500,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "RTL8852AE",
        commercial_name: "Realtek Wi-Fi 6 8852AE PCIe Adapter",
    },

    // --- Broadcom Corporation (BCM57xx, BCM43xx, NetXtreme) ---
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_BROADCOM,
        device_id: 0x165F,
        medium: NetworkPhyMedium::Ethernet1000BaseT,
        default_rx_ring_size: 512,
        default_tx_ring_size: 512,
        max_mtu_bytes: 9000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "BCM5720",
        commercial_name: "Broadcom NetXtreme BCM5720 Gigabit Ethernet",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_BROADCOM,
        device_id: 0x168E,
        medium: NetworkPhyMedium::Ethernet10GBaseT,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 9600,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "BCM57810S",
        commercial_name: "Broadcom NetXtreme II BCM57810 10 Gigabit Ethernet",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_BROADCOM,
        device_id: 0x43A0,
        medium: NetworkPhyMedium::Wifi5_80211ac,
        default_rx_ring_size: 512,
        default_tx_ring_size: 512,
        max_mtu_bytes: 1500,
        hardware_tso_support: false,
        hardware_csum_support: true,
        chip_name: "BCM4360",
        commercial_name: "Broadcom BCM4360 802.11ac Wireless Network Adapter 3x3",
    },

    // --- Qualcomm / Atheros (AR928x, QCA6174, FastConnect) ---
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_QUALCOMM_ATHEROS,
        device_id: 0x002B,
        medium: NetworkPhyMedium::Wifi4_80211n,
        default_rx_ring_size: 256,
        default_tx_ring_size: 256,
        max_mtu_bytes: 1500,
        hardware_tso_support: false,
        hardware_csum_support: true,
        chip_name: "AR9285",
        commercial_name: "Qualcomm Atheros AR9285 Wireless Network Adapter",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_QUALCOMM_ATHEROS,
        device_id: 0x003E,
        medium: NetworkPhyMedium::Wifi5_80211ac,
        default_rx_ring_size: 512,
        default_tx_ring_size: 512,
        max_mtu_bytes: 1500,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "QCA6174",
        commercial_name: "Qualcomm Atheros QCA6174 802.11ac Wireless Adapter",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_QUALCOMM,
        device_id: 0x1107,
        medium: NetworkPhyMedium::Wifi7_80211be,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 2304,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "WCN7850",
        commercial_name: "Qualcomm FastConnect 7800 Wi-Fi 7 High Band Simultaneous MLO",
    },

    // --- MediaTek (MT7921, MT7922, MT7925) ---
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x7961,
        medium: NetworkPhyMedium::Wifi6_80211ax,
        default_rx_ring_size: 1024,
        default_tx_ring_size: 1024,
        max_mtu_bytes: 1500,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "MT7921",
        commercial_name: "MediaTek MT7921 Wi-Fi 6 80MHz Wireless LAN Card",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x0616,
        medium: NetworkPhyMedium::Wifi6_80211ax,
        default_rx_ring_size: 1024,
        default_tx_ring_size: 1024,
        max_mtu_bytes: 1500,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "MT7922",
        commercial_name: "MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz Wireless LAN Card",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_MEDIATEK,
        device_id: 0x7925,
        medium: NetworkPhyMedium::Wifi7_80211be,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 2304,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "MT7925",
        commercial_name: "MediaTek Wi-Fi 7 MT7925 Wireless LAN Card",
    },

    // --- Aquantia / Marvell Multi-Gigabit (AQC107 10GbE, AQC113 10GbE) ---
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_AQUANTIA,
        device_id: 0x07B1,
        medium: NetworkPhyMedium::Ethernet10GBaseT,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 16000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "AQC107",
        commercial_name: "Aquantia AQtion AQC107 10GbE Multi-Gigabit Ethernet NIC",
    },
    NetworkDeviceEntry {
        vendor_id: PCI_VENDOR_AQUANTIA,
        device_id: 0x04C0,
        medium: NetworkPhyMedium::Ethernet10GBaseT,
        default_rx_ring_size: 2048,
        default_tx_ring_size: 2048,
        max_mtu_bytes: 16000,
        hardware_tso_support: true,
        hardware_csum_support: true,
        chip_name: "AQC113",
        commercial_name: "Marvell Aquantia AQC113CS 10GbE Network Adapter",
    },
];

/// Looks up a network card by vendor and device ID.
pub fn lookup_network_device(vendor_id: u16, device_id: u16) -> Option<&'static NetworkDeviceEntry> {
    NETWORK_HARDWARE_CATALOG
        .iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
}

/// Lists all Wi-Fi adapters in the registry.
pub fn list_wifi_adapters() -> Vec<&'static NetworkDeviceEntry> {
    NETWORK_HARDWARE_CATALOG
        .iter()
        .filter(|d| match d.medium {
            NetworkPhyMedium::Wifi4_80211n
            | NetworkPhyMedium::Wifi5_80211ac
            | NetworkPhyMedium::Wifi6_80211ax
            | NetworkPhyMedium::Wifi7_80211be => true,
            _ => false,
        })
        .collect()
}
