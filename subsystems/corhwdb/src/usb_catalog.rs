//! USB Vendor, Product, Device Class & Quirks Database.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

pub const USB_CLASS_PER_INTERFACE: u8 = 0x00;
pub const USB_CLASS_AUDIO: u8 = 0x01;
pub const USB_CLASS_COMM: u8 = 0x02;
pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_CLASS_PHYSICAL: u8 = 0x05;
pub const USB_CLASS_IMAGE: u8 = 0x06;
pub const USB_CLASS_PRINTER: u8 = 0x07;
pub const USB_CLASS_MASS_STORAGE: u8 = 0x08;
pub const USB_CLASS_HUB: u8 = 0x09;
pub const USB_CLASS_CDC_DATA: u8 = 0x0A;
pub const USB_CLASS_SMART_CARD: u8 = 0x0B;
pub const USB_CLASS_VIDEO: u8 = 0x0E;
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
pub const USB_CLASS_MISC: u8 = 0xEF;

/// Standard USB Device Speed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbSpeedGrade {
    LowSpeed1_5Mbps,
    FullSpeed12Mbps,
    HighSpeed480Mbps,
    SuperSpeed5Gbps,
    SuperSpeedPlus10Gbps,
    SuperSpeedPlus20Gbps,
    Usb4_40Gbps,
}

/// USB Peripheral Record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbDeviceRecord {
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub speed: UsbSpeedGrade,
    pub manufacturer: &'static str,
    pub product: &'static str,
}

/// Curated authentic table of well-known USB devices.
pub static USB_DEVICE_CATALOG: &[UsbDeviceRecord] = &[
    // --- Logitech (0x046D) Keyboards, Mice, Webcams, Headsets ---
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0xC077,
        bcd_device: 0x7200,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::LowSpeed1_5Mbps,
        manufacturer: "Logitech",
        product: "Logitech Optical USB Mouse M100/B100",
    },
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0xC31C,
        bcd_device: 0x6400,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::LowSpeed1_5Mbps,
        manufacturer: "Logitech",
        product: "Logitech USB Keyboard K120",
    },
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0xC52B,
        bcd_device: 0x2401,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Logitech",
        product: "Logitech Unifying USB Receiver",
    },
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0xC547,
        bcd_device: 0x0100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Logitech",
        product: "Logitech Bolt Wireless USB Receiver",
    },
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0x0825,
        bcd_device: 0x0010,
        device_class: USB_CLASS_MISC,
        device_subclass: 0x02,
        speed: UsbSpeedGrade::HighSpeed480Mbps,
        manufacturer: "Logitech",
        product: "Logitech HD Webcam C270 (UVC 1.0)",
    },
    UsbDeviceRecord {
        vendor_id: 0x046D,
        product_id: 0x082D,
        bcd_device: 0x0011,
        device_class: USB_CLASS_MISC,
        device_subclass: 0x02,
        speed: UsbSpeedGrade::HighSpeed480Mbps,
        manufacturer: "Logitech",
        product: "Logitech HD Pro Webcam C920 (1080p H.264/UVC)",
    },

    // --- Sony Interactive Entertainment (0x054C) DualShock & DualSense ---
    UsbDeviceRecord {
        vendor_id: 0x054C,
        product_id: 0x05C4,
        bcd_device: 0x0100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Sony Interactive Entertainment",
        product: "Wireless Controller (DUALSHOCK 4 CUH-ZCT1E)",
    },
    UsbDeviceRecord {
        vendor_id: 0x054C,
        product_id: 0x0CE6,
        bcd_device: 0x0100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Sony Interactive Entertainment",
        product: "DualSense Wireless Controller (PlayStation 5)",
    },

    // --- Microsoft Corporation (0x045E) Xbox Controllers & Surface Accessories ---
    UsbDeviceRecord {
        vendor_id: 0x045E,
        product_id: 0x02EA,
        bcd_device: 0x0301,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Microsoft Corporation",
        product: "Xbox One S Controller Model 1708",
    },
    UsbDeviceRecord {
        vendor_id: 0x045E,
        product_id: 0x0B12,
        bcd_device: 0x0515,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::FullSpeed12Mbps,
        manufacturer: "Microsoft Corporation",
        product: "Xbox Series X|S Wireless Controller Model 1914",
    },

    // --- Realtek USB Ethernet Dongles (RTL8153, RTL8156) ---
    UsbDeviceRecord {
        vendor_id: 0x0BDA,
        product_id: 0x8153,
        bcd_device: 0x3000,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::SuperSpeed5Gbps,
        manufacturer: "Realtek Semiconductor Corp.",
        product: "Realtek USB 10/100/1000 LAN RTL8153",
    },
    UsbDeviceRecord {
        vendor_id: 0x0BDA,
        product_id: 0x8156,
        bcd_device: 0x3100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::SuperSpeed5Gbps,
        manufacturer: "Realtek Semiconductor Corp.",
        product: "Realtek USB 2.5GbE LAN RTL8156B",
    },

    // --- SanDisk, Kingston & Samsung USB Flash Drives ---
    UsbDeviceRecord {
        vendor_id: 0x0781,
        product_id: 0x5583,
        bcd_device: 0x0100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::SuperSpeed5Gbps,
        manufacturer: "SanDisk Corp.",
        product: "SanDisk Ultra USB 3.0 Flash Drive",
    },
    UsbDeviceRecord {
        vendor_id: 0x0951,
        product_id: 0x1666,
        bcd_device: 0x0001,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::SuperSpeed5Gbps,
        manufacturer: "Kingston Technology",
        product: "Kingston DataTraveler 100 G3 / 3.0",
    },
    UsbDeviceRecord {
        vendor_id: 0x04E8,
        product_id: 0x61F5,
        bcd_device: 0x0100,
        device_class: USB_CLASS_PER_INTERFACE,
        device_subclass: 0x00,
        speed: UsbSpeedGrade::SuperSpeedPlus10Gbps,
        manufacturer: "Samsung Electronics Co., Ltd.",
        product: "Samsung Portable SSD T7 USB 3.2 Gen 2 (1050 MB/s)",
    },
];

/// Looks up a USB device by VID and PID.
pub fn lookup_usb_device(vid: u16, pid: u16) -> Option<&'static UsbDeviceRecord> {
    USB_DEVICE_CATALOG
        .iter()
        .find(|d| d.vendor_id == vid && d.product_id == pid)
}
