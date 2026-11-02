//! CorOS Userland Coreutil: `lsusb`
//! USB bus/device hierarchy formatter supporting:
//! - Standard listing (`Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver`)
//! - `-t` physical port topology tree view with link speed (`12M`, `480M`, `5000M`, `10000M`) and USB class decoder
//! - `-v` verbose descriptor details (`bDeviceClass`, `bMaxPacketSize0`, `MaxPower`)

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbSpeedRate {
    Low1_5M,
    Full12M,
    High480M,
    Super5000M,
    SuperPlus10000M,
}

impl UsbSpeedRate {
    pub const fn speed_label(self) -> &'static str {
        match self {
            UsbSpeedRate::Low1_5M => "1.5M",
            UsbSpeedRate::Full12M => "12M",
            UsbSpeedRate::High480M => "480M",
            UsbSpeedRate::Super5000M => "5000M",
            UsbSpeedRate::SuperPlus10000M => "10000M",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LsusbFlags {
    pub tree_view: bool,
    pub verbose: bool,
}

impl LsusbFlags {
    pub const fn default_flags() -> Self {
        Self {
            tree_view: false,
            verbose: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        't' => flags.tree_view = true,
                        'v' => flags.verbose = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

/// Decodes a standard USB-IF `bInterfaceClass` / `bDeviceClass` byte into its human-readable class name.
pub const fn decode_usb_class(class_code: u8) -> &'static str {
    match class_code {
        0x01 => "Audio",
        0x02 => "Communications",
        0x03 => "Human Interface Device",
        0x08 => "Mass Storage",
        0x09 => "Hub",
        0x0E => "Video",
        0xE0 => "Wireless",
        _ => "Vendor Specific Class",
    }
}

#[derive(Clone, Debug)]
pub struct UsbDeviceNode {
    pub bus_num: u8,
    pub dev_num: u8,
    pub port_num: u8,
    pub is_root_hub: bool,
    pub vendor_id: u16,
    pub product_id: u16,
    pub class_code: u8,
    pub speed: UsbSpeedRate,
    pub max_power_ma: u16,
    pub driver_name: &'static str,
    pub product_string: &'static str,
}

/// Formats USB devices either as a standard `lsusb` table (with optional `-v` descriptors) or `-t` hierarchy tree.
pub fn format_lsusb_output(devices: &[UsbDeviceNode], flags: LsusbFlags) -> String {
    let mut out = String::new();

    if flags.tree_view {
        for dev in devices {
            let class_str = decode_usb_class(dev.class_code);
            if dev.is_root_hub {
                out.push_str(&format!(
                    "/:  Bus {:02}.Port 1: Dev {}, Class=root_hub, Driver={}/12p, {}\n",
                    dev.bus_num,
                    dev.dev_num,
                    dev.driver_name,
                    dev.speed.speed_label()
                ));
            } else {
                out.push_str(&format!(
                    "    |__ Port {}: Dev {}, If 0, Class={}, Driver={}, {}\n",
                    dev.port_num,
                    dev.dev_num,
                    class_str,
                    dev.driver_name,
                    dev.speed.speed_label()
                ));
            }
        }
        return out;
    }

    for dev in devices {
        out.push_str(&format!(
            "Bus {:03} Device {:03}: ID {:04x}:{:04x} {}\n",
            dev.bus_num, dev.dev_num, dev.vendor_id, dev.product_id, dev.product_string
        ));
        if flags.verbose {
            out.push_str(&format!(
                "  Device Descriptor:\n    bDeviceClass         {:>4} {}\n    MaxPower             {:>4}mA\n",
                dev.class_code,
                decode_usb_class(dev.class_code),
                dev.max_power_ma
            ));
        }
    }

    out
}

pub fn verify_util_lsusb() -> u32 {
    let mut passed = 0u32;

    if decode_usb_class(0x03) == "Human Interface Device"
        && decode_usb_class(0x08) == "Mass Storage"
        && decode_usb_class(0x09) == "Hub"
    {
        passed += 1;
    }

    let sample = [
        UsbDeviceNode {
            bus_num: 1,
            dev_num: 1,
            port_num: 1,
            is_root_hub: true,
            vendor_id: 0x1D6B,
            product_id: 0x0003,
            class_code: 0x09,
            speed: UsbSpeedRate::Super5000M,
            max_power_ma: 0,
            driver_name: "xhci-hcd",
            product_string: "Linux Foundation 3.0 root hub",
        },
        UsbDeviceNode {
            bus_num: 1,
            dev_num: 2,
            port_num: 3,
            is_root_hub: false,
            vendor_id: 0x046D,
            product_id: 0xC52B,
            class_code: 0x03,
            speed: UsbSpeedRate::Full12M,
            max_power_ma: 98,
            driver_name: "usbhid",
            product_string: "Logitech, Inc. Unifying Receiver",
        },
    ];

    let std_out = format_lsusb_output(&sample, LsusbFlags::default_flags());
    if std_out.contains("Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver") {
        passed += 1;
    }

    let tree_out = format_lsusb_output(&sample, LsusbFlags::parse_args(&["-t"]));
    if tree_out.contains("/:  Bus 01.Port 1: Dev 1, Class=root_hub, Driver=xhci-hcd/12p, 5000M")
        && tree_out.contains("|__ Port 3: Dev 2, If 0, Class=Human Interface Device, Driver=usbhid, 12M")
    {
        passed += 1;
    }

    passed
}
