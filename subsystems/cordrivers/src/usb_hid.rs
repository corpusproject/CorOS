//! CorOS Hardware Driver Module: `usb_hid`
//!
//! USB Standard Descriptors (`Device`, `Configuration`, `Interface`, `Endpoint`),
//! USB Human Interface Device (`HID`) Descriptor, stateful HID Report Descriptor
//! item parser (`UsagePage`, `Usage`, `LogicalMinimum`, `LogicalMaximum`,
//! `ReportSize`, `ReportCount`, `Input`, `Output`, `Feature`), and Boot Protocol
//! 8-byte Keyboard & 4-byte Wheel Mouse packet decoders.

use alloc::vec::Vec;

/// Standard USB Descriptor Type codes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbDescriptorType {
    Device = 0x01,
    Configuration = 0x02,
    String = 0x03,
    Interface = 0x04,
    Endpoint = 0x05,
    Hid = 0x21,
    HidReport = 0x22,
    HidPhysical = 0x23,
}

/// 8-byte USB Control Setup Packet (`bmRequestType`, `bRequest`, `wValue`, `wIndex`, `wLength`).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbSetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl UsbSetupPacket {
    /// Builds a `GET_DESCRIPTOR` (`0x06`) setup packet.
    #[inline]
    pub const fn get_descriptor(desc_type: UsbDescriptorType, desc_index: u8, length: u16) -> Self {
        Self {
            bm_request_type: 0x80, // Device-to-Host, Standard, Device
            b_request: 0x06,
            w_value: ((desc_type as u16) << 8) | (desc_index as u16),
            w_index: 0,
            w_length: length,
        }
    }

    /// Builds a HID class `SET_PROTOCOL` (`0x0B`) request (`0 = Boot Protocol`, `1 = Report Protocol`).
    #[inline]
    pub const fn hid_set_protocol(interface_number: u16, report_protocol: bool) -> Self {
        Self {
            bm_request_type: 0x21, // Host-to-Device, Class, Interface
            b_request: 0x0B,
            w_value: if report_protocol { 1 } else { 0 },
            w_index: interface_number,
            w_length: 0,
        }
    }

    /// Builds a HID class `SET_IDLE` (`0x0A`) request.
    #[inline]
    pub const fn hid_set_idle(interface_number: u16, duration_4ms: u8, report_id: u8) -> Self {
        Self {
            bm_request_type: 0x21,
            b_request: 0x0A,
            w_value: ((duration_4ms as u16) << 8) | (report_id as u16),
            w_index: interface_number,
            w_length: 0,
        }
    }
}

/// 18-byte USB Standard Device Descriptor.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbDeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub bcd_usb: u16,
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

/// Decoded field from a USB HID Report Descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidReportField {
    pub usage_page: u16,
    pub usage: u16,
    pub logical_min: i32,
    pub logical_max: i32,
    pub report_size_bits: u16,
    pub report_count: u16,
    pub is_relative: bool,
    pub is_variable: bool,
}

/// Parses a binary USB HID Report Descriptor stream into a sequence of `HidReportField` Input items.
pub fn parse_hid_report_descriptor(report_desc: &[u8]) -> Vec<HidReportField> {
    let mut fields = Vec::new();
    let mut usage_page: u16 = 0;
    let mut current_usage: u16 = 0;
    let mut logical_min: i32 = 0;
    let mut logical_max: i32 = 0;
    let mut report_size_bits: u16 = 0;
    let mut report_count: u16 = 0;

    let mut idx = 0usize;
    while idx < report_desc.len() {
        let prefix = report_desc[idx];
        idx += 1;
        if prefix == 0xFE {
            // Long item: skip data_size + long_item_tag
            if idx + 2 <= report_desc.len() {
                let data_len = report_desc[idx] as usize;
                idx = (idx + 2 + data_len).min(report_desc.len());
            } else {
                break;
            }
            continue;
        }

        let b_size_code = prefix & 0x03;
        let data_len: usize = match b_size_code {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if idx + data_len > report_desc.len() {
            break;
        }

        let tag_and_type = prefix & 0xFC;
        let unsigned_val: u32 = match data_len {
            0 => 0,
            1 => report_desc[idx] as u32,
            2 => u16::from_le_bytes([report_desc[idx], report_desc[idx + 1]]) as u32,
            _ => u32::from_le_bytes([
                report_desc[idx],
                report_desc[idx + 1],
                report_desc[idx + 2],
                report_desc[idx + 3],
            ]),
        };
        let signed_val: i32 = match data_len {
            0 => 0,
            1 => (report_desc[idx] as i8) as i32,
            2 => (i16::from_le_bytes([report_desc[idx], report_desc[idx + 1]])) as i32,
            _ => unsigned_val as i32,
        };
        idx += data_len;

        match tag_and_type {
            0x04 => usage_page = unsigned_val as u16,      // Global: Usage Page
            0x14 => logical_min = signed_val,              // Global: Logical Minimum
            0x24 => logical_max = signed_val,              // Global: Logical Maximum
            0x74 => report_size_bits = unsigned_val as u16,// Global: Report Size
            0x94 => report_count = unsigned_val as u16,    // Global: Report Count
            0x08 => current_usage = unsigned_val as u16,   // Local: Usage
            0x80 => {
                // Main: Input item
                let is_constant = (unsigned_val & 0x01) != 0;
                if !is_constant {
                    fields.push(HidReportField {
                        usage_page,
                        usage: current_usage,
                        logical_min,
                        logical_max,
                        report_size_bits,
                        report_count,
                        is_variable: (unsigned_val & 0x02) != 0,
                        is_relative: (unsigned_val & 0x04) != 0,
                    });
                }
            }
            _ => {}
        }
    }

    fields
}

/// Decoded USB Boot Protocol Keyboard 8-byte report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbBootKeyboardEvent {
    pub left_ctrl: bool,
    pub left_shift: bool,
    pub left_alt: bool,
    pub left_gui: bool,
    pub right_ctrl: bool,
    pub right_shift: bool,
    pub right_alt: bool,
    pub right_gui: bool,
    pub active_keycodes: [u8; 6],
    pub ascii_primary: Option<u8>,
}

impl UsbBootKeyboardEvent {
    /// Decodes an 8-byte USB Boot Keyboard packet (`[modifiers, reserved, key0..key5]`).
    pub const fn decode(packet: &[u8; 8]) -> Self {
        let mods = packet[0];
        let shift = (mods & 0x22) != 0;
        let first_code = packet[2];
        let ascii = hid_usage_to_ascii(first_code, shift);
        Self {
            left_ctrl: (mods & (1 << 0)) != 0,
            left_shift: (mods & (1 << 1)) != 0,
            left_alt: (mods & (1 << 2)) != 0,
            left_gui: (mods & (1 << 3)) != 0,
            right_ctrl: (mods & (1 << 4)) != 0,
            right_shift: (mods & (1 << 5)) != 0,
            right_alt: (mods & (1 << 6)) != 0,
            right_gui: (mods & (1 << 7)) != 0,
            active_keycodes: [
                packet[2], packet[3], packet[4], packet[5], packet[6], packet[7],
            ],
            ascii_primary: ascii,
        }
    }
}

/// Translates USB HID Keyboard Usage Page (`0x07`) keycodes (`0x04..0x38`) to ASCII.
pub const fn hid_usage_to_ascii(usage: u8, shift: bool) -> Option<u8> {
    match usage {
        0x04..=0x1D => {
            let base = if shift { b'A' } else { b'a' };
            Some(base + (usage - 0x04))
        }
        0x1E..=0x26 => {
            if !shift {
                Some(b'1' + (usage - 0x1E))
            } else {
                const SHIFTED_DIGITS: [u8; 9] = [b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'('];
                Some(SHIFTED_DIGITS[(usage - 0x1E) as usize])
            }
        }
        0x27 => Some(if shift { b')' } else { b'0' }),
        0x28 => Some(b'\n'),
        0x2C => Some(b' '),
        _ => None,
    }
}

/// Decoded USB Boot Protocol / 4-byte Wheel Mouse packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbMouseEvent {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub delta_x: i8,
    pub delta_y: i8,
    pub wheel_delta: i8,
}

impl UsbMouseEvent {
    #[inline]
    pub const fn decode_boot_or_wheel(packet: &[u8]) -> Option<Self> {
        if packet.len() < 3 {
            return None;
        }
        let buttons = packet[0];
        let wheel = if packet.len() >= 4 {
            packet[3] as i8
        } else {
            0
        };
        Some(Self {
            left_button: (buttons & 0x01) != 0,
            right_button: (buttons & 0x02) != 0,
            middle_button: (buttons & 0x04) != 0,
            delta_x: packet[1] as i8,
            delta_y: packet[2] as i8,
            wheel_delta: wheel,
        })
    }
}

/// Self-test for `usb_hid` report descriptor parser, keyboard usage translation, and mouse decoding.
pub fn verify_driver_module_usb_hid() -> u32 {
    let mut passed = 0u32;

    // 1. Verify USB Device Descriptor size (18 bytes) and Setup Packet (8 bytes)
    if core::mem::size_of::<UsbDeviceDescriptor>() == 18
        && core::mem::size_of::<UsbSetupPacket>() == 8
    {
        passed += 1;
    }

    // 2. Verify HID Report Descriptor parser on a standard Mouse X/Y relative report snippet
    let mouse_report_desc: [u8; 20] = [
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x02, // Usage (Mouse)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x30, //   Usage (X)
        0x09, 0x31, //   Usage (Y)
        0x15, 0x81, //   Logical Minimum (-127)
        0x25, 0x7F, //   Logical Maximum (127)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x02, //   Report Count (2)
        0x81, 0x06, //   Input (Data, Variable, Relative)
    ];
    let fields = parse_hid_report_descriptor(&mouse_report_desc);
    if fields.len() == 1
        && fields[0].usage_page == 0x01
        && fields[0].logical_min == -127
        && fields[0].logical_max == 127
        && fields[0].report_size_bits == 8
        && fields[0].report_count == 2
        && fields[0].is_relative
    {
        passed += 1;
    }

    // 3. Verify Boot Keyboard packet decoding (Left Shift + 'c' -> 'C')
    let kbd_pkt: [u8; 8] = [0x02, 0x00, 0x06, 0, 0, 0, 0, 0];
    let kbd = UsbBootKeyboardEvent::decode(&kbd_pkt);
    if kbd.left_shift && kbd.ascii_primary == Some(b'C') {
        passed += 1;
    }

    // 4. Verify 4-byte Wheel Mouse packet decoding
    let mouse_pkt: [u8; 4] = [0x05, (-12i8) as u8, 25u8, (-1i8) as u8];
    if let Some(m) = UsbMouseEvent::decode_boot_or_wheel(&mouse_pkt) {
        if m.left_button && m.middle_button && m.delta_x == -12 && m.delta_y == 25 && m.wheel_delta == -1 {
            passed += 1;
        }
    }

    passed
}
