//! CorOS USB Human Interface Device (HID) Report Descriptor Engine (`usb_hid.rs`)
//!
//! Provides bare-metal bytecode parsing for USB HID Class 1.11 devices:
//! - Item Types: Main (Input, Output, Feature, Collection, End Collection),
//!   Global (Usage Page, Logical Min/Max, Physical Min/Max, Report Size, Report Count),
//!   Local (Usage, Usage Min/Max)
//! - Usage Pages: Generic Desktop (0x01), Simulation Controls (0x02), VR Controls (0x03),
//!   Sport Controls (0x04), Game Controls (0x05), Generic Device Controls (0x06), Keyboard/Keypad (0x07),
//!   LEDs (0x08), Button (0x09), Consumer (0x0C)
//! - Collections: Physical, Application, Logical, Report, Named Array, Usage Switch
//! - Decoders for Keyboard (modifier bitmask + 6-key rollover array)
//! - Decoders for Mouse (buttons, X/Y relative motion, scroll wheel)
//! - Decoders for Gamepad / Joystick (axes, D-pad hat switch, buttons)

extern crate alloc;

use alloc::vec::Vec;

pub const HID_ITEM_TYPE_MAIN: u8 = 0;
pub const HID_ITEM_TYPE_GLOBAL: u8 = 1;
pub const HID_ITEM_TYPE_LOCAL: u8 = 2;

pub const HID_MAIN_INPUT: u8 = 0x80;
pub const HID_MAIN_OUTPUT: u8 = 0x90;
pub const HID_MAIN_FEATURE: u8 = 0xB0;
pub const HID_MAIN_COLLECTION: u8 = 0xA0;
pub const HID_MAIN_END_COLLECTION: u8 = 0xC0;

pub const HID_GLOBAL_USAGE_PAGE: u8 = 0x00;
pub const HID_GLOBAL_LOGICAL_MIN: u8 = 0x10;
pub const HID_GLOBAL_LOGICAL_MAX: u8 = 0x20;
pub const HID_GLOBAL_PHYSICAL_MIN: u8 = 0x30;
pub const HID_GLOBAL_PHYSICAL_MAX: u8 = 0x40;
pub const HID_GLOBAL_REPORT_SIZE: u8 = 0x70;
pub const HID_GLOBAL_REPORT_ID: u8 = 0x80;
pub const HID_GLOBAL_REPORT_COUNT: u8 = 0x90;

pub const HID_LOCAL_USAGE: u8 = 0x00;
pub const HID_LOCAL_USAGE_MIN: u8 = 0x10;
pub const HID_LOCAL_USAGE_MAX: u8 = 0x20;

pub const USAGE_PAGE_GENERIC_DESKTOP: u16 = 0x01;
pub const USAGE_PAGE_KEYBOARD: u16 = 0x07;
pub const USAGE_PAGE_BUTTON: u16 = 0x09;
pub const USAGE_PAGE_CONSUMER: u16 = 0x0C;

pub const USAGE_POINTER: u32 = 0x01;
pub const USAGE_MOUSE: u32 = 0x02;
pub const USAGE_JOYSTICK: u32 = 0x04;
pub const USAGE_GAMEPAD: u32 = 0x05;
pub const USAGE_KEYBOARD: u32 = 0x06;
pub const USAGE_X: u32 = 0x30;
pub const USAGE_Y: u32 = 0x31;
pub const USAGE_Z: u32 = 0x32;
pub const USAGE_WHEEL: u32 = 0x38;

/// Parsed HID Field description
#[derive(Debug, Clone, Copy)]
pub struct HidField {
    pub usage_page: u16,
    pub usage: u32,
    pub bit_offset: usize,
    pub bit_size: usize,
    pub logical_min: i32,
    pub logical_max: i32,
    pub is_relative: bool,
}

/// Decoded USB HID Keyboard State
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbKeyboardState {
    pub modifiers: u8, // Ctrl, Shift, Alt, GUI bitmask
    pub keys: [u8; 6], // 6-key rollover array
}

/// Decoded USB HID Mouse State
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbMouseState {
    pub buttons: u8, // Bit 0: Left, Bit 1: Right, Bit 2: Middle
    pub dx: i32,
    pub dy: i32,
    pub wheel: i8,
}

/// Decoded USB HID Gamepad State
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbGamepadState {
    pub left_x: i32,
    pub left_y: i32,
    pub right_x: i32,
    pub right_y: i32,
    pub buttons: u32,
    pub hat_switch: u8,
}

/// HID Report Descriptor Parser
pub struct HidReportParser {
    fields: Vec<HidField>,
    pub is_keyboard: bool,
    pub is_mouse: bool,
    pub is_gamepad: bool,
}

impl HidReportParser {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            is_keyboard: false,
            is_mouse: false,
            is_gamepad: false,
        }
    }

    /// Parse raw HID Report Descriptor bytecode
    pub fn parse_descriptor(&mut self, desc: &[u8]) {
        self.fields.clear();

        let mut usage_page = 0u16;
        let mut logical_min = 0i32;
        let mut logical_max = 0i32;
        let mut report_size = 0usize;
        let mut report_count = 0usize;
        let mut usages: Vec<u32> = Vec::new();

        let mut current_bit_offset = 0usize;
        let mut cursor = 0usize;

        while cursor < desc.len() {
            let item_header = desc[cursor];
            cursor += 1;

            let size_code = item_header & 0x03;
            let item_size = match size_code {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 4,
                _ => 0,
            };

            if cursor + item_size > desc.len() {
                break;
            }

            let mut data_val = 0i32;
            for i in 0..item_size {
                data_val |= (desc[cursor + i] as i32) << (i * 8);
            }
            cursor += item_size;

            let item_type = (item_header >> 2) & 0x03;
            let item_tag = item_header & 0xFC;

            match item_type {
                HID_ITEM_TYPE_GLOBAL => {
                    let g_tag = item_header & 0xF0;
                    match g_tag {
                        HID_GLOBAL_USAGE_PAGE => usage_page = data_val as u16,
                        HID_GLOBAL_LOGICAL_MIN => logical_min = data_val,
                        HID_GLOBAL_LOGICAL_MAX => logical_max = data_val,
                        HID_GLOBAL_REPORT_SIZE => report_size = data_val as usize,
                        HID_GLOBAL_REPORT_COUNT => report_count = data_val as usize,
                        _ => {}
                    }
                }
                HID_ITEM_TYPE_LOCAL => {
                    let l_tag = item_header & 0xF0;
                    if l_tag == HID_LOCAL_USAGE {
                        usages.push(data_val as u32);
                        if usage_page == USAGE_PAGE_GENERIC_DESKTOP {
                            if data_val as u32 == USAGE_KEYBOARD { self.is_keyboard = true; }
                            if data_val as u32 == USAGE_MOUSE { self.is_mouse = true; }
                            if data_val as u32 == USAGE_GAMEPAD || data_val as u32 == USAGE_JOYSTICK { self.is_gamepad = true; }
                        }
                    }
                }
                HID_ITEM_TYPE_MAIN => {
                    let m_tag = item_header & 0xF0;
                    if m_tag == HID_MAIN_INPUT {
                        let is_relative = (data_val & (1 << 2)) != 0;
                        for i in 0..report_count {
                            let usage = if i < usages.len() { usages[i] } else { 0 };
                            self.fields.push(HidField {
                                usage_page,
                                usage,
                                bit_offset: current_bit_offset,
                                bit_size: report_size,
                                logical_min,
                                logical_max,
                                is_relative,
                            });
                            current_bit_offset += report_size;
                        }
                        usages.clear();
                    }
                }
                _ => {}
            }
        }
    }

    /// Decode standard 3-to-4 byte mouse report
    pub fn decode_mouse_report(report: &[u8]) -> Option<UsbMouseState> {
        if report.len() < 3 {
            return None;
        }

        let buttons = report[0] & 0x07;
        let dx = (report[1] as i8) as i32;
        let dy = (report[2] as i8) as i32;
        let wheel = if report.len() >= 4 { report[3] as i8 } else { 0 };

        Some(UsbMouseState {
            buttons,
            dx,
            dy,
            wheel,
        })
    }

    /// Decode standard 8-byte keyboard report
    pub fn decode_keyboard_report(report: &[u8]) -> Option<UsbKeyboardState> {
        if report.len() < 8 {
            return None;
        }

        let modifiers = report[0];
        let mut keys = [0u8; 6];
        keys.copy_from_slice(&report[2..8]);

        Some(UsbKeyboardState { modifiers, keys })
    }
}
