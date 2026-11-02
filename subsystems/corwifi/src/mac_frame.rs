//! IEEE 802.11 MAC Frame Structure, Frame Control & Information Elements (IE).
//! Pure `#![no_std]` Rust wireless registry without numbered repetition.

use alloc::vec::Vec;

/// 802.11 Frame Type (2 bits in Frame Control).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiFrameType {
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3,
}

/// 802.11 Management Subtypes (4 bits).
pub mod mgmt_subtypes {
    pub const ASSOCIATION_REQ: u8 = 0;
    pub const ASSOCIATION_RESP: u8 = 1;
    pub const REASSOCIATION_REQ: u8 = 2;
    pub const REASSOCIATION_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOCIATION: u8 = 10;
    pub const AUTHENTICATION: u8 = 11;
    pub const DEAUTHENTICATION: u8 = 12;
    pub const ACTION: u8 = 13;
}

/// 802.11 Information Element (IE) Element IDs.
pub mod ie_element_ids {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const DSSS_PARAMETER_SET: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY_INFO: u8 = 7;
    pub const BSS_LOAD: u8 = 11;
    pub const HT_CAPABILITIES: u8 = 45;
    pub const RSN_WPA2: u8 = 48;
    pub const EXTENDED_SUPPORTED_RATES: u8 = 50;
    pub const HT_OPERATION: u8 = 61;
    pub const VHT_CAPABILITIES: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const EXTENSION_TAG: u8 = 255;
}

/// 16-bit 802.11 Frame Control Field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: WifiFrameType,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_management: bool,
    pub more_data: bool,
    pub protected_frame: bool,
    pub order: bool,
}

impl FrameControl {
    pub fn parse(raw: u16) -> Self {
        let ftype = match (raw >> 2) & 0x03 {
            0 => WifiFrameType::Management,
            1 => WifiFrameType::Control,
            2 => WifiFrameType::Data,
            _ => WifiFrameType::Extension,
        };
        Self {
            protocol_version: (raw & 0x03) as u8,
            frame_type: ftype,
            subtype: ((raw >> 4) & 0x0F) as u8,
            to_ds: (raw & (1 << 8)) != 0,
            from_ds: (raw & (1 << 9)) != 0,
            more_fragments: (raw & (1 << 10)) != 0,
            retry: (raw & (1 << 11)) != 0,
            power_management: (raw & (1 << 12)) != 0,
            more_data: (raw & (1 << 13)) != 0,
            protected_frame: (raw & (1 << 14)) != 0,
            order: (raw & (1 << 15)) != 0,
        }
    }
}

/// 802.11 Generic Information Element (Tag, Length, Value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InformationElement<'a> {
    pub id: u8,
    pub length: u8,
    pub data: &'a [u8],
}

/// Walks raw byte buffer of 802.11 Information Elements.
pub fn parse_information_elements(raw_payload: &[u8]) -> Vec<InformationElement<'_>> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset + 2 <= raw_payload.len() {
        let id = raw_payload[offset];
        let len = raw_payload[offset + 1] as usize;
        offset += 2;
        if offset + len <= raw_payload.len() {
            elements.push(InformationElement {
                id,
                length: len as u8,
                data: &raw_payload[offset..offset + len],
            });
            offset += len;
        } else {
            break;
        }
    }
    elements
}
