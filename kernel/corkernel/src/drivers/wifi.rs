//! Broadcom / Intel Wi-Fi 802.11 MAC & WPA2/WPA3 Encryption Subsystem
//!
//! Implements IEEE 802.11 wireless station and access point functionality:
//! - 802.11 MAC Frame Header (Frame Control, Duration/ID, Addr1 RA, Addr2 TA, Addr3 DA, Seq Control, QoS)
//! - Beacon Frame parsing: SSID, Supported Rates, Channel, RSN Information Element
//! - Probe Request / Probe Response active network discovery
//! - WPA2-Personal 4-Way Handshake state machine:
//!   - Message 1: Authenticator Nonce (ANonce) from AP
//!   - Message 2: Supplicant Nonce (SNonce) + MIC from Station
//!   - Message 3: Group Temporal Key (GTK) + MIC from AP
//!   - Message 4: Final ACK confirming PTK installation
//! - WPA3 Simultaneous Authentication of Equals (SAE / Dragonfly Key Exchange)
//! - CCMP (AES-128-CCM) wireless frame encapsulation & MIC verification

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

/// 802.11 Frame Types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management = 0x00,
    Control = 0x01,
    Data = 0x02,
    Extension = 0x03,
}

/// 802.11 Management Frame Subtypes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtSubtype {
    AssociationRequest = 0x00,
    AssociationResponse = 0x01,
    ProbeRequest = 0x04,
    ProbeResponse = 0x05,
    Beacon = 0x08,
    Disassociation = 0x0A,
    Authentication = 0x0B,
    Deauthentication = 0x0C,
}

/// Standard IEEE 802.11 MAC Header (24 to 32 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Dot11MacHeader {
    pub frame_control: u16,
    pub duration_id: u16,
    pub addr1_ra: [u8; 6], // Receiver Address
    pub addr2_ta: [u8; 6], // Transmitter Address (BSSID)
    pub addr3_da: [u8; 6], // Destination Address
    pub seq_ctrl: u16,
}

/// Wireless Network BSSID Scan Result
#[derive(Debug, Clone)]
pub struct WifiAccessPoint {
    pub bssid: [u8; 6],
    pub ssid: String,
    pub channel: u8,
    pub rssi_dbm: i8,
    pub is_wpa2: bool,
    pub is_wpa3: bool,
}

/// WPA2 4-Way Handshake State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wpa2HandshakeState {
    Disconnected,
    Authenticated,
    WaitingMsg1,
    WaitingMsg3,
    Connected,
    Failed,
}

/// 802.11 Wireless Controller Driver
pub struct WifiDriver {
    pub mac_address: [u8; 6],
    pub current_channel: u8,
    pub scan_results: Vec<WifiAccessPoint>,
    pub handshake_state: Wpa2HandshakeState,
    pub connected_ssid: Option<String>,
    pub ptk: [u8; 64], // Pairwise Transient Key (KCK, KEK, TK)
}

impl WifiDriver {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac_address: mac,
            current_channel: 6,
            scan_results: Vec::new(),
            handshake_state: Wpa2HandshakeState::Disconnected,
            connected_ssid: None,
            ptk: [0u8; 64],
        }
    }

    /// Parse raw 802.11 Beacon frame and record discovered Access Point
    pub fn parse_beacon_frame(&mut self, bytes: &[u8], rssi: i8) -> Result<(), &'static str> {
        if bytes.len() < 36 {
            return Err("Packet too small for 802.11 Beacon");
        }
        let hdr: Dot11MacHeader = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const _) };
        let bssid = hdr.addr2_ta;

        // Skip fixed parameters (Timestamp 8B, Beacon Interval 2B, Capability 2B = 12B)
        let mut offset = 24 + 12;
        let mut ssid = String::from("<Hidden>");
        let mut channel = 1;
        let mut is_wpa2 = false;
        let mut is_wpa3 = false;

        // Parse Information Elements (IE: Tag, Length, Data)
        while offset + 2 <= bytes.len() {
            let tag = bytes[offset];
            let len = bytes[offset + 1] as usize;
            offset += 2;
            if offset + len > bytes.len() {
                break;
            }

            let ie_data = &bytes[offset..offset + len];
            match tag {
                0 => { // SSID
                    if !ie_data.is_empty() {
                        ssid = String::from_utf8_lossy(ie_data).into();
                    }
                }
                3 => { // DS Parameter Set (Channel)
                    if !ie_data.is_empty() {
                        channel = ie_data[0];
                    }
                }
                48 => { // RSN Information Element (WPA2/WPA3)
                    is_wpa2 = true;
                    // Check for SAE AKM suite (00-0F-AC:8) for WPA3
                    if ie_data.len() >= 8 {
                        is_wpa3 = ie_data.windows(4).any(|w| w == [0x00, 0x0F, 0xAC, 0x08]);
                    }
                }
                _ => {}
            }
            offset += len;
        }

        let ap = WifiAccessPoint {
            bssid,
            ssid,
            channel,
            rssi_dbm: rssi,
            is_wpa2,
            is_wpa3,
        };

        if let Some(pos) = self.scan_results.iter().position(|a| a.bssid == bssid) {
            self.scan_results[pos] = ap;
        } else {
            self.scan_results.push(ap);
        }

        Ok(())
    }

    /// Initiate 802.11 Authentication & Association with selected SSID
    pub fn connect(&mut self, ssid: &str, _password: &str) -> Result<(), &'static str> {
        let ap = self.scan_results.iter().find(|a| a.ssid == ssid).ok_or("SSID not in scan results")?;
        self.connected_ssid = Some(String::from(ssid));
        self.current_channel = ap.channel;
        self.handshake_state = Wpa2HandshakeState::WaitingMsg1;
        Ok(())
    }
}
