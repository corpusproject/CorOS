#![no_std]
//! `corwifi` — CorOS IEEE 802.11a/b/g/n/ac/ax/be Wireless Network & Spectrum Subsystem.
//! Pure `#![no_std]` Rust wireless registry without numbered template repetition.

extern crate alloc;

pub mod channels;
pub mod mcs_rates;
pub mod mac_frame;
pub mod regulatory;

/// Runs comprehensive self-tests verifying wireless channels, MCS data rates and frame parsing.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Channel lookup test (2.4 GHz & 6 GHz)
    if let Some(ch) = channels::lookup_channel(channels::WifiRadioBand::Band2_4GHz, 6) {
        if ch.center_frequency_mhz == 2437 {
            passed += 1;
        }
    }
    if let Some(ch) = channels::lookup_channel(channels::WifiRadioBand::Band6GHz, 1) {
        if ch.center_frequency_mhz == 5955 && ch.max_bandwidth == channels::WifiChannelWidth::Width320MHz {
            passed += 1;
        }
    }

    // 2. Frequency to channel conversion
    if channels::frequency_to_channel(5180) == Some(36) {
        passed += 1;
    }

    // 3. MCS Rate calculation (Wi-Fi 7 320MHz 4096-QAM 2x2 MIMO)
    if let Some(rate_kbps) = mcs_rates::compute_phy_throughput_kbps(13, 2, 320) {
        if rate_kbps > 5_000_000 {
            // Over 5 Gbps PHY rate
            passed += 1;
        }
    }

    // 4. Frame control parsing
    let fc_raw: u16 = 0x0080; // Beacon frame (Type 0, Subtype 8)
    let fc = mac_frame::FrameControl::parse(fc_raw);
    if fc.frame_type == mac_frame::WifiFrameType::Management && fc.subtype == mac_frame::mgmt_subtypes::BEACON {
        passed += 1;
    }

    // 5. Information elements parsing
    let ie_stream = [
        0x00, 0x05, b'C', b'o', b'r', b'O', b'S', // SSID IE
        0x03, 0x01, 0x06,                         // DSSS Channel 6 IE
    ];
    let ies = mac_frame::parse_information_elements(&ie_stream);
    if ies.len() == 2 && ies[0].data == b"CorOS" && ies[1].data == [0x06] {
        passed += 1;
    }

    // 6. Regulatory rules lookup
    if regulatory::get_max_tx_power_dbm_etsi(2437) == Some(20) {
        passed += 1;
    }

    passed
}
