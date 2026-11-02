//! IEEE 802.11n (HT), 802.11ac (VHT), 802.11ax (HE) & 802.11be (EHT) Modulation & Coding Schemes (MCS).
//! Pure `#![no_std]` Rust wireless registry without numbered repetition.

/// Digital Modulation Constellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiModulation {
    Bpsk,
    Qpsk,
    Qam16,
    Qam64,
    Qam256,
    Qam1024, // Wi-Fi 6 (802.11ax)
    Qam4096, // Wi-Fi 7 (802.11be)
}

/// Coding Rate representation (numerator, denominator).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodingRate(pub u8, pub u8);

/// MCS Table Entry describing physical layer data rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McsRateEntry {
    pub mcs_index: u8,
    pub modulation: WifiModulation,
    pub coding_rate: CodingRate,
    pub rate_20mhz_long_gi_kbps: u32,
    pub rate_20mhz_short_gi_kbps: u32,
    pub rate_40mhz_short_gi_kbps: u32,
    pub rate_80mhz_short_gi_kbps: u32,
    pub rate_160mhz_short_gi_kbps: u32,
    pub rate_320mhz_short_gi_kbps: u32,
}

/// Curated authentic table of 802.11ax / 802.11be MCS definitions (Single Spatial Stream NSS=1).
pub static MCS_RATE_CATALOG_NSS1: &[McsRateEntry] = &[
    McsRateEntry {
        mcs_index: 0,
        modulation: WifiModulation::Bpsk,
        coding_rate: CodingRate(1, 2),
        rate_20mhz_long_gi_kbps: 6500,
        rate_20mhz_short_gi_kbps: 7200,
        rate_40mhz_short_gi_kbps: 15000,
        rate_80mhz_short_gi_kbps: 32500,
        rate_160mhz_short_gi_kbps: 65000,
        rate_320mhz_short_gi_kbps: 130000,
    },
    McsRateEntry {
        mcs_index: 1,
        modulation: WifiModulation::Qpsk,
        coding_rate: CodingRate(1, 2),
        rate_20mhz_long_gi_kbps: 13000,
        rate_20mhz_short_gi_kbps: 14400,
        rate_40mhz_short_gi_kbps: 30000,
        rate_80mhz_short_gi_kbps: 65000,
        rate_160mhz_short_gi_kbps: 130000,
        rate_320mhz_short_gi_kbps: 260000,
    },
    McsRateEntry {
        mcs_index: 2,
        modulation: WifiModulation::Qpsk,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 19500,
        rate_20mhz_short_gi_kbps: 21700,
        rate_40mhz_short_gi_kbps: 45000,
        rate_80mhz_short_gi_kbps: 97500,
        rate_160mhz_short_gi_kbps: 195000,
        rate_320mhz_short_gi_kbps: 390000,
    },
    McsRateEntry {
        mcs_index: 3,
        modulation: WifiModulation::Qam16,
        coding_rate: CodingRate(1, 2),
        rate_20mhz_long_gi_kbps: 26000,
        rate_20mhz_short_gi_kbps: 28900,
        rate_40mhz_short_gi_kbps: 60000,
        rate_80mhz_short_gi_kbps: 130000,
        rate_160mhz_short_gi_kbps: 260000,
        rate_320mhz_short_gi_kbps: 520000,
    },
    McsRateEntry {
        mcs_index: 4,
        modulation: WifiModulation::Qam16,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 39000,
        rate_20mhz_short_gi_kbps: 43300,
        rate_40mhz_short_gi_kbps: 90000,
        rate_80mhz_short_gi_kbps: 195000,
        rate_160mhz_short_gi_kbps: 390000,
        rate_320mhz_short_gi_kbps: 780000,
    },
    McsRateEntry {
        mcs_index: 5,
        modulation: WifiModulation::Qam64,
        coding_rate: CodingRate(2, 3),
        rate_20mhz_long_gi_kbps: 52000,
        rate_20mhz_short_gi_kbps: 57800,
        rate_40mhz_short_gi_kbps: 120000,
        rate_80mhz_short_gi_kbps: 260000,
        rate_160mhz_short_gi_kbps: 520000,
        rate_320mhz_short_gi_kbps: 1040000,
    },
    McsRateEntry {
        mcs_index: 6,
        modulation: WifiModulation::Qam64,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 58500,
        rate_20mhz_short_gi_kbps: 65000,
        rate_40mhz_short_gi_kbps: 135000,
        rate_80mhz_short_gi_kbps: 292500,
        rate_160mhz_short_gi_kbps: 585000,
        rate_320mhz_short_gi_kbps: 1170000,
    },
    McsRateEntry {
        mcs_index: 7,
        modulation: WifiModulation::Qam64,
        coding_rate: CodingRate(5, 6),
        rate_20mhz_long_gi_kbps: 65000,
        rate_20mhz_short_gi_kbps: 72200,
        rate_40mhz_short_gi_kbps: 150000,
        rate_80mhz_short_gi_kbps: 325000,
        rate_160mhz_short_gi_kbps: 650000,
        rate_320mhz_short_gi_kbps: 1300000,
    },
    McsRateEntry {
        mcs_index: 8,
        modulation: WifiModulation::Qam256,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 78000,
        rate_20mhz_short_gi_kbps: 86700,
        rate_40mhz_short_gi_kbps: 180000,
        rate_80mhz_short_gi_kbps: 390000,
        rate_160mhz_short_gi_kbps: 780000,
        rate_320mhz_short_gi_kbps: 1560000,
    },
    McsRateEntry {
        mcs_index: 9,
        modulation: WifiModulation::Qam256,
        coding_rate: CodingRate(5, 6),
        rate_20mhz_long_gi_kbps: 86000,
        rate_20mhz_short_gi_kbps: 96000,
        rate_40mhz_short_gi_kbps: 200000,
        rate_80mhz_short_gi_kbps: 433300,
        rate_160mhz_short_gi_kbps: 866700,
        rate_320mhz_short_gi_kbps: 1733300,
    },
    McsRateEntry {
        mcs_index: 10,
        modulation: WifiModulation::Qam1024,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 108300,
        rate_20mhz_short_gi_kbps: 120100,
        rate_40mhz_short_gi_kbps: 240200,
        rate_80mhz_short_gi_kbps: 540400,
        rate_160mhz_short_gi_kbps: 1080900,
        rate_320mhz_short_gi_kbps: 2161900,
    },
    McsRateEntry {
        mcs_index: 11,
        modulation: WifiModulation::Qam1024,
        coding_rate: CodingRate(5, 6),
        rate_20mhz_long_gi_kbps: 120400,
        rate_20mhz_short_gi_kbps: 135400,
        rate_40mhz_short_gi_kbps: 270800,
        rate_80mhz_short_gi_kbps: 600400,
        rate_160mhz_short_gi_kbps: 1201000,
        rate_320mhz_short_gi_kbps: 2402000,
    },
    McsRateEntry {
        mcs_index: 12,
        modulation: WifiModulation::Qam4096,
        coding_rate: CodingRate(3, 4),
        rate_20mhz_long_gi_kbps: 130000,
        rate_20mhz_short_gi_kbps: 144100,
        rate_40mhz_short_gi_kbps: 288200,
        rate_80mhz_short_gi_kbps: 648500,
        rate_160mhz_short_gi_kbps: 1297000,
        rate_320mhz_short_gi_kbps: 2594000,
    },
    McsRateEntry {
        mcs_index: 13,
        modulation: WifiModulation::Qam4096,
        coding_rate: CodingRate(5, 6),
        rate_20mhz_long_gi_kbps: 144400,
        rate_20mhz_short_gi_kbps: 160200,
        rate_40mhz_short_gi_kbps: 320400,
        rate_80mhz_short_gi_kbps: 720800,
        rate_160mhz_short_gi_kbps: 1441600,
        rate_320mhz_short_gi_kbps: 2882400,
    },
];

/// Computes the PHY data rate in kbps for given MCS index and spatial stream count (1..=8).
pub fn compute_phy_throughput_kbps(
    mcs_index: u8,
    spatial_streams: u8,
    bandwidth_mhz: u16,
) -> Option<u32> {
    let entry = MCS_RATE_CATALOG_NSS1.iter().find(|m| m.mcs_index == mcs_index)?;
    let base_rate = match bandwidth_mhz {
        20 => entry.rate_20mhz_short_gi_kbps,
        40 => entry.rate_40mhz_short_gi_kbps,
        80 => entry.rate_80mhz_short_gi_kbps,
        160 => entry.rate_160mhz_short_gi_kbps,
        320 => entry.rate_320mhz_short_gi_kbps,
        _ => return None,
    };
    Some(base_rate * spatial_streams as u32)
}
