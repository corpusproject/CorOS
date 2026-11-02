//! IEEE 802.11 Wi-Fi Channel Frequency, Channel Widths (20/40/80/160/320 MHz) & Band Mappings.
//! Pure `#![no_std]` Rust wireless spectrum registry without numbered repetition.

/// Wi-Fi Radio Frequency Band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiRadioBand {
    Band2_4GHz,
    Band5GHz,
    Band6GHz, // Wi-Fi 6E & Wi-Fi 7 (UNII-5, UNII-6, UNII-7, UNII-8)
}

/// Channel Channel Width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiChannelWidth {
    Width20MHz,
    Width40MHz,
    Width80MHz,
    Width160MHz,
    Width320MHz, // Wi-Fi 7 (802.11be)
}

/// Regulatory DFS (Dynamic Frequency Selection) requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DfsRequirement {
    None,
    DfsRequired,
    WeatherRadarAvoidance,
}

/// Wi-Fi Operating Channel Definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiChannelEntry {
    pub channel_number: u8,
    pub band: WifiRadioBand,
    pub center_frequency_mhz: u16,
    pub max_bandwidth: WifiChannelWidth,
    pub dfs: DfsRequirement,
    pub max_tx_power_dbm: u8,
}

/// Standard 2.4 GHz, 5 GHz and 6 GHz Wi-Fi Channel Table (IEEE 802.11-2020 & 802.11be).
pub static WIFI_CHANNELS_TABLE: &[WifiChannelEntry] = &[
    // --- 2.4 GHz ISM Band (Channels 1 - 14) ---
    WifiChannelEntry { channel_number: 1, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2412, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 2, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2417, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 3, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2422, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 4, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2427, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 5, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2432, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 6, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2437, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 7, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2442, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 8, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2447, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 9, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2452, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 10, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2457, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 11, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2462, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 12, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2467, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },
    WifiChannelEntry { channel_number: 13, band: WifiRadioBand::Band2_4GHz, center_frequency_mhz: 2472, max_bandwidth: WifiChannelWidth::Width40MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 20 },

    // --- 5 GHz UNII-1 (Channels 36 - 48, Indoor, No DFS) ---
    WifiChannelEntry { channel_number: 36, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5180, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 40, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5200, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 44, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5220, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 48, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5240, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 23 },

    // --- 5 GHz UNII-2A (Channels 52 - 64, DFS Required) ---
    WifiChannelEntry { channel_number: 52, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5260, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 56, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5280, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 60, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5300, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 23 },
    WifiChannelEntry { channel_number: 64, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5320, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 23 },

    // --- 5 GHz UNII-2C Extended (Channels 100 - 144, Weather Radar on 120-128) ---
    WifiChannelEntry { channel_number: 100, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5500, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 104, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5520, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 108, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5540, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 112, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5560, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 116, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5580, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 120, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5600, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::WeatherRadarAvoidance, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 124, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5620, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::WeatherRadarAvoidance, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 128, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5640, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::WeatherRadarAvoidance, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 132, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5660, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 136, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5680, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 140, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5700, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 144, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5720, max_bandwidth: WifiChannelWidth::Width160MHz, dfs: DfsRequirement::DfsRequired, max_tx_power_dbm: 30 },

    // --- 5 GHz UNII-3 (Channels 149 - 165, Upper 5GHz) ---
    WifiChannelEntry { channel_number: 149, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5745, max_bandwidth: WifiChannelWidth::Width80MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 153, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5765, max_bandwidth: WifiChannelWidth::Width80MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 157, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5785, max_bandwidth: WifiChannelWidth::Width80MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 161, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5805, max_bandwidth: WifiChannelWidth::Width80MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 30 },
    WifiChannelEntry { channel_number: 165, band: WifiRadioBand::Band5GHz, center_frequency_mhz: 5825, max_bandwidth: WifiChannelWidth::Width80MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 30 },

    // --- 6 GHz UNII-5 (Wi-Fi 6E & Wi-Fi 7 320MHz Channels) ---
    WifiChannelEntry { channel_number: 1, band: WifiRadioBand::Band6GHz, center_frequency_mhz: 5955, max_bandwidth: WifiChannelWidth::Width320MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 24 },
    WifiChannelEntry { channel_number: 5, band: WifiRadioBand::Band6GHz, center_frequency_mhz: 5975, max_bandwidth: WifiChannelWidth::Width320MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 24 },
    WifiChannelEntry { channel_number: 33, band: WifiRadioBand::Band6GHz, center_frequency_mhz: 6115, max_bandwidth: WifiChannelWidth::Width320MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 24 },
    WifiChannelEntry { channel_number: 65, band: WifiRadioBand::Band6GHz, center_frequency_mhz: 6275, max_bandwidth: WifiChannelWidth::Width320MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 24 },
    WifiChannelEntry { channel_number: 97, band: WifiRadioBand::Band6GHz, center_frequency_mhz: 6435, max_bandwidth: WifiChannelWidth::Width320MHz, dfs: DfsRequirement::None, max_tx_power_dbm: 24 },
];

/// Finds a channel by operating band and channel number.
pub fn lookup_channel(band: WifiRadioBand, channel: u8) -> Option<&'static WifiChannelEntry> {
    WIFI_CHANNELS_TABLE
        .iter()
        .find(|c| c.band == band && c.channel_number == channel)
}

/// Converts a center frequency in MHz to the corresponding channel number.
pub fn frequency_to_channel(freq_mhz: u16) -> Option<u8> {
    WIFI_CHANNELS_TABLE
        .iter()
        .find(|c| c.center_frequency_mhz == freq_mhz)
        .map(|c| c.channel_number)
}
