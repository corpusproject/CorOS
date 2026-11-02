//! World Regulatory Domains (ETSI, FCC, MKK), Power Limits & DFS Rules.
//! Pure `#![no_std]` Rust wireless registry without numbered repetition.

/// International Regulatory Authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegulatoryDomainCode {
    World00,
    EtsiEuropeTR, // Turkey, Germany, France, etc.
    FccUnitedStates,
    MkkJapan,
    KccSouthKorea,
}

/// Regulatory rule for a specific frequency range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegulatoryFreqRule {
    pub start_freq_mhz: u16,
    pub end_freq_mhz: u16,
    pub max_bandwidth_mhz: u16,
    pub max_eirp_dbm: u8,
    pub dfs_required: bool,
    pub indoor_only: bool,
}

/// ETSI (TR / Europe) 802.11 spectrum limits.
pub static REGULATORY_RULES_ETSI_TR: &[RegulatoryFreqRule] = &[
    RegulatoryFreqRule {
        start_freq_mhz: 2400,
        end_freq_mhz: 2483,
        max_bandwidth_mhz: 40,
        max_eirp_dbm: 20, // 100 mW
        dfs_required: false,
        indoor_only: false,
    },
    RegulatoryFreqRule {
        start_freq_mhz: 5150,
        end_freq_mhz: 5250,
        max_bandwidth_mhz: 160,
        max_eirp_dbm: 23, // 200 mW
        dfs_required: false,
        indoor_only: true, // UNII-1 Indoor only
    },
    RegulatoryFreqRule {
        start_freq_mhz: 5250,
        end_freq_mhz: 5350,
        max_bandwidth_mhz: 160,
        max_eirp_dbm: 23,
        dfs_required: true,
        indoor_only: true,
    },
    RegulatoryFreqRule {
        start_freq_mhz: 5470,
        end_freq_mhz: 5725,
        max_bandwidth_mhz: 160,
        max_eirp_dbm: 30, // 1 W
        dfs_required: true,
        indoor_only: false,
    },
    RegulatoryFreqRule {
        start_freq_mhz: 5945,
        end_freq_mhz: 6425,
        max_bandwidth_mhz: 320,
        max_eirp_dbm: 23,
        dfs_required: false,
        indoor_only: true, // Wi-Fi 6E / 7 Lower 6GHz LPI
    },
];

/// Looks up maximum permissible EIRP transmission power for a frequency in ETSI/TR domain.
pub fn get_max_tx_power_dbm_etsi(freq_mhz: u16) -> Option<u8> {
    for rule in REGULATORY_RULES_ETSI_TR {
        if freq_mhz >= rule.start_freq_mhz && freq_mhz <= rule.end_freq_mhz {
            return Some(rule.max_eirp_dbm);
        }
    }
    None
}
