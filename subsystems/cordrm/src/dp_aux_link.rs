//! DisplayPort 1.4 AUX Channel, DPCD registers & Link Training state machine.

/// DPCD link rate codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpLinkRate {
    Rate1_62Gbps,
    Rate2_70Gbps,
    Rate5_40Gbps,
    Rate8_10Gbps,
}

impl DpLinkRate {
    pub fn to_dpcd_byte(self) -> u8 {
        match self {
            Self::Rate1_62Gbps => 0x06,
            Self::Rate2_70Gbps => 0x0A,
            Self::Rate5_40Gbps => 0x14,
            Self::Rate8_10Gbps => 0x1E,
        }
    }
}

/// DP AUX command request types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpAuxCommand {
    NativeWrite = 0x8,
    NativeRead = 0x9,
    I2cWrite = 0x0,
    I2cRead = 0x1,
}

/// DP Link Training phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkTrainingPhase {
    Idle,
    ClockRecovery,
    ChannelEqualization,
    Success,
    Failed,
}

/// DisplayPort Link Configuration & Training state.
#[derive(Clone, Debug)]
pub struct DpLinkTrainer {
    pub max_lanes: u8,
    pub active_lanes: u8,
    pub link_rate: DpLinkRate,
    pub voltage_swing_level: u8,
    pub pre_emphasis_level: u8,
    pub phase: LinkTrainingPhase,
}

impl DpLinkTrainer {
    pub fn new(max_lanes: u8, link_rate: DpLinkRate) -> Self {
        Self {
            max_lanes,
            active_lanes: max_lanes,
            link_rate,
            voltage_swing_level: 0,
            pre_emphasis_level: 0,
            phase: LinkTrainingPhase::Idle,
        }
    }

    /// Simulates clock recovery step. Advances swing level if clock lock is pending.
    pub fn step_clock_recovery(&mut self, clock_recovered: bool) {
        if clock_recovered {
            self.phase = LinkTrainingPhase::ChannelEqualization;
        } else if self.voltage_swing_level < 3 {
            self.voltage_swing_level += 1;
        } else {
            self.phase = LinkTrainingPhase::Failed;
        }
    }

    /// Simulates channel equalization step.
    pub fn step_channel_equalization(&mut self, symbol_locked: bool) {
        if symbol_locked {
            self.phase = LinkTrainingPhase::Success;
        } else if self.pre_emphasis_level < 3 {
            self.pre_emphasis_level += 1;
        } else {
            self.phase = LinkTrainingPhase::Failed;
        }
    }
}
