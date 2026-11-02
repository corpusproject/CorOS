//! Intel HD Audio (Azalia) codec pin-complex topology router (`PinWidgetCap`,
//! `DefaultPinConfig` port connectivity/location/device/color decoder, EAPD external
//! amplifier enable, and headphone jack-sense auto-mute state machine).

/// Intel HD Audio verb IDs for Pin Complex configuration and control.
pub const HDA_VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x707;
/// Intel HD Audio verb ID for enabling External Amplifier Power Down (`EAPD/BTL`).
pub const HDA_VERB_SET_EAPD_BTL_ENABLE: u16 = 0x70C;
/// Intel HD Audio verb ID for triggering/reading Pin Sense (`AC_VERB_GET_PIN_SENSE`).
pub const HDA_VERB_GET_PIN_SENSE: u16 = 0xF09;

/// Pin Widget Control bitflags (`AC_PINCTL_*`).
pub const PINCTL_OUT_EN: u8 = 1 << 6;
/// Pin Widget Control Headphone Amplifier Drive Enable (`HP_EN`).
pub const PINCTL_HP_EN: u8 = 1 << 7;
/// Pin Widget Control Input Buffer Enable (`IN_EN`).
pub const PINCTL_IN_EN: u8 = 1 << 5;

/// EAPD/BTL bitflag to power up external speaker amplifier (`EAPD = 1 << 1`).
pub const EAPD_ENABLE_BIT: u8 = 1 << 1;

/// Decoded Pin Widget Capabilities (`AC_PAR_PIN_CAP`, parameter `0x0C`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinWidgetCap(pub u32);

impl PinWidgetCap {
    /// Supports Impedance Sense (`bit 0`).
    #[inline]
    pub const fn impedance_sense(self) -> bool {
        (self.0 & (1 << 0)) != 0
    }

    /// Supports Jack Presence Detect (`bit 2`).
    #[inline]
    pub const fn presence_detect_capable(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }

    /// Capable of driving low-impedance headphones (`bit 3`).
    #[inline]
    pub const fn headphone_drive_capable(self) -> bool {
        (self.0 & (1 << 3)) != 0
    }

    /// Capable of driving an output signal (`bit 4`).
    #[inline]
    pub const fn output_capable(self) -> bool {
        (self.0 & (1 << 4)) != 0
    }

    /// Capable of receiving an input signal (`bit 5`).
    #[inline]
    pub const fn input_capable(self) -> bool {
        (self.0 & (1 << 5)) != 0
    }

    /// Has an External Amplifier Power Down (`EAPD`) pin (`bit 16`).
    #[inline]
    pub const fn eapd_capable(self) -> bool {
        (self.0 & (1 << 16)) != 0
    }
}

/// Physical port connectivity field (`bits 31:30` of `DefaultPinConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortConnectivity {
    /// External jack (`0b00`, e.g., 3.5mm TRS or RCA).
    Jack,
    /// Unconnected / disabled pin (`0b01`).
    NoPhysicalConnection,
    /// Fixed internal function (`0b10`, e.g., internal laptop speakers or internal mic).
    FixedDevice,
    /// Both internal device and external jack (`0b11`, e.g., docking station).
    JackAndInternal,
}

/// Default device role encoded in `bits 23:20` of `DefaultPinConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultDeviceRole {
    LineOut,
    Speaker,
    HpOut,
    Cd,
    SpdifOut,
    DigitalOtherOut,
    ModemLineSide,
    ModemHandsetSide,
    LineIn,
    Aux,
    MicIn,
    Telephony,
    SpdifIn,
    DigitalOtherIn,
    Reserved,
    Other,
}

/// Physical jack color encoded in `bits 15:12` of `DefaultPinConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JackColor {
    Unknown,
    Black,
    Grey,
    Blue,
    Green,
    Red,
    Orange,
    Yellow,
    Purple,
    Pink,
    Reserved,
    White,
    Other,
}

/// 32-bit HD Audio Configuration Default register (`AC_VERB_GET_CONFIG_DEFAULT = 0xF1C`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultPinConfig(pub u32);

impl DefaultPinConfig {
    /// Decode physical port connectivity (`bits 31:30`).
    pub const fn connectivity(self) -> PortConnectivity {
        match (self.0 >> 30) & 0x03 {
            0 => PortConnectivity::Jack,
            1 => PortConnectivity::NoPhysicalConnection,
            2 => PortConnectivity::FixedDevice,
            _ => PortConnectivity::JackAndInternal,
        }
    }

    /// Decode physical chassis location code (`bits 29:24`).
    #[inline]
    pub const fn location_code(self) -> u8 {
        ((self.0 >> 24) & 0x3F) as u8
    }

    /// Decode default device type (`bits 23:20`).
    pub const fn default_device(self) -> DefaultDeviceRole {
        match (self.0 >> 20) & 0x0F {
            0x0 => DefaultDeviceRole::LineOut,
            0x1 => DefaultDeviceRole::Speaker,
            0x2 => DefaultDeviceRole::HpOut,
            0x3 => DefaultDeviceRole::Cd,
            0x4 => DefaultDeviceRole::SpdifOut,
            0x5 => DefaultDeviceRole::DigitalOtherOut,
            0x6 => DefaultDeviceRole::ModemLineSide,
            0x7 => DefaultDeviceRole::ModemHandsetSide,
            0x8 => DefaultDeviceRole::LineIn,
            0x9 => DefaultDeviceRole::Aux,
            0xA => DefaultDeviceRole::MicIn,
            0xB => DefaultDeviceRole::Telephony,
            0xC => DefaultDeviceRole::SpdifIn,
            0xD => DefaultDeviceRole::DigitalOtherIn,
            0xE => DefaultDeviceRole::Reserved,
            _ => DefaultDeviceRole::Other,
        }
    }

    /// Decode physical connector color (`bits 15:12`).
    pub const fn color(self) -> JackColor {
        match (self.0 >> 12) & 0x0F {
            0x0 => JackColor::Unknown,
            0x1 => JackColor::Black,
            0x2 => JackColor::Grey,
            0x3 => JackColor::Blue,
            0x4 => JackColor::Green,
            0x5 => JackColor::Red,
            0x6 => JackColor::Orange,
            0x7 => JackColor::Yellow,
            0x8 => JackColor::Purple,
            0x9 => JackColor::Pink,
            0xE => JackColor::White,
            0xF => JackColor::Other,
            _ => JackColor::Reserved,
        }
    }

    /// Return whether the Misc `NO_PRESENCE` override bit (`bit 8`) is set.
    #[inline]
    pub const fn jack_detect_override(self) -> bool {
        (self.0 & (1 << 8)) != 0
    }

    /// Default association group (`bits 7:4`).
    #[inline]
    pub const fn association(self) -> u8 {
        ((self.0 >> 4) & 0x0F) as u8
    }

    /// Sequence number within the association (`bits 3:0`).
    #[inline]
    pub const fn sequence(self) -> u8 {
        (self.0 & 0x0F) as u8
    }
}

/// Encode an HD Audio 32-bit CORB command verb frame (`codec_addr`, `nid`, `verb_id`, `payload`).
#[inline]
pub const fn make_hda_corb_verb(codec_addr: u8, nid: u8, verb_id: u16, payload: u8) -> u32 {
    (((codec_addr as u32) & 0x0F) << 28)
        | (((nid as u32) & 0x7F) << 20)
        | (((verb_id as u32) & 0xFFF) << 8)
        | (payload as u32)
}

/// Active output routing state managed by the Headphone Jack-Sense Auto-Mute state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoMuteOutputRoute {
    /// Internal chassis speakers active (EAPD enabled), headphone amplifier muted.
    InternalSpeakersActive,
    /// External headphones plugged in: internal speakers muted (EAPD powered down), headphone drive enabled.
    HeadphonesActiveSpeakersMuted,
}

/// HD Audio codec pin-complex topology router and jack-sense auto-mute controller.
#[derive(Debug, Clone, Copy)]
pub struct HdaPinComplexRouter {
    /// Codec address on the HD Audio link (`0..15`).
    pub codec_addr: u8,
    /// Node ID (`NID`) of the fixed internal speaker Pin Complex.
    pub speaker_nid: u8,
    /// Capabilities of the speaker pin complex.
    pub speaker_cap: PinWidgetCap,
    /// Node ID (`NID`) of the external headphone jack Pin Complex.
    pub headphone_nid: u8,
    /// Capabilities of the headphone pin complex.
    pub headphone_cap: PinWidgetCap,
    /// Current auto-mute routing state.
    pub route: AutoMuteOutputRoute,
    /// Last latched Pin Widget Control byte for the speaker pin.
    pub speaker_pinctl: u8,
    /// Last latched EAPD register byte for the speaker pin.
    pub speaker_eapd: u8,
    /// Last latched Pin Widget Control byte for the headphone pin.
    pub headphone_pinctl: u8,
}

impl HdaPinComplexRouter {
    /// Create and initialize an HD Audio speaker + headphone pin topology router.
    pub fn new(
        codec_addr: u8,
        speaker_nid: u8,
        speaker_cap: PinWidgetCap,
        headphone_nid: u8,
        headphone_cap: PinWidgetCap,
    ) -> Self {
        let eapd = if speaker_cap.eapd_capable() {
            EAPD_ENABLE_BIT
        } else {
            0
        };
        Self {
            codec_addr,
            speaker_nid,
            speaker_cap,
            headphone_nid,
            headphone_cap,
            route: AutoMuteOutputRoute::InternalSpeakersActive,
            speaker_pinctl: PINCTL_OUT_EN,
            speaker_eapd: eapd,
            headphone_pinctl: 0,
        }
    }

    /// Process a 32-bit `AC_VERB_GET_PIN_SENSE` response from `headphone_nid` (`bit 31 == Presence Detect`)
    /// and return the sequence of 32-bit CORB verbs needed to update Pin Control and EAPD registers.
    pub fn update_jack_sense(&mut self, pin_sense_response: u32) -> [u32; 3] {
        let hp_plugged = (pin_sense_response & (1 << 31)) != 0
            && self.headphone_cap.presence_detect_capable();

        if hp_plugged {
            self.route = AutoMuteOutputRoute::HeadphonesActiveSpeakersMuted;
            self.speaker_pinctl = 0;
            self.speaker_eapd = 0;
            self.headphone_pinctl = if self.headphone_cap.headphone_drive_capable() {
                PINCTL_OUT_EN | PINCTL_HP_EN
            } else {
                PINCTL_OUT_EN
            };
        } else {
            self.route = AutoMuteOutputRoute::InternalSpeakersActive;
            self.speaker_pinctl = PINCTL_OUT_EN;
            self.speaker_eapd = if self.speaker_cap.eapd_capable() {
                EAPD_ENABLE_BIT
            } else {
                0
            };
            self.headphone_pinctl = 0;
        }

        [
            make_hda_corb_verb(
                self.codec_addr,
                self.speaker_nid,
                HDA_VERB_SET_PIN_WIDGET_CONTROL,
                self.speaker_pinctl,
            ),
            make_hda_corb_verb(
                self.codec_addr,
                self.speaker_nid,
                HDA_VERB_SET_EAPD_BTL_ENABLE,
                self.speaker_eapd,
            ),
            make_hda_corb_verb(
                self.codec_addr,
                self.headphone_nid,
                HDA_VERB_SET_PIN_WIDGET_CONTROL,
                self.headphone_pinctl,
            ),
        ]
    }
}
