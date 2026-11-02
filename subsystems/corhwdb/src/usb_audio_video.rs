//! `usb_audio_video` — USB Audio Class (UAC) & USB Video Class (UVC) Descriptors.
//! Industry standard terminal types, control unit structures, and video payload GUIDs.

pub const USB_CLASS_AUDIO: u8 = 0x01;
pub const USB_CLASS_VIDEO: u8 = 0x0E;

pub const USB_SUBCLASS_AUDIOCONTROL: u8 = 0x01;
pub const USB_SUBCLASS_AUDIOSTREAMING: u8 = 0x02;
pub const USB_SUBCLASS_MIDISTREAMING: u8 = 0x03;

pub const USB_SUBCLASS_VIDEOCONTROL: u8 = 0x01;
pub const USB_SUBCLASS_VIDEOSTREAMING: u8 = 0x02;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UacTerminalType {
    Undefined,
    Microphone,
    DesktopMicrophone,
    PersonalMicrophone,
    OmniMicrophone,
    MicrophoneArray,
    Speaker,
    Headphones,
    HeadMountedDisplayAudio,
    DesktopSpeaker,
    RoomSpeaker,
    SpdifInterface,
    DigitalAudioInterface,
    LineConnector,
    LegacyAudioConnector,
}

pub struct UacTerminalEntry {
    pub terminal_code: u16,
    pub terminal_type: UacTerminalType,
    pub is_input: bool,
    pub name: &'static str,
}

pub static UAC_TERMINAL_TABLE: &[UacTerminalEntry] = &[
    UacTerminalEntry {
        terminal_code: 0x0201,
        terminal_type: UacTerminalType::Microphone,
        is_input: true,
        name: "Omnidirectional / General Microphone",
    },
    UacTerminalEntry {
        terminal_code: 0x0202,
        terminal_type: UacTerminalType::DesktopMicrophone,
        is_input: true,
        name: "Desktop Microphone Stand",
    },
    UacTerminalEntry {
        terminal_code: 0x0205,
        terminal_type: UacTerminalType::MicrophoneArray,
        is_input: true,
        name: "Multi-element Microphone Array (Beamforming)",
    },
    UacTerminalEntry {
        terminal_code: 0x0301,
        terminal_type: UacTerminalType::Speaker,
        is_input: false,
        name: "General Generic Speaker",
    },
    UacTerminalEntry {
        terminal_code: 0x0302,
        terminal_type: UacTerminalType::Headphones,
        is_input: false,
        name: "Stereo Headphones / Earphones",
    },
    UacTerminalEntry {
        terminal_code: 0x0304,
        terminal_type: UacTerminalType::DesktopSpeaker,
        is_input: false,
        name: "Desktop Stereo Speakers (Active)",
    },
    UacTerminalEntry {
        terminal_code: 0x0605,
        terminal_type: UacTerminalType::SpdifInterface,
        is_input: false,
        name: "S/PDIF Optical / Coaxial Digital Out",
    },
    UacTerminalEntry {
        terminal_code: 0x0603,
        terminal_type: UacTerminalType::LineConnector,
        is_input: true,
        name: "Analog 3.5mm Stereo Line-In",
    },
];

pub struct UvcFormatGuid {
    pub guid: [u8; 16],
    pub fourcc: [u8; 4],
    pub description: &'static str,
    pub bits_per_pixel: u8,
}

pub static UVC_STREAMING_FORMATS: &[UvcFormatGuid] = &[
    UvcFormatGuid {
        guid: [
            0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        ],
        fourcc: *b"YUY2",
        description: "YUY2 Uncompressed 4:2:2 Packed",
        bits_per_pixel: 16,
    },
    UvcFormatGuid {
        guid: [
            0x4E, 0x56, 0x31, 0x32, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        ],
        fourcc: *b"NV12",
        description: "NV12 Planar 4:2:0 Bi-Planar",
        bits_per_pixel: 12,
    },
    UvcFormatGuid {
        guid: [
            0x4D, 0x4A, 0x50, 0x47, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        ],
        fourcc: *b"MJPG",
        description: "Motion JPEG Compressed Video",
        bits_per_pixel: 24,
    },
    UvcFormatGuid {
        guid: [
            0x48, 0x32, 0x36, 0x34, 0x00, 0x00, 0x10, 0x00,
            0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
        ],
        fourcc: *b"H264",
        description: "ITU-T H.264 / MPEG-4 AVC Stream",
        bits_per_pixel: 24,
    },
];

pub fn lookup_uac_terminal(code: u16) -> Option<&'static UacTerminalEntry> {
    UAC_TERMINAL_TABLE.iter().find(|t| t.terminal_code == code)
}

pub fn lookup_uvc_format(fourcc: &[u8; 4]) -> Option<&'static UvcFormatGuid> {
    UVC_STREAMING_FORMATS.iter().find(|f| &f.fourcc == fourcc)
}
