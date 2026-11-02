//! ACPI Embedded Controller (EC) Hardware Interface for CorOS
//! 100% in-house bare-metal implementation conforming to ACPI 6.4 Specification Section 12.
//!
//! Provides communication with motherboard Embedded Controllers over legacy I/O ports
//! 0x62 (Data) and 0x66 (Command/Status). Dispatches SCI (System Control Interrupt)
//! query events (_Qxx) for laptop Fn hotkeys, AC adapter state changes, thermal trips,
//! and lid switches.

extern crate alloc;

use alloc::vec::Vec;
use crate::arch::x86_64::cpu;

// Standard ACPI Embedded Controller Legacy I/O Ports
pub const EC_DATA_PORT: u16 = 0x62;
pub const EC_SC_PORT: u16 = 0x66; // Status (Read) / Command (Write)

// EC Status Register Bit Flags (ACPI 6.4 Table 12-2)
pub const EC_STAT_OBF: u8 = 1 << 0;     // Output Buffer Full (Data available to host)
pub const EC_STAT_IBF: u8 = 1 << 1;     // Input Buffer Full (EC busy processing command/data)
pub const EC_STAT_CMD: u8 = 1 << 3;     // Command/Data (1 = Command, 0 = Data)
pub const EC_STAT_BURST: u8 = 1 << 4;   // Burst Mode Enabled
pub const EC_STAT_SCI_EVT: u8 = 1 << 5; // SCI Event Pending (_Qxx query pending)
pub const EC_STAT_SMI_EVT: u8 = 1 << 6; // SMI Event Pending

// EC Standard Command Set (ACPI 6.4 Section 12.3)
pub const EC_CMD_READ: u8 = 0x80;         // Read Embedded Controller (RD_EC)
pub const EC_CMD_WRITE: u8 = 0x81;        // Write Embedded Controller (WR_EC)
pub const EC_CMD_BURST_ENABLE: u8 = 0x82; // Burst Enable (BE_EC)
pub const EC_CMD_BURST_DISABLE: u8 = 0x83;// Burst Disable (BD_EC)
pub const EC_CMD_QUERY: u8 = 0x84;        // Query Embedded Controller (QR_EC)

// Common ACPI SCI Query Event Codes (_Qxx)
pub const EC_EVENT_FN_BRIGHTNESS_DOWN: u8 = 0x10;
pub const EC_EVENT_FN_BRIGHTNESS_UP: u8 = 0x11;
pub const EC_EVENT_FN_DISPLAY_SWITCH: u8 = 0x12;
pub const EC_EVENT_FN_AIRPLANE_MODE: u8 = 0x13;
pub const EC_EVENT_FN_VOLUME_MUTE: u8 = 0x14;
pub const EC_EVENT_FN_VOLUME_DOWN: u8 = 0x15;
pub const EC_EVENT_FN_VOLUME_UP: u8 = 0x16;
pub const EC_EVENT_LID_OPEN: u8 = 0x20;
pub const EC_EVENT_LID_CLOSE: u8 = 0x21;
pub const EC_EVENT_AC_PLUGGED: u8 = 0x30;
pub const EC_EVENT_AC_UNPLUGGED: u8 = 0x31;
pub const EC_EVENT_BATTERY_LOW: u8 = 0x32;
pub const EC_EVENT_THERMAL_ALERT: u8 = 0x40;

/// ACPI EC System Control Event
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EcEvent {
    BrightnessDown,
    BrightnessUp,
    DisplaySwitch,
    AirplaneMode,
    VolumeMute,
    VolumeDown,
    VolumeUp,
    LidOpen,
    LidClose,
    AcPlugged,
    AcUnplugged,
    BatteryLow,
    ThermalAlert,
    Unknown(u8),
}

/// ACPI Embedded Controller Driver
pub struct EmbeddedController {
    pub data_port: u16,
    pub sc_port: u16,
    pub is_available: bool,
    pub burst_active: bool,
    pub pending_events: Vec<EcEvent>,
}

impl EmbeddedController {
    /// Creates a new EC driver instance initialized to standard I/O ports 0x62 / 0x66
    pub const fn new() -> Self {
        Self {
            data_port: EC_DATA_PORT,
            sc_port: EC_SC_PORT,
            is_available: false,
            burst_active: false,
            pending_events: Vec::new(),
        }
    }

    /// Read the EC status register
    #[inline(always)]
    pub fn read_status(&self) -> u8 {
        unsafe { cpu::in8(self.sc_port) }
    }

    /// Wait for Input Buffer Empty (IBF == 0) so host can send byte
    pub fn wait_ibf_clear(&self) -> bool {
        for _ in 0..100_000 {
            let stat = self.read_status();
            if (stat & EC_STAT_IBF) == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Wait for Output Buffer Full (OBF == 1) so host can read byte
    pub fn wait_obf_set(&self) -> bool {
        for _ in 0..100_000 {
            let stat = self.read_status();
            if (stat & EC_STAT_OBF) != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Probe whether an ACPI EC is responsive on ports 0x62/0x66
    pub fn probe(&mut self) -> bool {
        let stat = self.read_status();
        // If status returns 0xFF, no device decoded the I/O port
        if stat == 0xFF {
            self.is_available = false;
            return false;
        }

        self.is_available = true;
        true
    }

    /// Read a single byte from the EC's 256-byte internal address space
    pub fn read_byte(&self, address: u8) -> Option<u8> {
        if !self.is_available {
            return None;
        }

        if !self.wait_ibf_clear() {
            return None;
        }

        // Send RD_EC command
        unsafe { cpu::out8(self.sc_port, EC_CMD_READ) };

        if !self.wait_ibf_clear() {
            return None;
        }

        // Send Target Address
        unsafe { cpu::out8(self.data_port, address) };

        if !self.wait_obf_set() {
            return None;
        }

        // Read Data byte
        let data = unsafe { cpu::in8(self.data_port) };
        Some(data)
    }

    /// Write a single byte to the EC's 256-byte internal address space
    pub fn write_byte(&self, address: u8, data: u8) -> bool {
        if !self.is_available {
            return false;
        }

        if !self.wait_ibf_clear() {
            return false;
        }

        // Send WR_EC command
        unsafe { cpu::out8(self.sc_port, EC_CMD_WRITE) };

        if !self.wait_ibf_clear() {
            return false;
        }

        // Send Target Address
        unsafe { cpu::out8(self.data_port, address) };

        if !self.wait_ibf_clear() {
            return false;
        }

        // Send Data byte
        unsafe { cpu::out8(self.data_port, data) };
        true
    }

    /// Enter Burst Mode for rapid multi-byte sequential transactions
    pub fn enable_burst(&mut self) -> bool {
        if !self.wait_ibf_clear() {
            return false;
        }

        unsafe { cpu::out8(self.sc_port, EC_CMD_BURST_ENABLE) };

        if !self.wait_obf_set() {
            return false;
        }

        // Read burst acknowledgment (0x90)
        let ack = unsafe { cpu::in8(self.data_port) };
        if ack == 0x90 {
            self.burst_active = true;
            true
        } else {
            false
        }
    }

    /// Exit Burst Mode
    pub fn disable_burst(&mut self) {
        if self.burst_active {
            if self.wait_ibf_clear() {
                unsafe { cpu::out8(self.sc_port, EC_CMD_BURST_DISABLE) };
            }
            self.burst_active = false;
        }
    }

    /// Check if an SCI event is pending and query the event code (_Qxx)
    pub fn poll_query_event(&mut self) -> Option<EcEvent> {
        let stat = self.read_status();
        if (stat & EC_STAT_SCI_EVT) == 0 {
            return None;
        }

        if !self.wait_ibf_clear() {
            return None;
        }

        // Send QR_EC command
        unsafe { cpu::out8(self.sc_port, EC_CMD_QUERY) };

        if !self.wait_obf_set() {
            return None;
        }

        // Read query event code byte
        let event_code = unsafe { cpu::in8(self.data_port) };
        if event_code == 0 {
            return None; // 0 indicates no pending event
        }

        let ev = match event_code {
            EC_EVENT_FN_BRIGHTNESS_DOWN => EcEvent::BrightnessDown,
            EC_EVENT_FN_BRIGHTNESS_UP => EcEvent::BrightnessUp,
            EC_EVENT_FN_DISPLAY_SWITCH => EcEvent::DisplaySwitch,
            EC_EVENT_FN_AIRPLANE_MODE => EcEvent::AirplaneMode,
            EC_EVENT_FN_VOLUME_MUTE => EcEvent::VolumeMute,
            EC_EVENT_FN_VOLUME_DOWN => EcEvent::VolumeDown,
            EC_EVENT_FN_VOLUME_UP => EcEvent::VolumeUp,
            EC_EVENT_LID_OPEN => EcEvent::LidOpen,
            EC_EVENT_LID_CLOSE => EcEvent::LidClose,
            EC_EVENT_AC_PLUGGED => EcEvent::AcPlugged,
            EC_EVENT_AC_UNPLUGGED => EcEvent::AcUnplugged,
            EC_EVENT_BATTERY_LOW => EcEvent::BatteryLow,
            EC_EVENT_THERMAL_ALERT => EcEvent::ThermalAlert,
            code => EcEvent::Unknown(code),
        };

        self.pending_events.push(ev);
        Some(ev)
    }

    /// Drain all queued pending events
    pub fn drain_events(&mut self) -> Vec<EcEvent> {
        core::mem::take(&mut self.pending_events)
    }
}
