//! Controller Area Network (CAN-Bus) & Automotive Networking for CorOS.
//!
//! Implements ISO 11898-1:2015 CAN 2.0A (11-bit standard), CAN 2.0B (29-bit extended),
//! CAN-FD (Flexible Data-rate up to 64 bytes), Linux SocketCAN ABI compatibility,
//! and SAE J1979 / ISO 15031-5 On-Board Diagnostics II (OBD-II) PID telemetry decoding.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt;

/// Standard CAN identifier masks
pub const CAN_SFF_MASK: u32 = 0x0000_07FF; // Standard 11-bit frame mask
pub const CAN_EFF_MASK: u32 = 0x1FFF_FFFF; // Extended 29-bit frame mask
pub const CAN_ERR_MASK: u32 = 0x1FFF_FFFF; // Error frame mask

/// Special flag bits in CAN ID (SocketCAN convention)
pub const CAN_EFF_FLAG: u32 = 0x8000_0000; // Frame format flag: 0 = standard, 1 = extended
pub const CAN_RTR_FLAG: u32 = 0x4000_0000; // Remote transmission request flag
pub const CAN_ERR_FLAG: u32 = 0x2000_0000; // Error message frame flag

/// CAN-FD specific flags
pub const CANFD_BRS: u8 = 0x01; // Bit rate switch (transfer payload at higher baud)
pub const CANFD_ESI: u8 = 0x02; // Error state indicator of transmitting node
pub const CANFD_FDF: u8 = 0x04; // Flexible data frame format indicator

/// Standard OBD-II Request / Response CAN IDs
pub const OBD2_REQUEST_ID_BROADCAST: u32 = 0x7DF;
pub const OBD2_REQUEST_ID_ECU1: u32 = 0x7E0;
pub const OBD2_RESPONSE_ID_ECU1: u32 = 0x7E8;

/// Classic CAN 2.0 Frame (ISO 11898-1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CanFrame {
    pub can_id: u32,
    pub can_dlc: u8,
    pub __pad: u8,
    pub __res0: u8,
    pub __len8_dlc: u8,
    pub data: [u8; 8],
}

impl CanFrame {
    pub fn new_standard(id: u16, data: &[u8]) -> Self {
        let mut frame_data = [0u8; 8];
        let dlc = data.len().min(8);
        frame_data[..dlc].copy_from_slice(&data[..dlc]);

        Self {
            can_id: (id as u32) & CAN_SFF_MASK,
            can_dlc: dlc as u8,
            __pad: 0,
            __res0: 0,
            __len8_dlc: 0,
            data: frame_data,
        }
    }

    pub fn new_extended(id: u32, data: &[u8]) -> Self {
        let mut frame_data = [0u8; 8];
        let dlc = data.len().min(8);
        frame_data[..dlc].copy_from_slice(&data[..dlc]);

        Self {
            can_id: ((id & CAN_EFF_MASK) | CAN_EFF_FLAG),
            can_dlc: dlc as u8,
            __pad: 0,
            __res0: 0,
            __len8_dlc: 0,
            data: frame_data,
        }
    }

    pub fn is_extended(&self) -> bool {
        (self.can_id & CAN_EFF_FLAG) != 0
    }

    pub fn is_rtr(&self) -> bool {
        (self.can_id & CAN_RTR_FLAG) != 0
    }

    pub fn is_error(&self) -> bool {
        (self.can_id & CAN_ERR_FLAG) != 0
    }

    pub fn raw_id(&self) -> u32 {
        if self.is_extended() {
            self.can_id & CAN_EFF_MASK
        } else {
            self.can_id & CAN_SFF_MASK
        }
    }
}

/// CAN-FD Frame (ISO 11898-1:2015, up to 64 data bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CanFdFrame {
    pub can_id: u32,
    pub len: u8,
    pub flags: u8,
    pub __res0: u8,
    pub __res1: u8,
    pub data: [u8; 64],
}

impl CanFdFrame {
    pub fn new(can_id: u32, data: &[u8], is_brs: bool) -> Self {
        let mut frame_data = [0u8; 64];
        let len = data.len().min(64);
        frame_data[..len].copy_from_slice(&data[..len]);

        let mut flags = CANFD_FDF;
        if is_brs {
            flags |= CANFD_BRS;
        }

        Self {
            can_id,
            len: len as u8,
            flags,
            __res0: 0,
            __res1: 0,
            data: frame_data,
        }
    }
}

/// SocketCAN Filter for hardware / software message dispatching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CanFilter {
    pub can_id: u32,
    pub can_mask: u32,
}

impl CanFilter {
    pub fn new(can_id: u32, can_mask: u32) -> Self {
        Self { can_id, can_mask }
    }

    pub fn matches(&self, frame_id: u32) -> bool {
        (frame_id & self.can_mask) == (self.can_id & self.can_mask)
    }
}

/// Standard OBD-II Parameter IDs (Mode 01)
pub mod obd2_pids {
    pub const ENGINE_LOAD: u8 = 0x04;
    pub const COOLANT_TEMP: u8 = 0x05;
    pub const SHORT_FUEL_TRIM_1: u8 = 0x06;
    pub const LONG_FUEL_TRIM_1: u8 = 0x07;
    pub const FUEL_PRESSURE: u8 = 0x0A;
    pub const INTAKE_MAP: u8 = 0x0B;
    pub const ENGINE_RPM: u8 = 0x0C;
    pub const VEHICLE_SPEED: u8 = 0x0D;
    pub const TIMING_ADVANCE: u8 = 0x0E;
    pub const INTAKE_AIR_TEMP: u8 = 0x0F;
    pub const MAF_AIR_FLOW: u8 = 0x10;
    pub const THROTTLE_POS: u8 = 0x11;
    pub const RUN_TIME: u8 = 0x1F;
    pub const FUEL_TANK_LEVEL: u8 = 0x2F;
    pub const BAROMETRIC_PRESSURE: u8 = 0x33;
    pub const CONTROL_MODULE_VOLTAGE: u8 = 0x42;
    pub const AMBIENT_AIR_TEMP: u8 = 0x46;
    pub const ENGINE_OIL_TEMP: u8 = 0x5C;
    pub const FUEL_INJECTION_TIMING: u8 = 0x5D;
    pub const ENGINE_FUEL_RATE: u8 = 0x5E;
}

/// Decoded Automotive OBD-II Sensor Telemetry
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Obd2Value {
    EngineRpm(u32),                 // RPM
    VehicleSpeed(u8),               // km/h
    EngineLoad(f32),                // % (0.0 to 100.0)
    CoolantTemp(i16),               // Celsius (-40 to 215)
    IntakeAirTemp(i16),             // Celsius (-40 to 215)
    EngineOilTemp(i16),             // Celsius (-40 to 210)
    ThrottlePosition(f32),          // % (0.0 to 100.0)
    FuelTankLevel(f32),             // % (0.0 to 100.0)
    BarometricPressure(u8),         // kPa
    ControlModuleVoltage(f32),      // Volts
    RunTimeSeconds(u32),            // Seconds
    RawBytes([u8; 4], usize),       // Unparsed raw payload
}

/// OBD-II Protocol Handler & Engine Sensor Telemetry Decoder
pub struct Obd2Decoder;

impl Obd2Decoder {
    /// Build a standard 8-byte OBD-II Service 01 PID request frame
    pub fn build_request(pid: u8) -> CanFrame {
        // [length=2, mode=0x01, pid, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        let data = [0x02, 0x01, pid, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
        CanFrame::new_standard(OBD2_REQUEST_ID_BROADCAST as u16, &data)
    }

    /// Parse a standard OBD-II ECU response CAN frame (e.g. from 0x7E8)
    pub fn parse_response(frame: &CanFrame) -> Option<(u8, Obd2Value)> {
        let id = frame.raw_id();
        // Typically ECU responses are in range 0x7E8..=0x7EF
        if id < 0x7E8 || id > 0x7EF {
            return None;
        }

        let num_bytes = frame.data[0] as usize;
        if num_bytes < 2 || frame.data.len() < 3 {
            return None;
        }

        let mode = frame.data[1];
        if mode != 0x41 {
            // Mode 0x01 response is 0x41 (0x01 + 0x40)
            return None;
        }

        let pid = frame.data[2];
        let val_a = frame.data[3] as u32;
        let val_b = frame.data[4] as u32;

        let decoded = match pid {
            obd2_pids::ENGINE_RPM => {
                // RPM = (256 * A + B) / 4
                let rpm = (val_a * 256 + val_b) / 4;
                Obd2Value::EngineRpm(rpm)
            }
            obd2_pids::VEHICLE_SPEED => {
                // Speed = A km/h
                Obd2Value::VehicleSpeed(val_a as u8)
            }
            obd2_pids::ENGINE_LOAD => {
                // Load = A * 100 / 255 %
                let load = (val_a as f32 * 100.0) / 255.0;
                Obd2Value::EngineLoad(load)
            }
            obd2_pids::COOLANT_TEMP => {
                // Temp = A - 40 C
                let temp = (val_a as i16) - 40;
                Obd2Value::CoolantTemp(temp)
            }
            obd2_pids::INTAKE_AIR_TEMP => {
                let temp = (val_a as i16) - 40;
                Obd2Value::IntakeAirTemp(temp)
            }
            obd2_pids::ENGINE_OIL_TEMP => {
                let temp = (val_a as i16) - 40;
                Obd2Value::EngineOilTemp(temp)
            }
            obd2_pids::THROTTLE_POS => {
                let throttle = (val_a as f32 * 100.0) / 255.0;
                Obd2Value::ThrottlePosition(throttle)
            }
            obd2_pids::FUEL_TANK_LEVEL => {
                let fuel = (val_a as f32 * 100.0) / 255.0;
                Obd2Value::FuelTankLevel(fuel)
            }
            obd2_pids::BAROMETRIC_PRESSURE => {
                Obd2Value::BarometricPressure(val_a as u8)
            }
            obd2_pids::CONTROL_MODULE_VOLTAGE => {
                // Voltage = (256 * A + B) / 1000 V
                let mv = val_a * 256 + val_b;
                Obd2Value::ControlModuleVoltage((mv as f32) / 1000.0)
            }
            obd2_pids::RUN_TIME => {
                // Run time = 256 * A + B seconds
                let secs = val_a * 256 + val_b;
                Obd2Value::RunTimeSeconds(secs)
            }
            _ => {
                let mut raw = [0u8; 4];
                let count = num_bytes.saturating_sub(2).min(4);
                raw[..count].copy_from_slice(&frame.data[3..3 + count]);
                Obd2Value::RawBytes(raw, count)
            }
        };

        Some((pid, decoded))
    }
}

/// SocketCAN Virtual Controller Network Bus Interface
pub struct CanBusInterface {
    pub name: [u8; 16],
    pub rx_queue: Vec<CanFrame>,
    pub tx_queue: Vec<CanFrame>,
    pub filters: Vec<CanFilter>,
    pub rx_count: u64,
    pub tx_count: u64,
    pub err_count: u64,
}

impl CanBusInterface {
    pub fn new(name: &str) -> Self {
        let mut if_name = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(16);
        if_name[..len].copy_from_slice(&bytes[..len]);

        Self {
            name: if_name,
            rx_queue: Vec::with_capacity(128),
            tx_queue: Vec::with_capacity(128),
            filters: Vec::new(),
            rx_count: 0,
            tx_count: 0,
            err_count: 0,
        }
    }

    /// Add a reception filter (SocketCAN `setsockopt(SOL_CAN_RAW, CAN_RAW_FILTER)`)
    pub fn add_filter(&mut self, filter: CanFilter) {
        self.filters.push(filter);
    }

    /// Receive raw CAN frame from hardware controller (e.g. MCP2515, Bosch C_CAN, SocketCAN)
    pub fn receive_frame(&mut self, frame: CanFrame) {
        self.rx_count += 1;
        if frame.is_error() {
            self.err_count += 1;
        }

        // Apply filters if any are configured
        if !self.filters.is_empty() {
            let matches_any = self.filters.iter().any(|f| f.matches(frame.can_id));
            if !matches_any {
                return;
            }
        }

        if self.rx_queue.len() < 128 {
            self.rx_queue.push(frame);
        }
    }

    /// Enqueue a CAN frame to transmit
    pub fn send_frame(&mut self, frame: CanFrame) -> Result<(), &'static str> {
        if self.tx_queue.len() >= 128 {
            return Err("CAN TX queue full");
        }
        self.tx_count += 1;
        self.tx_queue.push(frame);
        Ok(())
    }

    /// Pop next frame from RX queue
    pub fn pop_rx(&mut self) -> Option<CanFrame> {
        if self.rx_queue.is_empty() {
            None
        } else {
            Some(self.rx_queue.remove(0))
        }
    }
}

impl fmt::Display for CanBusInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_str = core::str::from_utf8(&self.name).unwrap_or("can0");
        write!(
            f,
            "CanBusInterface({}, rx={}, tx={}, errors={})",
            name_str.trim_matches(char::from(0)),
            self.rx_count,
            self.tx_count,
            self.err_count
        )
    }
}
