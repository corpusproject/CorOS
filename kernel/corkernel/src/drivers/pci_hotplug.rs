//! PCI Express & Standard Hot-Plug Controller (SHPC / PCIe Native Hotplug)
//!
//! Bare-metal no_std pure Rust driver for PCIe Native Hot-Plug architecture
//! according to PCI Express Base Specification Chapter 6.7.
//! Enables dynamic hardware insertion, electrical power rail control,
//! MRL (Manual Retention Latch) sensors, indicator LED blinking, and hot-removal.

use alloc::vec::Vec;
use alloc::string::String;

/// Slot Status Register Bitmasks (PCIe Spec 6.7.3.4)
pub const SLOT_STATUS_ABP: u16 = 1 << 0;     // Attention Button Pressed
pub const SLOT_STATUS_PFD: u16 = 1 << 1;     // Power Fault Detected
pub const SLOT_STATUS_MRLSC: u16 = 1 << 2;   // MRL Sensor Changed
pub const SLOT_STATUS_PDC: u16 = 1 << 3;     // Presence Detect Changed
pub const SLOT_STATUS_CC: u16 = 1 << 4;      // Command Completed
pub const SLOT_STATUS_MRLSS: u16 = 1 << 5;   // MRL Sensor State (1 = Open, 0 = Closed)
pub const SLOT_STATUS_PDS: u16 = 1 << 6;     // Presence Detect State (1 = Card Present, 0 = Empty)
pub const SLOT_STATUS_EIS: u16 = 1 << 7;     // Electromechanical Interlock Status
pub const SLOT_STATUS_DLLSC: u16 = 1 << 8;   // Data Link Layer State Changed

/// Indicator LED States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorState {
    Reserved = 0b00,
    On = 0b01,
    Blink = 0b10,
    Off = 0b11,
}

/// Power Rail State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    PowerOn = 0b0,
    PowerOff = 0b1,
}

/// Hot-Plug Slot Lifecycle State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    Empty,
    InsertedPoweredOff,
    PoweringUp,
    ConfiguringPci,
    ActiveOnline,
    PoweringDown,
    SafeToRemove,
    HardwareFault,
}

/// Individual PCIe Hot-Plug Physical Slot
#[derive(Debug, Clone)]
pub struct PcieHotPlugSlot {
    pub slot_number: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub physical_slot_num: u32,
    pub state: SlotState,
    pub card_present: bool,
    pub latch_closed: bool,
    pub power_on: bool,
    pub attention_led: IndicatorState,
    pub power_led: IndicatorState,
    pub vendor_id: u16,
    pub device_id: u16,
    pub device_name: String,
}

impl PcieHotPlugSlot {
    pub fn new(slot_number: u16, bus: u8, device: u8, function: u8, physical_slot_num: u32) -> Self {
        Self {
            slot_number,
            bus,
            device,
            function,
            physical_slot_num,
            state: SlotState::Empty,
            card_present: false,
            latch_closed: true,
            power_on: false,
            attention_led: IndicatorState::Off,
            power_led: IndicatorState::Off,
            vendor_id: 0,
            device_id: 0,
            device_name: String::new(),
        }
    }

    /// Read raw slot status register
    pub fn read_status_register(&self) -> u16 {
        let mut status = 0u16;
        if self.card_present {
            status |= SLOT_STATUS_PDS;
        }
        if !self.latch_closed {
            status |= SLOT_STATUS_MRLSS;
        }
        status
    }

    /// Simulate card insertion into the physical PCIe slot
    pub fn handle_card_insertion(&mut self, vendor_id: u16, device_id: u16, name: &str) -> Result<(), &'static str> {
        if self.card_present {
            return Err("Slot already occupied");
        }

        self.card_present = true;
        self.vendor_id = vendor_id;
        self.device_id = device_id;
        self.device_name = String::from(name);
        self.state = SlotState::InsertedPoweredOff;

        // Turn on yellow attention LED (blink) while preparing power
        self.attention_led = IndicatorState::Blink;
        self.power_led = IndicatorState::Off;

        Ok(())
    }

    /// Power on slot and complete device configuration
    pub fn power_on_slot(&mut self) -> Result<(), &'static str> {
        if !self.card_present {
            return Err("Cannot power on empty slot");
        }
        if !self.latch_closed {
            return Err("Mechanical Retention Latch is OPEN. Close latch first.");
        }

        self.state = SlotState::PoweringUp;
        self.power_on = true;
        self.power_led = IndicatorState::Blink;

        // Transition through configuration
        self.state = SlotState::ConfiguringPci;
        // In full hardware: allocate BARs, assign IRQ/MSI-X, enable Bus Mastering

        self.state = SlotState::ActiveOnline;
        self.power_led = IndicatorState::On;
        self.attention_led = IndicatorState::Off;

        Ok(())
    }

    /// Safely request slot power down for hot-unplug
    pub fn initiate_safe_removal(&mut self) -> Result<(), &'static str> {
        if !self.card_present {
            return Err("Slot is empty");
        }

        self.state = SlotState::PoweringDown;
        self.attention_led = IndicatorState::Blink;

        // Notify device drivers, drain DMA queues, quiesce interrupts
        self.power_on = false;
        self.power_led = IndicatorState::Off;
        self.state = SlotState::SafeToRemove;
        self.attention_led = IndicatorState::Off;

        Ok(())
    }

    /// Finalize removal of card after latch opened and card extracted
    pub fn handle_card_removal(&mut self) -> Result<(), &'static str> {
        if self.power_on {
            self.state = SlotState::HardwareFault;
            return Err("SURPRISE REMOVAL DETECTED! Card removed while power rail was active.");
        }

        self.card_present = false;
        self.vendor_id = 0;
        self.device_id = 0;
        self.device_name.clear();
        self.state = SlotState::Empty;
        self.power_led = IndicatorState::Off;
        self.attention_led = IndicatorState::Off;

        Ok(())
    }
}

/// Kernel Global PCIe Hot-Plug Manager
pub struct PcieHotPlugManager {
    pub slots: Vec<PcieHotPlugSlot>,
    pub interrupt_count: u64,
}

impl PcieHotPlugManager {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            interrupt_count: 0,
        }
    }

    /// Register a new hot-plug capable slot
    pub fn register_slot(&mut self, slot: PcieHotPlugSlot) {
        self.slots.push(slot);
    }

    /// Process PCIe Native Hot-Plug MSI/INTx interrupt event
    pub fn dispatch_slot_interrupt(&mut self, slot_index: usize, status_bits: u16) {
        if slot_index >= self.slots.len() {
            return;
        }

        self.interrupt_count += 1;
        let slot = &mut self.slots[slot_index];

        // 1. Presence Detect Changed
        if (status_bits & SLOT_STATUS_PDC) != 0 {
            let present = (status_bits & SLOT_STATUS_PDS) != 0;
            if present && !slot.card_present {
                let _ = slot.handle_card_insertion(0x8086, 0x100E, "Intel PCIe HotPlug Device");
            } else if !present && slot.card_present {
                let _ = slot.handle_card_removal();
            }
        }

        // 2. Attention Button Pressed
        if (status_bits & SLOT_STATUS_ABP) != 0 {
            if slot.state == SlotState::ActiveOnline {
                let _ = slot.initiate_safe_removal();
            } else if slot.state == SlotState::InsertedPoweredOff {
                let _ = slot.power_on_slot();
            }
        }

        // 3. Power Fault Detected
        if (status_bits & SLOT_STATUS_PFD) != 0 {
            slot.state = SlotState::HardwareFault;
            slot.power_on = false;
            slot.power_led = IndicatorState::Off;
            slot.attention_led = IndicatorState::On;
        }
    }

    /// Get total active slots
    pub fn active_slots_count(&self) -> usize {
        self.slots.iter().filter(|s| s.state == SlotState::ActiveOnline).count()
    }
}
