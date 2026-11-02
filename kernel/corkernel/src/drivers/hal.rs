//! Universal Hardware Abstraction Layer (HAL) & Device Tree Registry
//!
//! Bare-metal no_std pure Rust Hardware Abstraction Layer for CorOS:
//! - Central hardware device registry unifying CPU, Memory, PCI, USB, Storage, Audio, and Net
//! - Device lifecycle state machine (Uninitialized, Active, LowPower, Fault)
//! - ACPI Device Power States (D0 Fully Operational, D1/D2 Intermediate, D3 Hot/Cold Powered Off)
//! - System-wide hardware topology introspection for Corpus Terminal & Task Manager

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::string::String;
use cordrivers::universal_device::{
    BlockDeviceDriver, NetworkDeviceDriver, DrmKmsDriver, InputDeviceDriver, AudioDeviceDriver,
};

/// Hardware Device Classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCategory {
    Processor,
    MemoryController,
    StorageController,
    DisplayAdapter,
    NetworkInterface,
    AudioDevice,
    InputPeripheral,
    SystemBus,
    SecurityChip,
    PowerManagement,
}

/// ACPI Device Power State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePowerState {
    D0_FullPower,
    D1_Standby,
    D2_Sleep,
    D3_PoweredOff,
}

/// Hardware Resource Descriptor
#[derive(Debug, Clone)]
pub enum HardwareResource {
    Mmio { base: u64, size: usize },
    IoPort { port: u16, count: u16 },
    Interrupt { gsi_or_vector: u32, is_msi: bool },
    DmaChannel { channel: u8 },
}

/// Unified Hardware Device Node
#[derive(Debug, Clone)]
pub struct HalDeviceNode {
    pub id: u32,
    pub name: String,
    pub category: DeviceCategory,
    pub vendor_id: u16,
    pub device_id: u16,
    pub power_state: DevicePowerState,
    pub is_online: bool,
    pub bound_driver: Option<String>,
    pub resources: Vec<HardwareResource>,
}

impl HalDeviceNode {
    pub fn new(id: u32, name: &str, category: DeviceCategory, vendor: u16, dev: u16) -> Self {
        Self {
            id,
            name: String::from(name),
            category,
            vendor_id: vendor,
            device_id: dev,
            power_state: DevicePowerState::D0_FullPower,
            is_online: true,
            bound_driver: None,
            resources: Vec::new(),
        }
    }

    pub fn bind_driver(&mut self, driver_name: &str) {
        self.bound_driver = Some(String::from(driver_name));
    }

    pub fn add_resource(&mut self, res: HardwareResource) {
        self.resources.push(res);
    }
}

/// Global Kernel Hardware Abstraction Manager
pub struct HalDeviceTree {
    pub devices: Vec<HalDeviceNode>,
    next_id: u32,
}

impl HalDeviceTree {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a newly detected hardware peripheral
    pub fn register_device(&mut self, name: &str, category: DeviceCategory, vendor: u16, dev: u16) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let node = HalDeviceNode::new(id, name, category, vendor, dev);
        self.devices.push(node);
        id
    }

    /// Populate standard platform base hardware (CPUs, APIC, Motherboard LPC, Timer)
    pub fn populate_platform_hardware(&mut self, total_cores: u32, cpu_freq_mhz: u64) {
        // CPU Cores
        for core in 0..total_cores {
            let mut name = String::from("x86_64 Processor Core #");
            name.push_str(if core < 10 { "0" } else { "" });
            let id = self.register_device(&name, DeviceCategory::Processor, 0x8086, 0x0001);
            if let Some(dev) = self.get_device_mut(id) {
                dev.add_resource(HardwareResource::Interrupt { gsi_or_vector: 32 + core, is_msi: false });
            }
        }

        // Local APIC & I/O APIC
        let ioapic_id = self.register_device("Intel I/O APIC Interrupt Controller", DeviceCategory::SystemBus, 0x8086, 0x8209);
        if let Some(dev) = self.get_device_mut(ioapic_id) {
            dev.add_resource(HardwareResource::Mmio { base: 0xFEC00000, size: 4096 });
        }

        // High Precision Event Timer (HPET) / APIC Timer
        let timer_id = self.register_device("High Precision Invariant TSC / APIC Timer", DeviceCategory::SystemBus, 0x8086, 0x1234);
        if let Some(dev) = self.get_device_mut(timer_id) {
            dev.add_resource(HardwareResource::Interrupt { gsi_or_vector: 32, is_msi: false });
        }
    }

    pub fn get_device(&self, id: u32) -> Option<&HalDeviceNode> {
        self.devices.iter().find(|d| d.id == id)
    }

    pub fn get_device_mut(&mut self, id: u32) -> Option<&mut HalDeviceNode> {
        self.devices.iter_mut().find(|d| d.id == id)
    }

    /// Query total online devices by category
    pub fn count_by_category(&self, cat: DeviceCategory) -> usize {
        self.devices.iter().filter(|d| d.category == cat && d.is_online).count()
    }

    /// Bind a driver name to a registered device
    pub fn bind_driver(&mut self, device_id: u32, driver_name: &str) -> bool {
        if let Some(dev) = self.get_device_mut(device_id) {
            dev.bind_driver(driver_name);
            true
        } else {
            false
        }
    }

    /// Register a storage block device and bind driver
    pub fn register_storage_device(&mut self, name: &str, vendor: u16, dev: u16, driver: &str) -> u32 {
        let id = self.register_device(name, DeviceCategory::StorageController, vendor, dev);
        self.bind_driver(id, driver);
        id
    }

    /// Register a network device and bind driver
    pub fn register_network_device(&mut self, name: &str, vendor: u16, dev: u16, driver: &str) -> u32 {
        let id = self.register_device(name, DeviceCategory::NetworkInterface, vendor, dev);
        self.bind_driver(id, driver);
        id
    }

    /// Register an audio device and bind driver
    pub fn register_audio_device(&mut self, name: &str, vendor: u16, dev: u16, driver: &str) -> u32 {
        let id = self.register_device(name, DeviceCategory::AudioDevice, vendor, dev);
        self.bind_driver(id, driver);
        id
    }

    /// Register an input peripheral and bind driver
    pub fn register_input_device(&mut self, name: &str, vendor: u16, dev: u16, driver: &str) -> u32 {
        let id = self.register_device(name, DeviceCategory::InputPeripheral, vendor, dev);
        self.bind_driver(id, driver);
        id
    }
}
