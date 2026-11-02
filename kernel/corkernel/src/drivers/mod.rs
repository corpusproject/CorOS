//! CorOS Hardware Abstraction Layer & Device Driver Framework
//!
//! Provides enterprise driver models:
//! - PCI Vendor & Device ID Hardware Database
//! - NVM Express (NVMe) PCIe High-Speed Storage Driver
//! - VirtIO High-Performance Para-virtualized Device Subsystem
//! - AHCI SATA Storage Controller
//! - PCI Express ECAM & MSI/MSI-X Subsystem
//! - USB 3.0/3.1 xHCI Extensible Host Controller
//! - Intel High Definition Audio (HDA) Subsystem

pub mod pci_db;
pub mod nvme;
pub mod virtio;
pub mod rtl8139;
pub mod hdaudio;
pub mod usb;
pub mod ps2;
pub mod rtc;
pub mod pit8254;
pub mod serial_16550;
pub mod ahci;
pub mod pci_express;
pub mod usb_xhci;
pub mod intel_hda;
pub mod usb_hid;
pub mod virtio_gpu;
pub mod usb_mass_storage;
pub mod i2c_smbus;
pub mod wifi;
pub mod bluetooth;
pub mod intel_e1000e;
pub mod virtio_balloon;
pub mod pci_hotplug;
pub mod cpu_power;
pub mod hwmon;
pub mod watchdog;
pub mod pci_resource;
pub mod hal;
pub mod gpu_manager;
pub mod chipset;
pub mod pnp;

pub use pnp::{PnpManager, DriverRegistration, DriverMatchRank};
pub use chipset::{MotherboardProfile, MotherboardChipset, PcieEcamSegment};
pub use gpu_manager::{UniversalGpuDevice, GpuFamily, GpuCapabilities, DisplayMode};
pub use hal::{HalDeviceTree, HalDeviceNode, DeviceCategory, DevicePowerState, HardwareResource};
pub use pci_resource::{PciResourceManager, PciBarResource, BarType};
pub use watchdog::{HardwareWatchdog, NmiLockupDetector};
pub use hwmon::{HardwareMonitor, SuperIoChip, MotherboardVoltages, FanSpeeds, SystemTemperatures};
pub use cpu_power::{CpuPowerManager, GovernorPolicy, CpuThermalStatus};
pub use pci_hotplug::{PcieHotPlugManager, PcieHotPlugSlot, SlotState, IndicatorState, PowerState};
pub use virtio_balloon::VirtioBalloonDevice;
pub use intel_e1000e::IntelE1000eDriver;
pub use pci_db::lookup_pci_device;
pub use nvme::{NvmeController, NvmeQueue, NvmeSubmissionQueueEntry, NvmeCompletionQueueEntry};
pub use virtio::{VirtioBlockDevice, VirtioNetDevice, VirtQueue, VirtqDesc};
pub use rtl8139::Rtl8139Device;
pub use hdaudio::{HdaController, HdaBdlEntry};
pub use usb::{XhciController, XhciTrb, UsbHidParser, UsbMouseReport};
pub use ps2::Ps2Controller;
pub use rtc::{RtcDriver, SystemTime};
pub use pit8254::PitDriver;
pub use serial_16550::{SerialPort, COM1_BASE, COM2_BASE};
pub use ahci::{AhciController, AhciPort, AhciDeviceType, SataIdentifyInfo};
pub use pci_express::{PcieEcamManager, PcieDeviceInfo, PcieLinkSpeed, PcieLinkWidth};
pub use usb_xhci::{XhciExtController, XhciTrb as XhciTrbExt, UsbDeviceDescriptor};
pub use intel_hda::IntelHdaController;
pub use usb_hid::{HidReportParser, UsbKeyboardState, UsbMouseState, UsbGamepadState};
pub use virtio_gpu::{VirtioGpuDevice, VirtioGpuFormat, VirtioGpuRect};
pub use usb_mass_storage::{UsbMassStorageDevice, CommandBlockWrapper, CommandStatusWrapper, ScsiInquiryData};
pub use i2c_smbus::{SmbusController, SpdModuleInfo, MemoryType};
pub use wifi::{WifiDriver, WifiAccessPoint, Wpa2HandshakeState};
pub use bluetooth::{BluetoothController, BluetoothDevice};



