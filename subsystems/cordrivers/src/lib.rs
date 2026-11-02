#![no_std]
//! `cordrivers` — CorOS Hardware Driver Subsystem & PCI/PCIe Device Registry.
//!
//! Pure `#![no_std]` Rust hardware protocol engines, MMIO/PIO register layouts,
//! DMA ring state machines, and curated PCI/PCIe hardware vendor identification tables.

extern crate alloc;

pub mod pcie_ecam;
pub mod nvme_admin;
pub mod nvme_io;
pub mod ahci_sata;
pub mod xhci_usb3;
pub mod usb_hid;
pub mod virtio_blk;
pub mod virtio_net;
pub mod virtio_gpu;
pub mod intel_e1000;
pub mod realtek_nic;
pub mod ac97_audio;
pub mod intel_hda;
pub mod gpu_intel_xe;
pub mod gpu_amd_rdna;
pub mod gpu_nvidia_ada;
pub mod acpi_power;
pub mod superio_hwmon;
pub mod ps2_8042;
pub mod rtc_cmos;
pub mod dma_engine;
pub mod pci_vendor_db_a;
pub mod pci_vendor_db_b;
pub mod pci_vendor_db_c;
pub mod virtio_input;
pub mod virtio_snd;
pub mod ata_ide;
pub mod universal_device;
pub mod traits;
pub mod pcie_dual_mode;

/// Executes hardware driver verification across all driver bus modules.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += pcie_ecam::verify_driver_module_pcie_ecam();
    passed += nvme_admin::verify_driver_module_nvme_admin();
    passed += nvme_io::verify_driver_module_nvme_io();
    passed += ahci_sata::verify_driver_module_ahci_sata();
    passed += xhci_usb3::verify_driver_module_xhci_usb3();
    passed += usb_hid::verify_driver_module_usb_hid();
    passed += virtio_blk::verify_driver_module_virtio_blk();
    passed += virtio_net::verify_driver_module_virtio_net();
    passed += virtio_gpu::verify_driver_module_virtio_gpu();
    passed += intel_e1000::verify_driver_module_intel_e1000();
    passed += realtek_nic::verify_driver_module_realtek_nic();
    passed += ac97_audio::verify_driver_module_ac97_audio();
    passed += intel_hda::verify_driver_module_intel_hda();
    passed += gpu_intel_xe::verify_driver_module_gpu_intel_xe();
    passed += gpu_amd_rdna::verify_driver_module_gpu_amd_rdna();
    passed += gpu_nvidia_ada::verify_driver_module_gpu_nvidia_ada();
    passed += acpi_power::verify_driver_module_acpi_power();
    passed += superio_hwmon::verify_driver_module_superio_hwmon();
    passed += ps2_8042::verify_driver_module_ps2_8042();
    passed += rtc_cmos::verify_driver_module_rtc_cmos();
    passed += dma_engine::verify_driver_module_dma_engine();
    passed += pci_vendor_db_a::verify_driver_module_pci_vendor_db_a();
    passed += pci_vendor_db_b::verify_driver_module_pci_vendor_db_b();
    passed += pci_vendor_db_c::verify_driver_module_pci_vendor_db_c();
    passed += virtio_input::verify_driver_module_virtio_input();
    passed += virtio_snd::verify_driver_module_virtio_snd();
    passed += ata_ide::verify_driver_module_ata_ide();
    passed += universal_device::verify_driver_module_universal_device();
    passed += traits::verify_driver_module_traits();
    passed += pcie_dual_mode::verify_driver_module_dual_mode_pci();
    passed
}
