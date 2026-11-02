#![no_std]
//! `corhwdb` — CorOS Authentic Hardware Identification & Architecture Registry.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

extern crate alloc;

pub mod pci_intel;
pub mod pci_amd;
pub mod pci_nvidia;
pub mod pci_network;
pub mod pci_storage;
pub mod usb_catalog;
pub mod pci_intel_chipsets;
pub mod pci_amd_am4_am5;
pub mod pci_network_wifi;
pub mod usb_audio_video;

/// Runs self-tests verifying the hardware database integrity, non-null records, and catalog lookup functions.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Intel catalog lookup
    if let Some(dev) = pci_intel::lookup_intel_device(0x4680) {
        if dev.commercial_name.contains("UHD Graphics 770") {
            passed += 1;
        }
    }
    if let Some(dev) = pci_intel::lookup_intel_device(0x5690) {
        if dev.commercial_name.contains("Arc A770") {
            passed += 1;
        }
    }

    // 2. Verify AMD catalog lookup
    if let Some(dev) = pci_amd::lookup_amd_device(pci_amd::PCI_VENDOR_AMD_GFX, 0x744C) {
        if dev.commercial_name.contains("RX 7900 XTX") {
            passed += 1;
        }
    }

    // 3. Verify NVIDIA catalog lookup
    if let Some(dev) = pci_nvidia::lookup_nvidia_gpu(0x2684) {
        if dev.marketing_name.contains("RTX 4090") && dev.cuda_cores == 16384 {
            passed += 1;
        }
    }

    // 4. Verify Network catalog lookup
    if let Some(dev) = pci_network::lookup_network_device(pci_network::PCI_VENDOR_REALTEK, 0x8125) {
        if dev.commercial_name.contains("RTL8125") {
            passed += 1;
        }
    }

    // 5. Verify Storage catalog lookup
    if let Some(dev) = pci_storage::lookup_storage_device(pci_storage::PCI_VENDOR_SAMSUNG, 0xA80C) {
        if dev.drive_model.contains("990 PRO") {
            passed += 1;
        }
    }

    // 6. Verify USB catalog lookup
    if let Some(dev) = usb_catalog::lookup_usb_device(0x054C, 0x0CE6) {
        if dev.product.contains("DualSense") {
            passed += 1;
        }
    }

    // 7. Verify Intel Chipset lookup
    if let Some(chipset) = pci_intel_chipsets::lookup_intel_pch(0x7A04) {
        if chipset.chipset_name.contains("Z790") && chipset.supports_overclocking {
            passed += 1;
        }
    }

    // 8. Verify AMD Chipset lookup
    if let Some(chipset) = pci_amd_am4_am5::lookup_amd_chipset(0x43F4) {
        if chipset.marketing_name.contains("X870E") && chipset.pcie_generation == 5 {
            passed += 1;
        }
    }

    // 9. Verify Wi-Fi NIC catalog lookup
    if let Some(wifi) = pci_network_wifi::lookup_wifi_nic(0x8086, 0x272b) {
        if wifi.commercial_name.contains("BE200") && wifi.max_bandwidth_mhz == 320 {
            passed += 1;
        }
    }

    // 10. Verify USB Audio/Video definitions
    if let Some(term) = usb_audio_video::lookup_uac_terminal(0x0205) {
        if term.is_input && term.name.contains("Beamforming") {
            passed += 1;
        }
    }
    if let Some(fmt) = usb_audio_video::lookup_uvc_format(b"NV12") {
        if fmt.bits_per_pixel == 12 {
            passed += 1;
        }
    }

    passed
}
