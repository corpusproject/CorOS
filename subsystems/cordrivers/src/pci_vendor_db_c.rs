//! CorOS Hardware Driver Module: `pci_vendor_db_c`
//!
//! Curated PCI/PCIe Hardware Identification Database — Table C:
//! - NVIDIA Corporation (`0x10DE`): Pascal, Turing, Ampere, Ada Lovelace GeForce/Data Center GPUs
//! - Samsung Electronics (`0x144D`): PM981/970 EVO/980 PRO/990 PRO/PM9A3 NVMe Controllers
//! - Red Hat, Inc. VirtIO (`0x1AF4`): Transitional (`0x1000..0x1009`) & Modern 1.0+ (`0x1041..0x105A`) VirtIO devices
//! - QEMU (`0x1234`, `0x1B36`): Bochs VGA (`0x1111`), QEMU XHCI (`0x000D`), QEMU NVMe (`0x0010`), PCIe Root Port
//! - VMware (`0x15AD`): SVGA II (`0x0405`), VMXNET3 (`0x07B0`), PVSCSI (`0x07C0`), USB xHCI (`0x0779`)
//! - InnoTek / Oracle VirtualBox (`0x80EE`): VBoxVGA (`0xBEEF`), VBoxGuest (`0xCAFE`)

/// PCI Vendor IDs covered by Database C.
pub mod vendor_ids_c {
    pub const NVIDIA: u16 = 0x10DE;
    pub const SAMSUNG: u16 = 0x144D;
    pub const REDHAT_VIRTIO: u16 = 0x1AF4;
    pub const QEMU_VGA: u16 = 0x1234;
    pub const REDHAT_QEMU: u16 = 0x1B36;
    pub const VMWARE: u16 = 0x15AD;
    pub const VIRTUALBOX: u16 = 0x80EE;
}

/// Driver Subsystem family for Table C devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorCDriverFamily {
    NvidiaDiscreteGpu,
    NvidiaHdmiAudio,
    SamsungNvmeSsd,
    VirtioNetwork,
    VirtioBlockStorage,
    VirtioConsole,
    VirtioScsi,
    VirtioGpuDisplay,
    VirtioInputHid,
    VirtioSocketVsock,
    QemuBochsLinearVga,
    QemuSystemPeripheral,
    VmwareParavirtDevice,
    VirtualBoxGuestDevice,
}

/// Curated PCI Device Record in Table C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VendorCPciDeviceRecord {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub family: VendorCDriverFamily,
    pub model_name: &'static str,
}

/// Curated Hardware Device Table for NVIDIA (`0x10DE`), Samsung (`0x144D`),
/// Red Hat VirtIO (`0x1AF4`), QEMU (`0x1234`, `0x1B36`), VMware (`0x15AD`), and VirtualBox (`0x80EE`).
pub static VENDOR_C_PCI_DEVICE_TABLE: &[VendorCPciDeviceRecord] = &[
    // NVIDIA Corporation (0x10DE)
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x1B80,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA GP104 [GeForce GTX 1080]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x1E04,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA TU102 [GeForce RTX 2080 Ti]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x2204,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA GA102 [GeForce RTX 3090]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x2206,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA GA102 [GeForce RTX 3080]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x20B0,
        class_code: 0x03,
        subclass: 0x02,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA GA100 [A100 SXM4 40GB / 80GB Tensor Core GPU]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x2684,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA AD102 [GeForce RTX 4090]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x2704,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA AD103 [GeForce RTX 4080]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x2782,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::NvidiaDiscreteGpu,
        model_name: "NVIDIA AD104 [GeForce RTX 4070 Ti]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x10DE,
        device_id: 0x22BA,
        class_code: 0x04,
        subclass: 0x03,
        family: VendorCDriverFamily::NvidiaHdmiAudio,
        model_name: "NVIDIA AD102 High Definition Audio Controller",
    },
    // Samsung Electronics Co., Ltd. NVMe SSDs (0x144D)
    VendorCPciDeviceRecord {
        vendor_id: 0x144D,
        device_id: 0xA804,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorCDriverFamily::SamsungNvmeSsd,
        model_name: "Samsung Electronics NVMe SSD Controller SM961/PM961/960 PRO",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x144D,
        device_id: 0xA808,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorCDriverFamily::SamsungNvmeSsd,
        model_name: "Samsung Electronics NVMe SSD Controller SM981/PM981/PM983 [970 EVO/PRO]",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x144D,
        device_id: 0xA80A,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorCDriverFamily::SamsungNvmeSsd,
        model_name: "Samsung Electronics NVMe SSD Controller PM9A1/PM9A3/980PRO",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x144D,
        device_id: 0xA80C,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorCDriverFamily::SamsungNvmeSsd,
        model_name: "Samsung Electronics NVMe SSD Controller 990 PRO",
    },
    // Red Hat, Inc. VirtIO Paravirtualized Devices (0x1AF4)
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1000,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtioNetwork,
        model_name: "Red Hat VirtIO Network Device (Transitional)",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1001,
        class_code: 0x01,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtioBlockStorage,
        model_name: "Red Hat VirtIO Block Device (Transitional)",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1003,
        class_code: 0x07,
        subclass: 0x80,
        family: VendorCDriverFamily::VirtioConsole,
        model_name: "Red Hat VirtIO Console (Transitional)",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1004,
        class_code: 0x01,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtioScsi,
        model_name: "Red Hat VirtIO SCSI Host Adapter (Transitional)",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1041,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtioNetwork,
        model_name: "Red Hat VirtIO 1.0+ Network Device",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1042,
        class_code: 0x01,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtioBlockStorage,
        model_name: "Red Hat VirtIO 1.0+ Block Device",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1050,
        class_code: 0x03,
        subclass: 0x80,
        family: VendorCDriverFamily::VirtioGpuDisplay,
        model_name: "Red Hat VirtIO 1.0+ GPU 2D/3D Display Accelerator",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1052,
        class_code: 0x09,
        subclass: 0x80,
        family: VendorCDriverFamily::VirtioInputHid,
        model_name: "Red Hat VirtIO 1.0+ Input Device",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1AF4,
        device_id: 0x1053,
        class_code: 0x07,
        subclass: 0x80,
        family: VendorCDriverFamily::VirtioSocketVsock,
        model_name: "Red Hat VirtIO 1.0+ Socket (vsock) Device",
    },
    // QEMU / Bochs Emulated Devices (0x1234, 0x1B36)
    VendorCPciDeviceRecord {
        vendor_id: 0x1234,
        device_id: 0x1111,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::QemuBochsLinearVga,
        model_name: "QEMU Standard VGA / Bochs VBE Linear Framebuffer",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1B36,
        device_id: 0x0008,
        class_code: 0x06,
        subclass: 0x00,
        family: VendorCDriverFamily::QemuSystemPeripheral,
        model_name: "QEMU PCIe Host Bridge",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1B36,
        device_id: 0x000D,
        class_code: 0x0C,
        subclass: 0x03,
        family: VendorCDriverFamily::QemuSystemPeripheral,
        model_name: "QEMU XHCI USB 3.0 Host Controller",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x1B36,
        device_id: 0x0010,
        class_code: 0x01,
        subclass: 0x08,
        family: VendorCDriverFamily::QemuSystemPeripheral,
        model_name: "QEMU NVM Express (NVMe) Controller",
    },
    // VMware Paravirtualized Hardware (0x15AD)
    VendorCPciDeviceRecord {
        vendor_id: 0x15AD,
        device_id: 0x0405,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::VmwareParavirtDevice,
        model_name: "VMware SVGA II Adapter",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x15AD,
        device_id: 0x07B0,
        class_code: 0x02,
        subclass: 0x00,
        family: VendorCDriverFamily::VmwareParavirtDevice,
        model_name: "VMware VMXNET3 Ethernet Controller",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x15AD,
        device_id: 0x07C0,
        class_code: 0x01,
        subclass: 0x07,
        family: VendorCDriverFamily::VmwareParavirtDevice,
        model_name: "VMware PVSCSI SCSI Controller",
    },
    // VirtualBox Guest Hardware (0x80EE)
    VendorCPciDeviceRecord {
        vendor_id: 0x80EE,
        device_id: 0xBEEF,
        class_code: 0x03,
        subclass: 0x00,
        family: VendorCDriverFamily::VirtualBoxGuestDevice,
        model_name: "InnoTek Systemberatung GmbH VirtualBox Graphics Adapter",
    },
    VendorCPciDeviceRecord {
        vendor_id: 0x80EE,
        device_id: 0xCAFE,
        class_code: 0x08,
        subclass: 0x80,
        family: VendorCDriverFamily::VirtualBoxGuestDevice,
        model_name: "InnoTek Systemberatung GmbH VirtualBox Guest Service",
    },
];

/// Looks up a PCI device in Database C by `(vendor_id, device_id)`.
pub fn lookup_vendor_c_device(
    vendor_id: u16,
    device_id: u16,
) -> Option<&'static VendorCPciDeviceRecord> {
    let mut i = 0;
    while i < VENDOR_C_PCI_DEVICE_TABLE.len() {
        let entry = &VENDOR_C_PCI_DEVICE_TABLE[i];
        if entry.vendor_id == vendor_id && entry.device_id == device_id {
            return Some(entry);
        }
        i += 1;
    }
    None
}

/// Self-test for `pci_vendor_db_c` NVIDIA/Samsung/VirtIO/QEMU/VMware/VirtualBox lookups and uniqueness.
pub fn verify_driver_module_pci_vendor_db_c() -> u32 {
    let mut passed = 0u32;

    // 1. Verify NVIDIA RTX 4090 (`0x10DE:0x2684`) and Samsung 990 PRO NVMe (`0x144D:0xA80C`)
    if let (Some(nv), Some(sam)) = (
        lookup_vendor_c_device(0x10DE, 0x2684),
        lookup_vendor_c_device(0x144D, 0xA80C),
    ) {
        if nv.family == VendorCDriverFamily::NvidiaDiscreteGpu
            && sam.family == VendorCDriverFamily::SamsungNvmeSsd
        {
            passed += 1;
        }
    }

    // 2. Verify Red Hat VirtIO 1.0+ GPU (`0x1AF4:0x1050`) and QEMU Bochs VGA (`0x1234:0x1111`)
    if let (Some(vg), Some(bochs)) = (
        lookup_vendor_c_device(0x1AF4, 0x1050),
        lookup_vendor_c_device(0x1234, 0x1111),
    ) {
        if vg.family == VendorCDriverFamily::VirtioGpuDisplay
            && bochs.family == VendorCDriverFamily::QemuBochsLinearVga
        {
            passed += 1;
        }
    }

    // 3. Verify VMware VMXNET3 (`0x15AD:0x07B0`) and VirtualBox Graphics (`0x80EE:0xBEEF`)
    if lookup_vendor_c_device(0x15AD, 0x07B0).is_some()
        && lookup_vendor_c_device(0x80EE, 0xBEEF).is_some()
    {
        passed += 1;
    }

    // 4. Verify all `(vendor_id, device_id)` pairs in VENDOR_C_PCI_DEVICE_TABLE are strictly distinct
    let mut all_unique = true;
    for i in 0..VENDOR_C_PCI_DEVICE_TABLE.len() {
        for j in (i + 1)..VENDOR_C_PCI_DEVICE_TABLE.len() {
            if VENDOR_C_PCI_DEVICE_TABLE[i].vendor_id == VENDOR_C_PCI_DEVICE_TABLE[j].vendor_id
                && VENDOR_C_PCI_DEVICE_TABLE[i].device_id == VENDOR_C_PCI_DEVICE_TABLE[j].device_id
            {
                all_unique = false;
            }
        }
    }
    if all_unique && VENDOR_C_PCI_DEVICE_TABLE.len() >= 30 {
        passed += 1;
    }

    passed
}
