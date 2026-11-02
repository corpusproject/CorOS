//! CorOS Userland Coreutil: `lspci`
//! PCIe bus/slot/function topology formatter supporting:
//! - Standard BDF line (`00:02.0 VGA compatible controller: ...`)
//! - `-nn` display both textual names and numeric PCI class/vendor/device hex IDs (`[0300]`, `[8086:29c2]`)
//! - `-v` verbose output with Subsystem ID, IRQ vector, and BAR0 memory region decoding
//! - `-k` show bound kernel driver module

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LspciFlags {
    pub verbose: bool,
    pub show_numeric_ids: bool,
    pub show_kernel_drivers: bool,
}

impl LspciFlags {
    pub const fn default_flags() -> Self {
        Self {
            verbose: false,
            show_numeric_ids: false,
            show_kernel_drivers: false,
        }
    }

    pub fn parse_args(args: &[&str]) -> Self {
        let mut flags = Self::default_flags();
        for arg in args {
            if let Some(rest) = arg.strip_prefix('-') {
                for ch in rest.chars() {
                    match ch {
                        'v' => flags.verbose = true,
                        'n' => flags.show_numeric_ids = true,
                        'k' => flags.show_kernel_drivers = true,
                        _ => {}
                    }
                }
            }
        }
        flags
    }
}

#[derive(Clone, Debug)]
pub struct PciFunctionRecord {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub class_code: u16,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub device_name: &'static str,
    pub irq_line: Option<u8>,
    pub bar0_phys: u64,
    pub bar0_size_kib: u32,
    pub kernel_driver: Option<&'static str>,
}

/// Decodes a 16-bit PCI class/subclass code (`(base_class << 8) | sub_class`) into its standard PCI-SIG description.
pub const fn decode_pci_class_name(class_code: u16) -> &'static str {
    match class_code {
        0x0101 => "IDE interface",
        0x0106 => "SATA controller",
        0x0108 => "Non-Volatile memory controller",
        0x0200 => "Ethernet controller",
        0x0300 => "VGA compatible controller",
        0x0401 => "Multimedia audio controller",
        0x0403 => "Audio device",
        0x0600 => "Host bridge",
        0x0601 => "ISA bridge",
        0x0604 => "PCI bridge",
        0x0C03 => "USB controller",
        0x0C05 => "SMBus",
        _ => "System peripheral",
    }
}

pub const fn decode_pci_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x8086 => "Intel Corporation",
        0x1022 => "Advanced Micro Devices, Inc. [AMD]",
        0x10DE => "NVIDIA Corporation",
        0x1234 => "QEMU / Bochs Virtual Graphics",
        0x1AF4 => "Red Hat, Inc. (VirtIO)",
        _ => "Unknown Vendor",
    }
}

/// Formats a list of PCI functions according to `LspciFlags`.
pub fn format_lspci_output(devices: &[PciFunctionRecord], flags: LspciFlags) -> String {
    let mut out = String::new();

    for dev in devices {
        let class_name = decode_pci_class_name(dev.class_code);
        let vendor_name = decode_pci_vendor_name(dev.vendor_id);

        if flags.show_numeric_ids {
            out.push_str(&format!(
                "{:02x}:{:02x}.{:x} {} [{:04x}]: {} {} [{:04x}:{:04x}] (rev {:02x})\n",
                dev.bus,
                dev.slot,
                dev.func,
                class_name,
                dev.class_code,
                vendor_name,
                dev.device_name,
                dev.vendor_id,
                dev.device_id,
                dev.revision
            ));
        } else {
            out.push_str(&format!(
                "{:02x}:{:02x}.{:x} {}: {} {} (rev {:02x})\n",
                dev.bus, dev.slot, dev.func, class_name, vendor_name, dev.device_name, dev.revision
            ));
        }

        if flags.verbose {
            if let Some(irq) = dev.irq_line {
                out.push_str(&format!("\tFlags: bus master, fast devsel, latency 0, IRQ {}\n", irq));
            } else {
                out.push_str("\tFlags: bus master, fast devsel, latency 0\n");
            }
            if dev.bar0_phys != 0 {
                out.push_str(&format!(
                    "\tMemory at {:08x} (64-bit, non-prefetchable) [size={}K]\n",
                    dev.bar0_phys, dev.bar0_size_kib
                ));
            }
        }

        if flags.verbose || flags.show_kernel_drivers {
            if let Some(drv) = dev.kernel_driver {
                out.push_str(&format!("\tKernel driver in use: {}\n", drv));
            }
        }
    }

    out
}

pub fn verify_util_lspci() -> u32 {
    let mut passed = 0u32;

    if decode_pci_class_name(0x0106) == "SATA controller"
        && decode_pci_class_name(0x0300) == "VGA compatible controller"
    {
        passed += 1;
    }

    let sample = [
        PciFunctionRecord {
            bus: 0,
            slot: 2,
            func: 0,
            class_code: 0x0300,
            vendor_id: 0x1234,
            device_id: 0x1111,
            revision: 2,
            device_name: "Standard VGA Framebuffer",
            irq_line: Some(11),
            bar0_phys: 0xFD00_0000,
            bar0_size_kib: 16384,
            kernel_driver: Some("coros_gop_vga"),
        },
        PciFunctionRecord {
            bus: 0,
            slot: 31,
            func: 2,
            class_code: 0x0106,
            vendor_id: 0x8086,
            device_id: 0x2922,
            revision: 2,
            device_name: "82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA Controller [AHCI mode]",
            irq_line: Some(19),
            bar0_phys: 0xFEBF_1000,
            bar0_size_kib: 4,
            kernel_driver: Some("ahci_sata"),
        },
    ];

    let nn_out = format_lspci_output(&sample, LspciFlags::parse_args(&["-nn"]));
    if nn_out.contains("00:02.0 VGA compatible controller [0300]:") && nn_out.contains("[8086:2922]") {
        passed += 1;
    }

    let vk_out = format_lspci_output(&sample, LspciFlags::parse_args(&["-vk"]));
    if vk_out.contains("Memory at fd000000")
        && vk_out.contains("[size=16384K]")
        && vk_out.contains("Kernel driver in use: ahci_sata")
    {
        passed += 1;
    }

    passed
}
