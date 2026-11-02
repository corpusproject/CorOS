//! CorOS Hardware Driver Module: `pcie_ecam`
//!
//! PCI Express Enhanced Configuration Access Mechanism (ECAM) decoder,
//! Type 0/Type 1 header parser, 32/64-bit Base Address Register (BAR) sizing
//! calculator, and PCI Capability linked-list walker (PM, MSI, MSI-X, PCIe).

use alloc::vec::Vec;

/// PCI Command Register bitflags (offset `0x04`).
pub mod pci_command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MEM_WRITE_INVALIDATE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_BACK_TO_BACK: u16 = 1 << 9;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// PCI Status Register bitflags (offset `0x06`).
pub mod pci_status {
    pub const INTERRUPT_STATUS: u16 = 1 << 3;
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_BACK_TO_BACK_CAPABLE: u16 = 1 << 7;
    pub const MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
    pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
    pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
    pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
    pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

/// Standard PCI Capability IDs.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciCapabilityId {
    PowerManagement = 0x01,
    Agp = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    Msi = 0x05,
    CompactPciHotSwap = 0x06,
    PciX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    DebugPort = 0x0A,
    PciExpress = 0x10,
    MsiX = 0x11,
    SataDataIndexConf = 0x12,
    AdvancedFeatures = 0x13,
    EnhancedAllocation = 0x14,
    FlatteningPortalBridge = 0x15,
    Unknown(u8),
}

impl PciCapabilityId {
    #[inline]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0x01 => Self::PowerManagement,
            0x02 => Self::Agp,
            0x03 => Self::VitalProductData,
            0x04 => Self::SlotIdentification,
            0x05 => Self::Msi,
            0x06 => Self::CompactPciHotSwap,
            0x07 => Self::PciX,
            0x08 => Self::HyperTransport,
            0x09 => Self::VendorSpecific,
            0x0A => Self::DebugPort,
            0x10 => Self::PciExpress,
            0x11 => Self::MsiX,
            0x12 => Self::SataDataIndexConf,
            0x13 => Self::AdvancedFeatures,
            0x14 => Self::EnhancedAllocation,
            0x15 => Self::FlatteningPortalBridge,
            other => Self::Unknown(other),
        }
    }
}

/// PCI Express Extended Capability IDs (offset `>= 0x100` in 4 KiB ECAM space).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcieExtCapabilityId {
    AdvancedErrorReporting = 0x0001,
    VirtualChannel = 0x0002,
    DeviceSerialNumber = 0x0003,
    PowerBudgeting = 0x0004,
    AccessControlServices = 0x000D,
    AlternativeRoutingId = 0x000E,
    AddressTranslationServices = 0x000F,
    SingleRootIoVirtualization = 0x0010,
    ResizableBar = 0x0015,
    LatencyToleranceReporting = 0x0018,
    L1PmSubstates = 0x001E,
    DataLinkFeature = 0x0025,
    PhysicalLayer16Gt = 0x0026,
    Unknown(u16),
}

impl PcieExtCapabilityId {
    #[inline]
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            0x0001 => Self::AdvancedErrorReporting,
            0x0002 => Self::VirtualChannel,
            0x0003 => Self::DeviceSerialNumber,
            0x0004 => Self::PowerBudgeting,
            0x000D => Self::AccessControlServices,
            0x000E => Self::AlternativeRoutingId,
            0x000F => Self::AddressTranslationServices,
            0x0010 => Self::SingleRootIoVirtualization,
            0x0015 => Self::ResizableBar,
            0x0018 => Self::LatencyToleranceReporting,
            0x001E => Self::L1PmSubstates,
            0x0025 => Self::DataLinkFeature,
            0x0026 => Self::PhysicalLayer16Gt,
            other => Self::Unknown(other),
        }
    }
}

/// Bus-Device-Function (BDF) coordinate within a PCIe segment group.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciBdf {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciBdf {
    #[inline]
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device: device & 0x1F,
            function: function & 0x07,
        }
    }

    /// Computes the byte offset from the segment's ECAM base address for `register_offset` (`0..4096`).
    #[inline]
    pub const fn ecam_offset(&self, register_offset: u16) -> u64 {
        let bus_bits = (self.bus as u64) << 20;
        let dev_bits = ((self.device & 0x1F) as u64) << 15;
        let fn_bits = ((self.function & 0x07) as u64) << 12;
        let reg_bits = (register_offset & 0x0FFF) as u64;
        bus_bits | dev_bits | fn_bits | reg_bits
    }

    /// Computes the physical MMIO address in the ECAM window.
    #[inline]
    pub const fn ecam_phys_addr(&self, ecam_base: u64, register_offset: u16) -> u64 {
        ecam_base.wrapping_add(self.ecam_offset(register_offset))
    }

    /// Computes legacy x86 I/O port `0xCF8` `CONFIG_ADDRESS` value for standard 256-byte space.
    #[inline]
    pub const fn legacy_cf8_address(&self, register_offset: u8) -> u32 {
        0x8000_0000
            | ((self.bus as u32) << 16)
            | (((self.device & 0x1F) as u32) << 11)
            | (((self.function & 0x07) as u32) << 8)
            | ((register_offset & 0xFC) as u32)
    }
}

/// PCI Common Configuration Space Header (first 64 bytes / 16 DWORDs of Type 0 header).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciType0Header {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision_id: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
    pub bar: [u32; 6],
    pub cardbus_cis_ptr: u32,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub expansion_rom_base: u32,
    pub capabilities_ptr: u8,
    pub reserved0: [u8; 3],
    pub reserved1: u32,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub min_grant: u8,
    pub max_latency: u8,
}

impl PciType0Header {
    /// Decodes a `PciType0Header` from a 64-byte raw configuration space slice.
    pub fn from_config_bytes(raw: &[u8; 64]) -> Self {
        let u16_at = |off: usize| u16::from_le_bytes([raw[off], raw[off + 1]]);
        let u32_at =
            |off: usize| u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);

        Self {
            vendor_id: u16_at(0x00),
            device_id: u16_at(0x02),
            command: u16_at(0x04),
            status: u16_at(0x06),
            revision_id: raw[0x08],
            prog_if: raw[0x09],
            subclass: raw[0x0A],
            class_code: raw[0x0B],
            cache_line_size: raw[0x0C],
            latency_timer: raw[0x0D],
            header_type: raw[0x0E],
            bist: raw[0x0F],
            bar: [
                u32_at(0x10),
                u32_at(0x14),
                u32_at(0x18),
                u32_at(0x1C),
                u32_at(0x20),
                u32_at(0x24),
            ],
            cardbus_cis_ptr: u32_at(0x28),
            subsystem_vendor_id: u16_at(0x2C),
            subsystem_id: u16_at(0x2E),
            expansion_rom_base: u32_at(0x30),
            capabilities_ptr: raw[0x34] & 0xFC,
            reserved0: [raw[0x35], raw[0x36], raw[0x37]],
            reserved1: u32_at(0x38),
            interrupt_line: raw[0x3C],
            interrupt_pin: raw[0x3D],
            min_grant: raw[0x3E],
            max_latency: raw[0x3F],
        }
    }

    #[inline]
    pub const fn is_present(&self) -> bool {
        self.vendor_id != 0xFFFF && self.vendor_id != 0x0000
    }

    #[inline]
    pub const fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }

    #[inline]
    pub const fn layout_type(&self) -> u8 {
        self.header_type & 0x7F
    }

    #[inline]
    pub const fn has_capabilities_list(&self) -> bool {
        (self.status & pci_status::CAPABILITIES_LIST) != 0 && self.capabilities_ptr >= 0x40
    }
}

/// Decoded Base Address Register (BAR) aperture descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciBarAperture {
    Unmapped,
    IoPort {
        bar_index: u8,
        base_port: u32,
        size_bytes: u32,
    },
    Mmio32 {
        bar_index: u8,
        base_addr: u32,
        size_bytes: u32,
        prefetchable: bool,
    },
    Mmio64 {
        bar_index: u8,
        base_addr: u64,
        size_bytes: u64,
        prefetchable: bool,
    },
}

/// Decodes a 32-bit or 64-bit BAR given the original register values and the all-1s sizing mask readback.
pub const fn decode_bar(
    bar_index: u8,
    raw_low: u32,
    raw_high: u32,
    mask_low: u32,
    mask_high: u32,
) -> PciBarAperture {
    if raw_low == 0 && mask_low == 0 {
        return PciBarAperture::Unmapped;
    }

    if (raw_low & 0x01) != 0 {
        // I/O Space BAR
        let base_port = raw_low & 0xFFFF_FFFC;
        let masked = mask_low & 0xFFFF_FFFC;
        if masked == 0 {
            return PciBarAperture::Unmapped;
        }
        let size_bytes = (!masked).wrapping_add(1);
        PciBarAperture::IoPort {
            bar_index,
            base_port,
            size_bytes,
        }
    } else {
        // Memory Space BAR
        let mem_type = (raw_low >> 1) & 0x03;
        let prefetchable = (raw_low & 0x08) != 0;
        if mem_type == 0x02 {
            // 64-bit MMIO BAR consuming two consecutive BAR slots
            let base_addr = ((raw_high as u64) << 32) | ((raw_low & 0xFFFF_FFF0) as u64);
            let full_mask = ((mask_high as u64) << 32) | ((mask_low & 0xFFFF_FFF0) as u64);
            if full_mask == 0 {
                return PciBarAperture::Unmapped;
            }
            let size_bytes = (!full_mask).wrapping_add(1);
            PciBarAperture::Mmio64 {
                bar_index,
                base_addr,
                size_bytes,
                prefetchable,
            }
        } else {
            // 32-bit MMIO BAR
            let base_addr = raw_low & 0xFFFF_FFF0;
            let masked = mask_low & 0xFFFF_FFF0;
            if masked == 0 {
                return PciBarAperture::Unmapped;
            }
            let size_bytes = (!masked).wrapping_add(1);
            PciBarAperture::Mmio32 {
                bar_index,
                base_addr,
                size_bytes,
                prefetchable,
            }
        }
    }
}

/// Parsed entry from the standard PCI Capability linked list (`0x40..0xFF`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciCapabilityNode {
    pub id: PciCapabilityId,
    pub offset: u8,
    pub next_ptr: u8,
}

/// Parsed MSI-X capability register structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiXCapability {
    pub cap_offset: u8,
    pub table_size: u16,
    pub function_mask: bool,
    pub enabled: bool,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

impl MsiXCapability {
    /// Decodes an MSI-X capability structure located at `cap_offset` in a 256-byte configuration space.
    pub fn parse(config_space: &[u8; 256], cap_offset: u8) -> Option<Self> {
        let off = cap_offset as usize;
        if off + 12 > config_space.len() || config_space[off] != 0x11 {
            return None;
        }
        let msg_ctrl = u16::from_le_bytes([config_space[off + 2], config_space[off + 3]]);
        let table_reg = u32::from_le_bytes([
            config_space[off + 4],
            config_space[off + 5],
            config_space[off + 6],
            config_space[off + 7],
        ]);
        let pba_reg = u32::from_le_bytes([
            config_space[off + 8],
            config_space[off + 9],
            config_space[off + 10],
            config_space[off + 11],
        ]);

        Some(Self {
            cap_offset,
            table_size: (msg_ctrl & 0x07FF) + 1,
            function_mask: (msg_ctrl & (1 << 14)) != 0,
            enabled: (msg_ctrl & (1 << 15)) != 0,
            table_bar: (table_reg & 0x07) as u8,
            table_offset: table_reg & !0x07,
            pba_bar: (pba_reg & 0x07) as u8,
            pba_offset: pba_reg & !0x07,
        })
    }
}

/// Walks the PCI Capability linked list inside a 256-byte configuration space buffer,
/// guarding against cyclic pointer loops and misaligned pointers.
pub fn walk_pci_capabilities(config_space: &[u8; 256]) -> Vec<PciCapabilityNode> {
    let mut nodes = Vec::new();
    let status = u16::from_le_bytes([config_space[0x06], config_space[0x07]]);
    if (status & pci_status::CAPABILITIES_LIST) == 0 {
        return nodes;
    }

    let mut ptr = config_space[0x34] & 0xFC;
    let mut visited_bitmap = 0u64;

    while ptr >= 0x40 {
        let slot_idx = ((ptr - 0x40) >> 2) as u32;
        if slot_idx < 64 {
            if (visited_bitmap & (1u64 << slot_idx)) != 0 {
                break; // Guard against malformed hardware capability loop
            }
            visited_bitmap |= 1u64 << slot_idx;
        }

        let off = ptr as usize;
        if off + 2 > config_space.len() {
            break;
        }
        let raw_id = config_space[off];
        let next = config_space[off + 1] & 0xFC;
        nodes.push(PciCapabilityNode {
            id: PciCapabilityId::from_raw(raw_id),
            offset: ptr,
            next_ptr: next,
        });
        if next == 0 {
            break;
        }
        ptr = next;
    }

    nodes
}

/// Parsed PCIe Extended Capability header (`0x100..0xFFF`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcieExtCapabilityNode {
    pub id: PcieExtCapabilityId,
    pub version: u8,
    pub offset: u16,
    pub next_offset: u16,
}

/// Walks the PCIe Extended Capability linked list in 4 KiB ECAM configuration space (`0x100..0xFFF`).
pub fn walk_pcie_ext_capabilities(ecam_space: &[u8; 4096]) -> Vec<PcieExtCapabilityNode> {
    let mut list = Vec::new();
    let mut offset = 0x100u16;
    let mut guard = 0u32;

    while offset >= 0x100 && (offset as usize) + 4 <= ecam_space.len() && guard < 96 {
        guard += 1;
        let idx = offset as usize;
        let header = u32::from_le_bytes([
            ecam_space[idx],
            ecam_space[idx + 1],
            ecam_space[idx + 2],
            ecam_space[idx + 3],
        ]);
        if header == 0 || header == 0xFFFF_FFFF {
            break;
        }
        let cap_id = (header & 0xFFFF) as u16;
        let version = ((header >> 16) & 0x0F) as u8;
        let next_offset = ((header >> 20) & 0x0FFC) as u16;
        list.push(PcieExtCapabilityNode {
            id: PcieExtCapabilityId::from_raw(cap_id),
            version,
            offset,
            next_offset,
        });
        if next_offset < 0x100 || next_offset == offset {
            break;
        }
        offset = next_offset;
    }
    list
}

/// Computes PCIe ECAM MMIO address using standard formula:
/// `base + ((bus as u64) << 20) | ((slot as u64) << 15) | ((func as u64) << 12) | (offset as u64)`.
#[inline]
pub const fn calculate_ecam_address(base: u64, bus: u8, slot: u8, func: u8, offset: u16) -> u64 {
    base + (((bus as u64) << 20) | (((slot & 0x1F) as u64) << 15) | (((func & 0x07) as u64) << 12) | ((offset & 0x0FFF) as u64))
}

/// Computes legacy x86 PCI Type 1 `0xCF8` `CONFIG_ADDRESS` value.
#[inline]
pub const fn calculate_cf8_address(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000
        | (((bus as u32) & 0xFF) << 16)
        | (((slot as u32) & 0x1F) << 11)
        | (((func as u32) & 0x07) << 8)
        | ((offset as u32) & 0xFC)
}

/// Discovered PCI/PCIe device node during bus hierarchy enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveredPciDevice {
    pub bdf: PciBdf,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
}

/// Scans PCI hierarchy across 256 buses, 32 devices (slots), and 8 functions.
/// Invokes `read_fn` for 32-bit config space DWORD reads.
pub fn scan_pci_bus_tree<F>(
    read_fn: &mut F,
) -> Vec<DiscoveredPciDevice>
where
    F: FnMut(u8, u8, u8, u16) -> u32,
{
    let mut discovered = Vec::new();

    for bus in 0..=255u8 {
        for slot in 0..32u8 {
            // Function 0 check
            let reg0 = read_fn(bus, slot, 0, 0x00);
            let vendor_id = (reg0 & 0xFFFF) as u16;
            if vendor_id == 0xFFFF || vendor_id == 0 {
                continue;
            }

            let device_id = ((reg0 >> 16) & 0xFFFF) as u16;
            let reg8 = read_fn(bus, slot, 0, 0x08);
            let class_code = ((reg8 >> 24) & 0xFF) as u8;
            let subclass = ((reg8 >> 16) & 0xFF) as u8;
            let prog_if = ((reg8 >> 8) & 0xFF) as u8;

            let regc = read_fn(bus, slot, 0, 0x0C);
            let header_type = ((regc >> 16) & 0xFF) as u8;
            let is_multi_function = (header_type & 0x80) != 0;

            discovered.push(DiscoveredPciDevice {
                bdf: PciBdf::new(0, bus, slot, 0),
                vendor_id,
                device_id,
                class_code,
                subclass,
                prog_if,
                header_type: header_type & 0x7F,
            });

            if is_multi_function {
                for func in 1..8u8 {
                    let fn_reg0 = read_fn(bus, slot, func, 0x00);
                    let fn_vendor = (fn_reg0 & 0xFFFF) as u16;
                    if fn_vendor != 0xFFFF && fn_vendor != 0 {
                        let fn_device = ((fn_reg0 >> 16) & 0xFFFF) as u16;
                        let fn_reg8 = read_fn(bus, slot, func, 0x08);
                        let fn_class = ((fn_reg8 >> 24) & 0xFF) as u8;
                        let fn_subclass = ((fn_reg8 >> 16) & 0xFF) as u8;
                        let fn_progif = ((fn_reg8 >> 8) & 0xFF) as u8;
                        let fn_regc = read_fn(bus, slot, func, 0x0C);
                        let fn_hdr = ((fn_regc >> 16) & 0x7F) as u8;

                        discovered.push(DiscoveredPciDevice {
                            bdf: PciBdf::new(0, bus, slot, func),
                            vendor_id: fn_vendor,
                            device_id: fn_device,
                            class_code: fn_class,
                            subclass: fn_subclass,
                            prog_if: fn_progif,
                            header_type: fn_hdr,
                        });
                    }
                }
            }
        }
    }

    discovered
}

/// Verifies the PCIe ECAM configuration space decoder, BAR sizing, and capability walker.
pub fn verify_driver_module_pcie_ecam() -> u32 {
    let mut passed = 0u32;

    // 1. Verify BDF ECAM physical address calculation
    let bdf = PciBdf::new(0, 3, 14, 2);
    let expected_off = (3u64 << 20) | (14u64 << 15) | (2u64 << 12) | 0x10;
    if bdf.ecam_offset(0x10) == expected_off
        && bdf.ecam_phys_addr(0xE000_0000, 0x10) == 0xE000_0000 + expected_off
    {
        passed += 1;
    }

    // 2. Verify standalone ECAM MMIO calculation formula
    let calc_addr = calculate_ecam_address(0xE000_0000, 1, 0, 0, 0);
    if calc_addr == 0xE010_0000 {
        passed += 1;
    }

    // 3. Verify legacy CF8 address calculation
    let cf8_val = calculate_cf8_address(0, 31, 2, 0);
    if (cf8_val & 0x8000_0000) != 0 && ((cf8_val >> 11) & 0x1F) == 31 && ((cf8_val >> 8) & 0x07) == 2 {
        passed += 1;
    }

    // 4. Verify 64-bit prefetchable MMIO BAR decoding (16 MiB NVMe/GPU aperture)
    let bar = decode_bar(0, 0xFE00_000C, 0x0000_0001, 0xFF00_000C, 0xFFFF_FFFF);
    if bar
        == (PciBarAperture::Mmio64 {
            bar_index: 0,
            base_addr: 0x0000_0001_FE00_0000,
            size_bytes: 16 * 1024 * 1024,
            prefetchable: true,
        })
    {
        passed += 1;
    }

    // 5. Verify I/O Port BAR decoding (256-byte PIO window at 0xC000)
    let io_bar = decode_bar(4, 0x0000_C001, 0, 0xFFFF_FF01, 0);
    if io_bar
        == (PciBarAperture::IoPort {
            bar_index: 4,
            base_port: 0xC000,
            size_bytes: 256,
        })
    {
        passed += 1;
    }

    // 6. Verify synthetic PCI Type 0 header & MSI-X / PCIe capability walking
    let mut cfg = [0u8; 256];
    cfg[0x00..0x02].copy_from_slice(&0x8086u16.to_le_bytes());
    cfg[0x02..0x04].copy_from_slice(&0x10D3u16.to_le_bytes());
    cfg[0x06..0x08].copy_from_slice(&pci_status::CAPABILITIES_LIST.to_le_bytes());
    cfg[0x0B] = 0x02; // Network controller
    cfg[0x34] = 0x50; // Capabilities pointer -> 0x50

    // Power Management at 0x50 -> next 0x70
    cfg[0x50] = 0x01;
    cfg[0x51] = 0x70;
    // MSI-X at 0x70 -> next 0xA0, 64 vectors (table_size - 1 = 63), enabled
    cfg[0x70] = 0x11;
    cfg[0x71] = 0xA0;
    cfg[0x72..0x74].copy_from_slice(&(63u16 | (1 << 15)).to_le_bytes());
    cfg[0x74..0x78].copy_from_slice(&(0x0000_2000u32 | 3).to_le_bytes()); // BAR 3, offset 0x2000
    cfg[0x78..0x7C].copy_from_slice(&(0x0000_4000u32 | 3).to_le_bytes()); // BAR 3, offset 0x4000
    // PCI Express at 0xA0 -> end (0x00)
    cfg[0xA0] = 0x10;
    cfg[0xA1] = 0x00;

    let mut hdr_bytes = [0u8; 64];
    hdr_bytes.copy_from_slice(&cfg[0..64]);
    let hdr = PciType0Header::from_config_bytes(&hdr_bytes);
    let caps = walk_pci_capabilities(&cfg);
    let msix = MsiXCapability::parse(&cfg, 0x70);

    if hdr.is_present()
        && hdr.vendor_id == 0x8086
        && caps.len() == 3
        && caps[1].id == PciCapabilityId::MsiX
    {
        passed += 1;
    }

    if let Some(m) = msix {
        if m.enabled && m.table_size == 64 && m.table_bar == 3 && m.table_offset == 0x2000 {
            passed += 1;
        }
    }

    // 7. Verify full BDF scanning over buses, devices, and functions
    let mut mock_reader = |bus: u8, slot: u8, func: u8, reg: u16| -> u32 {
        if bus == 0 && slot == 0 && func == 0 && reg == 0 {
            0x1234_8086 // Host bridge Intel
        } else if bus == 0 && slot == 3 && func == 0 && reg == 0 {
            0x100E_8086 // Intel e1000
        } else if bus == 0 && slot == 31 && func == 0 && reg == 0 {
            0x2918_8086 // LPC bridge, multi-function
        } else if bus == 0 && slot == 31 && func == 0 && reg == 0x0C {
            0x0080_0000 // Multi-function bit set
        } else if bus == 0 && slot == 31 && func == 2 && reg == 0 {
            0x2922_8086 // SATA AHCI
        } else {
            0xFFFF_FFFF // Empty slot
        }
    };

    let dev_list = scan_pci_bus_tree(&mut mock_reader);
    if dev_list.len() == 4
        && dev_list[0].vendor_id == 0x8086
        && dev_list[1].device_id == 0x100E
        && dev_list[3].bdf.function == 2
        && dev_list[3].device_id == 0x2922
    {
        passed += 1;
    }

    passed
}
