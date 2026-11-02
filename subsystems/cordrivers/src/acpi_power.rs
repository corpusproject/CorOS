//! CorOS Hardware Driver Module: `acpi_power`
//!
//! ACPI 6.4 Root System Description Pointer (`RSDP` v1/v2), 36-byte System Description
//! Table Header (`AcpiSdtHeader`), Multiple APIC Description Table (`MADT` / `APIC`)
//! Interrupt Controller Structure parser (Processor Local APIC, I/O APIC, Interrupt Source
//! Override, Local APIC NMI), PCIe `MCFG` segment allocation parser, and `FADT` (`PM1a_CNT`
//! `S5` Soft-Off / Reset Register) power state machine.

use alloc::vec::Vec;

/// 20-byte ACPI 1.0 + 16-byte ACPI 2.0+ Root System Description Pointer (`RSDP`, 36 bytes total).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiRsdpV2 {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

impl AcpiRsdpV2 {
    pub const SIGNATURE: [u8; 8] = *b"RSD PTR ";

    /// Validates the 8-byte `"RSD PTR "` signature, the first 20-byte checksum, and (if `revision >= 2`)
    /// the full 36-byte extended checksum.
    pub fn validate_bytes(raw: &[u8; 36]) -> Option<u64> {
        if raw[0..8] != Self::SIGNATURE {
            return None;
        }
        let mut sum20 = 0u8;
        let mut i = 0;
        while i < 20 {
            sum20 = sum20.wrapping_add(raw[i]);
            i += 1;
        }
        if sum20 != 0 {
            return None;
        }

        let revision = raw[15];
        if revision >= 2 {
            let mut sum36 = 0u8;
            let mut j = 0;
            while j < 36 {
                sum36 = sum36.wrapping_add(raw[j]);
                j += 1;
            }
            if sum36 != 0 {
                return None;
            }
            let xsdt = u64::from_le_bytes([
                raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
            ]);
            Some(xsdt)
        } else {
            let rsdt = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as u64;
            Some(rsdt)
        }
    }
}

/// 36-byte Standard ACPI System Description Table Header (`AcpiSdtHeader`).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiSdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// Verifies the modulo-256 byte checksum of an entire ACPI table slice (`length >= 36`).
pub fn verify_acpi_table_checksum(table_bytes: &[u8]) -> bool {
    if table_bytes.len() < 36 {
        return false;
    }
    let declared_len = u32::from_le_bytes([
        table_bytes[4],
        table_bytes[5],
        table_bytes[6],
        table_bytes[7],
    ]) as usize;
    if declared_len < 36 || declared_len > table_bytes.len() {
        return false;
    }
    let mut sum = 0u8;
    let mut i = 0;
    while i < declared_len {
        sum = sum.wrapping_add(table_bytes[i]);
        i += 1;
    }
    sum == 0
}

/// Parsed Interrupt Controller entry from the ACPI `MADT` (`"APIC"`) table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtEntry {
    ProcessorLocalApic {
        acpi_processor_uid: u8,
        apic_id: u8,
        enabled: bool,
        online_capable: bool,
    },
    IoApic {
        io_apic_id: u8,
        io_apic_phys_addr: u32,
        gsi_base: u32,
    },
    InterruptSourceOverride {
        bus: u8,
        source_irq: u8,
        global_system_interrupt: u32,
        flags: u16,
    },
    LocalApicNmi {
        acpi_processor_uid: u8,
        flags: u16,
        lint_pin: u8,
    },
    LocalApicAddressOverride {
        phys_addr_64: u64,
    },
}

/// Parses an ACPI `MADT` (`"APIC"`) byte slice into `(lapic_phys_addr, has_dual_8259_pic, Vec<MadtEntry>)`.
pub fn parse_madt(madt_bytes: &[u8]) -> Option<(u32, bool, Vec<MadtEntry>)> {
    if madt_bytes.len() < 44 || &madt_bytes[0..4] != b"APIC" {
        return None;
    }
    if !verify_acpi_table_checksum(madt_bytes) {
        return None;
    }

    let total_len =
        u32::from_le_bytes([madt_bytes[4], madt_bytes[5], madt_bytes[6], madt_bytes[7]]) as usize;
    let lapic_addr = u32::from_le_bytes([
        madt_bytes[36],
        madt_bytes[37],
        madt_bytes[38],
        madt_bytes[39],
    ]);
    let madt_flags = u32::from_le_bytes([
        madt_bytes[40],
        madt_bytes[41],
        madt_bytes[42],
        madt_bytes[43],
    ]);
    let has_8259 = (madt_flags & 0x01) != 0;

    let mut entries = Vec::new();
    let mut offset = 44usize;

    while offset + 2 <= total_len {
        let entry_type = madt_bytes[offset];
        let entry_len = madt_bytes[offset + 1] as usize;
        if entry_len < 2 || offset + entry_len > total_len {
            break;
        }
        let rec = &madt_bytes[offset..offset + entry_len];
        match entry_type {
            0 if entry_len >= 8 => {
                let flags = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                entries.push(MadtEntry::ProcessorLocalApic {
                    acpi_processor_uid: rec[2],
                    apic_id: rec[3],
                    enabled: (flags & 0x01) != 0,
                    online_capable: (flags & 0x02) != 0,
                });
            }
            1 if entry_len >= 12 => {
                let addr = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                let gsi = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
                entries.push(MadtEntry::IoApic {
                    io_apic_id: rec[2],
                    io_apic_phys_addr: addr,
                    gsi_base: gsi,
                });
            }
            2 if entry_len >= 10 => {
                let gsi = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                let flags = u16::from_le_bytes([rec[8], rec[9]]);
                entries.push(MadtEntry::InterruptSourceOverride {
                    bus: rec[2],
                    source_irq: rec[3],
                    global_system_interrupt: gsi,
                    flags,
                });
            }
            4 if entry_len >= 6 => {
                let flags = u16::from_le_bytes([rec[3], rec[4]]);
                entries.push(MadtEntry::LocalApicNmi {
                    acpi_processor_uid: rec[2],
                    flags,
                    lint_pin: rec[5],
                });
            }
            5 if entry_len >= 12 => {
                let addr64 = u64::from_le_bytes([
                    rec[4], rec[5], rec[6], rec[7], rec[8], rec[9], rec[10], rec[11],
                ]);
                entries.push(MadtEntry::LocalApicAddressOverride {
                    phys_addr_64: addr64,
                });
            }
            _ => {}
        }
        offset += entry_len;
    }

    Some((lapic_addr, has_8259, entries))
}

/// 16-byte PCIe `MCFG` Configuration Space Base Address Allocation entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcpiMcfgAllocation {
    pub ecam_base_address: u64,
    pub pci_segment_group: u16,
    pub start_bus_number: u8,
    pub end_bus_number: u8,
    pub reserved: u32,
}

/// Encodes the 16-bit `PM1a_CNT` / `PM1b_CNT` register value to enter ACPI Sleep State `S5` (Soft Off):
/// `SLP_EN` (`bit 13 = 1`) | `(slp_typa & 0x07) << 10`.
#[inline]
pub const fn encode_pm1_cnt_sleep(slp_typ: u8) -> u16 {
    (1u16 << 13) | (((slp_typ & 0x07) as u16) << 10)
}

/// Self-test for `acpi_power` RSDP v2 checksum validation, MADT APIC parsing, and S5 PM1_CNT encoding.
pub fn verify_driver_module_acpi_power() -> u32 {
    let mut passed = 0u32;

    // 1. Verify RSDP v2 validation & XSDT extraction
    let mut rsdp = [0u8; 36];
    rsdp[0..8].copy_from_slice(b"RSD PTR ");
    rsdp[9..15].copy_from_slice(b"COROS ");
    rsdp[15] = 2; // Revision 2
    rsdp[16..20].copy_from_slice(&0x7FFE_0000u32.to_le_bytes());
    let mut s20 = 0u8;
    for b in &rsdp[0..20] {
        s20 = s20.wrapping_add(*b);
    }
    rsdp[8] = 0u8.wrapping_sub(s20);

    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&0x0000_0001_7FFE_1000u64.to_le_bytes());
    let mut s36 = 0u8;
    for b in &rsdp[0..36] {
        s36 = s36.wrapping_add(*b);
    }
    rsdp[32] = 0u8.wrapping_sub(s36);

    if AcpiRsdpV2::validate_bytes(&rsdp) == Some(0x0000_0001_7FFE_1000) {
        passed += 1;
    }

    // 2. Verify synthetic MADT parsing (1 Local APIC + 1 I/O APIC + 1 IRQ0->GSI2 override)
    let mut madt = [0u8; 74];
    madt[0..4].copy_from_slice(b"APIC");
    madt[4..8].copy_from_slice(&74u32.to_le_bytes());
    madt[8] = 4;
    madt[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes()); // LAPIC base
    madt[40..44].copy_from_slice(&1u32.to_le_bytes()); // Dual 8259 present
    // Entry 0 (offset 44, len 8): Processor Local APIC (UID=0, APIC_ID=0, Flags=1)
    madt[44..52].copy_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]);
    // Entry 1 (offset 52, len 12): IOAPIC (ID=2, Addr=0xFEC0_0000, GSI=0)
    madt[52..56].copy_from_slice(&[1, 12, 2, 0]);
    madt[56..60].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
    madt[60..64].copy_from_slice(&0u32.to_le_bytes());
    // Entry 2 (offset 64, len 10): Interrupt Source Override (Bus 0, IRQ 0 -> GSI 2, Flags 0)
    madt[64..68].copy_from_slice(&[2, 10, 0, 0]);
    madt[68..72].copy_from_slice(&2u32.to_le_bytes());
    madt[72..74].copy_from_slice(&0u16.to_le_bytes());

    let mut msum = 0u8;
    for b in &madt {
        msum = msum.wrapping_add(*b);
    }
    madt[9] = 0u8.wrapping_sub(msum);

    if let Some((lapic, has_8259, entries)) = parse_madt(&madt) {
        if lapic == 0xFEE0_0000 && has_8259 && entries.len() == 3 {
            passed += 1;
        }
    }

    // 3. Verify S5 PM1a_CNT Sleep Enable + SLP_TYPa=5 encoding (`0x3400`)
    if encode_pm1_cnt_sleep(5) == 0x3400 {
        passed += 1;
    }

    passed
}
