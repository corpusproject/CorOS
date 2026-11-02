//! ACPI RSDP, RSDT/XSDT, and MADT Parser for CorOS SMP Support
//!
//! Safely navigates firmware ACPI tables passed via UEFI BootInfo to discover
//! all available physical CPU cores and the Local APIC memory-mapped base address.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuCore {
    pub apic_id: u8,
    pub processor_id: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct MadtInfo {
    pub local_apic_address: u64,
    pub cores: [Option<CpuCore>; 8],
    pub core_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct HpetInfo {
    pub base_address: u64,
    pub hpet_number: u8,
    pub min_tick: u16,
}

/// Discovers the HPET (High Precision Event Timer) table from ACPI
pub unsafe fn parse_hpet(rsdp_address: u64) -> Option<HpetInfo> {
    if rsdp_address == 0 { return None; }
    let rsdp = rsdp_address as *const u8;
    let sig = core::slice::from_raw_parts(rsdp, 8);
    if sig != b"RSD PTR " { return None; }

    let revision = *rsdp.add(15);
    let mut hpet_ptr: *const u8 = core::ptr::null();

    if revision >= 2 {
        let xsdt_addr = core::ptr::read_unaligned(rsdp.add(24) as *const u64);
        if xsdt_addr != 0 {
            hpet_ptr = find_table_in_xsdt(xsdt_addr as *const u8, b"HPET");
        }
    }
    if hpet_ptr.is_null() {
        let rsdt_addr = core::ptr::read_unaligned(rsdp.add(16) as *const u32);
        if rsdt_addr != 0 {
            hpet_ptr = find_table_in_rsdt(rsdt_addr as *const u8, b"HPET");
        }
    }
    if hpet_ptr.is_null() { return None; }

    // HPET table base address is at offset 44 (Generic Address Structure: address at offset 4)
    let gas_base = hpet_ptr.add(40);
    let base_address = core::ptr::read_unaligned(gas_base.add(4) as *const u64);
    let hpet_number = *hpet_ptr.add(48);
    let min_tick = core::ptr::read_unaligned(hpet_ptr.add(50) as *const u16);

    Some(HpetInfo {
        base_address,
        hpet_number,
        min_tick,
    })
}

/// Discovers the MADT (Multiple APIC Description Table) and enumerates all CPU cores.
///
/// # Safety
/// `rsdp_address` must point to valid firmware memory provided in `BootInfo`.
pub unsafe fn parse_madt(rsdp_address: u64) -> Option<MadtInfo> {
    if rsdp_address == 0 {
        return None;
    }
    let rsdp = rsdp_address as *const u8;
    // Check "RSD PTR " signature (8 bytes)
    let sig = core::slice::from_raw_parts(rsdp, 8);
    if sig != b"RSD PTR " {
        return None;
    }

    let revision = *rsdp.add(15);
    let mut madt_ptr: *const u8 = core::ptr::null();

    if revision >= 2 {
        // ACPI 2.0+ uses XSDT with 64-bit pointers
        let xsdt_addr = core::ptr::read_unaligned(rsdp.add(24) as *const u64);
        if xsdt_addr != 0 {
            madt_ptr = find_table_in_xsdt(xsdt_addr as *const u8, b"APIC");
        }
    }

    if madt_ptr.is_null() {
        // Fallback to RSDT (32-bit pointers)
        let rsdt_addr = core::ptr::read_unaligned(rsdp.add(16) as *const u32);
        if rsdt_addr != 0 {
            madt_ptr = find_table_in_rsdt(rsdt_addr as *const u8, b"APIC");
        }
    }

    if madt_ptr.is_null() {
        return None;
    }

    // Parse MADT table
    let length = core::ptr::read_unaligned(madt_ptr.add(4) as *const u32) as usize;
    let local_apic_address = core::ptr::read_unaligned(madt_ptr.add(36) as *const u32) as u64;

    let mut cores = [None; 8];
    let mut core_count = 0;

    let mut offset = 44usize;
    while offset + 2 <= length {
        let entry_type = *madt_ptr.add(offset);
        let entry_len = *madt_ptr.add(offset + 1) as usize;
        if entry_len < 2 || offset + entry_len > length {
            break;
        }

        if entry_type == 0 && entry_len >= 8 {
            // Processor Local APIC entry
            let processor_id = *madt_ptr.add(offset + 2);
            let apic_id = *madt_ptr.add(offset + 3);
            let flags = core::ptr::read_unaligned(madt_ptr.add(offset + 4) as *const u32);
            let enabled = (flags & 1 != 0) || (flags & 2 != 0);

            if enabled && core_count < 8 {
                cores[core_count] = Some(CpuCore {
                    apic_id,
                    processor_id,
                    enabled,
                });
                core_count += 1;
            }
        }
        offset += entry_len;
    }

    Some(MadtInfo {
        local_apic_address,
        cores,
        core_count,
    })
}

unsafe fn find_table_in_xsdt(xsdt_ptr: *const u8, target_sig: &[u8; 4]) -> *const u8 {
    let length = core::ptr::read_unaligned(xsdt_ptr.add(4) as *const u32) as usize;
    if length < 36 {
        return core::ptr::null();
    }
    let entries = (length - 36) / 8;
    let ptrs = xsdt_ptr.add(36) as *const u64;
    for i in 0..entries {
        let table_addr = core::ptr::read_unaligned(ptrs.add(i));
        if table_addr != 0 {
            let table = table_addr as *const u8;
            let sig = core::slice::from_raw_parts(table, 4);
            if sig == target_sig {
                return table;
            }
        }
    }
    core::ptr::null()
}

unsafe fn find_table_in_rsdt(rsdt_ptr: *const u8, target_sig: &[u8; 4]) -> *const u8 {
    let length = core::ptr::read_unaligned(rsdt_ptr.add(4) as *const u32) as usize;
    if length < 36 {
        return core::ptr::null();
    }
    let entries = (length - 36) / 4;
    let ptrs = rsdt_ptr.add(36) as *const u32;
    for i in 0..entries {
        let table_addr = core::ptr::read_unaligned(ptrs.add(i));
        if table_addr != 0 {
            let table = table_addr as *const u8;
            let sig = core::slice::from_raw_parts(table, 4);
            if sig == target_sig {
                return table;
            }
        }
    }
    core::ptr::null()
}
