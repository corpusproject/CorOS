//! VFIO-Style PCIe Device Passthrough (`AssignedPciDevice`), PCI Configuration Space
//! Virtualization (read-only/write-1-to-clear bit masks, virtual BAR relocation & sizing),
//! and MSI-X Host-to-Guest Interrupt Remapping Table.

use alloc::vec::Vec;

/// PCI Base Address Register (`BAR`) descriptor for virtual relocation and size probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualPciBar {
    pub bar_index: u8,
    pub is_mmio: bool,
    pub is_64bit: bool,
    pub is_prefetchable: bool,
    pub size_bytes: u32,
    pub host_phys_base: u64,
    pub guest_assigned_base: u32,
    pub sizing_probe_active: bool,
}

impl VirtualPciBar {
    /// Creates a 32-bit MMIO BAR with a power-of-two `size_bytes`.
    pub const fn new_mmio32(
        bar_index: u8,
        size_bytes: u32,
        host_phys_base: u64,
        initial_guest_base: u32,
        is_prefetchable: bool,
    ) -> Self {
        Self {
            bar_index,
            is_mmio: true,
            is_64bit: false,
            is_prefetchable,
            size_bytes,
            host_phys_base,
            guest_assigned_base: initial_guest_base & !(size_bytes.saturating_sub(1)),
            sizing_probe_active: false,
        }
    }

    /// Encodes the low 4 attribute bits of the PCI BAR register.
    pub const fn type_bits(&self) -> u32 {
        if !self.is_mmio {
            0x01 // I/O Space BAR
        } else {
            let mut bits = 0u32;
            if self.is_64bit {
                bits |= 0b10 << 1;
            }
            if self.is_prefetchable {
                bits |= 1 << 3;
            }
            bits
        }
    }

    /// Handles a guest 32-bit write to this BAR offset (`0xFFFF_FFFF` triggers BAR size discovery).
    pub fn write_bar(&mut self, written_val: u32) {
        if written_val == 0xFFFF_FFFF {
            self.sizing_probe_active = true;
        } else {
            self.sizing_probe_active = false;
            let align_mask = !(self.size_bytes.saturating_sub(1)) & !0xF;
            self.guest_assigned_base = written_val & align_mask;
        }
    }

    /// Reads the current 32-bit BAR register value (either the size mask or relocated guest base + attribute bits).
    pub const fn read_bar(&self) -> u32 {
        if self.sizing_probe_active {
            let size_mask = !(self.size_bytes.saturating_sub(1)) & !0xF;
            size_mask | self.type_bits()
        } else {
            (self.guest_assigned_base & !0xF) | self.type_bits()
        }
    }
}

/// 16-byte architectural MSI-X Table Entry (`msg_addr_lo`, `msg_addr_hi`, `msg_data`, `vector_ctrl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctrl: u32,
}

impl MsixTableEntry {
    pub const fn masked_default() -> Self {
        Self {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctrl: 1, // Bit 0 = Function/Vector Mask
        }
    }

    pub const fn is_masked(self) -> bool {
        (self.vector_ctrl & 1) != 0
    }

    /// Decodes the target Guest APIC ID from an x86 MSI address (`0xFEE0_0000 | (dest_id << 12)`).
    pub const fn target_guest_apic_id(self) -> u8 {
        ((self.msg_addr_lo >> 12) & 0xFF) as u8
    }

    /// Decodes the Guest Interrupt Vector (`bits [7:0]` of `msg_data`).
    pub const fn target_guest_vector(self) -> u8 {
        (self.msg_data & 0xFF) as u8
    }
}

/// Remapped MSI-X interrupt routing record translating a host physical IRQ vector to a guest vCPU APIC vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemappedMsixRoute {
    pub entry_index: u16,
    pub host_irq_vector: u8,
    pub guest_apic_id: u8,
    pub guest_vector: u8,
    pub delivery_mode: u8,
}

/// VFIO-assigned PCIe device with emulated 256-byte configuration space, BAR relocation, and MSI-X remapping.
#[derive(Debug, Clone)]
pub struct AssignedPciDevice {
    pub host_bdf: u16,
    pub guest_bdf: u16,
    pub config_space: [u8; 256],
    pub writable_mask: [u8; 256],
    pub w1c_mask: [u8; 256],
    pub bars: [Option<VirtualPciBar>; 6],
    pub msix_entries: Vec<MsixTableEntry>,
    pub host_vector_base: u8,
}

impl AssignedPciDevice {
    /// Creates a new VFIO-assigned PCIe device with realistic read-only Vendor/Device IDs,
    /// writable Command register, Write-1-to-Clear (`W1C`) Status register bits, and MSI-X table.
    pub fn new(
        host_bdf: u16,
        guest_bdf: u16,
        vendor_id: u16,
        device_id: u16,
        class_code_rev: u32,
        msix_table_size: u16,
        host_vector_base: u8,
    ) -> Self {
        let mut config_space = [0u8; 256];
        let mut writable_mask = [0u8; 256];
        let mut w1c_mask = [0u8; 256];

        // 0x00..0x02: Vendor ID (Read-Only)
        config_space[0..2].copy_from_slice(&vendor_id.to_le_bytes());
        // 0x02..0x04: Device ID (Read-Only)
        config_space[2..4].copy_from_slice(&device_id.to_le_bytes());
        // 0x04..0x06: Command Register (Writable bits: I/O Space, Mem Space, Bus Master, Int Disable)
        writable_mask[0x04] = 0x07;
        writable_mask[0x05] = 0x04;
        // 0x06..0x08: Status Register (Capabilities List bit 4 set; upper byte has W1C error bits)
        config_space[0x06] = 0x10;
        config_space[0x07] = 0x00;
        w1c_mask[0x07] = 0xF9; // Parity error, signaled target/master abort, etc. are W1C
        // 0x08..0x0C: Revision ID & Class Code (Read-Only)
        config_space[0x08..0x0C].copy_from_slice(&class_code_rev.to_le_bytes());
        // 0x34: Capabilities Pointer -> 0x40 (MSI-X capability)
        config_space[0x34] = 0x40;
        // 0x40: MSI-X Capability ID (0x11), Next Pointer (0x00), Message Control (table size N-1, Enable bit 15)
        config_space[0x40] = 0x11;
        config_space[0x41] = 0x00;
        let msg_ctrl = (msix_table_size.saturating_sub(1)) & 0x07FF;
        config_space[0x42..0x44].copy_from_slice(&msg_ctrl.to_le_bytes());
        writable_mask[0x43] = 0xC0; // MSI-X Enable (bit 15) and Function Mask (bit 14)

        let mut msix_entries = Vec::with_capacity(msix_table_size as usize);
        msix_entries.resize(msix_table_size as usize, MsixTableEntry::masked_default());

        Self {
            host_bdf,
            guest_bdf,
            config_space,
            writable_mask,
            w1c_mask,
            bars: [None; 6],
            msix_entries,
            host_vector_base,
        }
    }

    /// Attaches a virtualized MMIO BAR to slot `bar_index` (`0..6`).
    pub fn register_bar(&mut self, bar: VirtualPciBar) {
        let idx = bar.bar_index as usize;
        if idx < 6 {
            let offset = 0x10 + idx * 4;
            let raw = bar.read_bar();
            self.config_space[offset..offset + 4].copy_from_slice(&raw.to_le_bytes());
            self.bars[idx] = Some(bar);
        }
    }

    /// Reads a 32-bit aligned dword from the virtualized PCI configuration space.
    pub fn read_config_dword(&self, offset: u8) -> u32 {
        let aligned = (offset & !0x3) as usize;
        if (0x10..0x28).contains(&aligned) {
            let bar_idx = (aligned - 0x10) / 4;
            if let Some(bar) = self.bars[bar_idx] {
                return bar.read_bar();
            }
        }
        u32::from_le_bytes([
            self.config_space[aligned],
            self.config_space[aligned + 1],
            self.config_space[aligned + 2],
            self.config_space[aligned + 3],
        ])
    }

    /// Writes a 32-bit aligned dword to the virtualized PCI configuration space, enforcing
    /// read-only masks, Write-1-to-Clear (`W1C`) status bits, and BAR sizing/relocation probes.
    pub fn write_config_dword(&mut self, offset: u8, val: u32) {
        let aligned = (offset & !0x3) as usize;
        if (0x10..0x28).contains(&aligned) {
            let bar_idx = (aligned - 0x10) / 4;
            if let Some(bar) = &mut self.bars[bar_idx] {
                bar.write_bar(val);
                let updated = bar.read_bar();
                self.config_space[aligned..aligned + 4].copy_from_slice(&updated.to_le_bytes());
                return;
            }
        }

        let bytes = val.to_le_bytes();
        for i in 0..4 {
            let pos = aligned + i;
            let w_mask = self.writable_mask[pos];
            let c_mask = self.w1c_mask[pos];
            let mut cur = self.config_space[pos];
            // Apply writable bits
            cur = (cur & !w_mask) | (bytes[i] & w_mask);
            // Apply Write-1-to-Clear bits
            cur &= !(bytes[i] & c_mask);
            self.config_space[pos] = cur;
        }
    }

    /// Configures an MSI-X table entry and returns the active `RemappedMsixRoute` if unmasked.
    pub fn configure_msix_entry(
        &mut self,
        entry_idx: usize,
        msg_addr_lo: u32,
        msg_data: u32,
        masked: bool,
    ) -> Option<RemappedMsixRoute> {
        let entry = self.msix_entries.get_mut(entry_idx)?;
        entry.msg_addr_lo = msg_addr_lo;
        entry.msg_addr_hi = 0;
        entry.msg_data = msg_data;
        entry.vector_ctrl = u32::from(masked);

        if entry.is_masked() {
            return None;
        }
        Some(RemappedMsixRoute {
            entry_index: entry_idx as u16,
            host_irq_vector: self.host_vector_base.wrapping_add(entry_idx as u8),
            guest_apic_id: entry.target_guest_apic_id(),
            guest_vector: entry.target_guest_vector(),
            delivery_mode: ((msg_data >> 8) & 0x7) as u8,
        })
    }

    /// Translates an incoming host physical MSI-X interrupt vector into `(guest_apic_id, guest_vector)`.
    pub fn translate_host_msix_irq(&self, host_vector: u8) -> Option<(u8, u8)> {
        if host_vector < self.host_vector_base {
            return None;
        }
        let idx = (host_vector - self.host_vector_base) as usize;
        let entry = self.msix_entries.get(idx)?;
        if entry.is_masked() {
            return None;
        }
        Some((entry.target_guest_apic_id(), entry.target_guest_vector()))
    }
}
