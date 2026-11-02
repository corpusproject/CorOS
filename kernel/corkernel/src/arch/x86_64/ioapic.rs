//! Intel / AMD I/O Advanced Programmable Interrupt Controller (I/O APIC) Driver
//!
//! Bare-metal no_std pure Rust driver for x86_64 I/O APIC (Intel 82093AA & modern PCH):
//! - Direct MMIO register indexing (IOREGSEL at offset 0x00, IOWIN at offset 0x10)
//! - Redirection Table Entries (24-120 GSIs): Vector, Delivery Mode, Polarity, Trigger, Mask
//! - ACPI MADT Interrupt Source Override (ISO) resolution
//! - Routing of legacy ISA hardware interrupts (PIT, Keyboard, RTC, Mouse) and PCI INTx

#![allow(dead_code)]

use alloc::vec::Vec;

pub const DEFAULT_IOAPIC_BASE: u64 = 0xFEC00000;

// I/O APIC Direct MMIO Register Offsets
pub const IOREGSEL: usize = 0x00;
pub const IOWIN: usize    = 0x10;

// Indirect Register Indices
pub const IOAPIC_ID: u32     = 0x00;
pub const IOAPIC_VER: u32    = 0x01;
pub const IOAPIC_ARB: u32    = 0x02;
pub const IOAPIC_REDTBL_BASE: u32 = 0x10;

// Delivery Modes
pub const DELIVERY_FIXED: u32           = 0b000 << 8;
pub const DELIVERY_LOWEST_PRIORITY: u32 = 0b001 << 8;
pub const DELIVERY_SMI: u32             = 0b010 << 8;
pub const DELIVERY_NMI: u32             = 0b100 << 8;
pub const DELIVERY_INIT: u32            = 0b101 << 8;
pub const DELIVERY_EXTINT: u32          = 0b111 << 8;

// Destination Modes
pub const DEST_PHYSICAL: u32 = 0 << 11;
pub const DEST_LOGICAL: u32  = 1 << 11;

// Trigger & Polarity Modes
pub const POLARITY_ACTIVE_HIGH: u32 = 0 << 13;
pub const POLARITY_ACTIVE_LOW: u32  = 1 << 13;
pub const TRIGGER_EDGE: u32         = 0 << 15;
pub const TRIGGER_LEVEL: u32        = 1 << 15;
pub const MASKED: u32               = 1 << 16;

/// ACPI MADT Interrupt Source Override (ISO) Entry
#[derive(Debug, Clone, Copy)]
pub struct InterruptSourceOverride {
    pub bus_source: u8,
    pub irq_source: u8,
    pub global_system_interrupt: u32,
    pub flags: u16,
}

/// Redirection Table Entry (64-bit)
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    pub vector: u8,
    pub delivery_mode: u32,
    pub dest_mode: u32,
    pub polarity: u32,
    pub trigger: u32,
    pub masked: bool,
    pub destination: u8,
}

impl RedirectionEntry {
    pub fn new(vector: u8, dest_apic_id: u8) -> Self {
        Self {
            vector,
            delivery_mode: DELIVERY_FIXED,
            dest_mode: DEST_PHYSICAL,
            polarity: POLARITY_ACTIVE_HIGH,
            trigger: TRIGGER_EDGE,
            masked: false,
            destination: dest_apic_id,
        }
    }

    pub fn to_raw(&self) -> (u32, u32) {
        let mut low = self.vector as u32
            | self.delivery_mode
            | self.dest_mode
            | self.polarity
            | self.trigger;
        if self.masked {
            low |= MASKED;
        }
        let high = (self.destination as u32) << 24;
        (low, high)
    }

    pub fn from_raw(low: u32, high: u32) -> Self {
        Self {
            vector: (low & 0xFF) as u8,
            delivery_mode: low & (0b111 << 8),
            dest_mode: low & (1 << 11),
            polarity: low & (1 << 13),
            trigger: low & (1 << 15),
            masked: (low & MASKED) != 0,
            destination: (high >> 24) as u8,
        }
    }
}

/// I/O APIC Hardware Controller Instance
pub struct IoApic {
    base_address: u64,
    pub id: u8,
    pub max_redirection_entries: u8,
    pub version: u8,
    pub iso_overrides: Vec<InterruptSourceOverride>,
}

impl IoApic {
    /// Create I/O APIC wrapper from mapped MMIO physical/virtual base address
    pub unsafe fn new(base_address: u64) -> Self {
        let mut ioapic = Self {
            base_address,
            id: 0,
            max_redirection_entries: 24,
            version: 0x11,
            iso_overrides: Vec::new(),
        };

        ioapic.init();
        ioapic
    }

    /// Read 32-bit register from I/O APIC indirect window
    pub unsafe fn read(&self, reg: u32) -> u32 {
        let reg_ptr = self.base_address as *mut u32;
        let win_ptr = (self.base_address + IOWIN as u64) as *mut u32;

        reg_ptr.write_volatile(reg);
        win_ptr.read_volatile()
    }

    /// Write 32-bit register to I/O APIC indirect window
    pub unsafe fn write(&self, reg: u32, val: u32) {
        let reg_ptr = self.base_address as *mut u32;
        let win_ptr = (self.base_address + IOWIN as u64) as *mut u32;

        reg_ptr.write_volatile(reg);
        win_ptr.write_volatile(val);
    }

    fn init(&mut self) {
        unsafe {
            let id_reg = self.read(IOAPIC_ID);
            self.id = ((id_reg >> 24) & 0x0F) as u8;

            let ver_reg = self.read(IOAPIC_VER);
            self.version = (ver_reg & 0xFF) as u8;
            self.max_redirection_entries = (((ver_reg >> 16) & 0xFF) + 1) as u8;

            // Mask all redirection entries by default for safe initialization
            for i in 0..self.max_redirection_entries {
                let reg_low = IOAPIC_REDTBL_BASE + (i as u32) * 2;
                let reg_high = reg_low + 1;
                self.write(reg_low, MASKED);
                self.write(reg_high, 0);
            }
        }
    }

    /// Register ACPI MADT Interrupt Source Override (ISO)
    pub fn add_iso(&mut self, iso: InterruptSourceOverride) {
        self.iso_overrides.push(iso);
    }

    /// Resolve legacy ISA IRQ (0..15) to Global System Interrupt (GSI)
    pub fn resolve_irq_to_gsi(&self, irq: u8) -> (u32, u32, u32) {
        for iso in &self.iso_overrides {
            if iso.irq_source == irq {
                let polarity = if (iso.flags & 0b11) == 0b11 {
                    POLARITY_ACTIVE_LOW
                } else {
                    POLARITY_ACTIVE_HIGH
                };
                let trigger = if ((iso.flags >> 2) & 0b11) == 0b11 {
                    TRIGGER_LEVEL
                } else {
                    TRIGGER_EDGE
                };
                return (iso.global_system_interrupt, polarity, trigger);
            }
        }
        // Default 1:1 mapping for ISA IRQs (Active High, Edge Triggered)
        (irq as u32, POLARITY_ACTIVE_HIGH, TRIGGER_EDGE)
    }

    /// Configure and unmask hardware interrupt routing
    pub unsafe fn set_irq_route(&self, irq: u8, vector: u8, dest_apic_id: u8) {
        let (gsi, polarity, trigger) = self.resolve_irq_to_gsi(irq);
        if gsi >= self.max_redirection_entries as u32 {
            return;
        }

        let mut entry = RedirectionEntry::new(vector, dest_apic_id);
        entry.polarity = polarity;
        entry.trigger = trigger;
        entry.masked = false;

        let (low, high) = entry.to_raw();
        let reg_low = IOAPIC_REDTBL_BASE + gsi * 2;
        let reg_high = reg_low + 1;

        self.write(reg_high, high);
        self.write(reg_low, low);
    }

    /// Mask an interrupt line by GSI
    pub unsafe fn mask_gsi(&self, gsi: u32) {
        if gsi < self.max_redirection_entries as u32 {
            let reg_low = IOAPIC_REDTBL_BASE + gsi * 2;
            let current = self.read(reg_low);
            self.write(reg_low, current | MASKED);
        }
    }

    /// Unmask an interrupt line by GSI
    pub unsafe fn unmask_gsi(&self, gsi: u32) {
        if gsi < self.max_redirection_entries as u32 {
            let reg_low = IOAPIC_REDTBL_BASE + gsi * 2;
            let current = self.read(reg_low);
            self.write(reg_low, current & !MASKED);
        }
    }
}
