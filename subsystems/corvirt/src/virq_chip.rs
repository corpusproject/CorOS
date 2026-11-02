//! In-kernel Virtual Interrupt Controller (`vIRQChip`) emulating:
//! - Dual 8259A Programmable Interrupt Controller (`Master` & `Slave` PIC, ICW1..ICW4, IRR/ISR/IMR)
//! - 24-entry I/O APIC redirection table (`IoApicRedirEntry`)
//! - Per-vCPU Local APIC (`IRR`, `ISR`, `TPR`, `PPR`, `EOI`, and `ICR` Inter-Processor Interrupts)

/// Initialization state machine for a single Intel 8259A PIC chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicInitState {
    Ready,
    ExpectingIcw2,
    ExpectingIcw3,
    ExpectingIcw4,
}

/// Emulated single Intel 8259A Programmable Interrupt Controller (Master or Slave).
#[derive(Debug, Clone)]
pub struct Pic8259Chip {
    pub irr: u8,
    pub isr: u8,
    pub imr: u8,
    pub vector_offset: u8,
    pub cascade_mask: u8,
    pub auto_eoi: bool,
    pub read_isr_on_cmd: bool,
    pub init_state: PicInitState,
    pub icw4_needed: bool,
}

impl Pic8259Chip {
    pub const fn new(default_vector_offset: u8) -> Self {
        Self {
            irr: 0,
            isr: 0,
            imr: 0xFF,
            vector_offset: default_vector_offset,
            cascade_mask: 0x04,
            auto_eoi: false,
            read_isr_on_cmd: false,
            init_state: PicInitState::Ready,
            icw4_needed: false,
        }
    }

    /// Writes to the PIC command port (`0x20` for Master, `0xA0` for Slave).
    pub fn write_command(&mut self, val: u8) {
        if (val & 0x10) != 0 {
            // ICW1 initialization sequence start
            self.irr = 0;
            self.isr = 0;
            self.imr = 0;
            self.icw4_needed = (val & 0x01) != 0;
            self.init_state = PicInitState::ExpectingIcw2;
        } else if (val & 0x18) == 0x08 {
            // OCW3: select IRR (`0x0A`) or ISR (`0x0B`) read mode
            if (val & 0x02) != 0 {
                self.read_isr_on_cmd = (val & 0x01) != 0;
            }
        } else if (val & 0x18) == 0x00 {
            // OCW2: EOI commands
            let eoi_cmd = (val >> 5) & 0x07;
            match eoi_cmd {
                0b001 => {
                    // Non-specific EOI: clear highest priority bit in ISR
                    if self.isr != 0 {
                        let highest_irq = self.isr.trailing_zeros() as u8;
                        self.isr &= !(1 << highest_irq);
                    }
                }
                0b011 => {
                    // Specific EOI: low 3 bits specify IRQ line
                    let target_irq = val & 0x07;
                    self.isr &= !(1 << target_irq);
                }
                _ => {}
            }
        }
    }

    /// Writes to the PIC data port (`0x21` for Master, `0xA1` for Slave).
    pub fn write_data(&mut self, val: u8) {
        match self.init_state {
            PicInitState::ExpectingIcw2 => {
                self.vector_offset = val & 0xF8;
                self.init_state = PicInitState::ExpectingIcw3;
            }
            PicInitState::ExpectingIcw3 => {
                self.cascade_mask = val;
                self.init_state = if self.icw4_needed {
                    PicInitState::ExpectingIcw4
                } else {
                    PicInitState::Ready
                };
            }
            PicInitState::ExpectingIcw4 => {
                self.auto_eoi = (val & 0x02) != 0;
                self.init_state = PicInitState::Ready;
            }
            PicInitState::Ready => {
                self.imr = val;
            }
        }
    }

    /// Reads from the command port (returns ISR or IRR according to OCW3).
    pub fn read_command(&self) -> u8 {
        if self.read_isr_on_cmd {
            self.isr
        } else {
            self.irr
        }
    }

    /// Reads from the data port (returns the Interrupt Mask Register `IMR`).
    pub fn read_data(&self) -> u8 {
        self.imr
    }

    /// Returns the highest-priority unmasked pending IRQ (`0..=7`) if it outranks any in-service IRQ.
    pub fn highest_deliverable_irq(&self) -> Option<u8> {
        let deliverable = self.irr & !self.imr;
        if deliverable == 0 {
            return None;
        }
        let candidate = deliverable.trailing_zeros() as u8;
        if self.isr != 0 {
            let in_service_prio = self.isr.trailing_zeros() as u8;
            if candidate >= in_service_prio {
                return None;
            }
        }
        Some(candidate)
    }
}

/// Dual cascaded 8259A PIC (`Master` IRQ 0..7 + `Slave` IRQ 8..15 cascaded on Master IRQ 2).
#[derive(Debug, Clone)]
pub struct DualPic8259 {
    pub master: Pic8259Chip,
    pub slave: Pic8259Chip,
}

impl DualPic8259 {
    pub const fn new() -> Self {
        Self {
            master: Pic8259Chip::new(0x08),
            slave: Pic8259Chip::new(0x70),
        }
    }

    /// Raises an ISA IRQ line (`0..=15`).
    pub fn raise_irq(&mut self, irq: u8) {
        if irq < 8 {
            self.master.irr |= 1 << irq;
        } else if irq < 16 {
            let slave_line = irq - 8;
            self.slave.irr |= 1 << slave_line;
            if self.slave.highest_deliverable_irq().is_some() {
                // Assert cascade line IRQ 2 on Master PIC
                self.master.irr |= 1 << 2;
            }
        }
    }

    /// Acknowledges (`INTA`) and returns the CPU interrupt vector for the highest-priority pending PIC IRQ.
    pub fn acknowledge_irq(&mut self) -> Option<u8> {
        let master_irq = self.master.highest_deliverable_irq()?;
        self.master.irr &= !(1 << master_irq);
        if !self.master.auto_eoi {
            self.master.isr |= 1 << master_irq;
        }

        if master_irq == 2 {
            if let Some(slave_irq) = self.slave.highest_deliverable_irq() {
                self.slave.irr &= !(1 << slave_irq);
                if !self.slave.auto_eoi {
                    self.slave.isr |= 1 << slave_irq;
                }
                return Some(self.slave.vector_offset + slave_irq);
            }
        }
        Some(self.master.vector_offset + master_irq)
    }
}

/// I/O APIC 64-bit Redirection Table Entry (`IOREDTBL0..23`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicRedirEntry {
    pub raw: u64,
}

impl IoApicRedirEntry {
    /// Default masked redirection entry (`bit 16 = 1`).
    pub const fn masked_default() -> Self {
        Self { raw: 1 << 16 }
    }

    pub const fn vector(self) -> u8 {
        (self.raw & 0xFF) as u8
    }

    pub const fn delivery_mode(self) -> u8 {
        ((self.raw >> 8) & 0x7) as u8
    }

    pub const fn is_logical_dest(self) -> bool {
        ((self.raw >> 11) & 1) != 0
    }

    pub const fn is_level_triggered(self) -> bool {
        ((self.raw >> 15) & 1) != 0
    }

    pub const fn is_masked(self) -> bool {
        ((self.raw >> 16) & 1) != 0
    }

    pub const fn dest_apic_id(self) -> u8 {
        ((self.raw >> 56) & 0xFF) as u8
    }
}

/// Emulated 24-pin Intel I/O APIC (`0xFEC0_0000`).
#[derive(Debug, Clone)]
pub struct VirtualIoApic {
    pub id: u8,
    pub index_reg: u8,
    pub irr_pins: u32,
    pub redir_table: [IoApicRedirEntry; 24],
}

impl VirtualIoApic {
    pub const fn new(id: u8) -> Self {
        Self {
            id,
            index_reg: 0,
            irr_pins: 0,
            redir_table: [IoApicRedirEntry::masked_default(); 24],
        }
    }

    /// Writes a 32-bit MMIO value to `IOREGSEL` (`offset 0x00`) or `IOWIN` (`offset 0x10`).
    pub fn mmio_write(&mut self, offset: u64, val: u32) {
        match offset & 0xFF {
            0x00 => {
                self.index_reg = (val & 0xFF) as u8;
            }
            0x10 => match self.index_reg {
                0x00 => self.id = ((val >> 24) & 0x0F) as u8,
                0x10..=0x3F => {
                    let reg_offset = (self.index_reg - 0x10) as usize;
                    let pin = reg_offset / 2;
                    if pin < 24 {
                        if (reg_offset & 1) == 0 {
                            self.redir_table[pin].raw =
                                (self.redir_table[pin].raw & 0xFFFF_FFFF_0000_0000) | (val as u64);
                        } else {
                            self.redir_table[pin].raw =
                                (self.redir_table[pin].raw & 0x0000_0000_FFFF_FFFF)
                                    | ((val as u64) << 32);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Reads a 32-bit MMIO value from `IOREGSEL` (`offset 0x00`) or `IOWIN` (`offset 0x10`).
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset & 0xFF {
            0x00 => self.index_reg as u32,
            0x10 => match self.index_reg {
                0x00 => (self.id as u32) << 24,
                0x01 => (23 << 16) | 0x20, // Version 0x20, 24 redirection entries (max index 23)
                0x02 => (self.id as u32) << 24,
                0x10..=0x3F => {
                    let reg_offset = (self.index_reg - 0x10) as usize;
                    let pin = reg_offset / 2;
                    if pin < 24 {
                        if (reg_offset & 1) == 0 {
                            self.redir_table[pin].raw as u32
                        } else {
                            (self.redir_table[pin].raw >> 32) as u32
                        }
                    } else {
                        0
                    }
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    /// Asserts an I/O APIC input pin (`0..24`) and returns `(dest_apic_id, vector)` if unmasked.
    pub fn assert_pin(&mut self, pin: usize) -> Option<(u8, u8)> {
        if pin >= 24 {
            return None;
        }
        self.irr_pins |= 1 << pin;
        let entry = self.redir_table[pin];
        if entry.is_masked() || entry.vector() < 16 {
            return None;
        }
        Some((entry.dest_apic_id(), entry.vector()))
    }
}

/// Decoded Inter-Processor Interrupt (`IPI`) command generated via Local APIC `ICR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpiCommand {
    pub target_apic_id: u8,
    pub vector: u8,
    pub delivery_mode: u8,
    pub shorthand: u8,
}

/// Per-vCPU Local APIC (`LAPIC`) with 256-bit `IRR`, `ISR`, `TMR`, `TPR`, `PPR`, `EOI`, and `ICR`.
#[derive(Debug, Clone)]
pub struct VirtualLocalApic {
    pub apic_id: u8,
    pub irr: [u32; 8],
    pub isr: [u32; 8],
    pub tmr: [u32; 8],
    pub tpr: u8,
    pub svr: u32,
    pub lvt_timer: u32,
    pub timer_init_count: u32,
    pub timer_current_count: u32,
    pub timer_divide_config: u32,
    pub icr_low: u32,
    pub icr_high: u32,
}

impl VirtualLocalApic {
    pub const fn new(apic_id: u8) -> Self {
        Self {
            apic_id,
            irr: [0; 8],
            isr: [0; 8],
            tmr: [0; 8],
            tpr: 0,
            svr: 0x0000_01FF, // Software APIC enabled, spurious vector 0xFF
            lvt_timer: 1 << 16,
            timer_init_count: 0,
            timer_current_count: 0,
            timer_divide_config: 0,
            icr_low: 0,
            icr_high: 0,
        }
    }

    /// Returns the highest set bit (`16..=255`) in an 8x32-bit APIC register array.
    fn highest_bit_256(bitmap: &[u32; 8]) -> Option<u8> {
        for word_idx in (0..8).rev() {
            let word = bitmap[word_idx];
            if word != 0 {
                let bit_in_word = 31 - word.leading_zeros() as u8;
                let vec = (word_idx as u8) * 32 + bit_in_word;
                if vec >= 16 {
                    return Some(vec);
                }
            }
        }
        None
    }

    /// Computes the Processor Priority Register (`PPR`) from `TPR` and the highest in-service vector `ISRV`.
    pub fn compute_ppr(&self) -> u8 {
        let tpr_class = self.tpr & 0xF0;
        let isrv_class = Self::highest_bit_256(&self.isr)
            .map(|v| v & 0xF0)
            .unwrap_or(0);
        tpr_class.max(isrv_class)
    }

    /// Injects an interrupt vector (`16..=255`) into the Local APIC `IRR`.
    pub fn accept_interrupt(&mut self, vector: u8, level_triggered: bool) {
        if vector < 16 || (self.svr & 0x100) == 0 {
            return;
        }
        let word = (vector / 32) as usize;
        let bit = vector % 32;
        self.irr[word] |= 1u32 << bit;
        if level_triggered {
            self.tmr[word] |= 1u32 << bit;
        } else {
            self.tmr[word] &= !(1u32 << bit);
        }
    }

    /// Evaluates whether the highest pending `IRR` vector outranks `PPR`; if so, moves it from `IRR` to `ISR`.
    pub fn claim_deliverable_vector(&mut self) -> Option<u8> {
        let irrv = Self::highest_bit_256(&self.irr)?;
        let ppr = self.compute_ppr();
        if (irrv & 0xF0) <= (ppr & 0xF0) {
            return None;
        }
        let word = (irrv / 32) as usize;
        let bit = irrv % 32;
        self.irr[word] &= !(1u32 << bit);
        self.isr[word] |= 1u32 << bit;
        Some(irrv)
    }

    /// Performs End-Of-Interrupt (`EOI`), clearing the highest-priority bit in `ISR`.
    pub fn write_eoi(&mut self) -> Option<u8> {
        let isrv = Self::highest_bit_256(&self.isr)?;
        let word = (isrv / 32) as usize;
        let bit = isrv % 32;
        self.isr[word] &= !(1u32 << bit);
        Some(isrv)
    }

    /// Formats an Inter-Processor Interrupt (`IPI`) by writing `icr_high` and `icr_low`.
    pub fn write_icr(&mut self, icr_high: u32, icr_low: u32) -> IpiCommand {
        self.icr_high = icr_high;
        self.icr_low = icr_low & !(1 << 12); // Delivery status bit cleared on completion
        IpiCommand {
            target_apic_id: ((icr_high >> 24) & 0xFF) as u8,
            vector: (icr_low & 0xFF) as u8,
            delivery_mode: ((icr_low >> 8) & 0x7) as u8,
            shorthand: ((icr_low >> 18) & 0x3) as u8,
        }
    }
}
