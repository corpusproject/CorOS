//! Hardware Debug Registers & Watchpoints (`hw_watchpoints`)
//!
//! Provides x86_64 hardware debug register management (`DR0..DR7`),
//! execution breakpoints, data write/read watchpoints, alignment checking,
//! DR7 control bitmask construction, and DR6 status decode.

extern crate alloc;

use alloc::vec::Vec;

pub const DR6_B0: u64 = 1 << 0;
pub const DR6_B1: u64 = 1 << 1;
pub const DR6_B2: u64 = 1 << 2;
pub const DR6_B3: u64 = 1 << 3;
pub const DR6_BD: u64 = 1 << 13;
pub const DR6_BS: u64 = 1 << 14;
pub const DR6_BT: u64 = 1 << 15;

pub const DR7_LE: u64 = 1 << 8;
pub const DR7_GE: u64 = 1 << 9;
pub const DR7_GD: u64 = 1 << 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchCondition {
    Execute,
    Write,
    IoPort,
    ReadWrite,
}

impl WatchCondition {
    pub const fn to_dr7_bits(self) -> u64 {
        match self {
            Self::Execute => 0b00,
            Self::Write => 0b01,
            Self::IoPort => 0b10,
            Self::ReadWrite => 0b11,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchLength {
    Byte1,
    Byte2,
    Byte8,
    Byte4,
}

impl WatchLength {
    pub const fn to_dr7_bits(self) -> u64 {
        match self {
            Self::Byte1 => 0b00,
            Self::Byte2 => 0b01,
            Self::Byte8 => 0b10,
            Self::Byte4 => 0b11,
        }
    }

    pub const fn alignment(self) -> u64 {
        match self {
            Self::Byte1 => 1,
            Self::Byte2 => 2,
            Self::Byte4 => 4,
            Self::Byte8 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBpError {
    NoFreeSlot,
    InvalidSlot(usize),
    MisalignedAddress { address: u64, needed_align: u64 },
    SlotNotActive(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchpoint {
    pub slot: usize,
    pub address: u64,
    pub condition: WatchCondition,
    pub length: WatchLength,
    pub enabled: bool,
    pub global: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRegistersState {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwBpTriggerEvent {
    BreakpointHit { slot: usize, address: u64, condition: WatchCondition },
    SingleStep,
    GeneralDetect,
}

pub struct HwBreakpointManager {
    slots: [Option<Watchpoint>; 4],
    exact_match: bool,
    general_detect: bool,
}

impl HwBreakpointManager {
    pub fn new() -> Self {
        Self {
            slots: [None, None, None, None],
            exact_match: true,
            general_detect: false,
        }
    }

    pub fn set_watchpoint(
        &mut self,
        address: u64,
        condition: WatchCondition,
        length: WatchLength,
        global: bool,
    ) -> Result<usize, HwBpError> {
        let align = length.alignment();
        if (address & (align - 1)) != 0 {
            return Err(HwBpError::MisalignedAddress {
                address,
                needed_align: align,
            });
        }

        // Find available slot
        let mut target_slot = None;
        for i in 0..4 {
            if self.slots[i].is_none() {
                target_slot = Some(i);
                break;
            }
        }

        let slot = target_slot.ok_or(HwBpError::NoFreeSlot)?;
        self.slots[slot] = Some(Watchpoint {
            slot,
            address,
            condition,
            length,
            enabled: true,
            global,
        });

        Ok(slot)
    }

    pub fn clear_watchpoint(&mut self, slot: usize) -> Result<(), HwBpError> {
        if slot >= 4 {
            return Err(HwBpError::InvalidSlot(slot));
        }
        self.slots[slot] = None;
        Ok(())
    }

    pub fn disable_watchpoint(&mut self, slot: usize) -> Result<(), HwBpError> {
        if slot >= 4 {
            return Err(HwBpError::InvalidSlot(slot));
        }
        let wp = self.slots[slot].as_mut().ok_or(HwBpError::SlotNotActive(slot))?;
        wp.enabled = false;
        Ok(())
    }

    pub fn enable_watchpoint(&mut self, slot: usize) -> Result<(), HwBpError> {
        if slot >= 4 {
            return Err(HwBpError::InvalidSlot(slot));
        }
        let wp = self.slots[slot].as_mut().ok_or(HwBpError::SlotNotActive(slot))?;
        wp.enabled = true;
        Ok(())
    }

    pub fn compute_dr7(&self) -> u64 {
        let mut dr7 = 0u64;

        if self.exact_match {
            dr7 |= DR7_LE | DR7_GE;
        }
        if self.general_detect {
            dr7 |= DR7_GD;
        }

        for (i, opt) in self.slots.iter().enumerate() {
            if let Some(wp) = opt {
                if !wp.enabled {
                    continue;
                }

                // Enable bits (bits 0..7)
                if wp.global {
                    dr7 |= 1u64 << (i * 2 + 1); // G0..G3
                } else {
                    dr7 |= 1u64 << (i * 2);     // L0..L3
                }

                // RW field (bits 16, 20, 24, 28)
                let rw = wp.condition.to_dr7_bits();
                dr7 |= rw << (16 + i * 4);

                // LEN field (bits 18, 22, 26, 30)
                let len = wp.length.to_dr7_bits();
                dr7 |= len << (18 + i * 4);
            }
        }

        dr7
    }

    pub fn get_hardware_state(&self) -> DebugRegistersState {
        let dr0 = self.slots[0].map(|w| w.address).unwrap_or(0);
        let dr1 = self.slots[1].map(|w| w.address).unwrap_or(0);
        let dr2 = self.slots[2].map(|w| w.address).unwrap_or(0);
        let dr3 = self.slots[3].map(|w| w.address).unwrap_or(0);
        let dr7 = self.compute_dr7();

        DebugRegistersState {
            dr0,
            dr1,
            dr2,
            dr3,
            dr6: 0xFFFF_0FF0, // initial reserved bit state
            dr7,
        }
    }

    pub fn decode_db_status(&self, dr6: u64) -> Vec<HwBpTriggerEvent> {
        let mut events = Vec::new();

        for i in 0..4 {
            if (dr6 & (1u64 << i)) != 0 {
                if let Some(wp) = self.slots[i] {
                    events.push(HwBpTriggerEvent::BreakpointHit {
                        slot: i,
                        address: wp.address,
                        condition: wp.condition,
                    });
                }
            }
        }

        if (dr6 & DR6_BS) != 0 {
            events.push(HwBpTriggerEvent::SingleStep);
        }

        if (dr6 & DR6_BD) != 0 {
            events.push(HwBpTriggerEvent::GeneralDetect);
        }

        events
    }
}

pub fn verify_hw_watchpoints() -> u32 {
    let mut check_count = 0u32;

    let mut mgr = HwBreakpointManager::new();

    // Test 1: Set DR0 execution breakpoint
    let s0 = mgr.set_watchpoint(0x401000, WatchCondition::Execute, WatchLength::Byte1, false);
    if s0 == Ok(0) {
        check_count += 1;
    }

    // Test 2: Set DR1 data write watchpoint (4 bytes, aligned)
    let s1 = mgr.set_watchpoint(0x602004, WatchCondition::Write, WatchLength::Byte4, false);
    if s1 == Ok(1) {
        check_count += 1;
    }

    // Test 3: Set DR2 read/write watchpoint (8 bytes, aligned)
    let s2 = mgr.set_watchpoint(0x603008, WatchCondition::ReadWrite, WatchLength::Byte8, true);
    if s2 == Ok(2) {
        check_count += 1;
    }

    // Test 4: Misaligned address error check
    let s_err = mgr.set_watchpoint(0x603003, WatchCondition::Write, WatchLength::Byte4, false);
    if let Err(HwBpError::MisalignedAddress { address, needed_align }) = s_err {
        if address == 0x603003 && needed_align == 4 {
            check_count += 1;
        }
    }

    // Test 5: Verify DR7 bit computation
    let dr7 = mgr.compute_dr7();
    // L0 (bit 0) set, G1 (bit 3) not set (L1 bit 2 is set), G2 (bit 5) set
    let l0_set = (dr7 & 1) != 0;
    let l1_set = (dr7 & (1 << 2)) != 0;
    let g2_set = (dr7 & (1 << 5)) != 0;

    // Slot 0: Execute (00), Len 1 (00) -> bits 16..19 = 0
    // Slot 1: Write (01), Len 4 (11) -> bits 20..23 = (01) | (11 << 2) = 1 | 12 = 13 (0xD)
    let slot1_rw_len = (dr7 >> 20) & 0xF;
    // Slot 2: ReadWrite (11), Len 8 (10) -> bits 24..27 = (11) | (10 << 2) = 3 | 8 = 11 (0xB)
    let slot2_rw_len = (dr7 >> 24) & 0xF;

    if l0_set && l1_set && g2_set && slot1_rw_len == 0xD && slot2_rw_len == 0xB {
        check_count += 1;
    }

    // Test 6: Decode DR6 status register
    // Simulate trigger on DR0 and DR2 plus single step
    let mock_dr6 = DR6_B0 | DR6_B2 | DR6_BS;
    let events = mgr.decode_db_status(mock_dr6);
    if events.len() == 3 {
        let has_s0 = events.iter().any(|e| matches!(e, HwBpTriggerEvent::BreakpointHit { slot: 0, .. }));
        let has_s2 = events.iter().any(|e| matches!(e, HwBpTriggerEvent::BreakpointHit { slot: 2, .. }));
        let has_step = events.iter().any(|e| matches!(e, HwBpTriggerEvent::SingleStep));
        if has_s0 && has_s2 && has_step {
            check_count += 1;
        }
    }

    // Test 7: Slot exhaustion and deallocation
    // Fill slot 3
    let s3 = mgr.set_watchpoint(0x7000, WatchCondition::Execute, WatchLength::Byte1, false);
    if s3 == Ok(3) {
        // 5th attempt must fail
        let s4 = mgr.set_watchpoint(0x8000, WatchCondition::Execute, WatchLength::Byte1, false);
        if s4 == Err(HwBpError::NoFreeSlot) {
            check_count += 1;
        }
    }

    // Clear slot 1 and reallocate
    let clr = mgr.clear_watchpoint(1);
    let s1_new = mgr.set_watchpoint(0x605000, WatchCondition::Write, WatchLength::Byte2, false);
    if clr.is_ok() && s1_new == Ok(1) {
        check_count += 1;
    }

    check_count
}
