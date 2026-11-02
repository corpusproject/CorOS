//! DWARF Call Frame Information (`.eh_frame`) Unwinder (`dwarf_unwind`)
//!
//! Provides parsing of Common Information Entries (CIE), Frame Description Entries (FDE),
//! CFA (Canonical Frame Address) rule evaluation, and x86_64 stack frame unwinding.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const DWARF_REG_RAX: u8 = 0;
pub const DWARF_REG_RDX: u8 = 1;
pub const DWARF_REG_RCX: u8 = 2;
pub const DWARF_REG_RBX: u8 = 3;
pub const DWARF_REG_RSI: u8 = 4;
pub const DWARF_REG_RDI: u8 = 5;
pub const DWARF_REG_RBP: u8 = 6;
pub const DWARF_REG_RSP: u8 = 7;
pub const DWARF_REG_R8: u8 = 8;
pub const DWARF_REG_R9: u8 = 9;
pub const DWARF_REG_R10: u8 = 10;
pub const DWARF_REG_R11: u8 = 11;
pub const DWARF_REG_R12: u8 = 12;
pub const DWARF_REG_R13: u8 = 13;
pub const DWARF_REG_R14: u8 = 14;
pub const DWARF_REG_R15: u8 = 15;
pub const DWARF_REG_RIP: u8 = 16;

pub const DW_CFA_NOP: u8 = 0x00;
pub const DW_CFA_SET_LOC: u8 = 0x01;
pub const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
pub const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
pub const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
pub const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
pub const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
pub const DW_CFA_UNDEFINED: u8 = 0x07;
pub const DW_CFA_SAME_VALUE: u8 = 0x08;
pub const DW_CFA_REGISTER: u8 = 0x09;
pub const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
pub const DW_CFA_RESTORE_STATE: u8 = 0x0b;
pub const DW_CFA_DEF_CFA: u8 = 0x0c;
pub const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
pub const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
pub const DW_CFA_DEF_CFA_SF: u8 = 0x12;
pub const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindError {
    EndOfStream,
    InvalidLeb128,
    NoFdeFound(u64),
    UnsupportedInstruction(u8),
    EmptyStack,
    MemoryReadFailed(u64),
    InvalidCfa,
}

pub fn read_uleb128(bytes: &[u8], offset: &mut usize) -> Result<u64, UnwindError> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *offset >= bytes.len() {
            return Err(UnwindError::EndOfStream);
        }
        let byte = bytes[*offset];
        *offset += 1;

        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 64 {
            return Err(UnwindError::InvalidLeb128);
        }
    }
    Ok(result)
}

pub fn read_sleb128(bytes: &[u8], offset: &mut usize) -> Result<i64, UnwindError> {
    let mut result = 0i64;
    let mut shift = 0;
    let mut byte;
    loop {
        if *offset >= bytes.len() {
            return Err(UnwindError::EndOfStream);
        }
        byte = bytes[*offset];
        *offset += 1;

        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift > 64 {
            return Err(UnwindError::InvalidLeb128);
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfaRule {
    RegisterAndOffset { register: u8, offset: i64 },
    Expression(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterRule {
    Undefined,
    SameValue,
    Offset(i64),
    ValOffset(i64),
    Register(u8),
}

#[derive(Debug, Clone)]
pub struct UnwindRow {
    pub location: u64,
    pub cfa: CfaRule,
    pub registers: BTreeMap<u8, RegisterRule>,
}

impl UnwindRow {
    pub fn new(location: u64) -> Self {
        Self {
            location,
            cfa: CfaRule::RegisterAndOffset {
                register: DWARF_REG_RSP,
                offset: 8,
            },
            registers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommonInformationEntry {
    pub code_alignment_factor: u64,
    pub data_alignment_factor: i64,
    pub return_address_register: u8,
    pub initial_instructions: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FrameDescriptionEntry {
    pub initial_location: u64,
    pub address_range: u64,
    pub instructions: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnwindRegisters {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl UnwindRegisters {
    pub fn get(&self, reg: u8) -> u64 {
        match reg {
            DWARF_REG_RIP => self.rip,
            DWARF_REG_RSP => self.rsp,
            DWARF_REG_RBP => self.rbp,
            DWARF_REG_RBX => self.rbx,
            DWARF_REG_R12 => self.r12,
            DWARF_REG_R13 => self.r13,
            DWARF_REG_R14 => self.r14,
            DWARF_REG_R15 => self.r15,
            _ => 0,
        }
    }

    pub fn set(&mut self, reg: u8, val: u64) {
        match reg {
            DWARF_REG_RIP => self.rip = val,
            DWARF_REG_RSP => self.rsp = val,
            DWARF_REG_RBP => self.rbp = val,
            DWARF_REG_RBX => self.rbx = val,
            DWARF_REG_R12 => self.r12 = val,
            DWARF_REG_R13 => self.r13 = val,
            DWARF_REG_R14 => self.r14 = val,
            DWARF_REG_R15 => self.r15 = val,
            _ => {}
        }
    }
}

pub trait MemoryReader {
    fn read_u64(&self, addr: u64) -> Result<u64, UnwindError>;
}

pub struct SimpleMemorySlice<'a> {
    pub base_addr: u64,
    pub data: &'a [u8],
}

impl<'a> MemoryReader for SimpleMemorySlice<'a> {
    fn read_u64(&self, addr: u64) -> Result<u64, UnwindError> {
        if addr < self.base_addr {
            return Err(UnwindError::MemoryReadFailed(addr));
        }
        let offset = (addr - self.base_addr) as usize;
        if offset + 8 > self.data.len() {
            return Err(UnwindError::MemoryReadFailed(addr));
        }
        Ok(u64::from_le_bytes(self.data[offset..offset + 8].try_into().unwrap()))
    }
}

pub struct EhFrameTable {
    pub cie: CommonInformationEntry,
    pub fdes: Vec<FrameDescriptionEntry>,
}

impl EhFrameTable {
    pub fn new(cie: CommonInformationEntry) -> Self {
        Self {
            cie,
            fdes: Vec::new(),
        }
    }

    pub fn add_fde(&mut self, fde: FrameDescriptionEntry) {
        self.fdes.push(fde);
    }

    pub fn find_fde(&self, pc: u64) -> Option<&FrameDescriptionEntry> {
        self.fdes.iter().find(|fde| {
            pc >= fde.initial_location && pc < fde.initial_location + fde.address_range
        })
    }

    pub fn evaluate_row_at(&self, pc: u64) -> Result<UnwindRow, UnwindError> {
        let fde = self.find_fde(pc).ok_or(UnwindError::NoFdeFound(pc))?;

        let mut row = UnwindRow::new(fde.initial_location);
        let mut state_stack = Vec::new();

        // 1. Run CIE initial instructions
        self.execute_cfi_stream(
            &self.cie.initial_instructions,
            &mut row,
            &mut state_stack,
            u64::MAX, // evaluate all initial instructions
        )?;

        // 2. Run FDE instructions up to target PC
        self.execute_cfi_stream(
            &fde.instructions,
            &mut row,
            &mut state_stack,
            pc,
        )?;

        Ok(row)
    }

    fn execute_cfi_stream(
        &self,
        instructions: &[u8],
        row: &mut UnwindRow,
        stack: &mut Vec<UnwindRow>,
        target_pc: u64,
    ) -> Result<(), UnwindError> {
        let mut offset = 0;
        let mut loc = row.location;

        while offset < instructions.len() {
            if loc > target_pc {
                break;
            }

            let op = instructions[offset];
            offset += 1;

            let high2 = op & 0xc0;
            match high2 {
                0x40 => {
                    // DW_CFA_advance_loc (delta = op & 0x3f)
                    let delta = (op & 0x3f) as u64 * self.cie.code_alignment_factor;
                    if loc + delta > target_pc {
                        break;
                    }
                    loc += delta;
                    row.location = loc;
                    continue;
                }
                0x80 => {
                    // DW_CFA_offset (reg = op & 0x3f, uleb128 offset)
                    let reg = op & 0x3f;
                    let off_val = read_uleb128(instructions, &mut offset)?;
                    let scaled = (off_val as i64) * self.cie.data_alignment_factor;
                    row.registers.insert(reg, RegisterRule::Offset(scaled));
                    continue;
                }
                0xc0 => {
                    // DW_CFA_restore (reg = op & 0x3f)
                    let reg = op & 0x3f;
                    row.registers.remove(&reg);
                    continue;
                }
                _ => {}
            }

            match op {
                DW_CFA_NOP => {}
                DW_CFA_ADVANCE_LOC1 => {
                    if offset >= instructions.len() {
                        return Err(UnwindError::EndOfStream);
                    }
                    let delta = instructions[offset] as u64 * self.cie.code_alignment_factor;
                    offset += 1;
                    if loc + delta > target_pc {
                        break;
                    }
                    loc += delta;
                    row.location = loc;
                }
                DW_CFA_ADVANCE_LOC2 => {
                    if offset + 2 > instructions.len() {
                        return Err(UnwindError::EndOfStream);
                    }
                    let delta = u16::from_le_bytes(instructions[offset..offset + 2].try_into().unwrap()) as u64
                        * self.cie.code_alignment_factor;
                    offset += 2;
                    if loc + delta > target_pc {
                        break;
                    }
                    loc += delta;
                    row.location = loc;
                }
                DW_CFA_DEF_CFA => {
                    let reg = read_uleb128(instructions, &mut offset)? as u8;
                    let off = read_uleb128(instructions, &mut offset)? as i64;
                    row.cfa = CfaRule::RegisterAndOffset { register: reg, offset: off };
                }
                DW_CFA_DEF_CFA_REGISTER => {
                    let reg = read_uleb128(instructions, &mut offset)? as u8;
                    if let CfaRule::RegisterAndOffset { offset: off, .. } = row.cfa {
                        row.cfa = CfaRule::RegisterAndOffset { register: reg, offset: off };
                    }
                }
                DW_CFA_DEF_CFA_OFFSET => {
                    let off = read_uleb128(instructions, &mut offset)? as i64;
                    if let CfaRule::RegisterAndOffset { register: reg, .. } = row.cfa {
                        row.cfa = CfaRule::RegisterAndOffset { register: reg, offset: off };
                    }
                }
                DW_CFA_OFFSET_EXTENDED => {
                    let reg = read_uleb128(instructions, &mut offset)? as u8;
                    let off_val = read_uleb128(instructions, &mut offset)?;
                    let scaled = (off_val as i64) * self.cie.data_alignment_factor;
                    row.registers.insert(reg, RegisterRule::Offset(scaled));
                }
                DW_CFA_REMEMBER_STATE => {
                    stack.push(row.clone());
                }
                DW_CFA_RESTORE_STATE => {
                    let saved = stack.pop().ok_or(UnwindError::EmptyStack)?;
                    *row = saved;
                }
                other => return Err(UnwindError::UnsupportedInstruction(other)),
            }
        }

        Ok(())
    }

    pub fn step_frame(
        &self,
        current: &UnwindRegisters,
        memory: &dyn MemoryReader,
    ) -> Result<UnwindRegisters, UnwindError> {
        let row = self.evaluate_row_at(current.rip)?;

        // 1. Calculate CFA
        let cfa_val = match &row.cfa {
            CfaRule::RegisterAndOffset { register, offset } => {
                let base = current.get(*register);
                (base as i64).wrapping_add(*offset) as u64
            }
            CfaRule::Expression(_) => return Err(UnwindError::InvalidCfa),
        };

        let mut caller = *current;

        // Caller RSP is precisely the CFA value
        caller.rsp = cfa_val;

        // 2. Restore return address (RIP)
        let ret_rule = row.registers.get(&self.cie.return_address_register).unwrap_or(&RegisterRule::Offset(-8));
        match ret_rule {
            RegisterRule::Offset(off) => {
                let addr = (cfa_val as i64).wrapping_add(*off) as u64;
                caller.rip = memory.read_u64(addr)?;
            }
            _ => return Err(UnwindError::InvalidCfa),
        }

        // 3. Restore callee-saved registers
        for (&reg, rule) in &row.registers {
            if reg == self.cie.return_address_register {
                continue;
            }
            match rule {
                RegisterRule::Offset(off) => {
                    let addr = (cfa_val as i64).wrapping_add(*off) as u64;
                    let val = memory.read_u64(addr)?;
                    caller.set(reg, val);
                }
                RegisterRule::SameValue => {}
                RegisterRule::Undefined => {}
                _ => {}
            }
        }

        Ok(caller)
    }
}

pub fn verify_dwarf_unwind() -> u32 {
    let mut check_count = 0u32;

    // Test 1: ULEB128 decoding
    let uleb_bytes = [0xE5, 0x8E, 0x26]; // 624485
    let mut off = 0;
    if let Ok(val) = read_uleb128(&uleb_bytes, &mut off) {
        if val == 624485 && off == 3 {
            check_count += 1;
        }
    }

    // Test 2: SLEB128 decoding (-624485)
    let sleb_bytes = [0x9B, 0xF1, 0x59];
    let mut off2 = 0;
    if let Ok(val) = read_sleb128(&sleb_bytes, &mut off2) {
        if val == -624485 && off2 == 3 {
            check_count += 1;
        }
    }

    // Test 3: Construct CIE and FDE for standard function
    // Initial: CFA = RSP + 8; RIP = *(CFA - 8)
    let cie_instrs = alloc::vec![
        DW_CFA_DEF_CFA, DWARF_REG_RSP, 8, // CFA = RSP + 8
        0x80 | DWARF_REG_RIP, 1,          // offset RIP at -8 (1 * -8)
    ];

    let cie = CommonInformationEntry {
        code_alignment_factor: 1,
        data_alignment_factor: -8,
        return_address_register: DWARF_REG_RIP,
        initial_instructions: cie_instrs,
    };

    let mut eh_table = EhFrameTable::new(cie);

    // Function at 0x401000..0x401050
    // Prologue:
    // 0x401000: push rbp       (len 1) -> CFA is RSP + 16, RBP is at CFA - 16
    // 0x401001: mov rbp, rsp   (len 3) -> CFA is RBP + 16
    // 0x401004: sub rsp, 32
    let fde_instrs = alloc::vec![
        0x41,                           // DW_CFA_advance_loc 1 (to 0x401001)
        DW_CFA_DEF_CFA_OFFSET, 16,      // CFA = RSP + 16
        0x80 | DWARF_REG_RBP, 2,        // RBP at -16 (2 * -8)
        0x43,                           // DW_CFA_advance_loc 3 (to 0x401004)
        DW_CFA_DEF_CFA_REGISTER, DWARF_REG_RBP, // CFA = RBP + 16
    ];

    let fde = FrameDescriptionEntry {
        initial_location: 0x401000,
        address_range: 0x50,
        instructions: fde_instrs,
    };
    eh_table.add_fde(fde);

    // Test 4: Evaluate row at function entry (0x401000)
    if let Ok(row0) = eh_table.evaluate_row_at(0x401000) {
        if let CfaRule::RegisterAndOffset { register, offset } = row0.cfa {
            if register == DWARF_REG_RSP && offset == 8 {
                check_count += 1;
            }
        }
    }

    // Test 5: Evaluate row inside function body (0x401010)
    if let Ok(row_body) = eh_table.evaluate_row_at(0x401010) {
        if let CfaRule::RegisterAndOffset { register, offset } = row_body.cfa {
            if register == DWARF_REG_RBP && offset == 16 {
                check_count += 1;
            }
        }
        if let Some(RegisterRule::Offset(off)) = row_body.registers.get(&DWARF_REG_RBP) {
            if *off == -16 {
                check_count += 1;
            }
        }
    }

    // Test 6: Frame stepping / unwinding
    // Setup mock stack frame:
    // Caller RSP = 0x7fffffffe000
    // Callee called from 0x402500 -> Return address on stack = 0x402500 at 0x7fffffffdff8
    // Callee executes:
    // push rbp -> saved RBP (e.g. 0x7fffffffe050) at 0x7fffffffdff0
    // mov rbp, rsp -> RBP = 0x7fffffffdff0
    // sub rsp, 32 -> RSP = 0x7fffffffdfe0
    // Current RIP = 0x401020

    let mut stack_mem = [0u8; 128];
    // Base of our slice is 0x7fffffffdfe0
    let base = 0x7fff_ffff_dfe0u64;
    // Offset for saved RBP (at 0x7fffffffdff0): offset = 0x10 (16 bytes)
    stack_mem[16..24].copy_from_slice(&0x7fff_ffff_e050u64.to_le_bytes());
    // Offset for saved RIP (at 0x7fffffffdff8): offset = 0x18 (24 bytes)
    stack_mem[24..32].copy_from_slice(&0x402500u64.to_le_bytes());

    let mem_slice = SimpleMemorySlice {
        base_addr: base,
        data: &stack_mem,
    };

    let mut current_regs = UnwindRegisters::default();
    current_regs.rip = 0x401020;
    current_regs.rbp = 0x7fff_ffff_dff0;
    current_regs.rsp = 0x7fff_ffff_dfe0;

    let step_res = eh_table.step_frame(&current_regs, &mem_slice);
    if let Ok(caller_regs) = step_res {
        // CFA was RBP (0x7fffffffdff0) + 16 = 0x7fffffffe000
        // Caller RSP should be 0x7fffffffe000
        // Caller RIP should be 0x402500
        // Caller RBP should be 0x7fffffffe050
        if caller_regs.rsp == 0x7fff_ffff_e000
            && caller_regs.rip == 0x402500
            && caller_regs.rbp == 0x7fff_ffff_e050
        {
            check_count += 1;
        }
    }

    check_count
}
