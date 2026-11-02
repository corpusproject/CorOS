//! Static Extended BPF (`eBPF`) Safety Verifier.
//!
//! Performs abstract interpretation over register types, stack slot bounds,
//! jump targets, loop freedom, division-by-zero prevention, and exit reachability.

use crate::bpf_insn::*;
use alloc::vec;
use alloc::vec::Vec;

/// Maximum instructions permitted in a verified eBPF program.
pub const BPF_MAX_INSNS: usize = 4096;
/// Architectural eBPF stack size in bytes (`R10` points to top of 512-byte stack).
pub const BPF_STACK_SIZE: i32 = 512;

/// Abstract register type tracked by the static verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegType {
    /// Register has not yet been written on this control-flow path.
    Uninitialized,
    /// Arbitrary 64-bit scalar integer value, optionally with known constant value.
    ScalarValue(Option<i64>),
    /// Pointer to execution context (`R1` on entry) with fixed byte offset.
    PtrToCtx(i32),
    /// Pointer to a BPF map element value buffer of known byte capacity.
    PtrToMapValue { offset: i32, capacity: u32 },
    /// Pointer into the 512-byte eBPF stack frame (`offset` in `-512..=0`).
    PtrToStack(i32),
}

/// Static verification failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    EmptyProgram,
    ProgramTooLarge,
    InvalidRegister(usize, u8),
    WriteToReadOnlyFramePointer(usize),
    ReadUninitializedRegister(usize, u8),
    DivisionByZero(usize),
    InvalidShiftAmount(usize, i32),
    JumpOutOfBounds(usize, isize),
    BackEdgeLoopDetected(usize, usize),
    JumpIntoWideInstructionSecondSlot(usize, usize),
    StackAccessOutOfBounds(usize, i32, usize),
    ContextAccessOutOfBounds(usize, i32, usize),
    InvalidMemoryPointerBase(usize, u8),
    PointerArithmeticForbidden(usize),
    TruncatedWideInstruction(usize),
    UnterminatedFallthrough,
    UnknownOpcode(usize, u8),
}

/// Summary report emitted when an eBPF program passes static verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationReport {
    pub instruction_count: usize,
    pub max_stack_depth: u32,
    pub branch_count: usize,
    pub helper_call_count: usize,
}

/// Abstract state of the 11 eBPF registers at an instruction boundary.
#[derive(Clone, Copy)]
struct RegisterState {
    regs: [RegType; 11],
}

impl RegisterState {
    fn initial() -> Self {
        let mut regs = [RegType::Uninitialized; 11];
        regs[1] = RegType::PtrToCtx(0);
        regs[10] = RegType::PtrToStack(0);
        Self { regs }
    }
}

/// Static eBPF safety verifier.
pub struct BpfVerifier {
    ctx_size_limit: i32,
}

impl BpfVerifier {
    pub const fn new(ctx_size_limit: i32) -> Self {
        Self { ctx_size_limit }
    }

    /// Statically verify an eBPF instruction stream.
    pub fn verify(&self, prog: &[BpfInsn]) -> Result<VerificationReport, VerifyError> {
        if prog.is_empty() {
            return Err(VerifyError::EmptyProgram);
        }
        if prog.len() > BPF_MAX_INSNS {
            return Err(VerifyError::ProgramTooLarge);
        }

        // First pass: structural validation, register range checks, and jump target checks.
        let mut wide_second_slot = vec![false; prog.len()];
        let mut idx = 0usize;
        while idx < prog.len() {
            let insn = prog[idx];
            if insn.dst_reg() > 10 {
                return Err(VerifyError::InvalidRegister(idx, insn.dst_reg()));
            }
            if insn.src_reg() > 10 {
                return Err(VerifyError::InvalidRegister(idx, insn.src_reg()));
            }
            if insn.code == (BPF_LD | BPF_DW | BPF_IMM) {
                if idx + 1 >= prog.len() {
                    return Err(VerifyError::TruncatedWideInstruction(idx));
                }
                wide_second_slot[idx + 1] = true;
                idx += 2;
                continue;
            }
            idx += 1;
        }

        // Verify that the last instruction is a non-fallthrough terminator (`EXIT` or `JA`).
        let last_idx = prog.len() - 1;
        if wide_second_slot[last_idx] {
            return Err(VerifyError::UnterminatedFallthrough);
        }
        let last_insn = prog[last_idx];
        let is_terminator = last_insn.class() == BPF_JMP
            && (last_insn.op() == BPF_EXIT || last_insn.op() == BPF_JA);
        if !is_terminator {
            return Err(VerifyError::UnterminatedFallthrough);
        }

        // Second pass: Linear abstract interpretation with forward-branch state propagation.
        let mut states: Vec<Option<RegisterState>> = vec![None; prog.len()];
        states[0] = Some(RegisterState::initial());

        let mut max_stack_depth = 0u32;
        let mut branch_count = 0usize;
        let mut helper_call_count = 0usize;

        let mut pc = 0usize;
        while pc < prog.len() {
            if wide_second_slot[pc] {
                pc += 1;
                continue;
            }

            let Some(mut state) = states[pc] else {
                pc += 1;
                continue;
            };

            let insn = prog[pc];
            let dst = insn.dst_reg() as usize;
            let src = insn.src_reg() as usize;
            let class = insn.class();

            match class {
                BPF_LD => {
                    if insn.code == (BPF_LD | BPF_DW | BPF_IMM) {
                        if dst == 10 {
                            return Err(VerifyError::WriteToReadOnlyFramePointer(pc));
                        }
                        let low = insn.imm as u32 as u64;
                        let high = (prog[pc + 1].imm as u32 as u64) << 32;
                        let full = (low | high) as i64;
                        state.regs[dst] = RegType::ScalarValue(Some(full));
                        if pc + 2 < prog.len() {
                            Self::merge_state(&mut states[pc + 2], state);
                        }
                        pc += 2;
                        continue;
                    } else {
                        return Err(VerifyError::UnknownOpcode(pc, insn.code));
                    }
                }
                BPF_ALU | BPF_ALU64 => {
                    if dst == 10 {
                        return Err(VerifyError::WriteToReadOnlyFramePointer(pc));
                    }
                    let op = insn.op();
                    let is_src_reg = insn.source() == BPF_X;

                    if op != BPF_MOV && state.regs[dst] == RegType::Uninitialized {
                        return Err(VerifyError::ReadUninitializedRegister(pc, dst as u8));
                    }
                    let src_type = if is_src_reg {
                        if state.regs[src] == RegType::Uninitialized {
                            return Err(VerifyError::ReadUninitializedRegister(pc, src as u8));
                        }
                        state.regs[src]
                    } else {
                        RegType::ScalarValue(Some(insn.imm as i64))
                    };

                    if op == BPF_DIV || op == BPF_MOD {
                        match src_type {
                            RegType::ScalarValue(Some(0)) | RegType::ScalarValue(None)
                                if !is_src_reg && insn.imm == 0 =>
                            {
                                return Err(VerifyError::DivisionByZero(pc));
                            }
                            RegType::ScalarValue(Some(0)) => {
                                return Err(VerifyError::DivisionByZero(pc));
                            }
                            _ => {}
                        }
                    }

                    if (op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH) && !is_src_reg {
                        let max_shift = if class == BPF_ALU64 { 63 } else { 31 };
                        if insn.imm < 0 || insn.imm > max_shift {
                            return Err(VerifyError::InvalidShiftAmount(pc, insn.imm));
                        }
                    }

                    state.regs[dst] = match (op, state.regs[dst], src_type) {
                        (BPF_MOV, _, _) => src_type,
                        (BPF_ADD, RegType::PtrToStack(base), RegType::ScalarValue(Some(delta))) => {
                            let next_off = base.saturating_add(delta as i32);
                            if next_off < -BPF_STACK_SIZE || next_off > 0 {
                                return Err(VerifyError::StackAccessOutOfBounds(pc, next_off, 1));
                            }
                            RegType::PtrToStack(next_off)
                        }
                        (BPF_SUB, RegType::PtrToStack(base), RegType::ScalarValue(Some(delta))) => {
                            let next_off = base.saturating_sub(delta as i32);
                            if next_off < -BPF_STACK_SIZE || next_off > 0 {
                                return Err(VerifyError::StackAccessOutOfBounds(pc, next_off, 1));
                            }
                            RegType::PtrToStack(next_off)
                        }
                        (BPF_ADD, RegType::PtrToCtx(base), RegType::ScalarValue(Some(delta))) => {
                            RegType::PtrToCtx(base.saturating_add(delta as i32))
                        }
                        (
                            BPF_ADD,
                            RegType::ScalarValue(Some(a)),
                            RegType::ScalarValue(Some(b)),
                        ) => RegType::ScalarValue(Some(a.wrapping_add(b))),
                        (
                            BPF_SUB,
                            RegType::ScalarValue(Some(a)),
                            RegType::ScalarValue(Some(b)),
                        ) => RegType::ScalarValue(Some(a.wrapping_sub(b))),
                        (_, RegType::ScalarValue(_), RegType::ScalarValue(_)) => {
                            RegType::ScalarValue(None)
                        }
                        _ => return Err(VerifyError::PointerArithmeticForbidden(pc)),
                    };
                }
                BPF_LDX => {
                    if insn.mem_mode() != BPF_MEM {
                        return Err(VerifyError::UnknownOpcode(pc, insn.code));
                    }
                    if dst == 10 {
                        return Err(VerifyError::WriteToReadOnlyFramePointer(pc));
                    }
                    let width = insn.mem_byte_width();
                    if width == 0 {
                        return Err(VerifyError::UnknownOpcode(pc, insn.code));
                    }
                    self.check_mem_access(
                        pc,
                        state.regs[src],
                        src as u8,
                        insn.off as i32,
                        width,
                        &mut max_stack_depth,
                    )?;
                    state.regs[dst] = RegType::ScalarValue(None);
                }
                BPF_STX | BPF_ST => {
                    if insn.mem_mode() != BPF_MEM {
                        return Err(VerifyError::UnknownOpcode(pc, insn.code));
                    }
                    if class == BPF_STX && state.regs[src] == RegType::Uninitialized {
                        return Err(VerifyError::ReadUninitializedRegister(pc, src as u8));
                    }
                    let width = insn.mem_byte_width();
                    if width == 0 {
                        return Err(VerifyError::UnknownOpcode(pc, insn.code));
                    }
                    self.check_mem_access(
                        pc,
                        state.regs[dst],
                        dst as u8,
                        insn.off as i32,
                        width,
                        &mut max_stack_depth,
                    )?;
                }
                BPF_JMP | BPF_JMP32 => {
                    let op = insn.op();
                    if op == BPF_EXIT {
                        if state.regs[0] == RegType::Uninitialized {
                            return Err(VerifyError::ReadUninitializedRegister(pc, 0));
                        }
                        pc += 1;
                        continue;
                    } else if op == BPF_CALL {
                        helper_call_count += 1;
                        // Caller-saved registers R1..R5 are clobbered; R0 receives scalar return value.
                        state.regs[0] = RegType::ScalarValue(None);
                        state.regs[1] = RegType::Uninitialized;
                        state.regs[2] = RegType::Uninitialized;
                        state.regs[3] = RegType::Uninitialized;
                        state.regs[4] = RegType::Uninitialized;
                        state.regs[5] = RegType::Uninitialized;
                    } else if op == BPF_JA {
                        branch_count += 1;
                        let target = self.resolve_jump_target(
                            pc,
                            insn.off,
                            prog.len(),
                            &wide_second_slot,
                        )?;
                        Self::merge_state(&mut states[target], state);
                        pc += 1;
                        continue;
                    } else {
                        branch_count += 1;
                        if state.regs[dst] == RegType::Uninitialized {
                            return Err(VerifyError::ReadUninitializedRegister(pc, dst as u8));
                        }
                        if insn.source() == BPF_X && state.regs[src] == RegType::Uninitialized {
                            return Err(VerifyError::ReadUninitializedRegister(pc, src as u8));
                        }
                        let target = self.resolve_jump_target(
                            pc,
                            insn.off,
                            prog.len(),
                            &wide_second_slot,
                        )?;
                        Self::merge_state(&mut states[target], state);
                    }
                }
                _ => return Err(VerifyError::UnknownOpcode(pc, insn.code)),
            }

            if pc + 1 < prog.len() {
                Self::merge_state(&mut states[pc + 1], state);
            }
            pc += 1;
        }

        Ok(VerificationReport {
            instruction_count: prog.len(),
            max_stack_depth,
            branch_count,
            helper_call_count,
        })
    }

    fn resolve_jump_target(
        &self,
        pc: usize,
        off: i16,
        prog_len: usize,
        wide_second_slot: &[bool],
    ) -> Result<usize, VerifyError> {
        let target_isize = (pc as isize) + 1 + (off as isize);
        if target_isize < 0 || target_isize >= (prog_len as isize) {
            return Err(VerifyError::JumpOutOfBounds(pc, target_isize));
        }
        let target = target_isize as usize;
        if target <= pc {
            return Err(VerifyError::BackEdgeLoopDetected(pc, target));
        }
        if wide_second_slot[target] {
            return Err(VerifyError::JumpIntoWideInstructionSecondSlot(pc, target));
        }
        Ok(target)
    }

    fn check_mem_access(
        &self,
        pc: usize,
        base_reg: RegType,
        reg_idx: u8,
        off: i32,
        width: usize,
        max_stack_depth: &mut u32,
    ) -> Result<(), VerifyError> {
        match base_reg {
            RegType::Uninitialized => Err(VerifyError::ReadUninitializedRegister(pc, reg_idx)),
            RegType::PtrToStack(base) => {
                let start = base.saturating_add(off);
                let end = start.saturating_add(width as i32);
                if start < -BPF_STACK_SIZE || end > 0 {
                    return Err(VerifyError::StackAccessOutOfBounds(pc, start, width));
                }
                let depth = (-start) as u32;
                if depth > *max_stack_depth {
                    *max_stack_depth = depth;
                }
                Ok(())
            }
            RegType::PtrToCtx(base) => {
                let start = base.saturating_add(off);
                let end = start.saturating_add(width as i32);
                if start < 0 || end > self.ctx_size_limit {
                    return Err(VerifyError::ContextAccessOutOfBounds(pc, start, width));
                }
                Ok(())
            }
            RegType::PtrToMapValue { offset, capacity } => {
                let start = offset.saturating_add(off);
                let end = start.saturating_add(width as i32);
                if start < 0 || end > (capacity as i32) {
                    return Err(VerifyError::ContextAccessOutOfBounds(pc, start, width));
                }
                Ok(())
            }
            RegType::ScalarValue(_) => Err(VerifyError::InvalidMemoryPointerBase(pc, reg_idx)),
        }
    }

    fn merge_state(slot: &mut Option<RegisterState>, incoming: RegisterState) {
        match slot {
            None => *slot = Some(incoming),
            Some(existing) => {
                for (dst_reg, inc_reg) in existing.regs.iter_mut().zip(incoming.regs.iter()) {
                    *dst_reg = match (*dst_reg, *inc_reg) {
                        (a, b) if a == b => a,
                        (RegType::ScalarValue(_), RegType::ScalarValue(_)) => {
                            RegType::ScalarValue(None)
                        }
                        _ => RegType::Uninitialized,
                    };
                }
            }
        }
    }
}
