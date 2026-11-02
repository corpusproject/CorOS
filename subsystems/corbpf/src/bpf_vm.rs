//! 11-Register 64-bit Extended BPF (`eBPF`) Virtual Machine Interpreter.
//!
//! Executes verified eBPF bytecode with a 512-byte isolated stack frame,
//! instruction fuel budget, checked memory bounds, and kernel helper dispatch.

use crate::bpf_insn::*;

/// Default maximum instructions executed before triggering `FuelExhausted`.
pub const BPF_DEFAULT_FUEL: u64 = 100_000;

/// Built-in eBPF kernel helper IDs.
pub const BPF_FUNC_KTIME_GET_NS: i32 = 5;
pub const BPF_FUNC_GET_PRANDOM_U32: i32 = 7;
pub const BPF_FUNC_GET_SMP_PROCESSOR_ID: i32 = 8;

/// Runtime error returned by the eBPF virtual machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    FuelExhausted,
    DivisionByZero(usize),
    MemoryViolation { pc: usize, addr: u64, width: usize },
    InvalidJumpTarget(usize),
    InvalidHelperCall(i32),
    IllegalInstruction(usize, u8),
}

/// Signature of a registered eBPF kernel helper function (`R1..R5 -> R0`).
pub type BpfHelperFn = fn(u64, u64, u64, u64, u64) -> u64;

/// 64-bit eBPF Virtual Machine with 11 registers (`R0..R10`) and a 512-byte stack.
pub struct BpfVm {
    pub regs: [u64; 11],
    pub stack: [u8; 512],
    pub fuel_limit: u64,
    pub instructions_retired: u64,
    sim_clock_ns: u64,
    prng_state: u64,
    cpu_id: u32,
}

impl BpfVm {
    pub const fn new() -> Self {
        Self {
            regs: [0; 11],
            stack: [0; 512],
            fuel_limit: BPF_DEFAULT_FUEL,
            instructions_retired: 0,
            sim_clock_ns: 1_000_000_000,
            prng_state: 0x9e37_79b9_7f4a_7c15,
            cpu_id: 0,
        }
    }

    pub fn with_cpu_and_fuel(cpu_id: u32, fuel_limit: u64) -> Self {
        let mut vm = Self::new();
        vm.cpu_id = cpu_id;
        vm.fuel_limit = fuel_limit;
        vm
    }

    /// Execute an eBPF program against the supplied mutable context slice (`ctx`).
    pub fn execute(&mut self, prog: &[BpfInsn], ctx: &mut [u8]) -> Result<u64, VmError> {
        self.regs = [0; 11];
        self.stack = [0; 512];
        self.instructions_retired = 0;

        let stack_top_va = self.stack.as_ptr() as usize as u64 + 512;
        let ctx_base_va = ctx.as_mut_ptr() as usize as u64;
        let ctx_len = ctx.len() as u64;

        self.regs[1] = ctx_base_va;
        self.regs[10] = stack_top_va;

        let mut pc = 0usize;
        while pc < prog.len() {
            if self.instructions_retired >= self.fuel_limit {
                return Err(VmError::FuelExhausted);
            }
            self.instructions_retired += 1;
            self.sim_clock_ns = self.sim_clock_ns.wrapping_add(12);

            let insn = prog[pc];
            let dst = (insn.dst_reg() as usize).min(10);
            let src = (insn.src_reg() as usize).min(10);
            let class = insn.class();

            match class {
                BPF_LD => {
                    if insn.code == (BPF_LD | BPF_DW | BPF_IMM) {
                        if pc + 1 >= prog.len() {
                            return Err(VmError::IllegalInstruction(pc, insn.code));
                        }
                        let low = insn.imm as u32 as u64;
                        let high = (prog[pc + 1].imm as u32 as u64) << 32;
                        if dst < 10 {
                            self.regs[dst] = low | high;
                        }
                        pc += 2;
                        continue;
                    } else {
                        return Err(VmError::IllegalInstruction(pc, insn.code));
                    }
                }
                BPF_ALU64 | BPF_ALU => {
                    if dst == 10 {
                        return Err(VmError::IllegalInstruction(pc, insn.code));
                    }
                    let is_64 = class == BPF_ALU64;
                    let lhs = if is_64 {
                        self.regs[dst]
                    } else {
                        self.regs[dst] as u32 as u64
                    };
                    let rhs = if insn.source() == BPF_X {
                        if is_64 {
                            self.regs[src]
                        } else {
                            self.regs[src] as u32 as u64
                        }
                    } else if is_64 {
                        insn.imm as i64 as u64
                    } else {
                        insn.imm as u32 as u64
                    };

                    let res = match insn.op() {
                        BPF_ADD => lhs.wrapping_add(rhs),
                        BPF_SUB => lhs.wrapping_sub(rhs),
                        BPF_MUL => lhs.wrapping_mul(rhs),
                        BPF_DIV => {
                            if rhs == 0 {
                                return Err(VmError::DivisionByZero(pc));
                            }
                            lhs.wrapping_div(rhs)
                        }
                        BPF_MOD => {
                            if rhs == 0 {
                                return Err(VmError::DivisionByZero(pc));
                            }
                            lhs.wrapping_rem(rhs)
                        }
                        BPF_OR => lhs | rhs,
                        BPF_AND => lhs & rhs,
                        BPF_XOR => lhs ^ rhs,
                        BPF_LSH => {
                            let shift = if is_64 { rhs & 63 } else { rhs & 31 };
                            lhs.wrapping_shl(shift as u32)
                        }
                        BPF_RSH => {
                            let shift = if is_64 { rhs & 63 } else { rhs & 31 };
                            lhs.wrapping_shr(shift as u32)
                        }
                        BPF_ARSH => {
                            let shift = if is_64 { rhs & 63 } else { rhs & 31 };
                            if is_64 {
                                ((lhs as i64).wrapping_shr(shift as u32)) as u64
                            } else {
                                ((lhs as u32 as i32).wrapping_shr(shift as u32)) as u32 as u64
                            }
                        }
                        BPF_NEG => {
                            if is_64 {
                                (-(lhs as i64)) as u64
                            } else {
                                (-(lhs as u32 as i32)) as u32 as u64
                            }
                        }
                        BPF_MOV => rhs,
                        _ => return Err(VmError::IllegalInstruction(pc, insn.code)),
                    };

                    self.regs[dst] = if is_64 { res } else { res as u32 as u64 };
                }
                BPF_LDX => {
                    if dst == 10 {
                        return Err(VmError::IllegalInstruction(pc, insn.code));
                    }
                    let width = insn.mem_byte_width();
                    let addr = self.regs[src].wrapping_add(insn.off as i64 as u64);
                    self.regs[dst] =
                        self.read_checked(pc, addr, width, stack_top_va, ctx_base_va, ctx)?;
                }
                BPF_STX => {
                    let width = insn.mem_byte_width();
                    let addr = self.regs[dst].wrapping_add(insn.off as i64 as u64);
                    let val = self.regs[src];
                    self.write_checked(pc, addr, width, val, stack_top_va, ctx_base_va, ctx_len, ctx)?;
                }
                BPF_ST => {
                    let width = insn.mem_byte_width();
                    let addr = self.regs[dst].wrapping_add(insn.off as i64 as u64);
                    let val = insn.imm as i64 as u64;
                    self.write_checked(pc, addr, width, val, stack_top_va, ctx_base_va, ctx_len, ctx)?;
                }
                BPF_JMP | BPF_JMP32 => {
                    let op = insn.op();
                    if op == BPF_EXIT {
                        return Ok(self.regs[0]);
                    }
                    if op == BPF_CALL {
                        self.regs[0] = self.dispatch_helper(insn.imm)?;
                        pc += 1;
                        continue;
                    }
                    if op == BPF_JA {
                        let next_pc = (pc as isize) + 1 + (insn.off as isize);
                        if next_pc < 0 || next_pc >= (prog.len() as isize) {
                            return Err(VmError::InvalidJumpTarget(pc));
                        }
                        pc = next_pc as usize;
                        continue;
                    }

                    let is_64 = class == BPF_JMP;
                    let lhs = if is_64 {
                        self.regs[dst]
                    } else {
                        self.regs[dst] as u32 as u64
                    };
                    let rhs = if insn.source() == BPF_X {
                        if is_64 {
                            self.regs[src]
                        } else {
                            self.regs[src] as u32 as u64
                        }
                    } else if is_64 {
                        insn.imm as i64 as u64
                    } else {
                        insn.imm as u32 as u64
                    };

                    let lhs_s = if is_64 {
                        lhs as i64
                    } else {
                        lhs as u32 as i32 as i64
                    };
                    let rhs_s = if is_64 {
                        rhs as i64
                    } else {
                        rhs as u32 as i32 as i64
                    };

                    let taken = match op {
                        BPF_JEQ => lhs == rhs,
                        BPF_JNE => lhs != rhs,
                        BPF_JGT => lhs > rhs,
                        BPF_JGE => lhs >= rhs,
                        BPF_JLT => lhs < rhs,
                        BPF_JLE => lhs <= rhs,
                        BPF_JSET => (lhs & rhs) != 0,
                        BPF_JSGT => lhs_s > rhs_s,
                        BPF_JSGE => lhs_s >= rhs_s,
                        BPF_JSLT => lhs_s < rhs_s,
                        BPF_JSLE => lhs_s <= rhs_s,
                        _ => return Err(VmError::IllegalInstruction(pc, insn.code)),
                    };

                    if taken {
                        let next_pc = (pc as isize) + 1 + (insn.off as isize);
                        if next_pc < 0 || next_pc >= (prog.len() as isize) {
                            return Err(VmError::InvalidJumpTarget(pc));
                        }
                        pc = next_pc as usize;
                        continue;
                    }
                }
                _ => return Err(VmError::IllegalInstruction(pc, insn.code)),
            }

            pc += 1;
        }

        Ok(self.regs[0])
    }

    fn dispatch_helper(&mut self, helper_id: i32) -> Result<u64, VmError> {
        match helper_id {
            BPF_FUNC_KTIME_GET_NS => Ok(self.sim_clock_ns),
            BPF_FUNC_GET_PRANDOM_U32 => {
                // SplitMix64 step for deterministic, high-entropy 32-bit pseudo-random number.
                self.prng_state = self.prng_state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.prng_state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^= z >> 31;
                Ok((z as u32) as u64)
            }
            BPF_FUNC_GET_SMP_PROCESSOR_ID => Ok(self.cpu_id as u64),
            _ => Err(VmError::InvalidHelperCall(helper_id)),
        }
    }

    fn read_checked(
        &self,
        pc: usize,
        addr: u64,
        width: usize,
        stack_top_va: u64,
        ctx_base_va: u64,
        ctx: &[u8],
    ) -> Result<u64, VmError> {
        let stack_base_va = stack_top_va - 512;
        let slice = if addr >= stack_base_va && addr.saturating_add(width as u64) <= stack_top_va {
            let off = (addr - stack_base_va) as usize;
            &self.stack[off..off + width]
        } else if !ctx.is_empty()
            && addr >= ctx_base_va
            && addr.saturating_add(width as u64) <= ctx_base_va + (ctx.len() as u64)
        {
            let off = (addr - ctx_base_va) as usize;
            &ctx[off..off + width]
        } else {
            return Err(VmError::MemoryViolation { pc, addr, width });
        };

        let val = match width {
            1 => slice[0] as u64,
            2 => u16::from_le_bytes([slice[0], slice[1]]) as u64,
            4 => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64,
            8 => u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            _ => return Err(VmError::MemoryViolation { pc, addr, width }),
        };
        Ok(val)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_checked(
        &mut self,
        pc: usize,
        addr: u64,
        width: usize,
        val: u64,
        stack_top_va: u64,
        ctx_base_va: u64,
        ctx_len: u64,
        ctx: &mut [u8],
    ) -> Result<(), VmError> {
        let stack_base_va = stack_top_va - 512;
        let slice = if addr >= stack_base_va && addr.saturating_add(width as u64) <= stack_top_va {
            let off = (addr - stack_base_va) as usize;
            &mut self.stack[off..off + width]
        } else if ctx_len > 0
            && addr >= ctx_base_va
            && addr.saturating_add(width as u64) <= ctx_base_va + ctx_len
        {
            let off = (addr - ctx_base_va) as usize;
            &mut ctx[off..off + width]
        } else {
            return Err(VmError::MemoryViolation { pc, addr, width });
        };

        match width {
            1 => slice[0] = val as u8,
            2 => slice.copy_from_slice(&(val as u16).to_le_bytes()),
            4 => slice.copy_from_slice(&(val as u32).to_le_bytes()),
            8 => slice.copy_from_slice(&val.to_le_bytes()),
            _ => return Err(VmError::MemoryViolation { pc, addr, width }),
        }
        Ok(())
    }
}

impl Default for BpfVm {
    fn default() -> Self {
        Self::new()
    }
}
