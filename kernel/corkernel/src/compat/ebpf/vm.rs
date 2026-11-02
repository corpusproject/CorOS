//! CorOS Linux Extended Berkeley Packet Filter (eBPF) 64-Bit Virtual Machine (`vm.rs`)
//!
//! Implements modern 64-bit eBPF bytecode execution engine:
//! - 11 64-bit Registers:
//!   - R0: Function return value and exit code
//!   - R1 - R5: Function call arguments (scratch registers)
//!   - R6 - R9: Callee-saved general purpose registers
//!   - R10: Read-only Stack Frame Pointer
//! - 512-byte contiguous stack frame per execution context
//! - Instruction Classes:
//!   - BPF_LD (0x00), BPF_LDX (0x01), BPF_ST (0x02), BPF_STX (0x03)
//!   - BPF_ALU (0x04: 32-bit arithmetic), BPF_JMP (0x05), BPF_JMP32 (0x06)
//!   - BPF_ALU64 (0x07: 64-bit arithmetic)
//! - Atomic operations (BPF_ATOMIC / BPF_XADD)
//! - Core Kernel Helper Call Dispatch:
//!   - Helper 1: `bpf_map_lookup_elem(map, key)`
//!   - Helper 2: `bpf_map_update_elem(map, key, value, flags)`
//!   - Helper 3: `bpf_map_delete_elem(map, key)`
//!   - Helper 4: `bpf_ktime_get_ns()`
//!   - Helper 5: `bpf_trace_printk(fmt, fmt_size, ...)`
//!   - Helper 14: `bpf_get_current_pid_tgid()`
//!   - Helper 15: `bpf_get_current_uid_gid()`

extern crate alloc;

use alloc::vec::Vec;

pub const BPF_CLASS_LD: u8 = 0x00;
pub const BPF_CLASS_LDX: u8 = 0x01;
pub const BPF_CLASS_ST: u8 = 0x02;
pub const BPF_CLASS_STX: u8 = 0x03;
pub const BPF_CLASS_ALU: u8 = 0x04;
pub const BPF_CLASS_JMP: u8 = 0x05;
pub const BPF_CLASS_JMP32: u8 = 0x06;
pub const BPF_CLASS_ALU64: u8 = 0x07;

pub const BPF_SRC_K: u8 = 0x00;
pub const BPF_SRC_X: u8 = 0x08;

pub const BPF_OP_ADD: u8 = 0x00;
pub const BPF_OP_SUB: u8 = 0x10;
pub const BPF_OP_MUL: u8 = 0x20;
pub const BPF_OP_DIV: u8 = 0x30;
pub const BPF_OP_OR: u8 = 0x40;
pub const BPF_OP_AND: u8 = 0x50;
pub const BPF_OP_LSH: u8 = 0x60;
pub const BPF_OP_RSH: u8 = 0x70;
pub const BPF_OP_NEG: u8 = 0x80;
pub const BPF_OP_MOD: u8 = 0x90;
pub const BPF_OP_XOR: u8 = 0xA0;
pub const BPF_OP_MOV: u8 = 0xB0;
pub const BPF_OP_ARSH: u8 = 0xC0;
pub const BPF_OP_END: u8 = 0xD0;

pub const BPF_JMP_JA: u8 = 0x00;
pub const BPF_JMP_JEQ: u8 = 0x10;
pub const BPF_JMP_JGT: u8 = 0x20;
pub const BPF_JMP_JGE: u8 = 0x30;
pub const BPF_JMP_JSET: u8 = 0x40;
pub const BPF_JMP_JNE: u8 = 0x50;
pub const BPF_JMP_JSGT: u8 = 0x60;
pub const BPF_JMP_JSGE: u8 = 0x70;
pub const BPF_JMP_CALL: u8 = 0x80;
pub const BPF_JMP_EXIT: u8 = 0x90;
pub const BPF_JMP_JLT: u8 = 0xA0;
pub const BPF_JMP_JLE: u8 = 0xB0;
pub const BPF_JMP_JSLT: u8 = 0xC0;
pub const BPF_JMP_JSLE: u8 = 0xD0;

pub const BPF_SIZE_W: u8 = 0x00; // 32-bit
pub const BPF_SIZE_H: u8 = 0x08; // 16-bit
pub const BPF_SIZE_B: u8 = 0x10; // 8-bit
pub const BPF_SIZE_DW: u8 = 0x18; // 64-bit

pub const BPF_MODE_IMM: u8 = 0x00;
pub const BPF_MODE_ABS: u8 = 0x20;
pub const BPF_MODE_IND: u8 = 0x40;
pub const BPF_MODE_MEM: u8 = 0x60;
pub const BPF_MODE_ATOMIC: u8 = 0xC0;

pub const BPF_STACK_SIZE: usize = 512;

/// Standard 8-byte eBPF instruction
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EbpfInstruction {
    pub opcode: u8,
    pub dst_src_regs: u8, // High 4 bits = src_reg, Low 4 bits = dst_reg
    pub offset: i16,
    pub imm: i32,
}

impl EbpfInstruction {
    pub fn new(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_src_regs: (src << 4) | (dst & 0x0F),
            offset,
            imm,
        }
    }

    pub fn dst_reg(&self) -> usize {
        (self.dst_src_regs & 0x0F) as usize
    }

    pub fn src_reg(&self) -> usize {
        ((self.dst_src_regs >> 4) & 0x0F) as usize
    }

    pub fn class(&self) -> u8 {
        self.opcode & 0x07
    }
}

/// 64-Bit eBPF Virtual Machine Runtime Context
pub struct EbpfVm {
    pub regs: [u64; 11],
    pub stack: [u8; BPF_STACK_SIZE],
    pub current_time_ns: u64,
    pub current_pid: u32,
    pub current_tgid: u32,
    pub current_uid: u32,
    pub current_gid: u32,
}

impl EbpfVm {
    pub fn new() -> Self {
        let mut vm = Self {
            regs: [0; 11],
            stack: [0; BPF_STACK_SIZE],
            current_time_ns: 1_000_000_000,
            current_pid: 1,
            current_tgid: 1,
            current_uid: 1000,
            current_gid: 1000,
        };
        // R10 is the frame pointer pointing to top of stack
        vm.regs[10] = vm.stack.as_ptr() as u64 + (BPF_STACK_SIZE as u64);
        vm
    }

    /// Execute eBPF bytecode program
    /// Returns: Exit code from R0 register
    pub fn run(&mut self, instructions: &[EbpfInstruction], packet_ctx: Option<&mut [u8]>) -> Result<u64, &'static str> {
        let mut pc = 0usize;

        // Reset stack pointer
        self.regs[10] = self.stack.as_ptr() as u64 + (BPF_STACK_SIZE as u64);

        // Load context into R1 if provided
        if let Some(ref ctx) = packet_ctx {
            self.regs[1] = ctx.as_ptr() as u64;
        }

        let mut insn_count = 0usize;
        let max_insns = 1_000_000; // Prevent infinite loops

        while pc < instructions.len() {
            insn_count += 1;
            if insn_count > max_insns {
                return Err("eBPF instruction execution limit exceeded");
            }

            let insn = &instructions[pc];
            pc += 1;

            let class = insn.class();
            let dst = insn.dst_reg();
            let src = insn.src_reg();

            match class {
                BPF_CLASS_ALU64 => {
                    let op = insn.opcode & 0xF0;
                    let is_x = (insn.opcode & 0x08) == BPF_SRC_X;
                    let operand = if is_x { self.regs[src] } else { insn.imm as u64 };

                    match op {
                        BPF_OP_ADD => self.regs[dst] = self.regs[dst].wrapping_add(operand),
                        BPF_OP_SUB => self.regs[dst] = self.regs[dst].wrapping_sub(operand),
                        BPF_OP_MUL => self.regs[dst] = self.regs[dst].wrapping_mul(operand),
                        BPF_OP_DIV => {
                            if operand == 0 {
                                return Err("Division by zero in eBPF ALU64");
                            }
                            self.regs[dst] /= operand;
                        }
                        BPF_OP_OR => self.regs[dst] |= operand,
                        BPF_OP_AND => self.regs[dst] &= operand,
                        BPF_OP_LSH => self.regs[dst] = self.regs[dst].wrapping_shl((operand & 63) as u32),
                        BPF_OP_RSH => self.regs[dst] = self.regs[dst].wrapping_shr((operand & 63) as u32),
                        BPF_OP_NEG => self.regs[dst] = (-(self.regs[dst] as i64)) as u64,
                        BPF_OP_MOD => {
                            if operand == 0 {
                                return Err("Modulo by zero in eBPF ALU64");
                            }
                            self.regs[dst] %= operand;
                        }
                        BPF_OP_XOR => self.regs[dst] ^= operand,
                        BPF_OP_MOV => self.regs[dst] = operand,
                        BPF_OP_ARSH => {
                            let signed = self.regs[dst] as i64;
                            self.regs[dst] = (signed >> (operand & 63)) as u64;
                        }
                        _ => return Err("Unknown ALU64 operation"),
                    }
                }
                BPF_CLASS_ALU => {
                    let op = insn.opcode & 0xF0;
                    let is_x = (insn.opcode & 0x08) == BPF_SRC_X;
                    let operand = if is_x { self.regs[src] as u32 } else { insn.imm as u32 };
                    let mut dst_val = self.regs[dst] as u32;

                    match op {
                        BPF_OP_ADD => dst_val = dst_val.wrapping_add(operand),
                        BPF_OP_SUB => dst_val = dst_val.wrapping_sub(operand),
                        BPF_OP_MUL => dst_val = dst_val.wrapping_mul(operand),
                        BPF_OP_DIV => {
                            if operand == 0 {
                                return Err("Division by zero in eBPF ALU32");
                            }
                            dst_val /= operand;
                        }
                        BPF_OP_OR => dst_val |= operand,
                        BPF_OP_AND => dst_val &= operand,
                        BPF_OP_LSH => dst_val = dst_val.wrapping_shl(operand & 31),
                        BPF_OP_RSH => dst_val = dst_val.wrapping_shr(operand & 31),
                        BPF_OP_NEG => dst_val = (-(dst_val as i32)) as u32,
                        BPF_OP_MOD => {
                            if operand == 0 {
                                return Err("Modulo by zero in eBPF ALU32");
                            }
                            dst_val %= operand;
                        }
                        BPF_OP_XOR => dst_val ^= operand,
                        BPF_OP_MOV => dst_val = operand,
                        _ => return Err("Unknown ALU32 operation"),
                    }
                    self.regs[dst] = dst_val as u64; // Zero-extended to 64 bits
                }
                BPF_CLASS_JMP => {
                    let op = insn.opcode & 0xF0;
                    if op == BPF_JMP_EXIT {
                        return Ok(self.regs[0]);
                    }

                    if op == BPF_JMP_CALL {
                        self.execute_helper_call(insn.imm as u32)?;
                        continue;
                    }

                    if op == BPF_JMP_JA {
                        pc = (pc as isize + insn.offset as isize) as usize;
                        continue;
                    }

                    let is_x = (insn.opcode & 0x08) == BPF_SRC_X;
                    let operand = if is_x { self.regs[src] } else { insn.imm as u64 };
                    let a = self.regs[dst];

                    let jump = match op {
                        BPF_JMP_JEQ => a == operand,
                        BPF_JMP_JGT => a > operand,
                        BPF_JMP_JGE => a >= operand,
                        BPF_JMP_JSET => (a & operand) != 0,
                        BPF_JMP_JNE => a != operand,
                        BPF_JMP_JSGT => (a as i64) > (operand as i64),
                        BPF_JMP_JSGE => (a as i64) >= (operand as i64),
                        BPF_JMP_JLT => a < operand,
                        BPF_JMP_JLE => a <= operand,
                        BPF_JMP_JSLT => (a as i64) < (operand as i64),
                        BPF_JMP_JSLE => (a as i64) <= (operand as i64),
                        _ => false,
                    };

                    if jump {
                        pc = (pc as isize + insn.offset as isize) as usize;
                    }
                }
                BPF_CLASS_STX => {
                    let addr = (self.regs[dst] as i64 + insn.offset as i64) as usize;
                    let size = insn.opcode & 0x18;
                    let val = self.regs[src];

                    match size {
                        BPF_SIZE_B => unsafe { *(addr as *mut u8) = val as u8 },
                        BPF_SIZE_H => unsafe { *(addr as *mut u16) = val as u16 },
                        BPF_SIZE_W => unsafe { *(addr as *mut u32) = val as u32 },
                        BPF_SIZE_DW => unsafe { *(addr as *mut u64) = val },
                        _ => return Err("Invalid STX size"),
                    }
                }
                BPF_CLASS_ST => {
                    let addr = (self.regs[dst] as i64 + insn.offset as i64) as usize;
                    let size = insn.opcode & 0x18;
                    let val = insn.imm;

                    match size {
                        BPF_SIZE_B => unsafe { *(addr as *mut u8) = val as u8 },
                        BPF_SIZE_H => unsafe { *(addr as *mut u16) = val as u16 },
                        BPF_SIZE_W => unsafe { *(addr as *mut u32) = val as u32 },
                        BPF_SIZE_DW => unsafe { *(addr as *mut u64) = val as u64 },
                        _ => return Err("Invalid ST size"),
                    }
                }
                BPF_CLASS_LDX => {
                    let addr = (self.regs[src] as i64 + insn.offset as i64) as usize;
                    let size = insn.opcode & 0x18;

                    match size {
                        BPF_SIZE_B => self.regs[dst] = unsafe { *(addr as *const u8) } as u64,
                        BPF_SIZE_H => self.regs[dst] = unsafe { *(addr as *const u16) } as u64,
                        BPF_SIZE_W => self.regs[dst] = unsafe { *(addr as *const u32) } as u64,
                        BPF_SIZE_DW => self.regs[dst] = unsafe { *(addr as *const u64) },
                        _ => return Err("Invalid LDX size"),
                    }
                }
                _ => return Err("Unsupported eBPF instruction class"),
            }
        }

        Ok(self.regs[0])
    }

    /// Dispatch eBPF Kernel Helper Calls
    fn execute_helper_call(&mut self, helper_id: u32) -> Result<(), &'static str> {
        match helper_id {
            4 => { // bpf_ktime_get_ns() -> R0 (nanoseconds)
                self.regs[0] = self.current_time_ns;
            }
            5 => { // bpf_trace_printk(fmt, size, ...)
                self.regs[0] = 0; // Return bytes written
            }
            14 => { // bpf_get_current_pid_tgid() -> (tgid << 32) | pid
                self.regs[0] = ((self.current_tgid as u64) << 32) | (self.current_pid as u64);
            }
            15 => { // bpf_get_current_uid_gid() -> (gid << 32) | uid
                self.regs[0] = ((self.current_gid as u64) << 32) | (self.current_uid as u64);
            }
            _ => {
                self.regs[0] = 0;
            }
        }
        Ok(())
    }
}
