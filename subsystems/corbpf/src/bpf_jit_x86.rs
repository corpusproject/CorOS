//! eBPF-to-x86_64 Native Machine Code JIT Compiler.
//!
//! Translates verified 64-bit eBPF instructions into canonical x86_64 native
//! machine code bytes with System V / CorOS ABI prologue, register mapping,
//! REX.W prefixes, memory load/store emission, and two-pass relative jump fixup.

use crate::bpf_insn::*;
use alloc::vec;
use alloc::vec::Vec;

/// Physical x86_64 register encoding alongside its `REX` extension bit (`r8..r15`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86Reg {
    /// 3-bit low hardware register code (`0..=7`).
    pub hw_code: u8,
    /// True if register is an extended x86_64 register (`r8..r15`).
    pub is_ext: bool,
}

/// Map an architectural eBPF register (`R0..R10`) to its physical x86_64 register:
/// - `R0`  -> `rax` (return value)
/// - `R1`  -> `rdi` (1st arg / context pointer)
/// - `R2`  -> `rsi` (2nd arg)
/// - `R3`  -> `rdx` (3rd arg)
/// - `R4`  -> `rcx` (4th arg)
/// - `R5`  -> `r8`  (5th arg)
/// - `R6`  -> `rbx` (callee-saved)
/// - `R7`  -> `r13` (callee-saved)
/// - `R8`  -> `r14` (callee-saved)
/// - `R9`  -> `r15` (callee-saved)
/// - `R10` -> `rbp` (stack frame pointer)
pub const fn map_ebpf_reg_to_x86(bpf_reg: u8) -> Option<X86Reg> {
    match bpf_reg {
        0 => Some(X86Reg { hw_code: 0, is_ext: false }), // rax
        1 => Some(X86Reg { hw_code: 7, is_ext: false }), // rdi
        2 => Some(X86Reg { hw_code: 6, is_ext: false }), // rsi
        3 => Some(X86Reg { hw_code: 2, is_ext: false }), // rdx
        4 => Some(X86Reg { hw_code: 1, is_ext: false }), // rcx
        5 => Some(X86Reg { hw_code: 0, is_ext: true }),  // r8
        6 => Some(X86Reg { hw_code: 3, is_ext: false }), // rbx
        7 => Some(X86Reg { hw_code: 5, is_ext: true }),  // r13
        8 => Some(X86Reg { hw_code: 6, is_ext: true }),  // r14
        9 => Some(X86Reg { hw_code: 7, is_ext: true }),  // r15
        10 => Some(X86Reg { hw_code: 5, is_ext: false }), // rbp
        _ => None,
    }
}

/// Error emitted during eBPF-to-x86_64 JIT compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitError {
    EmptyProgram,
    InvalidRegister(u8),
    UnsupportedOpcode(usize, u8),
    JumpTargetOutOfRange(usize),
}

/// Pending 32-bit signed relative jump relocation (`rel32`).
struct JumpFixup {
    /// Offset in `code` where the 4-byte `rel32` displacement is stored.
    disp_offset: usize,
    /// Offset in `code` immediately after the jump instruction (base for `rel32`).
    next_rip_offset: usize,
    /// Target eBPF instruction index (`pc + 1 + insn.off`).
    target_insn_idx: usize,
}

/// Compiled x86_64 machine code buffer produced by the eBPF JIT compiler.
pub struct X86JitBuffer {
    pub code: Vec<u8>,
    pub insn_byte_offsets: Vec<usize>,
    pub epilogue_offset: usize,
}

impl X86JitBuffer {
    pub fn len(&self) -> usize {
        self.code.len()
    }

    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }
}

/// eBPF-to-x86_64 native machine code compiler.
pub struct X86JitCompiler;

impl X86JitCompiler {
    /// Compile a verified eBPF program into a self-contained x86_64 machine code buffer.
    pub fn compile(prog: &[BpfInsn]) -> Result<X86JitBuffer, JitError> {
        if prog.is_empty() {
            return Err(JitError::EmptyProgram);
        }

        let mut code = Vec::with_capacity(prog.len() * 12 + 32);
        let mut insn_byte_offsets = vec![0usize; prog.len() + 1];
        let mut fixups: Vec<JumpFixup> = Vec::new();

        // --- Function Prologue ---
        // push rbp (0x55)
        code.push(0x55);
        // mov rbp, rsp (0x48 0x89 0xE5)
        code.extend_from_slice(&[0x48, 0x89, 0xE5]);
        // Save callee-saved registers: push rbx; push r13; push r14; push r15
        code.push(0x53);
        code.extend_from_slice(&[0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        // Allocate 512-byte eBPF stack frame: sub rsp, 512 (0x48 0x81 0xEC 0x00 0x02 0x00 0x00)
        code.extend_from_slice(&[0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00]);

        let mut pc = 0usize;
        while pc < prog.len() {
            insn_byte_offsets[pc] = code.len();
            let insn = prog[pc];
            let dst = map_ebpf_reg_to_x86(insn.dst_reg())
                .ok_or(JitError::InvalidRegister(insn.dst_reg()))?;
            let src = map_ebpf_reg_to_x86(insn.src_reg())
                .ok_or(JitError::InvalidRegister(insn.src_reg()))?;

            match insn.class() {
                BPF_LD => {
                    if insn.code == (BPF_LD | BPF_DW | BPF_IMM) && pc + 1 < prog.len() {
                        let low = insn.imm as u32 as u64;
                        let high = (prog[pc + 1].imm as u32 as u64) << 32;
                        let imm64 = low | high;
                        // movabs dst, imm64: REX.W (+ REX.B) + (0xB8 + reg) + imm64
                        let rex = 0x48 | if dst.is_ext { 0x01 } else { 0x00 };
                        code.push(rex);
                        code.push(0xB8 + dst.hw_code);
                        code.extend_from_slice(&imm64.to_le_bytes());
                        insn_byte_offsets[pc + 1] = code.len();
                        pc += 2;
                        continue;
                    } else {
                        return Err(JitError::UnsupportedOpcode(pc, insn.code));
                    }
                }
                BPF_ALU64 => {
                    Self::emit_alu64(&mut code, pc, insn, dst, src)?;
                }
                BPF_LDX => {
                    if insn.mem_mode() != BPF_MEM {
                        return Err(JitError::UnsupportedOpcode(pc, insn.code));
                    }
                    // Emit 64-bit or 32-bit load: mov dst, [src + disp32]
                    let rex = 0x48
                        | if dst.is_ext { 0x04 } else { 0x00 }
                        | if src.is_ext { 0x01 } else { 0x00 };
                    code.push(rex);
                    code.push(0x8B);
                    let modrm = 0x80 | ((dst.hw_code & 7) << 3) | (src.hw_code & 7);
                    code.push(modrm);
                    if (src.hw_code & 7) == 4 {
                        code.push(0x24); // SIB byte when base is rsp/r12
                    }
                    code.extend_from_slice(&(insn.off as i32).to_le_bytes());
                }
                BPF_STX => {
                    if insn.mem_mode() != BPF_MEM {
                        return Err(JitError::UnsupportedOpcode(pc, insn.code));
                    }
                    // Emit store: mov [dst + disp32], src
                    let rex = 0x48
                        | if src.is_ext { 0x04 } else { 0x00 }
                        | if dst.is_ext { 0x01 } else { 0x00 };
                    code.push(rex);
                    code.push(0x89);
                    let modrm = 0x80 | ((src.hw_code & 7) << 3) | (dst.hw_code & 7);
                    code.push(modrm);
                    if (dst.hw_code & 7) == 4 {
                        code.push(0x24);
                    }
                    code.extend_from_slice(&(insn.off as i32).to_le_bytes());
                }
                BPF_ST => {
                    if insn.mem_mode() != BPF_MEM {
                        return Err(JitError::UnsupportedOpcode(pc, insn.code));
                    }
                    // mov qword ptr [dst + disp32], imm32 (0x48 0xC7 /0)
                    let rex = 0x48 | if dst.is_ext { 0x01 } else { 0x00 };
                    code.push(rex);
                    code.push(0xC7);
                    let modrm = 0x80 | (dst.hw_code & 7);
                    code.push(modrm);
                    if (dst.hw_code & 7) == 4 {
                        code.push(0x24);
                    }
                    code.extend_from_slice(&(insn.off as i32).to_le_bytes());
                    code.extend_from_slice(&insn.imm.to_le_bytes());
                }
                BPF_JMP => {
                    let op = insn.op();
                    if op == BPF_EXIT {
                        // Jump to shared epilogue (`jmp rel32` to `prog.len()`).
                        code.push(0xE9);
                        let disp_offset = code.len();
                        code.extend_from_slice(&[0, 0, 0, 0]);
                        fixups.push(JumpFixup {
                            disp_offset,
                            next_rip_offset: code.len(),
                            target_insn_idx: prog.len(),
                        });
                    } else if op == BPF_JA {
                        let target = (pc as isize) + 1 + (insn.off as isize);
                        if target < 0 || target > (prog.len() as isize) {
                            return Err(JitError::JumpTargetOutOfRange(pc));
                        }
                        code.push(0xE9);
                        let disp_offset = code.len();
                        code.extend_from_slice(&[0, 0, 0, 0]);
                        fixups.push(JumpFixup {
                            disp_offset,
                            next_rip_offset: code.len(),
                            target_insn_idx: target as usize,
                        });
                    } else {
                        let target = (pc as isize) + 1 + (insn.off as isize);
                        if target < 0 || target > (prog.len() as isize) {
                            return Err(JitError::JumpTargetOutOfRange(pc));
                        }
                        if insn.source() == BPF_X {
                            // cmp dst, src (REX.W + 0x39 /r)
                            let rex = 0x48
                                | if src.is_ext { 0x04 } else { 0x00 }
                                | if dst.is_ext { 0x01 } else { 0x00 };
                            code.push(rex);
                            code.push(0x39);
                            code.push(0xC0 | ((src.hw_code & 7) << 3) | (dst.hw_code & 7));
                        } else {
                            // cmp dst, imm32 (REX.W + 0x81 /7 imm32)
                            let rex = 0x48 | if dst.is_ext { 0x01 } else { 0x00 };
                            code.push(rex);
                            code.push(0x81);
                            code.push(0xF8 | (dst.hw_code & 7));
                            code.extend_from_slice(&insn.imm.to_le_bytes());
                        }

                        let jcc_opcode = match op {
                            BPF_JEQ => 0x84,  // je rel32
                            BPF_JNE => 0x85,  // jne rel32
                            BPF_JGT => 0x87,  // ja rel32
                            BPF_JGE => 0x83,  // jae rel32
                            BPF_JLT => 0x82,  // jb rel32
                            BPF_JLE => 0x86,  // jbe rel32
                            BPF_JSGT => 0x8F, // jg rel32
                            BPF_JSGE => 0x8D, // jge rel32
                            BPF_JSLT => 0x8C, // jl rel32
                            BPF_JSLE => 0x8E, // jle rel32
                            _ => return Err(JitError::UnsupportedOpcode(pc, insn.code)),
                        };

                        code.push(0x0F);
                        code.push(jcc_opcode);
                        let disp_offset = code.len();
                        code.extend_from_slice(&[0, 0, 0, 0]);
                        fixups.push(JumpFixup {
                            disp_offset,
                            next_rip_offset: code.len(),
                            target_insn_idx: target as usize,
                        });
                    }
                }
                _ => return Err(JitError::UnsupportedOpcode(pc, insn.code)),
            }

            pc += 1;
        }

        // --- Function Epilogue ---
        let epilogue_offset = code.len();
        insn_byte_offsets[prog.len()] = epilogue_offset;
        // add rsp, 512 (0x48 0x81 0xC4 0x00 0x02 0x00 0x00)
        code.extend_from_slice(&[0x48, 0x81, 0xC4, 0x00, 0x02, 0x00, 0x00]);
        // Restore callee-saved registers: pop r15; pop r14; pop r13; pop rbx
        code.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D]);
        code.push(0x5B);
        // leave (0xC9); ret (0xC3)
        code.push(0xC9);
        code.push(0xC3);

        // --- Second Pass: Patch all relative jump displacements ---
        for fixup in fixups {
            let target_byte = insn_byte_offsets[fixup.target_insn_idx];
            let rel32 = (target_byte as isize - fixup.next_rip_offset as isize) as i32;
            let bytes = rel32.to_le_bytes();
            code[fixup.disp_offset..fixup.disp_offset + 4].copy_from_slice(&bytes);
        }

        Ok(X86JitBuffer {
            code,
            insn_byte_offsets,
            epilogue_offset,
        })
    }

    fn emit_alu64(
        code: &mut Vec<u8>,
        pc: usize,
        insn: BpfInsn,
        dst: X86Reg,
        src: X86Reg,
    ) -> Result<(), JitError> {
        let op = insn.op();
        if insn.source() == BPF_X {
            let rex = 0x48
                | if src.is_ext { 0x04 } else { 0x00 }
                | if dst.is_ext { 0x01 } else { 0x00 };
            let modrm = 0xC0 | ((src.hw_code & 7) << 3) | (dst.hw_code & 7);
            match op {
                BPF_MOV => {
                    code.extend_from_slice(&[rex, 0x89, modrm]);
                }
                BPF_ADD => {
                    code.extend_from_slice(&[rex, 0x01, modrm]);
                }
                BPF_SUB => {
                    code.extend_from_slice(&[rex, 0x29, modrm]);
                }
                BPF_OR => {
                    code.extend_from_slice(&[rex, 0x09, modrm]);
                }
                BPF_AND => {
                    code.extend_from_slice(&[rex, 0x21, modrm]);
                }
                BPF_XOR => {
                    code.extend_from_slice(&[rex, 0x31, modrm]);
                }
                BPF_MUL => {
                    // imul dst, src (REX.W + 0x0F 0xAF /r)
                    let rex_imul = 0x48
                        | if dst.is_ext { 0x04 } else { 0x00 }
                        | if src.is_ext { 0x01 } else { 0x00 };
                    let modrm_imul = 0xC0 | ((dst.hw_code & 7) << 3) | (src.hw_code & 7);
                    code.extend_from_slice(&[rex_imul, 0x0F, 0xAF, modrm_imul]);
                }
                _ => return Err(JitError::UnsupportedOpcode(pc, insn.code)),
            }
        } else {
            let rex = 0x48 | if dst.is_ext { 0x01 } else { 0x00 };
            match op {
                BPF_MOV => {
                    // mov dst, sign_ext_imm32 (REX.W + 0xC7 /0 imm32)
                    code.extend_from_slice(&[rex, 0xC7, 0xC0 | (dst.hw_code & 7)]);
                    code.extend_from_slice(&insn.imm.to_le_bytes());
                }
                BPF_ADD | BPF_SUB | BPF_OR | BPF_AND | BPF_XOR => {
                    let subcode = match op {
                        BPF_ADD => 0,
                        BPF_OR => 1,
                        BPF_AND => 4,
                        BPF_SUB => 5,
                        BPF_XOR => 6,
                        _ => 0,
                    };
                    code.extend_from_slice(&[rex, 0x81, 0xC0 | (subcode << 3) | (dst.hw_code & 7)]);
                    code.extend_from_slice(&insn.imm.to_le_bytes());
                }
                BPF_LSH | BPF_RSH | BPF_ARSH => {
                    let subcode = match op {
                        BPF_LSH => 4,  // shl
                        BPF_RSH => 5,  // shr
                        BPF_ARSH => 7, // sar
                        _ => 4,
                    };
                    code.extend_from_slice(&[
                        rex,
                        0xC1,
                        0xC0 | (subcode << 3) | (dst.hw_code & 7),
                        (insn.imm as u8) & 63,
                    ]);
                }
                BPF_NEG => {
                    code.extend_from_slice(&[rex, 0xF7, 0xD8 | (dst.hw_code & 7)]);
                }
                _ => return Err(JitError::UnsupportedOpcode(pc, insn.code)),
            }
        }
        Ok(())
    }
}
