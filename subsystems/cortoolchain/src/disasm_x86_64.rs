//! x86_64 Machine Code Disassembler (`disasm_x86_64`)
//!
//! Provides prefix decoding, REX prefixes, ModR/M & SIB calculation,
//! displacement, immediate parsing, and Intel-syntax formatting.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RexPrefix {
    pub present: bool,
    pub w: bool, // 64-bit operand size
    pub r: bool, // ModR/M reg extension
    pub x: bool, // SIB index extension
    pub b: bool, // ModR/M r/m or SIB base extension
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefixGroup {
    pub rex: RexPrefix,
    pub op_size_override: bool, // 0x66
    pub addr_size_override: bool, // 0x67
    pub lock: bool,              // 0xF0
    pub repne: bool,             // 0xF2
    pub rep_repe: bool,          // 0xF3
    pub segment_override: Option<SegmentReg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentReg {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegSize {
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub id: u8,
    pub size: RegSize,
}

impl Register {
    pub fn name(&self) -> &'static str {
        match self.size {
            RegSize::Qword => match self.id {
                0 => "rax",
                1 => "rcx",
                2 => "rdx",
                3 => "rbx",
                4 => "rsp",
                5 => "rbp",
                6 => "rsi",
                7 => "rdi",
                8 => "r8",
                9 => "r9",
                10 => "r10",
                11 => "r11",
                12 => "r12",
                13 => "r13",
                14 => "r14",
                15 => "r15",
                _ => "r??",
            },
            RegSize::Dword => match self.id {
                0 => "eax",
                1 => "ecx",
                2 => "edx",
                3 => "ebx",
                4 => "esp",
                5 => "ebp",
                6 => "esi",
                7 => "edi",
                8 => "r8d",
                9 => "r9d",
                10 => "r10d",
                11 => "r11d",
                12 => "r12d",
                13 => "r13d",
                14 => "r14d",
                15 => "r15d",
                _ => "e??",
            },
            RegSize::Word => match self.id {
                0 => "ax",
                1 => "cx",
                2 => "dx",
                3 => "bx",
                4 => "sp",
                5 => "bp",
                6 => "si",
                7 => "di",
                8 => "r8w",
                9 => "r9w",
                10 => "r10w",
                11 => "r11w",
                12 => "r12w",
                13 => "r13w",
                14 => "r14w",
                15 => "r15w",
                _ => "??w",
            },
            RegSize::Byte => match self.id {
                0 => "al",
                1 => "cl",
                2 => "dl",
                3 => "bl",
                4 => "spl",
                5 => "bpl",
                6 => "sil",
                7 => "dil",
                8 => "r8b",
                9 => "r9b",
                10 => "r10b",
                11 => "r11b",
                12 => "r12b",
                13 => "r13b",
                14 => "r14b",
                15 => "r15b",
                _ => "??b",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryOperand {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub scale: u8,
    pub disp: i64,
    pub is_rip_relative: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Reg(Register),
    Mem(MemoryOperand),
    Imm(i64),
}

#[derive(Debug, Clone)]
pub struct DisassembledInst {
    pub address: u64,
    pub length: usize,
    pub mnemonic: &'static str,
    pub operands: Vec<Operand>,
    pub formatted: String,
}

pub struct Disassembler;

impl Disassembler {
    pub fn decode_one(bytes: &[u8], address: u64) -> Option<DisassembledInst> {
        if bytes.is_empty() {
            return None;
        }

        let mut offset = 0;
        let mut prefixes = PrefixGroup::default();

        // 1. Decode prefixes
        while offset < bytes.len() {
            match bytes[offset] {
                0x66 => prefixes.op_size_override = true,
                0x67 => prefixes.addr_size_override = true,
                0xF0 => prefixes.lock = true,
                0xF2 => prefixes.repne = true,
                0xF3 => prefixes.rep_repe = true,
                0x2E => prefixes.segment_override = Some(SegmentReg::CS),
                0x36 => prefixes.segment_override = Some(SegmentReg::SS),
                0x3E => prefixes.segment_override = Some(SegmentReg::DS),
                0x26 => prefixes.segment_override = Some(SegmentReg::ES),
                0x64 => prefixes.segment_override = Some(SegmentReg::FS),
                0x65 => prefixes.segment_override = Some(SegmentReg::GS),
                b if (0x40..=0x4F).contains(&b) => {
                    prefixes.rex = RexPrefix {
                        present: true,
                        w: (b & 0x08) != 0,
                        r: (b & 0x04) != 0,
                        x: (b & 0x02) != 0,
                        b: (b & 0x01) != 0,
                    };
                }
                _ => break,
            }
            offset += 1;
        }

        if offset >= bytes.len() {
            return None;
        }

        let default_reg_size = if prefixes.rex.w {
            RegSize::Qword
        } else if prefixes.op_size_override {
            RegSize::Word
        } else {
            RegSize::Dword
        };

        let op = bytes[offset];
        offset += 1;

        // Two-byte opcode (0x0F)
        if op == 0x0F {
            if offset >= bytes.len() {
                return None;
            }
            let op2 = bytes[offset];
            offset += 1;

            match op2 {
                0x05 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "syscall",
                        operands: Vec::new(),
                        formatted: String::from("syscall"),
                    });
                }
                0x07 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "sysret",
                        operands: Vec::new(),
                        formatted: String::from("sysret"),
                    });
                }
                0xA2 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "cpuid",
                        operands: Vec::new(),
                        formatted: String::from("cpuid"),
                    });
                }
                0x31 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "rdtsc",
                        operands: Vec::new(),
                        formatted: String::from("rdtsc"),
                    });
                }
                0x32 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "rdmsr",
                        operands: Vec::new(),
                        formatted: String::from("rdmsr"),
                    });
                }
                0x30 => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "wrmsr",
                        operands: Vec::new(),
                        formatted: String::from("wrmsr"),
                    });
                }
                0x0B => {
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "ud2",
                        operands: Vec::new(),
                        formatted: String::from("ud2"),
                    });
                }
                0x80..=0x8F => {
                    let cond_name = Self::condition_name(op2 & 0x0F);
                    if offset + 4 > bytes.len() {
                        return None;
                    }
                    let rel = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                    offset += 4;
                    let target = (address as i64)
                        .wrapping_add(offset as i64)
                        .wrapping_add(rel as i64) as u64;
                    let mnem = match cond_name {
                        "e" => "je",
                        "ne" => "jne",
                        "l" => "jl",
                        "le" => "jle",
                        "g" => "jg",
                        "ge" => "jge",
                        "b" => "jb",
                        "be" => "jbe",
                        "a" => "ja",
                        "ae" => "jae",
                        _ => "jcc",
                    };
                    return Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: mnem,
                        operands: alloc::vec![Operand::Imm(target as i64)],
                        formatted: format!("{} 0x{:x}", mnem, target),
                    });
                }
                _ => {}
            }
        }

        // Single-byte opcodes
        match op {
            0x90 => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "nop",
                operands: Vec::new(),
                formatted: String::from("nop"),
            }),
            0xCC => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "int3",
                operands: Vec::new(),
                formatted: String::from("int3"),
            }),
            0xC3 => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "ret",
                operands: Vec::new(),
                formatted: String::from("ret"),
            }),
            0xFA => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "cli",
                operands: Vec::new(),
                formatted: String::from("cli"),
            }),
            0xFB => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "sti",
                operands: Vec::new(),
                formatted: String::from("sti"),
            }),
            0xF4 => Some(DisassembledInst {
                address,
                length: offset,
                mnemonic: "hlt",
                operands: Vec::new(),
                formatted: String::from("hlt"),
            }),

            // PUSH r64 (0x50..=0x57)
            0x50..=0x57 => {
                let reg_id = (op - 0x50) + if prefixes.rex.b { 8 } else { 0 };
                let reg = Register { id: reg_id, size: RegSize::Qword };
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "push",
                    operands: alloc::vec![Operand::Reg(reg)],
                    formatted: format!("push {}", reg.name()),
                })
            }

            // POP r64 (0x58..=0x5F)
            0x58..=0x5F => {
                let reg_id = (op - 0x58) + if prefixes.rex.b { 8 } else { 0 };
                let reg = Register { id: reg_id, size: RegSize::Qword };
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "pop",
                    operands: alloc::vec![Operand::Reg(reg)],
                    formatted: format!("pop {}", reg.name()),
                })
            }

            // JMP rel8 (0xEB)
            0xEB => {
                if offset >= bytes.len() {
                    return None;
                }
                let rel = bytes[offset] as i8;
                offset += 1;
                let target = (address as i64)
                    .wrapping_add(offset as i64)
                    .wrapping_add(rel as i64) as u64;
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "jmp",
                    operands: alloc::vec![Operand::Imm(target as i64)],
                    formatted: format!("jmp 0x{:x}", target),
                })
            }

            // JMP rel32 (0xE9)
            0xE9 => {
                if offset + 4 > bytes.len() {
                    return None;
                }
                let rel = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let target = (address as i64)
                    .wrapping_add(offset as i64)
                    .wrapping_add(rel as i64) as u64;
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "jmp",
                    operands: alloc::vec![Operand::Imm(target as i64)],
                    formatted: format!("jmp 0x{:x}", target),
                })
            }

            // CALL rel32 (0xE8)
            0xE8 => {
                if offset + 4 > bytes.len() {
                    return None;
                }
                let rel = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let target = (address as i64)
                    .wrapping_add(offset as i64)
                    .wrapping_add(rel as i64) as u64;
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "call",
                    operands: alloc::vec![Operand::Imm(target as i64)],
                    formatted: format!("call 0x{:x}", target),
                })
            }

            // MOV r/m, reg (0x89)
            0x89 => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("mov {}, {}", Self::fmt_op(&mem_or_rm), reg.name());
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "mov",
                    operands: alloc::vec![mem_or_rm, Operand::Reg(reg)],
                    formatted,
                })
            }

            // MOV reg, r/m (0x8B)
            0x8B => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("mov {}, {}", reg.name(), Self::fmt_op(&mem_or_rm));
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "mov",
                    operands: alloc::vec![Operand::Reg(reg), mem_or_rm],
                    formatted,
                })
            }

            // LEA reg, mem (0x8D)
            0x8D => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("lea {}, {}", reg.name(), Self::fmt_op(&mem_or_rm));
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "lea",
                    operands: alloc::vec![Operand::Reg(reg), mem_or_rm],
                    formatted,
                })
            }

            // XOR r/m, reg (0x31)
            0x31 => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("xor {}, {}", Self::fmt_op(&mem_or_rm), reg.name());
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "xor",
                    operands: alloc::vec![mem_or_rm, Operand::Reg(reg)],
                    formatted,
                })
            }

            // ADD r/m, reg (0x01)
            0x01 => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("add {}, {}", Self::fmt_op(&mem_or_rm), reg.name());
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "add",
                    operands: alloc::vec![mem_or_rm, Operand::Reg(reg)],
                    formatted,
                })
            }

            // SUB r/m, reg (0x29)
            0x29 => {
                let (reg, mem_or_rm, consumed) = Self::decode_modrm(bytes, offset, &prefixes, default_reg_size)?;
                offset += consumed;
                let formatted = format!("sub {}, {}", Self::fmt_op(&mem_or_rm), reg.name());
                Some(DisassembledInst {
                    address,
                    length: offset,
                    mnemonic: "sub",
                    operands: alloc::vec![mem_or_rm, Operand::Reg(reg)],
                    formatted,
                })
            }

            // MOV reg, imm32/imm64 (0xB8..=0xBF)
            0xB8..=0xBF => {
                let reg_id = (op - 0xB8) + if prefixes.rex.b { 8 } else { 0 };
                let reg = Register { id: reg_id, size: default_reg_size };
                if prefixes.rex.w {
                    // 64-bit immediate (movabs)
                    if offset + 8 > bytes.len() {
                        return None;
                    }
                    let imm = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                    offset += 8;
                    Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "movabs",
                        operands: alloc::vec![Operand::Reg(reg), Operand::Imm(imm)],
                        formatted: format!("movabs {}, 0x{:x}", reg.name(), imm),
                    })
                } else {
                    // 32-bit immediate
                    if offset + 4 > bytes.len() {
                        return None;
                    }
                    let imm = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as i64;
                    offset += 4;
                    Some(DisassembledInst {
                        address,
                        length: offset,
                        mnemonic: "mov",
                        operands: alloc::vec![Operand::Reg(reg), Operand::Imm(imm)],
                        formatted: format!("mov {}, 0x{:x}", reg.name(), imm),
                    })
                }
            }

            _ => None,
        }
    }

    fn decode_modrm(
        bytes: &[u8],
        start: usize,
        prefixes: &PrefixGroup,
        reg_size: RegSize,
    ) -> Option<(Register, Operand, usize)> {
        if start >= bytes.len() {
            return None;
        }

        let modrm = bytes[start];
        let mut consumed = 1;

        let mod_bits = (modrm >> 6) & 3;
        let reg_bits = ((modrm >> 3) & 7) | if prefixes.rex.r { 8 } else { 0 };
        let rm_bits = (modrm & 7) | if prefixes.rex.b { 8 } else { 0 };

        let reg = Register { id: reg_bits, size: reg_size };

        if mod_bits == 3 {
            // Register-direct
            let rm_reg = Register { id: rm_bits, size: reg_size };
            return Some((reg, Operand::Reg(rm_reg), consumed));
        }

        // Memory operand
        if mod_bits == 0 && (rm_bits & 7) == 5 {
            // RIP-relative addressing
            if start + consumed + 4 > bytes.len() {
                return None;
            }
            let disp = i32::from_le_bytes(bytes[start + consumed..start + consumed + 4].try_into().unwrap()) as i64;
            consumed += 4;
            let mem = MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                disp,
                is_rip_relative: true,
            };
            return Some((reg, Operand::Mem(mem), consumed));
        }

        // Check for SIB byte
        let (base_reg, index_reg, scale) = if (rm_bits & 7) == 4 {
            if start + consumed >= bytes.len() {
                return None;
            }
            let sib = bytes[start + consumed];
            consumed += 1;

            let sib_scale = 1u8 << ((sib >> 6) & 3);
            let sib_index = ((sib >> 3) & 7) | if prefixes.rex.x { 8 } else { 0 };
            let sib_base = (sib & 7) | if prefixes.rex.b { 8 } else { 0 };

            let idx = if sib_index == 4 { None } else { Some(sib_index) };
            let base = if mod_bits == 0 && (sib_base & 7) == 5 {
                None
            } else {
                Some(sib_base)
            };
            (base, idx, sib_scale)
        } else {
            (Some(rm_bits), None, 1)
        };

        // Displacements
        let disp = match mod_bits {
            1 => {
                if start + consumed >= bytes.len() {
                    return None;
                }
                let d = bytes[start + consumed] as i8 as i64;
                consumed += 1;
                d
            }
            2 => {
                if start + consumed + 4 > bytes.len() {
                    return None;
                }
                let d = i32::from_le_bytes(bytes[start + consumed..start + consumed + 4].try_into().unwrap()) as i64;
                consumed += 4;
                d
            }
            _ => 0,
        };

        let mem = MemoryOperand {
            base: base_reg,
            index: index_reg,
            scale,
            disp,
            is_rip_relative: false,
        };

        Some((reg, Operand::Mem(mem), consumed))
    }

    fn fmt_op(op: &Operand) -> String {
        match op {
            Operand::Reg(r) => String::from(r.name()),
            Operand::Imm(imm) => format!("0x{:x}", imm),
            Operand::Mem(m) => {
                if m.is_rip_relative {
                    if m.disp >= 0 {
                        format!("[rip + 0x{:x}]", m.disp)
                    } else {
                        format!("[rip - 0x{:x}]", -m.disp)
                    }
                } else {
                    let base_str = m.base.map(|b| Register { id: b, size: RegSize::Qword }.name()).unwrap_or("");
                    if let Some(idx) = m.index {
                        let idx_str = Register { id: idx, size: RegSize::Qword }.name();
                        if m.disp > 0 {
                            format!("[{} + {}*{} + 0x{:x}]", base_str, idx_str, m.scale, m.disp)
                        } else if m.disp < 0 {
                            format!("[{} + {}*{} - 0x{:x}]", base_str, idx_str, m.scale, -m.disp)
                        } else {
                            format!("[{} + {}*{}]", base_str, idx_str, m.scale)
                        }
                    } else if m.disp > 0 {
                        format!("[{} + 0x{:x}]", base_str, m.disp)
                    } else if m.disp < 0 {
                        format!("[{} - 0x{:x}]", base_str, -m.disp)
                    } else {
                        format!("[{}]", base_str)
                    }
                }
            }
        }
    }

    fn condition_name(cond: u8) -> &'static str {
        match cond {
            0 => "o",
            1 => "no",
            2 => "b",
            3 => "ae",
            4 => "e",
            5 => "ne",
            6 => "be",
            7 => "a",
            8 => "s",
            9 => "ns",
            10 => "p",
            11 => "np",
            12 => "l",
            13 => "ge",
            14 => "le",
            15 => "g",
            _ => "??",
        }
    }
}

pub fn verify_disasm_x86_64() -> u32 {
    let mut check_count = 0u32;

    // Test 1: NOP
    let nop_bytes = [0x90];
    if let Some(inst) = Disassembler::decode_one(&nop_bytes, 0x1000) {
        if inst.mnemonic == "nop" && inst.length == 1 {
            check_count += 1;
        }
    }

    // Test 2: INT3
    let int3_bytes = [0xCC];
    if let Some(inst) = Disassembler::decode_one(&int3_bytes, 0x1000) {
        if inst.mnemonic == "int3" && inst.length == 1 {
            check_count += 1;
        }
    }

    // Test 3: RET
    let ret_bytes = [0xC3];
    if let Some(inst) = Disassembler::decode_one(&ret_bytes, 0x1000) {
        if inst.mnemonic == "ret" && inst.length == 1 {
            check_count += 1;
        }
    }

    // Test 4: PUSH RBP (0x55)
    let push_rbp = [0x55];
    if let Some(inst) = Disassembler::decode_one(&push_rbp, 0x1000) {
        if inst.mnemonic == "push" && inst.formatted == "push rbp" && inst.length == 1 {
            check_count += 1;
        }
    }

    // Test 5: MOV RBP, RSP (0x48, 0x89, 0xE5)
    let mov_rbp_rsp = [0x48, 0x89, 0xE5];
    if let Some(inst) = Disassembler::decode_one(&mov_rbp_rsp, 0x1000) {
        if inst.mnemonic == "mov" && inst.formatted == "mov rbp, rsp" && inst.length == 3 {
            check_count += 1;
        }
    }

    // Test 6: XOR RAX, RAX (0x48, 0x31, 0xC0)
    let xor_rax = [0x48, 0x31, 0xC0];
    if let Some(inst) = Disassembler::decode_one(&xor_rax, 0x1000) {
        if inst.mnemonic == "xor" && inst.formatted == "xor rax, rax" && inst.length == 3 {
            check_count += 1;
        }
    }

    // Test 7: SYSCALL (0x0F, 0x05)
    let syscall_bytes = [0x0F, 0x05];
    if let Some(inst) = Disassembler::decode_one(&syscall_bytes, 0x1000) {
        if inst.mnemonic == "syscall" && inst.length == 2 {
            check_count += 1;
        }
    }

    // Test 8: LEA RAX, [RIP + 0x20] (0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00)
    let lea_bytes = [0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00];
    if let Some(inst) = Disassembler::decode_one(&lea_bytes, 0x1000) {
        if inst.mnemonic == "lea" && inst.formatted == "lea rax, [rip + 0x20]" && inst.length == 7 {
            check_count += 1;
        }
    }

    // Test 9: CALL rel32 (0xE8, 0x10, 0x00, 0x00, 0x00)
    // At addr 0x2000, length 5. Next PC = 0x2005. Target = 0x2005 + 0x10 = 0x2015.
    let call_bytes = [0xE8, 0x10, 0x00, 0x00, 0x00];
    if let Some(inst) = Disassembler::decode_one(&call_bytes, 0x2000) {
        if inst.mnemonic == "call" && inst.formatted == "call 0x2015" && inst.length == 5 {
            check_count += 1;
        }
    }

    check_count
}
