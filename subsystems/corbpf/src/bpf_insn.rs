//! 64-bit Extended BPF (`eBPF`) Instruction Representation, Opcodes, and Program Builder.

use alloc::vec::Vec;

/// Instruction classes (lowest 3 bits of `code`).
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

/// Operand source flag (bit 3 of `code`).
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

/// Memory access sizes (bits 3..4 of `code` for LD/LDX/ST/STX).
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

/// Memory addressing modes (bits 5..7 of `code` for LD/LDX/ST/STX).
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_ATOMIC: u8 = 0xc0;

/// ALU / ALU64 operation codes (upper 4 bits of `code`).
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

/// Jump operation codes (upper 4 bits of `code` for JMP / JMP32).
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

/// Architectural eBPF registers (`R0` through `R10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfReg {
    /// Return value from functions and exit value of eBPF programs.
    RetVal = 0,
    /// First argument / context pointer (`ctx`).
    ArgFirst = 1,
    /// Second function argument.
    ArgSecond = 2,
    /// Third function argument.
    ArgThird = 3,
    /// Fourth function argument.
    ArgFourth = 4,
    /// Fifth function argument.
    ArgFifth = 5,
    /// Callee-saved register A.
    CalleeSavedA = 6,
    /// Callee-saved register B.
    CalleeSavedB = 7,
    /// Callee-saved register C.
    CalleeSavedC = 8,
    /// Callee-saved register D.
    CalleeSavedD = 9,
    /// Read-only stack frame pointer.
    FramePointer = 10,
}

impl BpfReg {
    pub const fn from_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(Self::RetVal),
            1 => Some(Self::ArgFirst),
            2 => Some(Self::ArgSecond),
            3 => Some(Self::ArgThird),
            4 => Some(Self::ArgFourth),
            5 => Some(Self::ArgFifth),
            6 => Some(Self::CalleeSavedA),
            7 => Some(Self::CalleeSavedB),
            8 => Some(Self::CalleeSavedC),
            9 => Some(Self::CalleeSavedD),
            10 => Some(Self::FramePointer),
            _ => None,
        }
    }
}

/// Canonical 64-bit eBPF instruction (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode combining instruction class, source/mode, and operation.
    pub code: u8,
    /// Low nibble = destination register (`dst_reg`), high nibble = source register (`src_reg`).
    pub regs: u8,
    /// Signed 16-bit offset for memory accesses or relative jumps.
    pub off: i16,
    /// Signed 32-bit immediate constant or helper function ID.
    pub imm: i32,
}

impl BpfInsn {
    /// Construct a raw eBPF instruction.
    pub const fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst_reg & 0x0f) | ((src_reg & 0x0f) << 4),
            off,
            imm,
        }
    }

    /// Extract destination register index (`0..=15`).
    #[inline]
    pub const fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Extract source register index (`0..=15`).
    #[inline]
    pub const fn src_reg(&self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    /// Extract instruction class (`BPF_LD..=BPF_ALU64`).
    #[inline]
    pub const fn class(&self) -> u8 {
        self.code & 0x07
    }

    /// Extract ALU or JMP operation field (`code & 0xf0`).
    #[inline]
    pub const fn op(&self) -> u8 {
        self.code & 0xf0
    }

    /// Extract source operand flag (`BPF_K` or `BPF_X`).
    #[inline]
    pub const fn source(&self) -> u8 {
        self.code & 0x08
    }

    /// Extract memory access width (`BPF_W`, `BPF_H`, `BPF_B`, `BPF_DW`).
    #[inline]
    pub const fn mem_size(&self) -> u8 {
        self.code & 0x18
    }

    /// Extract memory mode (`BPF_IMM`, `BPF_ABS`, `BPF_IND`, `BPF_MEM`, `BPF_ATOMIC`).
    #[inline]
    pub const fn mem_mode(&self) -> u8 {
        self.code & 0xe0
    }

    /// Return byte width of a memory instruction (1, 2, 4, or 8 bytes).
    pub const fn mem_byte_width(&self) -> usize {
        match self.mem_size() {
            BPF_B => 1,
            BPF_H => 2,
            BPF_W => 4,
            BPF_DW => 8,
            _ => 0,
        }
    }

    /// Serialize into little-endian 8-byte representation.
    pub const fn to_le_bytes(&self) -> [u8; 8] {
        let off_bytes = self.off.to_le_bytes();
        let imm_bytes = self.imm.to_le_bytes();
        [
            self.code,
            self.regs,
            off_bytes[0],
            off_bytes[1],
            imm_bytes[0],
            imm_bytes[1],
            imm_bytes[2],
            imm_bytes[3],
        ]
    }

    /// Parse from little-endian 8-byte slice.
    pub const fn from_le_bytes(raw: [u8; 8]) -> Self {
        let off = i16::from_le_bytes([raw[2], raw[3]]);
        let imm = i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        Self {
            code: raw[0],
            regs: raw[1],
            off,
            imm,
        }
    }

    // --- Instruction Builder Helpers ---

    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
    }

    pub const fn add64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_X, dst, src, 0, 0)
    }

    pub const fn sub64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_SUB | BPF_K, dst, 0, 0, imm)
    }

    pub const fn sub64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_SUB | BPF_X, dst, src, 0, 0)
    }

    pub const fn mul64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MUL | BPF_K, dst, 0, 0, imm)
    }

    pub const fn mul64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MUL | BPF_X, dst, src, 0, 0)
    }

    pub const fn div64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_DIV | BPF_K, dst, 0, 0, imm)
    }

    pub const fn div64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_DIV | BPF_X, dst, src, 0, 0)
    }

    pub const fn mod64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOD | BPF_K, dst, 0, 0, imm)
    }

    pub const fn and64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm)
    }

    pub const fn or64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_OR | BPF_K, dst, 0, 0, imm)
    }

    pub const fn xor64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_XOR | BPF_X, dst, src, 0, 0)
    }

    pub const fn lsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_LSH | BPF_K, dst, 0, 0, imm)
    }

    pub const fn rsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm)
    }

    pub const fn arsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_ARSH | BPF_K, dst, 0, 0, imm)
    }

    pub const fn neg64(dst: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_NEG, dst, 0, 0, 0)
    }

    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | (size & 0x18), dst, src, off, 0)
    }

    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_STX | BPF_MEM | (size & 0x18), dst, src, off, 0)
    }

    pub const fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_ST | BPF_MEM | (size & 0x18), dst, 0, off, imm)
    }

    pub const fn ja(off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
    }

    pub const fn jeq_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm)
    }

    pub const fn jeq_reg(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JEQ | BPF_X, dst, src, off, 0)
    }

    pub const fn jne_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JNE | BPF_K, dst, 0, off, imm)
    }

    pub const fn jgt_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGT | BPF_K, dst, 0, off, imm)
    }

    pub const fn jge_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JGE | BPF_K, dst, 0, off, imm)
    }

    pub const fn jsgt_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JSGT | BPF_K, dst, 0, off, imm)
    }

    pub const fn jsge_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JSGE | BPF_K, dst, 0, off, imm)
    }

    pub const fn jset_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JSET | BPF_K, dst, 0, off, imm)
    }

    pub const fn call_helper(helper_id: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id)
    }

    pub const fn exit_insn() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }
}

/// Fluent builder for assembling an eBPF program.
pub struct BpfProgramBuilder {
    insns: Vec<BpfInsn>,
}

impl BpfProgramBuilder {
    pub fn new() -> Self {
        Self { insns: Vec::new() }
    }

    pub fn push(&mut self, insn: BpfInsn) -> &mut Self {
        self.insns.push(insn);
        self
    }

    /// Emit wide 64-bit immediate load (`BPF_LD | BPF_DW | BPF_IMM`), occupying 2 instruction slots.
    pub fn push_ld_imm64(&mut self, dst: u8, val: u64) -> &mut Self {
        let low = (val & 0xffff_ffff) as i32;
        let high = (val >> 32) as i32;
        self.insns
            .push(BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, dst, 0, 0, low));
        self.insns.push(BpfInsn::new(0, 0, 0, 0, high));
        self
    }

    pub fn build(self) -> Vec<BpfInsn> {
        self.insns
    }
}

impl Default for BpfProgramBuilder {
    fn default() -> Self {
        Self::new()
    }
}
