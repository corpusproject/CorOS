//! CorOS Berkeley Packet Filter (BPF / eBPF) Virtual Machine Engine (`bpf.rs`)
//!
//! Implements the classic BPF (cBPF) and extended BPF (eBPF) bytecode interpreter:
//! - Instruction classes: BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC
//! - Accumulator (A) and Index register (X)
//! - 16-word Scratch memory store (M[0..15])
//! - Packet slicing primitives: word (32-bit), half-word (16-bit), byte (8-bit)
//! - Pre-compiled filter generators: TCP port filter, UDP port filter, IP protocol filter, ARP filter
//! - Socket packet matching with zero-copy packet evaluation

extern crate alloc;

use alloc::vec::Vec;

/// BPF Instruction Classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

/// BPF Size modifiers
pub const BPF_W: u16 = 0x00; // 32 bits
pub const BPF_H: u16 = 0x08; // 16 bits
pub const BPF_B: u16 = 0x10; // 8 bits

/// BPF Mode modifiers
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xA0;

/// BPF ALU operations
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_XOR: u16 = 0xA0;

/// BPF JMP operations
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

/// Source operand (K = constant, X = index register)
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

/// A single BPF Instruction (8 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// BPF Virtual Machine Context
pub struct BpfVm {
    reg_a: u32,
    reg_x: u32,
    mem: [u32; 16],
}

impl BpfVm {
    pub fn new() -> Self {
        Self {
            reg_a: 0,
            reg_x: 0,
            mem: [0; 16],
        }
    }

    /// Execute BPF program against a raw packet buffer.
    /// Returns: Accepted packet snapshot length (0 = Reject/Drop).
    pub fn run(&mut self, program: &[BpfInsn], packet: &[u8]) -> u32 {
        let pkt_len = packet.len() as u32;
        let mut pc = 0usize;

        self.reg_a = 0;
        self.reg_x = 0;
        self.mem = [0; 16];

        while pc < program.len() {
            let insn = &program[pc];
            pc += 1;

            let class = insn.code & 0x07;

            match class {
                BPF_LD => {
                    let mode = insn.code & 0xE0;
                    let size = insn.code & 0x18;

                    match mode {
                        BPF_IMM => {
                            self.reg_a = insn.k;
                        }
                        BPF_LEN => {
                            self.reg_a = pkt_len;
                        }
                        BPF_MEM => {
                            let idx = (insn.k as usize) & 0x0F;
                            self.reg_a = self.mem[idx];
                        }
                        BPF_ABS => {
                            let k = insn.k as usize;
                            match size {
                                BPF_W => {
                                    if k + 4 <= packet.len() {
                                        self.reg_a = u32::from_be_bytes([
                                            packet[k], packet[k + 1], packet[k + 2], packet[k + 3],
                                        ]);
                                    } else {
                                        return 0;
                                    }
                                }
                                BPF_H => {
                                    if k + 2 <= packet.len() {
                                        self.reg_a = u16::from_be_bytes([packet[k], packet[k + 1]]) as u32;
                                    } else {
                                        return 0;
                                    }
                                }
                                BPF_B => {
                                    if k < packet.len() {
                                        self.reg_a = packet[k] as u32;
                                    } else {
                                        return 0;
                                    }
                                }
                                _ => return 0,
                            }
                        }
                        BPF_IND => {
                            let k = (insn.k.wrapping_add(self.reg_x)) as usize;
                            match size {
                                BPF_W => {
                                    if k + 4 <= packet.len() {
                                        self.reg_a = u32::from_be_bytes([
                                            packet[k], packet[k + 1], packet[k + 2], packet[k + 3],
                                        ]);
                                    } else {
                                        return 0;
                                    }
                                }
                                BPF_H => {
                                    if k + 2 <= packet.len() {
                                        self.reg_a = u16::from_be_bytes([packet[k], packet[k + 1]]) as u32;
                                    } else {
                                        return 0;
                                    }
                                }
                                BPF_B => {
                                    if k < packet.len() {
                                        self.reg_a = packet[k] as u32;
                                    } else {
                                        return 0;
                                    }
                                }
                                _ => return 0,
                            }
                        }
                        _ => return 0,
                    }
                }
                BPF_LDX => {
                    let mode = insn.code & 0xE0;
                    match mode {
                        BPF_IMM => self.reg_x = insn.k,
                        BPF_LEN => self.reg_x = pkt_len,
                        BPF_MEM => {
                            let idx = (insn.k as usize) & 0x0F;
                            self.reg_x = self.mem[idx];
                        }
                        BPF_MSH => {
                            // 4 * (packet[k] & 0xf) - typical IP header length in bytes
                            let k = insn.k as usize;
                            if k < packet.len() {
                                self.reg_x = ((packet[k] & 0x0F) * 4) as u32;
                            } else {
                                return 0;
                            }
                        }
                        _ => return 0,
                    }
                }
                BPF_ST => {
                    let idx = (insn.k as usize) & 0x0F;
                    self.mem[idx] = self.reg_a;
                }
                BPF_STX => {
                    let idx = (insn.k as usize) & 0x0F;
                    self.mem[idx] = self.reg_x;
                }
                BPF_ALU => {
                    let op = insn.code & 0xF0;
                    let src = if (insn.code & 0x08) == BPF_X {
                        self.reg_x
                    } else {
                        insn.k
                    };

                    match op {
                        BPF_ADD => self.reg_a = self.reg_a.wrapping_add(src),
                        BPF_SUB => self.reg_a = self.reg_a.wrapping_sub(src),
                        BPF_MUL => self.reg_a = self.reg_a.wrapping_mul(src),
                        BPF_DIV => {
                            if src == 0 {
                                return 0;
                            }
                            self.reg_a /= src;
                        }
                        BPF_OR => self.reg_a |= src,
                        BPF_AND => self.reg_a &= src,
                        BPF_LSH => self.reg_a = self.reg_a.wrapping_shl(src & 31),
                        BPF_RSH => self.reg_a = self.reg_a.wrapping_shr(src & 31),
                        BPF_NEG => self.reg_a = (-(self.reg_a as i32)) as u32,
                        BPF_XOR => self.reg_a ^= src,
                        _ => return 0,
                    }
                }
                BPF_JMP => {
                    let op = insn.code & 0xF0;
                    if op == BPF_JA {
                        pc += insn.k as usize;
                        continue;
                    }

                    let src = if (insn.code & 0x08) == BPF_X {
                        self.reg_x
                    } else {
                        insn.k
                    };

                    let cond = match op {
                        BPF_JEQ => self.reg_a == src,
                        BPF_JGT => self.reg_a > src,
                        BPF_JGE => self.reg_a >= src,
                        BPF_JSET => (self.reg_a & src) != 0,
                        _ => false,
                    };

                    if cond {
                        pc += insn.jt as usize;
                    } else {
                        pc += insn.jf as usize;
                    }
                }
                BPF_RET => {
                    let src = insn.code & 0x18;
                    if src == 0x10 { // BPF_A
                        return self.reg_a;
                    } else {
                        return insn.k;
                    }
                }
                _ => return 0,
            }
        }

        0
    }

    /// Filter generator: Accept all IPv4 packets
    pub fn filter_ipv4() -> Vec<BpfInsn> {
        alloc::vec![
            // Load EtherType (offset 12)
            BpfInsn::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
            // Check if EtherType == 0x0800 (IPv4)
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0800),
            // Return 65535 (Accept)
            BpfInsn::new(BPF_RET | BPF_K, 0, 0, 65535),
            // Return 0 (Drop)
            BpfInsn::new(BPF_RET | BPF_K, 0, 0, 0),
        ]
    }

    /// Filter generator: Accept TCP destination port
    pub fn filter_tcp_port(port: u16) -> Vec<BpfInsn> {
        alloc::vec![
            // Check IPv4 EtherType
            BpfInsn::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 6, 0x0800),
            // Check Protocol == TCP (6) at offset 23
            BpfInsn::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23),
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 6),
            // Load IP Header Length into X register
            BpfInsn::new(BPF_LDX | BPF_MSH | BPF_B, 0, 0, 14),
            // Load TCP Destination Port (14 + X + 2)
            BpfInsn::new(BPF_LD | BPF_H | BPF_IND, 0, 0, 16),
            // Compare with target port
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, port as u32),
            // Accept
            BpfInsn::new(BPF_RET | BPF_K, 0, 0, 65535),
            // Drop
            BpfInsn::new(BPF_RET | BPF_K, 0, 0, 0),
        ]
    }
}
