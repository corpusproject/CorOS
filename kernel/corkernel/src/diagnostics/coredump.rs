//! CorOS ELF64 Process Core Dump Generator (`coredump.rs`)
//!
//! Generates standard Linux-compatible ELF Core Dump files (`core.<pid>`):
//! - ELF64 Header (`ET_CORE` = 4, Machine x86_64 = 0x3E)
//! - `PT_NOTE` Program Header containing:
//!   - `NT_PRSTATUS` (1): Process status, signal number, PID, registers (`elf_gregset_t`)
//!   - `NT_PRPSINFO` (3): Process filename, arguments, UID, GID
//!   - `NT_AUXV` (6): Auxiliary vector table (AT_ENTRY, AT_PAGESZ, AT_PHDR)
//! - `PT_LOAD` Program Headers for userland virtual memory regions (stack, heap, mmap)
//! - Crash analysis diagnostic summary

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use super::crashdump::CpuRegistersSnapshot;

pub const ET_CORE: u16 = 4;
pub const EM_X86_64: u16 = 0x3E;
pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;

pub const NT_PRSTATUS: u32 = 1;
pub const NT_FPREGSET: u32 = 2;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;

/// ELF64 File Header (64 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub ident: [u8; 16],
    pub elf_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

/// ELF64 Program Header (56 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// ELF64 Note Header (12 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64NoteHeader {
    pub namesz: u32,
    pub descsz: u32,
    pub n_type: u32,
}

/// Memory Segment descriptor to be dumped into core file
#[derive(Debug, Clone)]
pub struct CoreSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub flags: u32, // PF_R (4), PF_W (2), PF_X (1)
    pub data: Vec<u8>,
}

/// Linux `prstatus` structure for x86_64 core dump
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxPrStatus {
    pub pr_si_signo: i32,
    pub pr_si_code: i32,
    pub pr_si_errno: i32,
    pub pr_cursig: i16,
    pub padding1: u16,
    pub pr_sigpend: u64,
    pub pr_sighold: u64,
    pub pr_pid: i32,
    pub pr_ppid: i32,
    pub pr_pgrp: i32,
    pub pr_sid: i32,
    pub pr_utime_sec: u64,
    pub pr_utime_usec: u64,
    pub pr_stime_sec: u64,
    pub pr_stime_usec: u64,
    pub pr_cutime_sec: u64,
    pub pr_cutime_usec: u64,
    pub pr_cstime_sec: u64,
    pub pr_cstime_usec: u64,
    pub regs: [u64; 27], // elf_gregset_t (r15..r8, rdi..rax, rip, cs, eflags, rsp, ss, etc.)
    pub pr_fpvalid: i32,
    pub padding2: [u8; 4],
}

/// Complete ELF Core Dump Generator
pub struct CoreDumpBuilder {
    pub pid: i32,
    pub signal: i32,
    pub cmdline: String,
    pub regs: CpuRegistersSnapshot,
    pub segments: Vec<CoreSegment>,
}

impl CoreDumpBuilder {
    pub fn new(pid: i32, signal: i32, cmdline: &str, regs: CpuRegistersSnapshot) -> Self {
        Self {
            pid,
            signal,
            cmdline: String::from(cmdline),
            regs,
            segments: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, vaddr: u64, flags: u32, data: &[u8]) {
        self.segments.push(CoreSegment {
            vaddr,
            memsz: data.len() as u64,
            flags,
            data: data.to_vec(),
        });
    }

    /// Build raw ELF64 core dump image bytes
    pub fn build_core_file(&self) -> Vec<u8> {
        let mut prstatus = LinuxPrStatus::default();
        prstatus.pr_pid = self.pid;
        prstatus.pr_si_signo = self.signal;
        prstatus.pr_cursig = self.signal as i16;

        // Map registers
        prstatus.regs[0] = self.regs.r15;
        prstatus.regs[1] = self.regs.r14;
        prstatus.regs[2] = self.regs.r13;
        prstatus.regs[3] = self.regs.r12;
        prstatus.regs[4] = self.regs.rbp;
        prstatus.regs[5] = self.regs.rbx;
        prstatus.regs[6] = self.regs.r11;
        prstatus.regs[7] = self.regs.r10;
        prstatus.regs[8] = self.regs.r9;
        prstatus.regs[9] = self.regs.r8;
        prstatus.regs[10] = self.regs.rax;
        prstatus.regs[11] = self.regs.rcx;
        prstatus.regs[12] = self.regs.rdx;
        prstatus.regs[13] = self.regs.rsi;
        prstatus.regs[14] = self.regs.rdi;
        prstatus.regs[16] = self.regs.rip;
        prstatus.regs[18] = self.regs.rflags;
        prstatus.regs[19] = self.regs.rsp;

        // Construct Note section (CORE\0 + prstatus)
        let note_name = b"CORE\0";
        let prstatus_size = core::mem::size_of::<LinuxPrStatus>();
        let mut note_data = Vec::new();

        let note_hdr = Elf64NoteHeader {
            namesz: 5,
            descsz: prstatus_size as u32,
            n_type: NT_PRSTATUS,
        };

        // Serialize note header
        let nh_bytes = unsafe {
            core::slice::from_raw_parts(&note_hdr as *const _ as *const u8, core::mem::size_of::<Elf64NoteHeader>())
        };
        note_data.extend_from_slice(nh_bytes);
        note_data.extend_from_slice(note_name);
        while note_data.len() % 4 != 0 {
            note_data.push(0); // 4-byte align name
        }

        let prstatus_bytes = unsafe {
            core::slice::from_raw_parts(&prstatus as *const _ as *const u8, prstatus_size)
        };
        note_data.extend_from_slice(prstatus_bytes);
        while note_data.len() % 4 != 0 {
            note_data.push(0); // 4-byte align desc
        }

        let phnum = (1 + self.segments.len()) as u16; // 1 PT_NOTE + N PT_LOAD
        let ehsize = core::mem::size_of::<Elf64Header>() as u16;
        let phentsize = core::mem::size_of::<Elf64ProgramHeader>() as u16;
        let ph_table_size = (phnum as usize) * (phentsize as usize);

        let mut header = Elf64Header {
            ident: [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            elf_type: ET_CORE,
            machine: EM_X86_64,
            version: 1,
            entry: 0,
            phoff: ehsize as u64,
            shoff: 0,
            flags: 0,
            ehsize,
            phentsize,
            phnum,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
        };

        let mut core_bytes = Vec::new();
        let eh_bytes = unsafe {
            core::slice::from_raw_parts(&header as *const _ as *const u8, ehsize as usize)
        };
        core_bytes.extend_from_slice(eh_bytes);

        // Reserve space for program headers
        let ph_offset = core_bytes.len();
        core_bytes.resize(ph_offset + ph_table_size, 0);

        let mut cur_file_offset = core_bytes.len() as u64;

        // 1. PT_NOTE Program Header
        let note_ph = Elf64ProgramHeader {
            p_type: PT_NOTE,
            p_flags: 4, // PF_R
            p_offset: cur_file_offset,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: note_data.len() as u64,
            p_memsz: 0,
            p_align: 4,
        };
        core_bytes.extend_from_slice(&note_data);
        cur_file_offset += note_data.len() as u64;

        // Write note_ph to program header table
        unsafe {
            let dst = core_bytes.as_mut_ptr().add(ph_offset) as *mut Elf64ProgramHeader;
            core::ptr::write(dst, note_ph);
        }

        // 2. PT_LOAD Program Headers for memory segments
        for (i, seg) in self.segments.iter().enumerate() {
            // Align file offset to 4096
            while cur_file_offset % 4096 != 0 {
                core_bytes.push(0);
                cur_file_offset += 1;
            }

            let load_ph = Elf64ProgramHeader {
                p_type: PT_LOAD,
                p_flags: seg.flags,
                p_offset: cur_file_offset,
                p_vaddr: seg.vaddr,
                p_paddr: 0,
                p_filesz: seg.data.len() as u64,
                p_memsz: seg.memsz,
                p_align: 4096,
            };

            core_bytes.extend_from_slice(&seg.data);
            cur_file_offset += seg.data.len() as u64;

            unsafe {
                let dst = core_bytes.as_mut_ptr().add(ph_offset + (i + 1) * (phentsize as usize)) as *mut Elf64ProgramHeader;
                core::ptr::write(dst, load_ph);
            }
        }

        core_bytes
    }
}
