//! ELF64 Core Dump Builder & Parser (`coredump`)
//!
//! Provides ELF64 core file generation, PT_NOTE segment formatting (`NT_PRSTATUS`,
//! `NT_PRPSINFO`, `NT_SIGINFO`, `NT_AUXV`), thread register snapshots, and memory mapping dumps.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;
pub const ET_CORE: u16 = 4;
pub const EM_X86_64: u16 = 62;

pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;
pub const NT_SIGINFO: u32 = 0x5349_4749;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct CoreRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[derive(Debug, Clone)]
pub struct MemorySegment {
    pub vaddr: u64,
    pub flags: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CoreDumpBuilder {
    pub pid: u32,
    pub ppid: u32,
    pub signal: u32,
    pub fault_addr: u64,
    pub comm: String,
    pub cmdline: String,
    pub registers: CoreRegisters,
    pub auxv: Vec<(u64, u64)>,
    pub memory_segments: Vec<MemorySegment>,
}

impl CoreDumpBuilder {
    pub fn new(pid: u32, ppid: u32, signal: u32, comm: &str) -> Self {
        Self {
            pid,
            ppid,
            signal,
            fault_addr: 0,
            comm: String::from(comm),
            cmdline: String::from(comm),
            registers: CoreRegisters::default(),
            auxv: Vec::new(),
            memory_segments: Vec::new(),
        }
    }

    pub fn set_fault_addr(&mut self, addr: u64) {
        self.fault_addr = addr;
    }

    pub fn set_registers(&mut self, regs: CoreRegisters) {
        self.registers = regs;
    }

    pub fn add_auxv(&mut self, a_type: u64, a_val: u64) {
        self.auxv.push((a_type, a_val));
    }

    pub fn add_memory_segment(&mut self, vaddr: u64, flags: u32, data: &[u8]) {
        self.memory_segments.push(MemorySegment {
            vaddr,
            flags,
            data: data.to_vec(),
        });
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut note_data = Vec::new();

        // 1. NT_PRSTATUS Note
        let mut prstatus = Vec::new();
        // pr_cursig (2 bytes), padding (2 bytes)
        prstatus.extend_from_slice(&(self.signal as u16).to_le_bytes());
        prstatus.extend_from_slice(&[0u8; 2]);
        // pr_pid (4 bytes), pr_ppid (4 bytes)
        prstatus.extend_from_slice(&self.pid.to_le_bytes());
        prstatus.extend_from_slice(&self.ppid.to_le_bytes());
        // Registers (27 * 8 = 216 bytes)
        let regs_bytes: [u8; core::mem::size_of::<CoreRegisters>()] = unsafe {
            core::mem::transmute_copy(&self.registers)
        };
        prstatus.extend_from_slice(&regs_bytes);
        Self::append_note(&mut note_data, "CORE", NT_PRSTATUS, &prstatus);

        // 2. NT_PRPSINFO Note
        let mut prpsinfo = Vec::new();
        prpsinfo.push(b'R'); // state: running
        prpsinfo.push(0);   // sname
        prpsinfo.push(0);   // zomb
        prpsinfo.push(0);   // nice
        prpsinfo.extend_from_slice(&self.pid.to_le_bytes());
        prpsinfo.extend_from_slice(&self.ppid.to_le_bytes());
        // fname (16 bytes)
        let mut fname = [0u8; 16];
        let comm_bytes = self.comm.as_bytes();
        let copy_len = comm_bytes.len().min(15);
        fname[..copy_len].copy_from_slice(&comm_bytes[..copy_len]);
        prpsinfo.extend_from_slice(&fname);
        // psargs (80 bytes)
        let mut psargs = [0u8; 80];
        let args_bytes = self.cmdline.as_bytes();
        let copy_args = args_bytes.len().min(79);
        psargs[..copy_args].copy_from_slice(&args_bytes[..copy_args]);
        prpsinfo.extend_from_slice(&psargs);
        Self::append_note(&mut note_data, "CORE", NT_PRPSINFO, &prpsinfo);

        // 3. NT_SIGINFO Note
        let mut siginfo = Vec::new();
        siginfo.extend_from_slice(&self.signal.to_le_bytes()); // si_signo
        siginfo.extend_from_slice(&0u32.to_le_bytes());         // si_errno
        siginfo.extend_from_slice(&1u32.to_le_bytes());         // si_code
        siginfo.extend_from_slice(&0u32.to_le_bytes());         // padding
        siginfo.extend_from_slice(&self.fault_addr.to_le_bytes()); // si_addr
        Self::append_note(&mut note_data, "CORE", NT_SIGINFO, &siginfo);

        // 4. NT_AUXV Note
        if !self.auxv.is_empty() {
            let mut auxv_data = Vec::new();
            for &(atype, aval) in &self.auxv {
                auxv_data.extend_from_slice(&atype.to_le_bytes());
                auxv_data.extend_from_slice(&aval.to_le_bytes());
            }
            auxv_data.extend_from_slice(&[0u8; 16]); // AT_NULL terminator
            Self::append_note(&mut note_data, "CORE", NT_AUXV, &auxv_data);
        }

        // Layout offsets
        let elf_hdr_size = 64usize;
        let phdr_size = 56usize;
        let num_phdrs = 1 + self.memory_segments.len(); // 1 PT_NOTE + N PT_LOAD
        let phdr_table_size = num_phdrs * phdr_size;

        let note_offset = elf_hdr_size + phdr_table_size;
        let note_size = note_data.len();

        let mut current_offset = note_offset + note_size;

        // Build file buffer
        let mut file = Vec::new();

        // 1. ELF Header (64 bytes)
        file.extend_from_slice(&ELF_MAGIC);
        file.push(ELFCLASS64);
        file.push(ELFDATA2LSB);
        file.push(EV_CURRENT);
        file.extend_from_slice(&[0u8; 9]); // padding
        file.extend_from_slice(&ET_CORE.to_le_bytes());
        file.extend_from_slice(&EM_X86_64.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes()); // e_version
        file.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        file.extend_from_slice(&(elf_hdr_size as u64).to_le_bytes()); // e_phoff
        file.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        file.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        file.extend_from_slice(&(elf_hdr_size as u16).to_le_bytes()); // e_ehsize
        file.extend_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
        file.extend_from_slice(&(num_phdrs as u16).to_le_bytes()); // e_phnum
        file.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        file.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        file.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // 2. Program Headers
        // PT_NOTE header
        Self::append_phdr(
            &mut file,
            PT_NOTE,
            PF_R,
            note_offset as u64,
            0,
            note_size as u64,
            note_size as u64,
            4,
        );

        // PT_LOAD headers for memory segments
        let mut segment_offsets = Vec::new();
        for seg in &self.memory_segments {
            // Align offset to 4096
            let aligned_offset = (current_offset + 0xfff) & !0xfff;
            segment_offsets.push(aligned_offset);
            Self::append_phdr(
                &mut file,
                PT_LOAD,
                seg.flags,
                aligned_offset as u64,
                seg.vaddr,
                seg.data.len() as u64,
                seg.data.len() as u64,
                0x1000,
            );
            current_offset = aligned_offset + seg.data.len();
        }

        // 3. Write Note data
        file.extend_from_slice(&note_data);

        // 4. Write Memory Segment data
        for (idx, seg) in self.memory_segments.iter().enumerate() {
            let target_off = segment_offsets[idx];
            if file.len() < target_off {
                file.resize(target_off, 0);
            }
            file.extend_from_slice(&seg.data);
        }

        file
    }

    fn append_note(buf: &mut Vec<u8>, name: &str, note_type: u32, desc: &[u8]) {
        let name_bytes = name.as_bytes();
        let name_len_with_null = name_bytes.len() + 1;
        let namesz = name_len_with_null as u32;
        let descsz = desc.len() as u32;

        buf.extend_from_slice(&namesz.to_le_bytes());
        buf.extend_from_slice(&descsz.to_le_bytes());
        buf.extend_from_slice(&note_type.to_le_bytes());

        // Name with null terminator + 4-byte padding
        buf.extend_from_slice(name_bytes);
        buf.push(0);
        let name_pad = (4 - (name_len_with_null % 4)) % 4;
        buf.extend_from_slice(&alloc::vec![0u8; name_pad]);

        // Descriptor + 4-byte padding
        buf.extend_from_slice(desc);
        let desc_pad = (4 - (desc.len() % 4)) % 4;
        buf.extend_from_slice(&alloc::vec![0u8; desc_pad]);
    }

    fn append_phdr(
        buf: &mut Vec<u8>,
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_align: u64,
    ) {
        buf.extend_from_slice(&p_type.to_le_bytes());
        buf.extend_from_slice(&p_flags.to_le_bytes());
        buf.extend_from_slice(&p_offset.to_le_bytes());
        buf.extend_from_slice(&p_vaddr.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
        buf.extend_from_slice(&p_filesz.to_le_bytes());
        buf.extend_from_slice(&p_memsz.to_le_bytes());
        buf.extend_from_slice(&p_align.to_le_bytes());
    }
}

pub struct CoreDumpParser<'a> {
    data: &'a [u8],
}

impl<'a> CoreDumpParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn validate_header(&self) -> bool {
        if self.data.len() < 64 {
            return false;
        }
        if self.data[0..4] != ELF_MAGIC {
            return false;
        }
        let e_type = u16::from_le_bytes(self.data[16..18].try_into().unwrap());
        let e_machine = u16::from_le_bytes(self.data[18..20].try_into().unwrap());
        e_type == ET_CORE && e_machine == EM_X86_64
    }

    pub fn count_phdrs(&self) -> u16 {
        if self.data.len() < 64 {
            return 0;
        }
        u16::from_le_bytes(self.data[56..58].try_into().unwrap())
    }

    pub fn find_prstatus(&self) -> Option<(u32, u32, CoreRegisters)> {
        let e_phoff = u64::from_le_bytes(self.data[32..40].try_into().unwrap()) as usize;
        let e_phnum = self.count_phdrs() as usize;

        for i in 0..e_phnum {
            let ph_offset = e_phoff + i * 56;
            if ph_offset + 56 > self.data.len() {
                break;
            }
            let p_type = u32::from_le_bytes(self.data[ph_offset..ph_offset + 4].try_into().unwrap());
            if p_type == PT_NOTE {
                let note_off = u64::from_le_bytes(self.data[ph_offset + 8..ph_offset + 16].try_into().unwrap()) as usize;
                let note_sz = u64::from_le_bytes(self.data[ph_offset + 32..ph_offset + 40].try_into().unwrap()) as usize;

                let mut cur = note_off;
                let end = note_off + note_sz;

                while cur + 12 <= end && cur + 12 <= self.data.len() {
                    let namesz = u32::from_le_bytes(self.data[cur..cur + 4].try_into().unwrap()) as usize;
                    let descsz = u32::from_le_bytes(self.data[cur + 4..cur + 8].try_into().unwrap()) as usize;
                    let ntype = u32::from_le_bytes(self.data[cur + 8..cur + 12].try_into().unwrap());
                    cur += 12;

                    let name_pad = (4 - (namesz % 4)) % 4;
                    cur += namesz + name_pad;

                    if ntype == NT_PRSTATUS && descsz >= 12 + core::mem::size_of::<CoreRegisters>() {
                        let sig = u16::from_le_bytes(self.data[cur..cur + 2].try_into().unwrap()) as u32;
                        let pid = u32::from_le_bytes(self.data[cur + 4..cur + 8].try_into().unwrap());
                        let regs_slice = &self.data[cur + 12..cur + 12 + core::mem::size_of::<CoreRegisters>()];
                        let regs: CoreRegisters = unsafe {
                            core::ptr::read_unaligned(regs_slice.as_ptr() as *const CoreRegisters)
                        };
                        return Some((pid, sig, regs));
                    }

                    let desc_pad = (4 - (descsz % 4)) % 4;
                    cur += descsz + desc_pad;
                }
            }
        }
        None
    }
}

pub fn verify_coredump() -> u32 {
    let mut check_count = 0u32;

    let mut builder = CoreDumpBuilder::new(1337, 1, 11, "test_daemon"); // 11 = SIGSEGV
    builder.set_fault_addr(0xdead_beef_0000);

    let mut regs = CoreRegisters::default();
    regs.rip = 0x401122;
    regs.rsp = 0x7fff_ffff_e000;
    regs.rax = 42;
    regs.rbx = 99;
    builder.set_registers(regs);

    builder.add_auxv(3, 0x400040); // AT_PHDR
    builder.add_auxv(4, 56);       // AT_PHENT
    builder.add_auxv(5, 4);        // AT_PHNUM

    // Memory segment 1: stack memory
    let stack_data = [0xAAu8; 128];
    builder.add_memory_segment(0x7fff_ffff_df80, PF_R | PF_W, &stack_data);

    // Memory segment 2: data segment
    let global_data = [0x55u8; 64];
    builder.add_memory_segment(0x601000, PF_R | PF_W, &global_data);

    let core_bytes = builder.serialize();

    // Test 1: ELF Header Magic and Type
    let parser = CoreDumpParser::new(&core_bytes);
    if parser.validate_header() {
        check_count += 1;
    }

    // Test 2: Program Header Count (1 PT_NOTE + 2 PT_LOAD = 3)
    if parser.count_phdrs() == 3 {
        check_count += 1;
    }

    // Test 3: Note Extraction (NT_PRSTATUS)
    if let Some((pid, sig, restored_regs)) = parser.find_prstatus() {
        if pid == 1337 && sig == 11 && restored_regs.rip == 0x401122 && restored_regs.rax == 42 && restored_regs.rbx == 99 {
            check_count += 1;
        }
    }

    // Test 4: Memory segment content preserved
    // Check global data byte pattern exists in file
    if core_bytes.windows(64).any(|w| w == &global_data[..]) {
        check_count += 1;
    }

    check_count
}
