//! CorOS VFS Module: `elf64_loader`
//!
//! Real ELF64 binary loader & validator (`Elf64Ehdr`, `Elf64Phdr`, `Elf64Shdr`,
//! `Elf64Rela`, `PT_LOAD`/`PT_DYNAMIC`/`PT_INTERP`/`PT_GNU_STACK` segment inspector,
//! W^X security policy verifier, and `R_X86_64_RELATIVE` relocation applier).

use alloc::string::String;
use alloc::vec::Vec;

/// ELF Magic bytes: `\x7FELF`.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_X86_64: u16 = 62;

/// ELF Object file types (`e_type`).
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

/// ELF Program Header segment types (`p_type`).
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_STACK: u32 = 0x6474_E551;
pub const PT_GNU_RELRO: u32 = 0x6474_E552;

/// ELF Program Header permission flags (`p_flags`).
pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

/// x86_64 dynamic relocation types.
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;

/// Standard Linux ELF Auxiliary Vector Types (`auxv`).
pub const AT_NULL: u64 = 0;
pub const AT_IGNORE: u64 = 1;
pub const AT_EXECFD: u64 = 2;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_NOTELF: u64 = 10;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_BASE_PLATFORM: u64 = 24;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;

/// ELF64 Auxiliary Vector entry (`Elf64_auxv_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxvEntry {
    pub a_type: u64,
    pub a_val: u64,
}

impl AuxvEntry {
    pub const fn new(a_type: u64, a_val: u64) -> Self {
        Self { a_type, a_val }
    }
}

/// Standard 64-byte ELF64 File Header (`Elf64_Ehdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Standard 56-byte ELF64 Program Header (`Elf64_Phdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64Phdr {
    /// Returns true if a segment violates W^X (Write XOR Execute) by having both `PF_W` and `PF_X`.
    #[inline]
    pub const fn violates_wx(&self) -> bool {
        (self.p_flags & (PF_W | PF_X)) == (PF_W | PF_X)
    }
}

/// Standard 64-byte ELF64 Section Header (`Elf64_Shdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Standard 24-byte ELF64 Relocation with Addend (`Elf64_Rela`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    #[inline]
    pub const fn r_sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    #[inline]
    pub const fn r_type(&self) -> u32 {
        (self.r_info & 0xFFFF_FFFF) as u32
    }
}

/// Errors returned during ELF64 binary validation and loading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfLoadError {
    BufferTooSmall,
    BadMagic,
    UnsupportedClassOrEndian,
    UnsupportedMachine,
    UnsupportedType,
    InvalidProgramHeaderTable,
    SegmentOutOfBounds,
    WxPolicyViolation,
    RelocationOutOfBounds,
}

/// Validated loadable segment plan produced by the ELF64 parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedElfImage {
    pub ehdr: Elf64Ehdr,
    pub is_pie: bool,
    pub entry_point: u64,
    pub load_segments: Vec<Elf64Phdr>,
    pub dynamic_segment: Option<Elf64Phdr>,
    pub interpreter_path: Option<String>,
    pub nx_stack: bool,
}

impl Elf64Ehdr {
    /// Decodes and validates a 64-byte `Elf64Ehdr` from raw file bytes.
    pub fn parse(raw: &[u8]) -> Result<Self, ElfLoadError> {
        if raw.len() < 64 {
            return Err(ElfLoadError::BufferTooSmall);
        }
        if raw[0..4] != ELF_MAGIC {
            return Err(ElfLoadError::BadMagic);
        }
        if raw[4] != ELFCLASS64 || raw[5] != ELFDATA2LSB {
            return Err(ElfLoadError::UnsupportedClassOrEndian);
        }

        let mut e_ident = [0u8; 16];
        e_ident.copy_from_slice(&raw[0..16]);

        let e_type = u16::from_le_bytes([raw[16], raw[17]]);
        let e_machine = u16::from_le_bytes([raw[18], raw[19]]);
        if e_machine != EM_X86_64 {
            return Err(ElfLoadError::UnsupportedMachine);
        }
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(ElfLoadError::UnsupportedType);
        }

        Ok(Self {
            e_ident,
            e_type,
            e_machine,
            e_version: u32::from_le_bytes([raw[20], raw[21], raw[22], raw[23]]),
            e_entry: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
            e_phoff: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
            e_shoff: u64::from_le_bytes(raw[40..48].try_into().unwrap()),
            e_flags: u32::from_le_bytes([raw[48], raw[49], raw[50], raw[51]]),
            e_ehsize: u16::from_le_bytes([raw[52], raw[53]]),
            e_phentsize: u16::from_le_bytes([raw[54], raw[55]]),
            e_phnum: u16::from_le_bytes([raw[56], raw[57]]),
            e_shentsize: u16::from_le_bytes([raw[58], raw[59]]),
            e_shnum: u16::from_le_bytes([raw[60], raw[61]]),
            e_shstrndx: u16::from_le_bytes([raw[62], raw[63]]),
        })
    }
}

/// Parses and validates an ELF64 executable or PIE binary image, enforcing W^X segment rules.
pub fn parse_and_validate_elf64(raw: &[u8], enforce_wx: bool) -> Result<ValidatedElfImage, ElfLoadError> {
    let ehdr = Elf64Ehdr::parse(raw)?;
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;

    if phentsize < 56 || phoff.saturating_add(phentsize.saturating_mul(phnum)) > raw.len() {
        return Err(ElfLoadError::InvalidProgramHeaderTable);
    }

    let mut load_segments = Vec::new();
    let mut dynamic_segment = None;
    let mut interpreter_path = None;
    let mut nx_stack = true;

    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p = &raw[off..off + 56];
        let phdr = Elf64Phdr {
            p_type: u32::from_le_bytes(p[0..4].try_into().unwrap()),
            p_flags: u32::from_le_bytes(p[4..8].try_into().unwrap()),
            p_offset: u64::from_le_bytes(p[8..16].try_into().unwrap()),
            p_vaddr: u64::from_le_bytes(p[16..24].try_into().unwrap()),
            p_paddr: u64::from_le_bytes(p[24..32].try_into().unwrap()),
            p_filesz: u64::from_le_bytes(p[32..40].try_into().unwrap()),
            p_memsz: u64::from_le_bytes(p[40..48].try_into().unwrap()),
            p_align: u64::from_le_bytes(p[48..56].try_into().unwrap()),
        };

        let seg_end = (phdr.p_offset as usize).saturating_add(phdr.p_filesz as usize);
        if seg_end > raw.len() || phdr.p_filesz > phdr.p_memsz {
            return Err(ElfLoadError::SegmentOutOfBounds);
        }

        match phdr.p_type {
            PT_LOAD => {
                if enforce_wx && phdr.violates_wx() {
                    return Err(ElfLoadError::WxPolicyViolation);
                }
                load_segments.push(phdr);
            }
            PT_DYNAMIC => {
                dynamic_segment = Some(phdr);
            }
            PT_INTERP => {
                let slice = &raw[phdr.p_offset as usize..seg_end];
                let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                if let Ok(s) = core::str::from_utf8(&slice[..len]) {
                    interpreter_path = Some(String::from(s));
                }
            }
            PT_GNU_STACK => {
                nx_stack = (phdr.p_flags & PF_X) == 0;
            }
            _ => {}
        }
    }

    Ok(ValidatedElfImage {
        ehdr,
        is_pie: ehdr.e_type == ET_DYN,
        entry_point: ehdr.e_entry,
        load_segments,
        dynamic_segment,
        interpreter_path,
        nx_stack,
    })
}

/// Applies `R_X86_64_RELATIVE` (`B + A`) relocations to a loaded memory image at `base_load_bias`.
pub fn apply_rela_relocations(
    memory_image: &mut [u8],
    base_load_bias: u64,
    relas: &[Elf64Rela],
) -> Result<usize, ElfLoadError> {
    let mut applied = 0usize;
    for rela in relas {
        if rela.r_type() == R_X86_64_RELATIVE {
            let target_off = rela.r_offset as usize;
            if target_off.saturating_add(8) > memory_image.len() {
                return Err(ElfLoadError::RelocationOutOfBounds);
            }
            let relocated_val = (base_load_bias as i128 + rela.r_addend as i128) as u64;
            memory_image[target_off..target_off + 8].copy_from_slice(&relocated_val.to_le_bytes());
            applied += 1;
        }
    }
    Ok(applied)
}

/// Initial user-space process stack layout produced for `execve`.
#[derive(Debug, Clone)]
pub struct UserStackLayout {
    pub initial_rsp: u64,
    pub stack_bytes: Vec<u8>,
}

/// Sets up the initial user-mode process stack according to System V AMD64 ABI:
/// [argc] [argv_0 .. argv_n] [NULL] [envp_0 .. envp_m] [NULL] [auxv_0 .. auxv_k] [NULL]
/// with 16-byte aligned RSP (`initial_rsp % 16 == 0`).
pub fn setup_user_stack(
    stack_top: u64,
    argv: &[&str],
    envp: &[&str],
    auxv: &[AuxvEntry],
) -> Result<UserStackLayout, ElfLoadError> {
    let mut total_string_len = 0usize;
    for arg in argv {
        total_string_len += arg.len() + 1;
    }
    for env in envp {
        total_string_len += env.len() + 1;
    }

    // 16 bytes reserved for AT_RANDOM seed data
    let random_bytes_size = 16usize;

    // Table elements:
    // argc (8 bytes)
    // argv pointers ((argv.len() + 1) * 8 bytes)
    // envp pointers ((envp.len() + 1) * 8 bytes)
    // auxv entries ((auxv.len() + 1) * 16 bytes)
    let table_bytes = 8 + (argv.len() + 1) * 8 + (envp.len() + 1) * 8 + (auxv.len() + 1) * 16;

    let strings_and_random = total_string_len + random_bytes_size;
    let strings_start = stack_top.saturating_sub(strings_and_random as u64);
    let unaligned_rsp = strings_start.saturating_sub(table_bytes as u64);
    // Align initial_rsp down to 16 bytes boundary
    let initial_rsp = unaligned_rsp & !15;

    let total_size = (stack_top.saturating_sub(initial_rsp)) as usize;
    let mut stack_bytes = alloc::vec![0u8; total_size];

    let random_addr = stack_top.saturating_sub(16);
    let rand_off = (random_addr.saturating_sub(initial_rsp)) as usize;
    if rand_off + 16 <= stack_bytes.len() {
        stack_bytes[rand_off..rand_off + 16].copy_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
        ]);
    }

    let mut curr_vaddr = strings_start;
    let mut argv_addrs = Vec::with_capacity(argv.len());
    for arg in argv {
        argv_addrs.push(curr_vaddr);
        let bytes = arg.as_bytes();
        let off = (curr_vaddr.saturating_sub(initial_rsp)) as usize;
        if off + bytes.len() + 1 <= stack_bytes.len() {
            stack_bytes[off..off + bytes.len()].copy_from_slice(bytes);
            stack_bytes[off + bytes.len()] = 0;
        }
        curr_vaddr += (bytes.len() + 1) as u64;
    }

    let mut envp_addrs = Vec::with_capacity(envp.len());
    for env in envp {
        envp_addrs.push(curr_vaddr);
        let bytes = env.as_bytes();
        let off = (curr_vaddr.saturating_sub(initial_rsp)) as usize;
        if off + bytes.len() + 1 <= stack_bytes.len() {
            stack_bytes[off..off + bytes.len()].copy_from_slice(bytes);
            stack_bytes[off + bytes.len()] = 0;
        }
        curr_vaddr += (bytes.len() + 1) as u64;
    }

    // Write table starting at offset 0 (initial_rsp)
    let mut off = 0usize;
    // argc
    let argc = argv.len() as u64;
    stack_bytes[off..off + 8].copy_from_slice(&argc.to_le_bytes());
    off += 8;

    // argv pointers
    for &addr in &argv_addrs {
        stack_bytes[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        off += 8;
    }
    // argv NULL terminator
    stack_bytes[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    off += 8;

    // envp pointers
    for &addr in &envp_addrs {
        stack_bytes[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        off += 8;
    }
    // envp NULL terminator
    stack_bytes[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
    off += 8;

    // auxv entries
    for entry in auxv {
        let val = if entry.a_type == AT_RANDOM && entry.a_val == 0 {
            random_addr
        } else {
            entry.a_val
        };
        stack_bytes[off..off + 8].copy_from_slice(&entry.a_type.to_le_bytes());
        off += 8;
        stack_bytes[off..off + 8].copy_from_slice(&val.to_le_bytes());
        off += 8;
    }
    // auxv AT_NULL terminator
    stack_bytes[off..off + 8].copy_from_slice(&AT_NULL.to_le_bytes());
    off += 8;
    stack_bytes[off..off + 8].copy_from_slice(&0u64.to_le_bytes());

    Ok(UserStackLayout {
        initial_rsp,
        stack_bytes,
    })
}

/// Dual binary loading plan for dynamically linked ELF executables requiring an interpreter (ld.so).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualBinaryPlan {
    pub main_image: ValidatedElfImage,
    pub interp_image: Option<ValidatedElfImage>,
    pub entry_point: u64,
    pub auxv: Vec<AuxvEntry>,
}

/// Loads and validates a primary binary and its optional dynamic linker interpreter (`PT_INTERP`),
/// configuring program headers, load bases, entry points, and the standard auxiliary vector.
pub fn load_with_interpreter(
    main_raw: &[u8],
    interp_raw: Option<&[u8]>,
    main_base: u64,
    interp_base: u64,
) -> Result<DualBinaryPlan, ElfLoadError> {
    let main_image = parse_and_validate_elf64(main_raw, true)?;
    let main_entry = if main_image.is_pie {
        main_base + main_image.entry_point
    } else {
        main_image.entry_point
    };

    let (interp_image, entry_point, interp_load_addr) = if let Some(interp_bytes) = interp_raw {
        let interp = parse_and_validate_elf64(interp_bytes, true)?;
        let interp_entry = if interp.is_pie {
            interp_base + interp.entry_point
        } else {
            interp.entry_point
        };
        (Some(interp), interp_entry, interp_base)
    } else {
        (None, main_entry, 0)
    };

    let phdr_addr = main_base + main_image.ehdr.e_phoff;
    let mut auxv = Vec::new();
    auxv.push(AuxvEntry::new(AT_PHDR, phdr_addr));
    auxv.push(AuxvEntry::new(AT_PHENT, main_image.ehdr.e_phentsize as u64));
    auxv.push(AuxvEntry::new(AT_PHNUM, main_image.ehdr.e_phnum as u64));
    auxv.push(AuxvEntry::new(AT_PAGESZ, 4096));
    auxv.push(AuxvEntry::new(AT_BASE, interp_load_addr));
    auxv.push(AuxvEntry::new(AT_FLAGS, 0));
    auxv.push(AuxvEntry::new(AT_ENTRY, main_entry));
    auxv.push(AuxvEntry::new(AT_UID, 0));
    auxv.push(AuxvEntry::new(AT_EUID, 0));
    auxv.push(AuxvEntry::new(AT_GID, 0));
    auxv.push(AuxvEntry::new(AT_EGID, 0));
    auxv.push(AuxvEntry::new(AT_SECURE, 0));
    auxv.push(AuxvEntry::new(AT_RANDOM, 0));

    Ok(DualBinaryPlan {
        main_image,
        interp_image,
        entry_point,
        auxv,
    })
}

/// Self-test suite for `elf64_loader`.
pub fn verify_vfs_elf64_loader() -> u32 {
    let mut passed = 0u32;

    // Synthesize a valid 256-byte ELF64 PIE binary with 2 Program Headers (PT_LOAD RX + PT_INTERP)
    let mut elf = [0u8; 256];
    elf[0..4].copy_from_slice(&ELF_MAGIC);
    elf[4] = ELFCLASS64;
    elf[5] = ELFDATA2LSB;
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    elf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1040u64.to_le_bytes()); // e_entry
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56
    elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2

    // Program Header 0 (at offset 64..120): PT_LOAD (RX)
    elf[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
    elf[68..72].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    elf[72..80].copy_from_slice(&0u64.to_le_bytes()); // p_offset
    elf[80..88].copy_from_slice(&0x1000u64.to_le_bytes()); // p_vaddr
    elf[96..104].copy_from_slice(&128u64.to_le_bytes()); // p_filesz
    elf[104..112].copy_from_slice(&4096u64.to_le_bytes()); // p_memsz
    elf[112..120].copy_from_slice(&4096u64.to_le_bytes()); // p_align

    // Program Header 1 (at offset 120..176): PT_INTERP pointing to offset 200 ("/lib/ld-coros.so\0")
    let interp_bytes = b"/lib/ld-coros.so\0";
    elf[200..200 + interp_bytes.len()].copy_from_slice(interp_bytes);
    elf[120..124].copy_from_slice(&PT_INTERP.to_le_bytes());
    elf[124..128].copy_from_slice(&PF_R.to_le_bytes());
    elf[128..136].copy_from_slice(&200u64.to_le_bytes()); // p_offset = 200
    elf[152..160].copy_from_slice(&(interp_bytes.len() as u64).to_le_bytes()); // p_filesz
    elf[160..168].copy_from_slice(&(interp_bytes.len() as u64).to_le_bytes()); // p_memsz

    if let Ok(img) = parse_and_validate_elf64(&elf, true) {
        if img.is_pie
            && img.entry_point == 0x1040
            && img.load_segments.len() == 1
            && img.interpreter_path.as_deref() == Some("/lib/ld-coros.so")
        {
            passed += 1;
        }
    }

    // Verify W^X violation detection when a segment has PF_R | PF_W | PF_X
    elf[68..72].copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
    if parse_and_validate_elf64(&elf, true) == Err(ElfLoadError::WxPolicyViolation) {
        passed += 1;
    }

    // Verify R_X86_64_RELATIVE relocation application
    let mut mem = [0u8; 64];
    let relas = [Elf64Rela {
        r_offset: 16,
        r_info: R_X86_64_RELATIVE as u64,
        r_addend: 0x2400,
    }];
    if apply_rela_relocations(&mut mem, 0x0000_5555_5555_0000, &relas) == Ok(1) {
        let patched = u64::from_le_bytes(mem[16..24].try_into().unwrap());
        if patched == 0x0000_5555_5555_2400 {
            passed += 1;
        }
    }

    // Test 4: setup_user_stack alignment and auxiliary vector layout
    let test_auxv = [
        AuxvEntry::new(AT_PHDR, 0x400040),
        AuxvEntry::new(AT_BASE, 0x7F8000),
        AuxvEntry::new(AT_ENTRY, 0x401000),
    ];
    if let Ok(layout) = setup_user_stack(
        0x0000_7FFF_FFFF_0000,
        &["/bin/init", "-v"],
        &["PATH=/bin"],
        &test_auxv,
    ) {
        if (layout.initial_rsp % 16) == 0 && layout.stack_bytes.len() > 64 {
            let argc = u64::from_le_bytes(layout.stack_bytes[0..8].try_into().unwrap());
            if argc == 2 {
                passed += 1;
            }
        }
    }

    // Test 5: load_with_interpreter dual binary plan synthesis
    // Reset elf flags back to valid PF_R | PF_X
    elf[68..72].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    if let Ok(plan) = load_with_interpreter(&elf, Some(&elf), 0x400000, 0x7F8000) {
        if plan.entry_point == 0x7F8000 + 0x1040 {
            let has_base = plan.auxv.iter().any(|a| a.a_type == AT_BASE && a.a_val == 0x7F8000);
            let has_entry = plan.auxv.iter().any(|a| a.a_type == AT_ENTRY && a.a_val == 0x400000 + 0x1040);
            if has_base && has_entry {
                passed += 1;
            }
        }
    }

    passed
}
