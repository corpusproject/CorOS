//! ELF64 Relocation Engine (`elf64_reloc`)
//!
//! Provides x86_64 relocation calculations for dynamic executables, shared libraries,
//! and kernel modules according to the System V AMD64 ABI.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_16: u32 = 12;
pub const R_X86_64_PC16: u32 = 13;
pub const R_X86_64_8: u32 = 14;
pub const R_X86_64_PC8: u32 = 15;
pub const R_X86_64_PC64: u32 = 24;
pub const R_X86_64_GOTOFF64: u32 = 25;
pub const R_X86_64_GOTPC32: u32 = 26;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocError {
    BufferOverflow { offset: u64, needed: usize, capacity: usize },
    UnsupportedReloc(u32),
    SymbolNotFound(u32),
    ValueOverflow { reloc_type: u32, value: i64 },
    InvalidOffset(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    pub const fn new(offset: u64, sym_idx: u32, reloc_type: u32, addend: i64) -> Self {
        let info = ((sym_idx as u64) << 32) | (reloc_type as u64);
        Self {
            r_offset: offset,
            r_info: info,
            r_addend: addend,
        }
    }

    pub const fn sym_idx(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    pub const fn reloc_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

pub trait SymbolResolver {
    fn resolve_symbol(&self, sym_idx: u32) -> Option<u64>;
    fn resolve_name(&self, name: &str) -> Option<u64>;
}

pub struct RelocContext {
    pub base_address: u64,
    pub got_address: u64,
    pub plt_address: u64,
    pub eager_binding: bool,
}

impl RelocContext {
    pub const fn new(base_address: u64, got_address: u64, plt_address: u64) -> Self {
        Self {
            base_address,
            got_address,
            plt_address,
            eager_binding: false,
        }
    }

    pub const fn with_eager(base_address: u64, got_address: u64, plt_address: u64, eager_binding: bool) -> Self {
        Self {
            base_address,
            got_address,
            plt_address,
            eager_binding,
        }
    }
}

pub struct SimpleSymbolMap {
    symbols_by_index: BTreeMap<u32, u64>,
    symbols_by_name: BTreeMap<String, u64>,
}

impl SimpleSymbolMap {
    pub fn new() -> Self {
        Self {
            symbols_by_index: BTreeMap::new(),
            symbols_by_name: BTreeMap::new(),
        }
    }

    pub fn insert_symbol(&mut self, idx: u32, name: &str, addr: u64) {
        self.symbols_by_index.insert(idx, addr);
        self.symbols_by_name.insert(String::from(name), addr);
    }
}

impl SymbolResolver for SimpleSymbolMap {
    fn resolve_symbol(&self, sym_idx: u32) -> Option<u64> {
        self.symbols_by_index.get(&sym_idx).copied()
    }

    fn resolve_name(&self, name: &str) -> Option<u64> {
        self.symbols_by_name.get(name).copied()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RelocStats {
    pub applied_count: u32,
    pub bytes_patched: u64,
}

pub struct RelocationEngine;

impl RelocationEngine {
    pub fn apply_rela(
        buffer: &mut [u8],
        rela: &Elf64Rela,
        ctx: &RelocContext,
        resolver: &dyn SymbolResolver,
        stats: &mut RelocStats,
    ) -> Result<(), RelocError> {
        let offset = rela.r_offset as usize;
        let r_type = rela.reloc_type();
        let sym_idx = rela.sym_idx();
        let addend = rela.r_addend;

        // P is the place (address of the storage unit being relocated)
        let place = ctx.base_address.wrapping_add(rela.r_offset);

        match r_type {
            R_X86_64_NONE => Ok(()),

            R_X86_64_64 => {
                // S + A
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let val = (sym_addr as i64).wrapping_add(addend) as u64;
                Self::write_u64(buffer, offset, val)?;
                stats.applied_count += 1;
                stats.bytes_patched += 8;
                Ok(())
            }

            R_X86_64_RELATIVE => {
                // B + A
                let val = (ctx.base_address as i64).wrapping_add(addend) as u64;
                Self::write_u64(buffer, offset, val)?;
                stats.applied_count += 1;
                stats.bytes_patched += 8;
                Ok(())
            }

            R_X86_64_PC32 => {
                // S + A - P
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let target = (sym_addr as i64).wrapping_add(addend);
                let diff = target.wrapping_sub(place as i64);
                if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: diff });
                }
                Self::write_u32(buffer, offset, diff as u32)?;
                stats.applied_count += 1;
                stats.bytes_patched += 4;
                Ok(())
            }

            R_X86_64_PLT32 => {
                // L + A - P
                let sym_addr = resolver.resolve_symbol(sym_idx).unwrap_or(ctx.plt_address);
                let target = (sym_addr as i64).wrapping_add(addend);
                let diff = target.wrapping_sub(place as i64);
                if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: diff });
                }
                Self::write_u32(buffer, offset, diff as u32)?;
                stats.applied_count += 1;
                stats.bytes_patched += 4;
                Ok(())
            }

            R_X86_64_COPY => {
                // S (copy symbol address / data into destination buffer)
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let copy_size = if addend > 0 { addend as usize } else { 8 };
                Self::write_u64(buffer, offset, sym_addr)?;
                stats.applied_count += 1;
                stats.bytes_patched += copy_size as u64;
                Ok(())
            }

            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                // S
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                Self::write_u64(buffer, offset, sym_addr)?;
                stats.applied_count += 1;
                stats.bytes_patched += 8;
                Ok(())
            }

            R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
                // G + GOT + A - P
                let got_target = (ctx.got_address as i64).wrapping_add(addend);
                let diff = got_target.wrapping_sub(place as i64);
                if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: diff });
                }
                Self::write_u32(buffer, offset, diff as u32)?;
                stats.applied_count += 1;
                stats.bytes_patched += 4;
                Ok(())
            }

            R_X86_64_32 => {
                // S + A (zero extended)
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let val = (sym_addr as i64).wrapping_add(addend);
                if val < 0 || val > u32::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: val });
                }
                Self::write_u32(buffer, offset, val as u32)?;
                stats.applied_count += 1;
                stats.bytes_patched += 4;
                Ok(())
            }

            R_X86_64_32S => {
                // S + A (sign extended)
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let val = (sym_addr as i64).wrapping_add(addend);
                if val < i32::MIN as i64 || val > i32::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: val });
                }
                Self::write_u32(buffer, offset, val as u32)?;
                stats.applied_count += 1;
                stats.bytes_patched += 4;
                Ok(())
            }

            R_X86_64_16 => {
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let val = (sym_addr as i64).wrapping_add(addend);
                if val < 0 || val > u16::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: val });
                }
                Self::write_u16(buffer, offset, val as u16)?;
                stats.applied_count += 1;
                stats.bytes_patched += 2;
                Ok(())
            }

            R_X86_64_PC16 => {
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let diff = (sym_addr as i64).wrapping_add(addend).wrapping_sub(place as i64);
                if diff < i16::MIN as i64 || diff > i16::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: diff });
                }
                Self::write_u16(buffer, offset, diff as u16)?;
                stats.applied_count += 1;
                stats.bytes_patched += 2;
                Ok(())
            }

            R_X86_64_8 => {
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let val = (sym_addr as i64).wrapping_add(addend);
                if val < 0 || val > u8::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: val });
                }
                Self::write_u8(buffer, offset, val as u8)?;
                stats.applied_count += 1;
                stats.bytes_patched += 1;
                Ok(())
            }

            R_X86_64_PC8 => {
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let diff = (sym_addr as i64).wrapping_add(addend).wrapping_sub(place as i64);
                if diff < i8::MIN as i64 || diff > i8::MAX as i64 {
                    return Err(RelocError::ValueOverflow { reloc_type: r_type, value: diff });
                }
                Self::write_u8(buffer, offset, diff as u8)?;
                stats.applied_count += 1;
                stats.bytes_patched += 1;
                Ok(())
            }

            R_X86_64_PC64 => {
                let sym_addr = resolver.resolve_symbol(sym_idx).ok_or(RelocError::SymbolNotFound(sym_idx))?;
                let diff = (sym_addr as i64).wrapping_add(addend).wrapping_sub(place as i64);
                Self::write_u64(buffer, offset, diff as u64)?;
                stats.applied_count += 1;
                stats.bytes_patched += 8;
                Ok(())
            }

            other => Err(RelocError::UnsupportedReloc(other)),
        }
    }

    pub fn apply_batch(
        buffer: &mut [u8],
        relas: &[Elf64Rela],
        ctx: &RelocContext,
        resolver: &dyn SymbolResolver,
    ) -> Result<RelocStats, RelocError> {
        let mut stats = RelocStats::default();
        for rela in relas {
            Self::apply_rela(buffer, rela, ctx, resolver, &mut stats)?;
        }
        Ok(stats)
    }

    fn write_u64(buffer: &mut [u8], offset: usize, val: u64) -> Result<(), RelocError> {
        if offset + 8 > buffer.len() {
            return Err(RelocError::BufferOverflow {
                offset: offset as u64,
                needed: 8,
                capacity: buffer.len(),
            });
        }
        buffer[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_u32(buffer: &mut [u8], offset: usize, val: u32) -> Result<(), RelocError> {
        if offset + 4 > buffer.len() {
            return Err(RelocError::BufferOverflow {
                offset: offset as u64,
                needed: 4,
                capacity: buffer.len(),
            });
        }
        buffer[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_u16(buffer: &mut [u8], offset: usize, val: u16) -> Result<(), RelocError> {
        if offset + 2 > buffer.len() {
            return Err(RelocError::BufferOverflow {
                offset: offset as u64,
                needed: 2,
                capacity: buffer.len(),
            });
        }
        buffer[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_u8(buffer: &mut [u8], offset: usize, val: u8) -> Result<(), RelocError> {
        if offset >= buffer.len() {
            return Err(RelocError::BufferOverflow {
                offset: offset as u64,
                needed: 1,
                capacity: buffer.len(),
            });
        }
        buffer[offset] = val;
        Ok(())
    }
}

pub fn verify_elf64_reloc() -> u32 {
    let mut check_count = 0u32;

    let mut mock_buffer = [0u8; 128];
    let mut sym_map = SimpleSymbolMap::new();
    sym_map.insert_symbol(1, "main", 0x401000);
    sym_map.insert_symbol(2, "g_data", 0x602000);
    sym_map.insert_symbol(3, "printf", 0x403000);

    let ctx = RelocContext::new(0x400000, 0x600000, 0x402000);

    // Test 1: R_X86_64_64
    let r1 = Elf64Rela::new(0x10, 1, R_X86_64_64, 0x20);
    let mut stats = RelocStats::default();
    let res1 = RelocationEngine::apply_rela(&mut mock_buffer, &r1, &ctx, &sym_map, &mut stats);
    if res1.is_ok() {
        let val = u64::from_le_bytes(mock_buffer[0x10..0x18].try_into().unwrap());
        if val == 0x401020 {
            check_count += 1;
        }
    }

    // Test 2: R_X86_64_RELATIVE
    let r2 = Elf64Rela::new(0x20, 0, R_X86_64_RELATIVE, 0x1500);
    let res2 = RelocationEngine::apply_rela(&mut mock_buffer, &r2, &ctx, &sym_map, &mut stats);
    if res2.is_ok() {
        let val = u64::from_le_bytes(mock_buffer[0x20..0x28].try_into().unwrap());
        if val == 0x401500 {
            check_count += 1;
        }
    }

    // Test 3: R_X86_64_PC32
    // Place = 0x400000 + 0x30 = 0x400030
    // Target = 0x401000 + 4 = 0x401004
    // Diff = 0x401004 - 0x400030 = 0xFD4
    let r3 = Elf64Rela::new(0x30, 1, R_X86_64_PC32, 4);
    let res3 = RelocationEngine::apply_rela(&mut mock_buffer, &r3, &ctx, &sym_map, &mut stats);
    if res3.is_ok() {
        let diff = u32::from_le_bytes(mock_buffer[0x30..0x34].try_into().unwrap());
        if diff == 0x0FD4 {
            check_count += 1;
        }
    }

    // Test 4: R_X86_64_JUMP_SLOT
    let r4 = Elf64Rela::new(0x40, 3, R_X86_64_JUMP_SLOT, 0);
    let res4 = RelocationEngine::apply_rela(&mut mock_buffer, &r4, &ctx, &sym_map, &mut stats);
    if res4.is_ok() {
        let val = u64::from_le_bytes(mock_buffer[0x40..0x48].try_into().unwrap());
        if val == 0x403000 {
            check_count += 1;
        }
    }

    // Test 5: Symbol Not Found Error
    let r_missing = Elf64Rela::new(0x50, 999, R_X86_64_64, 0);
    let res_missing = RelocationEngine::apply_rela(&mut mock_buffer, &r_missing, &ctx, &sym_map, &mut stats);
    if let Err(RelocError::SymbolNotFound(999)) = res_missing {
        check_count += 1;
    }

    // Test 6: Buffer Overflow Detection
    let r_overflow = Elf64Rela::new(125, 1, R_X86_64_64, 0);
    let res_overflow = RelocationEngine::apply_rela(&mut mock_buffer, &r_overflow, &ctx, &sym_map, &mut stats);
    if let Err(RelocError::BufferOverflow { .. }) = res_overflow {
        check_count += 1;
    }

    // Test 7: Batch application
    let batch = [
        Elf64Rela::new(0x00, 2, R_X86_64_64, 8),
        Elf64Rela::new(0x08, 0, R_X86_64_RELATIVE, 0x200),
    ];
    let batch_res = RelocationEngine::apply_batch(&mut mock_buffer, &batch, &ctx, &sym_map);
    if let Ok(b_stats) = batch_res {
        if b_stats.applied_count == 2 && b_stats.bytes_patched == 16 {
            check_count += 1;
        }
    }

    // Test 8: R_X86_64_COPY
    let r_copy = Elf64Rela::new(0x60, 2, R_X86_64_COPY, 8);
    let res_copy = RelocationEngine::apply_rela(&mut mock_buffer, &r_copy, &ctx, &sym_map, &mut stats);
    if res_copy.is_ok() {
        let val = u64::from_le_bytes(mock_buffer[0x60..0x68].try_into().unwrap());
        if val == 0x602000 {
            check_count += 1;
        }
    }

    check_count
}
