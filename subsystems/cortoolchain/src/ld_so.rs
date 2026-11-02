//! Dynamic Linker (`ld.so`)
//!
//! Provides GNU hash table symbol resolution, ELF `DT_NEEDED` dependency resolution
//! with topological sorting, and lazy PLT binding stubs.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;

pub const DF_BIND_NOW: u64 = 0x8;
pub const DF_1_NOW: u64 = 0x1;

/// Standard 16-byte ELF64 Dynamic Array Entry (`Elf64_Dyn`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Dyn {
    pub d_tag: u64,
    pub d_val: u64,
}

/// Parsed ELF Dynamic Section (`PT_DYNAMIC`) containing table offsets and link flags.
#[derive(Debug, Clone, Default)]
pub struct ParsedDynamicSection {
    pub needed: Vec<u64>,
    pub symtab: Option<u64>,
    pub strtab: Option<u64>,
    pub strsz: Option<u64>,
    pub syment: Option<u64>,
    pub rela: Option<u64>,
    pub relasz: Option<u64>,
    pub relaent: Option<u64>,
    pub jmprel: Option<u64>,
    pub pltrelsz: Option<u64>,
    pub pltgot: Option<u64>,
    pub gnu_hash: Option<u64>,
    pub hash: Option<u64>,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<u64>,
    pub init_arraysz: Option<u64>,
    pub fini_array: Option<u64>,
    pub fini_arraysz: Option<u64>,
    pub flags: Option<u64>,
    pub flags_1: Option<u64>,
    pub is_bind_now: bool,
}

impl ParsedDynamicSection {
    pub fn parse(raw: &[u8]) -> Result<Self, LinkerError> {
        let entry_size = core::mem::size_of::<Elf64Dyn>();
        if raw.len() % entry_size != 0 {
            return Err(LinkerError::CorruptedHeader("Dynamic section not aligned to Elf64Dyn"));
        }
        let count = raw.len() / entry_size;
        let mut parsed = Self::default();
        for i in 0..count {
            let offset = i * entry_size;
            let d_tag = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
            let d_val = u64::from_le_bytes(raw[offset + 8..offset + 16].try_into().unwrap());
            if d_tag == DT_NULL {
                break;
            }
            match d_tag {
                DT_NEEDED => parsed.needed.push(d_val),
                DT_SYMTAB => parsed.symtab = Some(d_val),
                DT_STRTAB => parsed.strtab = Some(d_val),
                DT_STRSZ => parsed.strsz = Some(d_val),
                DT_SYMENT => parsed.syment = Some(d_val),
                DT_RELA => parsed.rela = Some(d_val),
                DT_RELASZ => parsed.relasz = Some(d_val),
                DT_RELAENT => parsed.relaent = Some(d_val),
                DT_JMPREL => parsed.jmprel = Some(d_val),
                DT_PLTRELSZ => parsed.pltrelsz = Some(d_val),
                DT_PLTGOT => parsed.pltgot = Some(d_val),
                DT_GNU_HASH => parsed.gnu_hash = Some(d_val),
                DT_HASH => parsed.hash = Some(d_val),
                DT_INIT => parsed.init = Some(d_val),
                DT_FINI => parsed.fini = Some(d_val),
                DT_INIT_ARRAY => parsed.init_array = Some(d_val),
                DT_INIT_ARRAYSZ => parsed.init_arraysz = Some(d_val),
                DT_FINI_ARRAY => parsed.fini_array = Some(d_val),
                DT_FINI_ARRAYSZ => parsed.fini_arraysz = Some(d_val),
                DT_FLAGS => {
                    parsed.flags = Some(d_val);
                    if (d_val & DF_BIND_NOW) != 0 {
                        parsed.is_bind_now = true;
                    }
                }
                DT_FLAGS_1 => {
                    parsed.flags_1 = Some(d_val);
                    if (d_val & DF_1_NOW) != 0 {
                        parsed.is_bind_now = true;
                    }
                }
                DT_BIND_NOW => parsed.is_bind_now = true,
                _ => {}
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkerError {
    SymbolNotFound(String),
    CircularDependency(String),
    MissingDependency(String),
    CorruptedHeader(&'static str),
    RelocationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Sym {
    pub const fn new(name_idx: u32, value: u64, size: u64, bind: u8, sym_type: u8) -> Self {
        Self {
            st_name: name_idx,
            st_info: (bind << 4) | (sym_type & 0xf),
            st_other: 0,
            st_shndx: 1,
            st_value: value,
            st_size: size,
        }
    }

    pub const fn sym_bind(&self) -> u8 {
        self.st_info >> 4
    }

    pub const fn sym_type(&self) -> u8 {
        self.st_info & 0xf
    }
}

pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h = 5381u32;
    for &byte in name {
        h = h.wrapping_mul(33).wrapping_add(byte as u32);
    }
    h
}

pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    for &byte in name {
        h = (h << 4).wrapping_add(byte as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

#[derive(Debug, Clone)]
pub struct GnuHashTable {
    pub nbuckets: u32,
    pub symoffset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
    pub bloom_filter: Vec<u64>,
    pub buckets: Vec<u32>,
    pub chain: Vec<u32>,
}

impl GnuHashTable {
    pub fn new(
        nbuckets: u32,
        symoffset: u32,
        bloom_shift: u32,
        bloom_filter: Vec<u64>,
        buckets: Vec<u32>,
        chain: Vec<u32>,
    ) -> Self {
        let bloom_size = bloom_filter.len() as u32;
        Self {
            nbuckets,
            symoffset,
            bloom_size,
            bloom_shift,
            bloom_filter,
            buckets,
            chain,
        }
    }

    pub fn lookup(&self, name: &str, symtab: &[Elf64Sym], strtab: &[u8]) -> Option<usize> {
        if self.bloom_size == 0 || self.nbuckets == 0 {
            return None;
        }

        let name_bytes = name.as_bytes();
        let h = gnu_hash(name_bytes);

        // 1. Bloom filter check
        let elfclass_bits = 64u32;
        let word_idx = ((h / elfclass_bits) % self.bloom_size) as usize;
        let word = self.bloom_filter.get(word_idx).copied()?;

        let mask1 = 1u64 << (h % elfclass_bits);
        let mask2 = 1u64 << ((h >> self.bloom_shift) % elfclass_bits);
        let combined_mask = mask1 | mask2;

        if (word & combined_mask) != combined_mask {
            // Definite miss via Bloom filter
            return None;
        }

        // 2. Bucket index
        let bucket_idx = (h % self.nbuckets) as usize;
        let mut sym_idx = *self.buckets.get(bucket_idx)? as usize;
        if sym_idx < self.symoffset as usize {
            return None;
        }

        // 3. Chain traversal
        loop {
            let chain_idx = sym_idx - self.symoffset as usize;
            let chain_hash = *self.chain.get(chain_idx)?;

            // Hashes match ignoring lowest bit (chain terminator bit)
            if (chain_hash | 1) == (h | 1) {
                if let Some(sym) = symtab.get(sym_idx) {
                    if let Some(sym_name) = Self::read_string(strtab, sym.st_name as usize) {
                        if sym_name == name {
                            return Some(sym_idx);
                        }
                    }
                }
            }

            // Lowest bit indicates end of hash bucket chain
            if (chain_hash & 1) != 0 {
                break;
            }
            sym_idx += 1;
        }

        None
    }

    fn read_string(strtab: &[u8], offset: usize) -> Option<&str> {
        if offset >= strtab.len() {
            return None;
        }
        let rest = &strtab[offset..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        core::str::from_utf8(&rest[..len]).ok()
    }
}

#[derive(Debug, Clone)]
pub struct SharedObject {
    pub soname: String,
    pub load_bias: u64,
    pub needed_libraries: Vec<String>,
    pub symtab: Vec<Elf64Sym>,
    pub strtab: Vec<u8>,
    pub gnu_hash: Option<GnuHashTable>,
    pub got_entries: BTreeMap<usize, u64>,
    pub init_called: bool,
}

impl SharedObject {
    pub fn new(soname: &str, load_bias: u64) -> Self {
        Self {
            soname: String::from(soname),
            load_bias,
            needed_libraries: Vec::new(),
            symtab: Vec::new(),
            strtab: Vec::new(),
            gnu_hash: None,
            got_entries: BTreeMap::new(),
            init_called: false,
        }
    }

    pub fn add_symbol(&mut self, name: &str, offset: u64, size: u64) -> usize {
        let name_offset = self.strtab.len() as u32;
        self.strtab.extend_from_slice(name.as_bytes());
        self.strtab.push(0);

        let sym_idx = self.symtab.len();
        self.symtab.push(Elf64Sym::new(name_offset, self.load_bias + offset, size, 1, 2));
        sym_idx
    }

    pub fn lookup_symbol(&self, name: &str) -> Option<u64> {
        if let Some(ref gh) = self.gnu_hash {
            if let Some(idx) = gh.lookup(name, &self.symtab, &self.strtab) {
                return Some(self.symtab[idx].st_value);
            }
        }

        // Linear fallback
        for sym in &self.symtab {
            if let Some(sname) = GnuHashTable::read_string(&self.strtab, sym.st_name as usize) {
                if sname == name {
                    return Some(sym.st_value);
                }
            }
        }
        None
    }
}

pub struct LazyBindingStub {
    pub total_calls: u32,
    pub cache_hits: u32,
    pub resolved_trampolines: BTreeMap<usize, u64>,
}

impl LazyBindingStub {
    pub fn new() -> Self {
        Self {
            total_calls: 0,
            cache_hits: 0,
            resolved_trampolines: BTreeMap::new(),
        }
    }

    pub fn resolve(
        &mut self,
        plt_idx: usize,
        sym_name: &str,
        dso_pool: &[SharedObject],
    ) -> Result<u64, LinkerError> {
        self.total_calls += 1;

        if let Some(&cached) = self.resolved_trampolines.get(&plt_idx) {
            self.cache_hits += 1;
            return Ok(cached);
        }

        // Search DSOs in load order
        for dso in dso_pool {
            if let Some(addr) = dso.lookup_symbol(sym_name) {
                self.resolved_trampolines.insert(plt_idx, addr);
                return Ok(addr);
            }
        }

        Err(LinkerError::SymbolNotFound(String::from(sym_name)))
    }
}

pub struct DynamicLinker {
    pub loaded_objects: Vec<SharedObject>,
    pub search_paths: Vec<String>,
    pub lazy_stub: LazyBindingStub,
    pub eager_binding: bool,
    pub got_table: BTreeMap<u64, u64>,
}

impl DynamicLinker {
    pub fn new() -> Self {
        Self::with_eager(false)
    }

    pub fn with_eager(eager_binding: bool) -> Self {
        let mut search_paths = Vec::new();
        search_paths.push(String::from("/lib64"));
        search_paths.push(String::from("/usr/lib64"));

        Self {
            loaded_objects: Vec::new(),
            search_paths,
            lazy_stub: LazyBindingStub::new(),
            eager_binding,
            got_table: BTreeMap::new(),
        }
    }

    pub fn register_object(&mut self, obj: SharedObject) {
        self.loaded_objects.push(obj);
    }

    pub fn compute_initialization_order(&self) -> Result<Vec<String>, LinkerError> {
        let mut order = Vec::new();
        let mut visited = BTreeMap::new(); // 0 = unvisited, 1 = in progress, 2 = done

        for obj in &self.loaded_objects {
            visited.insert(obj.soname.clone(), 0u8);
        }

        fn dfs(
            soname: &str,
            objects: &[SharedObject],
            visited: &mut BTreeMap<String, u8>,
            order: &mut Vec<String>,
        ) -> Result<(), LinkerError> {
            let state = visited.get(soname).copied().unwrap_or(0);
            if state == 1 {
                return Err(LinkerError::CircularDependency(String::from(soname)));
            }
            if state == 2 {
                return Ok(());
            }

            visited.insert(String::from(soname), 1);

            if let Some(obj) = objects.iter().find(|o| o.soname == soname) {
                for dep in &obj.needed_libraries {
                    if visited.contains_key(dep) {
                        dfs(dep, objects, visited, order)?;
                    }
                }
            }

            visited.insert(String::from(soname), 2);
            order.push(String::from(soname));
            Ok(())
        }

        for obj in &self.loaded_objects {
            if visited.get(&obj.soname).copied().unwrap_or(0) == 0 {
                dfs(&obj.soname, &self.loaded_objects, &mut visited, &mut order)?;
            }
        }

        Ok(order)
    }

    pub fn resolve_symbol(&self, name: &str) -> Option<u64> {
        for obj in &self.loaded_objects {
            if let Some(addr) = obj.lookup_symbol(name) {
                return Some(addr);
            }
        }
        None
    }

    pub fn apply_relocation(
        &mut self,
        reloc_type: u32,
        target_slot: u64,
        sym_name: Option<&str>,
        addend: i64,
        base_addr: u64,
    ) -> Result<u64, LinkerError> {
        match reloc_type {
            crate::elf64_reloc::R_X86_64_RELATIVE => {
                let resolved = (base_addr as i64).wrapping_add(addend) as u64;
                self.got_table.insert(target_slot, resolved);
                Ok(resolved)
            }
            crate::elf64_reloc::R_X86_64_GLOB_DAT => {
                let name = sym_name.ok_or_else(|| LinkerError::CorruptedHeader("Missing sym_name for GLOB_DAT"))?;
                let sym_addr = self.resolve_symbol(name).ok_or_else(|| LinkerError::SymbolNotFound(String::from(name)))?;
                self.got_table.insert(target_slot, sym_addr);
                Ok(sym_addr)
            }
            crate::elf64_reloc::R_X86_64_JUMP_SLOT => {
                let name = sym_name.ok_or_else(|| LinkerError::CorruptedHeader("Missing sym_name for JUMP_SLOT"))?;
                if self.eager_binding {
                    let sym_addr = self.resolve_symbol(name).ok_or_else(|| LinkerError::SymbolNotFound(String::from(name)))?;
                    self.got_table.insert(target_slot, sym_addr);
                    Ok(sym_addr)
                } else {
                    let trampoline = target_slot + 6;
                    self.got_table.insert(target_slot, trampoline);
                    Ok(trampoline)
                }
            }
            _ => Err(LinkerError::RelocationFailed),
        }
    }

    pub fn dl_runtime_resolve(&mut self, target_slot: u64, sym_name: &str) -> Result<u64, LinkerError> {
        let sym_addr = self.resolve_symbol(sym_name).ok_or_else(|| LinkerError::SymbolNotFound(String::from(sym_name)))?;
        self.got_table.insert(target_slot, sym_addr);
        Ok(sym_addr)
    }
}

pub fn verify_ld_so() -> u32 {
    let mut check_count = 0u32;

    // Test 1: GNU hash deterministic calculation
    let hash_printf = gnu_hash(b"printf");
    let hash_puts = gnu_hash(b"puts");
    if hash_printf != 0 && hash_puts != 0 && hash_printf != hash_puts {
        check_count += 1;
    }

    // Test 2: SysV hash calculation
    let sysv_printf = sysv_hash(b"printf");
    if sysv_printf != 0 {
        check_count += 1;
    }

    // Test 3: SharedObject symbol insertion and linear lookup
    let mut libc = SharedObject::new("libc.so.6", 0x7fff_f700_0000);
    libc.add_symbol("printf", 0x1020, 64);
    libc.add_symbol("malloc", 0x2040, 128);
    libc.add_symbol("free", 0x3060, 48);

    if libc.lookup_symbol("printf") == Some(0x7fff_f700_0000 + 0x1020) {
        check_count += 1;
    }
    if libc.lookup_symbol("free") == Some(0x7fff_f700_0000 + 0x3060) {
        check_count += 1;
    }

    // Test 4: GNU Hash Table construction and lookup
    // Construct single-entry bloom filter for "printf"
    let p_hash = gnu_hash(b"printf");
    let bloom_mask = (1u64 << (p_hash % 64)) | (1u64 << ((p_hash >> 6) % 64));
    let bloom_filter = alloc::vec![bloom_mask];
    let buckets = alloc::vec![0]; // index 0 in symtab
    let chain = alloc::vec![p_hash | 1]; // terminator bit set
    let gnu_table = GnuHashTable::new(1, 0, 6, bloom_filter, buckets, chain);
    libc.gnu_hash = Some(gnu_table);

    if libc.lookup_symbol("printf") == Some(0x7fff_f700_0000 + 0x1020) {
        check_count += 1;
    }

    // Test 5: DT_NEEDED Dependency Topological Resolution
    // libc has no dependencies
    // libm depends on libc
    // app depends on libm and libc
    let mut libm = SharedObject::new("libm.so.6", 0x7fff_f720_0000);
    libm.needed_libraries.push(String::from("libc.so.6"));
    libm.add_symbol("sin", 0x500, 32);

    let mut app = SharedObject::new("my_app", 0x400000);
    app.needed_libraries.push(String::from("libm.so.6"));
    app.needed_libraries.push(String::from("libc.so.6"));

    let mut linker = DynamicLinker::new();
    linker.register_object(libc);
    linker.register_object(libm);
    linker.register_object(app);

    let order_res = linker.compute_initialization_order();
    if let Ok(order) = order_res {
        // Initialization order must have libc before libm, and libm before my_app
        let pos_libc = order.iter().position(|s| s == "libc.so.6");
        let pos_libm = order.iter().position(|s| s == "libm.so.6");
        let pos_app = order.iter().position(|s| s == "my_app");

        if let (Some(c), Some(m), Some(a)) = (pos_libc, pos_libm, pos_app) {
            if c < m && m < a {
                check_count += 1;
            }
        }
    }

    // Test 6: Lazy binding stub resolution and caching
    let r1 = linker.lazy_stub.resolve(10, "sin", &linker.loaded_objects);
    if r1 == Ok(0x7fff_f720_0000 + 0x500) {
        check_count += 1;
    }
    // 2nd call should hit cache
    let r2 = linker.lazy_stub.resolve(10, "sin", &linker.loaded_objects);
    if r2 == Ok(0x7fff_f720_0000 + 0x500) && linker.lazy_stub.cache_hits == 1 {
        check_count += 1;
    }

    // Test 7: ParsedDynamicSection::parse
    let mut dyn_bytes = alloc::vec![0u8; 32];
    dyn_bytes[0..8].copy_from_slice(&DT_NEEDED.to_le_bytes());
    dyn_bytes[8..16].copy_from_slice(&42u64.to_le_bytes()); // needed string offset
    dyn_bytes[16..24].copy_from_slice(&DT_NULL.to_le_bytes());
    if let Ok(parsed_dyn) = ParsedDynamicSection::parse(&dyn_bytes) {
        if parsed_dyn.needed == alloc::vec![42] {
            check_count += 1;
        }
    }

    // Test 8: apply_relocation with R_X86_64_RELATIVE and R_X86_64_GLOB_DAT
    let mut d_linker = DynamicLinker::new();
    let mut test_obj = SharedObject::new("libtest.so", 0x7F0000);
    test_obj.add_symbol("read", 0x120, 32);
    d_linker.register_object(test_obj);

    if let Ok(rel_addr) = d_linker.apply_relocation(crate::elf64_reloc::R_X86_64_RELATIVE, 0x8000, None, 0x50, 0x7F0000) {
        if rel_addr == 0x7F0050 && d_linker.got_table.get(&0x8000) == Some(&0x7F0050) {
            check_count += 1;
        }
    }
    if let Ok(glob_addr) = d_linker.apply_relocation(crate::elf64_reloc::R_X86_64_GLOB_DAT, 0x8008, Some("read"), 0, 0) {
        if glob_addr == 0x7F0120 && d_linker.got_table.get(&0x8008) == Some(&0x7F0120) {
            check_count += 1;
        }
    }

    // Test 9: Eager vs Lazy binding and dl_runtime_resolve
    let mut eager_l = DynamicLinker::with_eager(true);
    let mut lazy_l = DynamicLinker::with_eager(false);
    let mut libm_obj = SharedObject::new("libm.so", 0x600000);
    libm_obj.add_symbol("sin", 0x40, 32);
    eager_l.register_object(libm_obj.clone());
    lazy_l.register_object(libm_obj);

    let eager_res = eager_l.apply_relocation(crate::elf64_reloc::R_X86_64_JUMP_SLOT, 0x6500, Some("sin"), 0, 0);
    let lazy_res = lazy_l.apply_relocation(crate::elf64_reloc::R_X86_64_JUMP_SLOT, 0x6500, Some("sin"), 0, 0);
    if eager_res == Ok(0x600040) && lazy_res == Ok(0x6506) {
        if lazy_l.dl_runtime_resolve(0x6500, "sin") == Ok(0x600040) && lazy_l.got_table.get(&0x6500) == Some(&0x600040) {
            check_count += 1;
        }
    }

    check_count
}
