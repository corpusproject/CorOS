//! Kernel Symbol Table & Address Resolver (`kallsyms`)
//!
//! Provides binary-search address-to-symbol resolution with offset and size,
//! symbol name matching, token compression/decompression, and module attribution.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KallSymbol {
    pub address: u64,
    pub size: u32,
    pub sym_type: char,
    pub name: String,
    pub module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolLookup {
    pub name: String,
    pub offset: u64,
    pub size: u32,
    pub module: Option<String>,
    pub formatted: String,
}

pub struct TokenCompressor {
    tokens: [ &'static str; 16],
}

impl TokenCompressor {
    pub fn new() -> Self {
        Self {
            tokens: [
                "sys_",
                "kernel_",
                "handler",
                "alloc",
                "free",
                "init",
                "exit",
                "read",
                "write",
                "lock",
                "unlock",
                "device",
                "driver",
                "pci_",
                "irq_",
                "task_",
            ],
        }
    }

    pub fn compress(&self, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = name;

        while !rest.is_empty() {
            let mut matched_idx = None;
            for (idx, &token) in self.tokens.iter().enumerate() {
                if rest.starts_with(token) {
                    matched_idx = Some((idx, token.len()));
                    break;
                }
            }

            if let Some((idx, len)) = matched_idx {
                out.push(0x80 | (idx as u8));
                rest = &rest[len..];
            } else {
                out.push(rest.as_bytes()[0]);
                rest = &rest[1..];
            }
        }

        out
    }

    pub fn decompress(&self, data: &[u8]) -> String {
        let mut s = String::new();
        for &b in data {
            if (b & 0x80) != 0 {
                let idx = (b & 0x7f) as usize;
                if idx < self.tokens.len() {
                    s.push_str(self.tokens[idx]);
                }
            } else {
                s.push(b as char);
            }
        }
        s
    }
}

pub struct KallsymsRegistry {
    symbols: Vec<KallSymbol>,
    name_map: BTreeMap<String, u64>,
    compressor: TokenCompressor,
}

impl KallsymsRegistry {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            name_map: BTreeMap::new(),
            compressor: TokenCompressor::new(),
        }
    }

    pub fn add_symbol(
        &mut self,
        address: u64,
        size: u32,
        sym_type: char,
        name: &str,
        module: Option<&str>,
    ) {
        let sym = KallSymbol {
            address,
            size,
            sym_type,
            name: String::from(name),
            module: module.map(String::from),
        };
        self.symbols.push(sym);
        self.name_map.insert(String::from(name), address);
    }

    pub fn finalize(&mut self) {
        self.symbols.sort_by_key(|s| s.address);
    }

    pub fn lookup_address(&self, addr: u64) -> Option<SymbolLookup> {
        if self.symbols.is_empty() {
            return None;
        }

        let mut low = 0;
        let mut high = self.symbols.len();

        while low < high {
            let mid = low + (high - low) / 2;
            if self.symbols[mid].address <= addr {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        if low == 0 {
            return None;
        }

        let best_idx = low - 1;
        let sym = &self.symbols[best_idx];

        let offset = addr - sym.address;
        let max_range = if sym.size > 0 { sym.size as u64 } else { 0x4000 };

        if offset >= max_range {
            return None;
        }

        let formatted = if let Some(ref m) = sym.module {
            format!("{}+0x{:x}/0x{:x} [{}]", sym.name, offset, sym.size, m)
        } else {
            format!("{}+0x{:x}/0x{:x}", sym.name, offset, sym.size)
        };

        Some(SymbolLookup {
            name: sym.name.clone(),
            offset,
            size: sym.size,
            module: sym.module.clone(),
            formatted,
        })
    }

    pub fn lookup_name(&self, name: &str) -> Option<u64> {
        self.name_map.get(name).copied()
    }

    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&KallSymbol> {
        self.symbols.iter().filter(|s| s.name.starts_with(prefix)).collect()
    }

    pub fn total_symbols(&self) -> usize {
        self.symbols.len()
    }

    pub fn compressor(&self) -> &TokenCompressor {
        &self.compressor
    }
}

pub fn verify_kallsyms() -> u32 {
    let mut check_count = 0u32;

    let mut registry = KallsymsRegistry::new();
    registry.add_symbol(0xffff_ffff_8100_0000, 0x100, 'T', "init_kernel", None);
    registry.add_symbol(0xffff_ffff_8100_0200, 0x80, 'T', "sys_read", None);
    registry.add_symbol(0xffff_ffff_8100_0300, 0xC0, 'T', "sys_write", None);
    registry.add_symbol(0xffff_ffff_8100_0500, 0x150, 'T', "e1000_rx_poll", Some("e1000"));
    registry.add_symbol(0xffff_ffff_8100_1000, 0x40, 'D', "jiffies_64", None);
    registry.finalize();

    // Test 1: Total symbols
    if registry.total_symbols() == 5 {
        check_count += 1;
    }

    // Test 2: Exact address lookup
    if let Some(res) = registry.lookup_address(0xffff_ffff_8100_0200) {
        if res.name == "sys_read" && res.offset == 0 && res.formatted == "sys_read+0x0/0x80" {
            check_count += 1;
        }
    }

    // Test 3: Offset lookup within function
    if let Some(res) = registry.lookup_address(0xffff_ffff_8100_0224) {
        if res.name == "sys_read" && res.offset == 0x24 {
            check_count += 1;
        }
    }

    // Test 4: Module symbol lookup with formatted string
    if let Some(res) = registry.lookup_address(0xffff_ffff_8100_0510) {
        if res.name == "e1000_rx_poll"
            && res.offset == 0x10
            && res.module == Some(String::from("e1000"))
            && res.formatted == "e1000_rx_poll+0x10/0x150 [e1000]"
        {
            check_count += 1;
        }
    }

    // Test 5: Name lookup
    if registry.lookup_name("sys_write") == Some(0xffff_ffff_8100_0300) {
        check_count += 1;
    }

    // Test 6: Prefix matching
    let sys_syms = registry.find_by_prefix("sys_");
    if sys_syms.len() == 2 {
        check_count += 1;
    }

    // Test 7: Token compression and decompression
    let comp = registry.compressor();
    let original = "sys_read_init";
    let compressed = comp.compress(original);
    let decompressed = comp.decompress(&compressed);
    if original == decompressed && compressed.len() < original.len() {
        check_count += 1;
    }

    check_count
}
