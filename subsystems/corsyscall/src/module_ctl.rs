//! CorOS Syscall Domain Module: `module_ctl`
//! Loadable Kernel Module Management (`init_module`, `finit_module`, `delete_module`, `query_module`).

use alloc::string::String;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EEXIST: i64 = -17;
pub const ENOENT: i64 = -2;
pub const EBUSY: i64 = -16;
pub const ENOEXEC: i64 = -8;

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const O_NONBLOCK: u32 = 0x0800;

/// Lifecycle state of a dynamically loaded kernel module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleState {
    Coming,
    Live,
    Going,
    Unloaded,
}

/// Exported kernel symbol entry (`EXPORT_SYMBOL` / `EXPORT_SYMBOL_GPL`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolExport {
    pub name: String,
    pub address: u64,
    pub gpl_only: bool,
}

/// Binary header & metadata describing a CorOS loadable kernel module (`.ko`).
#[derive(Clone, Debug)]
pub struct KernelModuleHeader {
    pub name: String,
    pub version: String,
    pub state: ModuleState,
    pub base_addr: u64,
    pub core_size: usize,
    pub refcount: u32,
    pub dependencies: Vec<String>,
    pub exported_symbols: Vec<SymbolExport>,
    pub param_args: String,
}

/// Kernel Module Registry handling ELF verification, symbol resolution, and reference counting.
pub struct ModuleRegistry {
    modules: Vec<KernelModuleHeader>,
    next_load_addr: u64,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            next_load_addr: 0xFFFF_FFFF_A000_0000,
        }
    }

    /// `sys_init_module`: Validates an ELF `.ko` image, resolves dependencies, and loads the module into `Live` state.
    pub fn sys_init_module(
        &mut self,
        elf_image: &[u8],
        name: &str,
        version: &str,
        deps: &[&str],
        exports: &[(&str, u64, bool)],
        param_values: &str,
    ) -> i64 {
        if elf_image.len() < 64 || elf_image[0..4] != ELF_MAGIC {
            return ENOEXEC;
        }
        if name.is_empty() {
            return EINVAL;
        }
        if self.modules.iter().any(|m| m.name == name && m.state == ModuleState::Live) {
            return EEXIST;
        }

        // Verify all dependencies exist and are Live, then increment their refcounts
        for &dep in deps {
            if !self.modules.iter().any(|m| m.name == dep && m.state == ModuleState::Live) {
                return ENOENT;
            }
        }
        for &dep in deps {
            if let Some(m) = self.modules.iter_mut().find(|m| m.name == dep && m.state == ModuleState::Live) {
                m.refcount += 1;
            }
        }

        let base = self.next_load_addr;
        let aligned_size = (elf_image.len() + 4095) & !4095;
        self.next_load_addr += aligned_size as u64;

        let exported_symbols = exports
            .iter()
            .map(|(sym, offset, gpl)| SymbolExport {
                name: String::from(*sym),
                address: base + *offset,
                gpl_only: *gpl,
            })
            .collect();

        self.modules.push(KernelModuleHeader {
            name: String::from(name),
            version: String::from(version),
            state: ModuleState::Live,
            base_addr: base,
            core_size: aligned_size,
            refcount: 0,
            dependencies: deps.iter().map(|d| String::from(*d)).collect(),
            exported_symbols,
            param_args: String::from(param_values),
        });
        0
    }

    /// `sys_finit_module`: Loads a kernel module from a file descriptor with flags validation.
    pub fn sys_finit_module(
        &mut self,
        fd: i32,
        elf_image: &[u8],
        name: &str,
        deps: &[&str],
        exports: &[(&str, u64, bool)],
        param_values: &str,
        flags: u32,
    ) -> i64 {
        if fd < 0 || (flags & !0x3) != 0 {
            return EINVAL;
        }
        self.sys_init_module(elf_image, name, "1.0.0", deps, exports, param_values)
    }

    /// `sys_delete_module`: Unloads a module if its `refcount == 0`, decrementing dependencies' refcounts.
    pub fn sys_delete_module(&mut self, name: &str, _flags: u32) -> i64 {
        let idx = match self.modules.iter().position(|m| m.name == name && m.state == ModuleState::Live) {
            Some(i) => i,
            None => return ENOENT,
        };
        if self.modules[idx].refcount > 0 {
            return EBUSY;
        }
        let deps = self.modules[idx].dependencies.clone();
        self.modules[idx].state = ModuleState::Going;
        self.modules.remove(idx);

        for dep in deps {
            if let Some(m) = self.modules.iter_mut().find(|m| m.name == dep) {
                m.refcount = m.refcount.saturating_sub(1);
            }
        }
        0
    }

    /// `sys_query_module`: Resolves exported symbols or module metadata.
    pub fn sys_query_module(&self, name: &str) -> Result<&KernelModuleHeader, i64> {
        self.modules
            .iter()
            .find(|m| m.name == name && m.state == ModuleState::Live)
            .ok_or(ENOENT)
    }

    /// Looks up a global kernel symbol address across all live modules.
    pub fn resolve_symbol(&self, sym_name: &str) -> Option<u64> {
        for m in &self.modules {
            if m.state == ModuleState::Live {
                for s in &m.exported_symbols {
                    if s.name == sym_name {
                        return Some(s.address);
                    }
                }
            }
        }
        None
    }
}

/// Runs comprehensive self-tests on `module_ctl` structs and module dependency refcounting.
pub fn verify_domain_module_ctl() -> u32 {
    let mut passed = 0u32;
    let mut reg = ModuleRegistry::new();

    let mut fake_elf = [0u8; 128];
    fake_elf[0..4].copy_from_slice(&ELF_MAGIC);

    // 1. Reject non-ELF binary with ENOEXEC
    if reg.sys_init_module(&[0u8; 128], "bad_mod", "0.1", &[], &[], "") == ENOEXEC {
        passed += 1;
    }

    // 2. Load base module `cor_pci` exporting `pci_register_driver`
    if reg.sys_init_module(
        &fake_elf,
        "cor_pci",
        "2.4.0",
        &[],
        &[("pci_register_driver", 0x120, false)],
        "msi=1",
    ) == 0
    {
        passed += 1;
    }

    // 3. Load dependent module `cor_nvme` via finit_module depending on `cor_pci`
    if reg.sys_finit_module(
        3,
        &fake_elf,
        "cor_nvme",
        &["cor_pci"],
        &[("nvme_submit_cmd", 0x400, true)],
        "io_queues=8",
        0,
    ) == 0
    {
        passed += 1;
    }

    // 4. Verify `cor_pci` cannot be unloaded while `cor_nvme` holds a reference (EBUSY)
    if reg.sys_delete_module("cor_pci", 0) == EBUSY {
        passed += 1;
    }

    // 5. Resolve exported symbol address and query module header
    if reg.resolve_symbol("pci_register_driver").is_some()
        && reg.sys_query_module("cor_nvme").map(|m| m.core_size).unwrap_or(0) == 4096
    {
        passed += 1;
    }

    // 6. Unload `cor_nvme` then `cor_pci` cleanly
    if reg.sys_delete_module("cor_nvme", 0) == 0 && reg.sys_delete_module("cor_pci", 0) == 0 {
        passed += 1;
    }

    passed
}
