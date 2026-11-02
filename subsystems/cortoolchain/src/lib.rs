#![no_std]
//! `cortoolchain` — CorOS Toolchain, Dynamic Linker (`ld.so`), Disassembler,
//! DWARF Unwinder, Symbol Resolver & Livepatch Subsystem.

extern crate alloc;

pub mod binfmt_misc;
pub mod coredump;
pub mod disasm_x86_64;
pub mod dwarf_unwind;
pub mod elf64_reloc;
pub mod hw_watchpoints;
pub mod kallsyms;
pub mod ld_so;
pub mod livepatch;
pub mod vdso;

// Re-export primary types for kernel convenience
pub use binfmt_misc::{BinfmtEntry, BinfmtExecutionPlan, BinfmtRegistry};
pub use coredump::{CoreDumpBuilder, CoreDumpParser, CoreRegisters};
pub use disasm_x86_64::{DisassembledInst, Disassembler};
pub use dwarf_unwind::{EhFrameTable, UnwindRegisters, UnwindRow};
pub use elf64_reloc::{Elf64Rela, RelocContext, RelocError, RelocStats, RelocationEngine, SymbolResolver};
pub use hw_watchpoints::{DebugRegistersState, HwBreakpointManager, WatchCondition, WatchLength};
pub use kallsyms::{KallSymbol, KallsymsRegistry, SymbolLookup};
pub use ld_so::{DynamicLinker, Elf64Dyn, GnuHashTable, LazyBindingStub, ParsedDynamicSection, SharedObject};
pub use livepatch::{Livepatch, LivepatchManager, PatchFunction, PatchState};
pub use vdso::{TimeSpec, TimeVal, VdsoTimekeeperPage};

/// Executes comprehensive self-tests across all 10 toolchain and debugging modules.
///
/// Returns the total count of verified assertions.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += elf64_reloc::verify_elf64_reloc();
    passed += ld_so::verify_ld_so();
    passed += disasm_x86_64::verify_disasm_x86_64();
    passed += dwarf_unwind::verify_dwarf_unwind();
    passed += kallsyms::verify_kallsyms();
    passed += livepatch::verify_livepatch();
    passed += coredump::verify_coredump();
    passed += hw_watchpoints::verify_hw_watchpoints();
    passed += vdso::verify_vdso();
    passed += binfmt_misc::verify_binfmt_misc();
    passed
}
