//! x86_64 architecture boundary. CPU/GDT/TSS/IDT foundations are implemented;
//! page-table ownership and interrupt routing remain incomplete.
pub mod cpu;
pub use cpu::{disable_interrupts, enable_interrupts, halt_forever, X86Cpu};

pub mod mmu;
pub use mmu::X86Mmu;

pub mod trap;
pub use trap::X86Trap;

pub mod timer;
pub use timer::X86Timer;

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod paging;
pub mod interrupts;
pub mod pic;
pub mod acpi;
pub mod smp;
pub use smp::X86Smp;

pub mod syscall;
pub use syscall::X86Syscall;
pub mod msr;
pub mod cpuid;
pub mod simd;
pub mod vtd;
pub mod svm;
pub mod ioapic;
pub mod cpu_features;
pub mod memory_pat;

pub use msr::Msr;
pub use cpuid::{CpuInfo, CpuFeatures};
pub use simd::{SimdManager, FxSaveArea};
pub use vtd::{VmxHypervisor, VmcsArea, VmExitReason};
pub use svm::{AmdVirtualMachine, VmcbControlArea, VmcbGuestSaveArea, SvmExitCode};
pub use ioapic::{IoApic, RedirectionEntry, InterruptSourceOverride, DEFAULT_IOAPIC_BASE};
pub use cpu_features::{CpuProfile, CpuVendor, CoreType, AmdZenGeneration, CpuFeatureMatrix};
pub use memory_pat::{MemoryPatManager, MEMORY_TYPE_WC, MEMORY_TYPE_WB, MEMORY_TYPE_UC};




