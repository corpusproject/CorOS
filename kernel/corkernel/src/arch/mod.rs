//! Modular Architecture Abstraction Layer (HAL).
//!
//! Provides abstract interfaces (`traits`) and hardware implementations for:
//! - `x86_64`: Intel & AMD 64-bit processors (GDT, IDT, APIC, PAT, MSR_LSTAR)
//! - `aarch64`: ARMv8-A / ARMv9-A processors (VBAR_EL1, GICv2/v3, TTBR0/1, PSCI)
//! - `riscv64`: RISC-V 64-bit processors (stvec, PLIC/CLINT, satp Sv39/Sv48, SBI)

pub mod traits;
pub use traits::{CpuOps, TrapOps, MmuOps, SyscallOps, TimerOps, SmpOps, SyscallRegisters};

pub mod x86_64;
pub mod aarch64;
pub mod riscv64;

// Default / active target re-exports for HAL:
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
pub use x86_64::{
    cpu,
    mmu,
    trap,
    syscall,
    timer,
    smp,
};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    cpu,
    mmu,
    trap,
    syscall,
    timer,
    smp,
};

#[cfg(target_arch = "riscv64")]
pub use riscv64::{
    cpu,
    mmu,
    trap,
    syscall,
    timer,
    smp,
};
