//! Modular AArch64 Hardware Abstraction Layer (HAL).
//!
//! Provides bare-metal implementations for ARMv8-A / ARMv9-A:
//! - VBAR_EL1 exception vectors and ARM GICv2/v3 interrupt controllers
//! - TTBR0_EL1 / TTBR1_EL1 4-level paging and TCR/MAIR attribute configuration
//! - ARM Generic Timer (`cntvct_el0` / `cntfrq_el0`)
//! - ARM PSCI v0.2+ and GIC SGIR Multiprocessor management
//! - Hardware SVC #0 system call frame and Linux ABI dispatch

pub mod cpu;
pub mod interrupts;
pub mod trap;
pub mod mmu;
pub mod syscall;
pub mod timer;
pub mod smp;

pub use cpu::AArch64Cpu;
pub use interrupts::AArch64Trap;
pub use mmu::AArch64Mmu;
pub use syscall::AArch64Syscall;
pub use timer::AArch64Timer;
pub use smp::AArch64Smp;
