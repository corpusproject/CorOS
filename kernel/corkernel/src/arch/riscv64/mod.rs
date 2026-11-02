//! Modular RISC-V (RV64GC) Hardware Abstraction Layer (HAL).
//!
//! Provides bare-metal implementations for RISC-V 64-bit architectures:
//! - Supervisor Trap Vectors (`stvec`), CSRs (`sstatus`, `sie`, `scause`), and PLIC driver
//! - Address translation via `satp` with Sv39 and Sv48 paging modes and `sfence.vma`
//! - RISC-V Timer (`rdtime` / `time` CSR) and SBI Set Timer Extension
//! - Multi-hart Symmetric Multiprocessing (SMP) via SBI HSM and SBI IPI
//! - Hardware ECALL system call frame and Linux ABI dispatch

pub mod cpu;
pub mod interrupts;
pub mod trap;
pub mod mmu;
pub mod syscall;
pub mod timer;
pub mod smp;

pub use cpu::Riscv64Cpu;
pub use interrupts::Riscv64Trap;
pub use mmu::Riscv64Mmu;
pub use syscall::Riscv64Syscall;
pub use timer::Riscv64Timer;
pub use smp::Riscv64Smp;
