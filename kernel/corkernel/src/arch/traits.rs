//! Hardware Abstraction Layer (HAL) Core Architecture Traits.
//!
//! Provides architecture-agnostic abstractions for CPU lifecycle, interrupt/trap
//! handling, virtual memory (MMU), hardware system calls, timers, and symmetric
//! multiprocessing (SMP) across x86_64, AArch64, and RISC-V.

/// Architecture-neutral system call registers context frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyscallRegisters {
    pub rax: u64, // Syscall number / return code
    pub rdi: u64, // Arg 1
    pub rsi: u64, // Arg 2
    pub rdx: u64, // Arg 3
    pub r10: u64, // Arg 4
    pub r8:  u64, // Arg 5
    pub r9:  u64, // Arg 6
    pub r11: u64, // RFLAGS / status flags
    pub rcx: u64, // User RIP / instruction pointer
    pub rsp: u64, // User RSP / stack pointer
}

/// CPU lifecycle, interrupt masking, and execution state operations.
pub trait CpuOps {
    fn halt() -> !;
    fn enable_interrupts();
    fn disable_interrupts();
    fn interrupts_enabled() -> bool;
    fn relax();
    fn current_cpu_id() -> u32;
}

/// Interrupt and exception trap vector table management.
pub trait TrapOps {
    fn initialize();
    fn register_handler(vector: u8, handler: usize);
    fn is_active() -> bool;
}

/// Memory Management Unit (MMU) and page table translation operations.
pub trait MmuOps {
    fn current_page_table_root() -> u64;
    unsafe fn switch_page_table(root: u64);
    fn flush_tlb(vaddr: u64);
    fn flush_tlb_all();
}

/// Hardware-accelerated system call entry and ABI register frame operations.
pub trait SyscallOps {
    fn initialize();
    fn register_frame() -> &'static mut SyscallRegisters;
}

/// High-resolution hardware timekeeping and busy-wait delay operations.
pub trait TimerOps {
    fn read_ticks() -> u64;
    fn ticks_per_second() -> u64;
    fn sleep_ns(ns: u64);
}

/// Symmetric Multiprocessing (SMP) core bootstrap and Inter-Processor Interrupts (IPI).
pub trait SmpOps {
    fn boot_secondary_cores(entry: u64) -> u32;
    fn send_ipi(target_cpu: u32, vector: u8);
}
