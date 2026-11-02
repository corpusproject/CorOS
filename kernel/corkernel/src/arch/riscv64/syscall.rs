//! RISC-V Hardware System Call (ECALL) & ABI Register Frame.

use crate::arch::traits::{SyscallOps, SyscallRegisters};

static mut RISCV64_SYSCALL_FRAME: SyscallRegisters = SyscallRegisters {
    rax: 0,
    rdi: 0,
    rsi: 0,
    rdx: 0,
    r10: 0,
    r8: 0,
    r9: 0,
    r11: 0,
    rcx: 0,
    rsp: 0,
};

pub struct Riscv64Syscall;

impl SyscallOps for Riscv64Syscall {
    fn initialize() {
        initialize();
    }

    fn register_frame() -> &'static mut SyscallRegisters {
        register_frame()
    }
}

pub fn initialize() {
    // RISC-V ecall exceptions are routed via stvec and cause 8 (User ECALL)
}

pub fn register_frame() -> &'static mut SyscallRegisters {
    unsafe { &mut *core::ptr::addr_of_mut!(RISCV64_SYSCALL_FRAME) }
}

/// Dispatches an incoming ECALL exception into the CorOS Linux-equivalent syscall router.
/// In RISC-V Linux ABI:
/// - `a7` contains the system call number
/// - `a0..a5` contain arguments 1 through 6
/// - `a0` receives the return code
pub unsafe fn handle_ecall_syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let frame = register_frame();
    frame.rax = nr;
    frame.rdi = a0;
    frame.rsi = a1;
    frame.rdx = a2;
    frame.r10 = a3;
    frame.r8 = a4;
    frame.r9 = a5;

    // Dispatches through standard CorOS syscall matrix
    crate::arch::x86_64::syscall::coros_syscall_handler(nr, a0, a1, a2) as i64
}
