//! AArch64 Hardware System Call (SVC #0) & ABI Register Frame.

use crate::arch::traits::{SyscallOps, SyscallRegisters};

static mut AARCH64_SYSCALL_FRAME: SyscallRegisters = SyscallRegisters {
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

pub struct AArch64Syscall;

impl SyscallOps for AArch64Syscall {
    fn initialize() {
        initialize();
    }

    fn register_frame() -> &'static mut SyscallRegisters {
        register_frame()
    }
}

pub fn initialize() {
    // AArch64 system call traps are routed to VBAR_EL1 Synchronous vector (offset 0x400 for EL0)
}

pub fn register_frame() -> &'static mut SyscallRegisters {
    unsafe { &mut *core::ptr::addr_of_mut!(AARCH64_SYSCALL_FRAME) }
}

/// Dispatches an incoming SVC exception into the CorOS Linux-equivalent syscall router.
/// In AArch64:
/// - `x8` contains the system call number
/// - `x0..x5` contain arguments 1 through 6
/// - `x0` receives the return code
pub unsafe fn handle_svc_syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
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
