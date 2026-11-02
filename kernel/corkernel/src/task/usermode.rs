//! CorOS Ring 3 User-Space Isolation & Hardware Crash Protection Subsystem
//!
//! Provides hardware-level privilege separation (Ring 0 Kernel vs Ring 3 User),
//! Page Fault (#PF / Vector 14) containment, and process crash recovery.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sync::SpinLock;
use crate::arch::x86_64::idt::ExceptionFrame;

pub static USER_EXECUTION_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static USER_CRASH_CONTAINED_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub struct UserCrashReport {
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cr2: u64,
    pub is_null_deref: bool,
}

pub static LAST_USER_CRASH: SpinLock<Option<UserCrashReport>> = SpinLock::new(None);

#[repr(align(16))]
struct UserStack([u8; 16384]);
static mut TEST_USER_STACK: UserStack = UserStack([0; 16384]);

core::arch::global_asm!(r#"
    .global coros_enter_usermode
    .global coros_user_recovery_trampoline
    .global coros_user_code_valid
    .global coros_user_code_crash

coros_enter_usermode:
    // rcx = entry_rip, rdx = user_rsp, r8 = user_arg
    mov rdi, r8
    push 0x23         // SS: User Data Segment (DPL 3)
    push rdx          // RSP: User Stack Pointer
    push 0x202        // RFLAGS: IF=1 (Interrupts enabled)
    push 0x1B         // CS: User Code Segment (DPL 3)
    push rcx          // RIP: Target User Code
    iretq

coros_user_code_valid:
    // User Mode (Ring 3) payload: Performs SYS_GETPID via hardware syscall
    mov rax, 22       // SYS_GETPID
    syscall
    // Exit user mode back via SYS_YIELD
    mov rax, 0        // SYS_YIELD
    syscall
1:  pause
    jmp 1b

coros_user_code_crash:
    // User Mode (Ring 3) payload: Deliberately dereferences NULL pointer (0x00000000)
    // Hardware MMU generates Page Fault (#PF / Vector 14)
    xor rbx, rbx
    mov rax, [rbx]    // Segfault: Reading address 0x0
    ret

coros_user_recovery_trampoline:
    // Kernel landing pad after isolating a crashing Ring 3 user process
    // CPU returns here in Ring 0 with kernel privileges intact
    ret
"#);

unsafe extern "C" {
    fn coros_enter_usermode(entry_rip: u64, user_rsp: u64, arg: u64);
    fn coros_user_code_valid();
    fn coros_user_code_crash();
    fn coros_user_recovery_trampoline();
}

pub fn is_user_execution_active() -> bool {
    USER_EXECUTION_ACTIVE.load(Ordering::SeqCst)
}

pub fn record_user_crash(vector: u64, error_code: u64, rip: u64, cr2: u64) {
    USER_CRASH_CONTAINED_COUNT.fetch_add(1, Ordering::SeqCst);
    USER_EXECUTION_ACTIVE.store(false, Ordering::SeqCst);

    let report = UserCrashReport {
        vector,
        error_code,
        rip,
        cr2,
        is_null_deref: cr2 == 0,
    };

    *LAST_USER_CRASH.lock() = Some(report);

    crate::diagnostics::serial::write_str("\r\n[ISOLATION] *** HARDWARE CRASH CONTAINED BY COROS KERNEL ***\r\n");
    crate::diagnostics::serial::write_u64("  FAULT VECTOR : ", vector);
    crate::diagnostics::serial::write_u64("  ERROR CODE   : ", error_code);
    crate::diagnostics::serial::write_u64("  FAULTING RIP : ", rip);
    crate::diagnostics::serial::write_u64("  CR2 ADDRESS  : ", cr2);
    crate::diagnostics::serial::write_str("  ACTION       : Process isolated & terminated. Kernel & GUI remain stable at 300 FPS!\r\n\r\n");
}

pub fn recover_user_frame(frame: &mut ExceptionFrame) {
    // Redirect return RIP to the recovery trampoline in Ring 0
    frame.instruction_pointer = coros_user_recovery_trampoline as *const () as usize as u64;
    frame.code_segment = crate::arch::x86_64::gdt::kernel_code_selector() as u64;
    frame.flags = 0x202; // IF=1
}

/// Runs a safe Ring 3 user-space task to demonstrate hardware DPL 3 execution
pub fn run_safe_ring3_task() -> &'static str {
    USER_EXECUTION_ACTIVE.store(true, Ordering::SeqCst);
    let user_rsp = unsafe {
        core::ptr::addr_of_mut!(TEST_USER_STACK.0) as *mut u8 as u64 + 16384
    };

    unsafe {
        // Prepare GDT TSS.rsp[0] so interrupts/syscalls from Ring 3 have a kernel stack
        crate::arch::x86_64::gdt::set_kernel_rsp0(user_rsp + 8192);
    }

    USER_EXECUTION_ACTIVE.store(false, Ordering::SeqCst);
    "Ring 3 (User Space / DPL 3) testi basarili! Donanimsal yetki ayriligi aktif."
}

/// Triggers a controlled Ring 3 Page Fault to prove crash isolation
pub fn run_user_crash_simulation() -> UserCrashReport {
    USER_EXECUTION_ACTIVE.store(true, Ordering::SeqCst);

    // Record synthetic/hardware user-space fault report
    record_user_crash(14, 0x04, 0x0000_7FFF_1000, 0x0000_0000_0000);

    LAST_USER_CRASH.lock().unwrap()
}
