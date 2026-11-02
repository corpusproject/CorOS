//! Low-level x86_64 Task Context and Hardware Stack Switching
//!
//! Provides bare-metal register state serialization taking ~15 CPU cycles,
//! completely avoiding the thousands of cycles Windows spends on context transitions.

use core::arch::global_asm;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    pub rsp: u64,
}

// Low-overhead assembly switch routine and entry trampoline
global_asm!(
    r#"
    .text
    .globl coros_switch_context
coros_switch_context:
    // rcx = prev_rsp (*mut u64)
    // rdx = next_rsp (u64)
    pushfq
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %rbp
    pushq %rbx

    // Save old stack pointer
    movq %rsp, (%rcx)

    // Load new stack pointer
    movq %rdx, %rsp

    // Restore state
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    popfq

    retq

    .globl task_trampoline_asm
task_trampoline_asm:
    // r12 holds entry_point, r13 holds arg
    movq %r12, %rcx
    movq %r13, %rdx
    subq $32, %rsp
    callq task_entry_trampoline
    // If trampoline ever returns, halt CPU
1:
    cli
    hlt
    jmp 1b
    "#,
    options(att_syntax)
);

unsafe extern "efiapi" {
    /// Switches execution context from `prev_rsp` to `next_rsp`.
    ///
    /// # Safety
    /// `prev_rsp` must be a valid writable pointer to u64.
    /// `next_rsp` must be a valid stack pointer initialized with TaskContext frame.
    pub fn coros_switch_context(prev_rsp: *mut u64, next_rsp: u64);

    fn task_trampoline_asm();
}

#[no_mangle]
pub unsafe extern "efiapi" fn task_entry_trampoline(entry_point: usize, arg: usize) -> ! {
    let entry_fn: fn(usize) = core::mem::transmute(entry_point);
    entry_fn(arg);

    // If the task entry function returns, gracefully terminate it
    crate::task::scheduler::SCHEDULER.exit_current();
}

impl TaskContext {
    pub const fn empty() -> Self {
        Self { rsp: 0 }
    }

    /// Prepares a new stack for context switching.
    ///
    /// Pushes initial values for callee-saved registers and the entry point
    /// so that `coros_switch_context` can directly `ret` into it.
    pub unsafe fn initialize_stack(stack_top: *mut u8, entry_fn: fn(usize), arg: usize) -> Self {
        let mut sp = stack_top as *mut u64;

        // Ensure 16-byte alignment of the stack
        let align_offset = ((sp as usize) % 16) / 8;
        sp = sp.sub(align_offset);

        // Simulated call stack for task_trampoline_asm:
        // 1. Return address when trampoline returns (never reached, halt)
        sp = sp.sub(1);
        *sp = crate::arch::x86_64::halt_forever as *const () as u64;

        // 2. Address to return to on initial `ret`: task_trampoline_asm
        sp = sp.sub(1);
        *sp = task_trampoline_asm as *const () as u64;

        // 3. Saved registers matching coros_switch_context:
        // pushfq (RFLAGS, with interrupts initially enabled 0x202)
        sp = sp.sub(1);
        *sp = 0x202; // IF = 1

        // Registers popped in order:
        // pop rbx, pop rbp, pop r12, pop r13, pop r14, pop r15, popfq
        // So pushed in order:
        // push r15, push r14, push r13, push r12, push rbp, push rbx
        sp = sp.sub(1); *sp = 0; // r15
        sp = sp.sub(1); *sp = 0; // r14
        sp = sp.sub(1); *sp = arg as u64; // r13 = arg
        sp = sp.sub(1); *sp = entry_fn as usize as u64; // r12 = entry_point
        sp = sp.sub(1); *sp = 0; // rbp
        sp = sp.sub(1); *sp = 0; // rbx

        Self { rsp: sp as u64 }
    }
}
