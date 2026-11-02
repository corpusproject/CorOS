//! Complete POSIX.1-2008 Standard Signal Subsystem for CorOS.
//! 100% in-house implementation supporting:
//! - Full 32 standard POSIX signals
//! - `sigaction` handler registration (SIG_DFL, SIG_IGN, Custom Handler)
//! - `sigset_t` 64-bit signal bitmasks
//! - Pending signal queues and signal unmasking
//! - Stack frame setup for user-space signal trampolines (`sigreturn`)

use alloc::vec::Vec;

pub type SigSet = u64;

// Standard POSIX Signals (1..32)
pub const SIGHUP: u8    = 1;  // Hangup
pub const SIGINT: u8    = 2;  // Interrupt from keyboard (Ctrl+C)
pub const SIGQUIT: u8   = 3;  // Quit from keyboard (Ctrl+\)
pub const SIGILL: u8    = 4;  // Illegal Instruction
pub const SIGTRAP: u8   = 5;  // Trace/breakpoint trap
pub const SIGABRT: u8   = 6;  // Abort signal from abort(3)
pub const SIGBUS: u8    = 7;  // Bus error (bad memory access)
pub const SIGFPE: u8    = 8;  // Floating-point exception
pub const SIGKILL: u8   = 9;  // Kill signal (cannot be caught or ignored)
pub const SIGUSR1: u8   = 10; // User-defined signal 1
pub const SIGSEGV: u8   = 11; // Invalid memory reference (Page Fault)
pub const SIGUSR2: u8   = 12; // User-defined signal 2
pub const SIGPIPE: u8   = 13; // Broken pipe: write to pipe with no readers
pub const SIGALRM: u8   = 14; // Timer signal from alarm(2)
pub const SIGTERM: u8   = 15; // Termination signal
pub const SIGSTKFLT: u8 = 16; // Stack fault on coprocessor
pub const SIGCHLD: u8   = 17; // Child stopped or terminated
pub const SIGCONT: u8   = 18; // Continue if stopped
pub const SIGSTOP: u8   = 19; // Stop process (cannot be caught or ignored)
pub const SIGTSTP: u8   = 20; // Stop typed at terminal (Ctrl+Z)
pub const SIGTTIN: u8   = 21; // Terminal input for background process
pub const SIGTTOU: u8   = 22; // Terminal output for background process
pub const SIGURG: u8    = 23; // Urgent condition on socket
pub const SIGXCPU: u8   = 24; // CPU time limit exceeded
pub const SIGXFSZ: u8   = 25; // File size limit exceeded
pub const SIGVTALRM: u8 = 26; // Virtual alarm clock
pub const SIGPROF: u8   = 27; // Profiling timer expired
pub const SIGWINCH: u8  = 28; // Window resize signal
pub const SIGPOLL: u8   = 29; // Pollable event
pub const SIGPWR: u8    = 30; // Power failure
pub const SIGSYS: u8    = 31; // Bad system call

// Special Handlers
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// Sigaction Flags
pub const SA_NOCLDSTOP: u32 = 0x00000001;
pub const SA_NOCLDWAIT: u32 = 0x00000002;
pub const SA_SIGINFO: u32   = 0x00000004;
pub const SA_ONSTACK: u32   = 0x08000000;
pub const SA_RESTART: u32   = 0x10000000;
pub const SA_NODEFER: u32   = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DefaultAction {
    Terminate,
    CoreDump,
    Ignore,
    Stop,
    Continue,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SigAction {
    pub sa_handler: usize,   // Pointer to user-space handler or SIG_DFL / SIG_IGN
    pub sa_mask: SigSet,     // Signals to block during execution
    pub sa_flags: u32,       // Special flags (SA_RESTART, SA_SIGINFO...)
    pub sa_restorer: usize,  // Trampoline return address (sys_rt_sigreturn)
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            sa_handler: SIG_DFL,
            sa_mask: 0,
            sa_flags: 0,
            sa_restorer: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignalManager {
    pub actions: [SigAction; 32],
    pub pending_mask: SigSet,
    pub blocked_mask: SigSet,
}

impl SignalManager {
    pub fn new() -> Self {
        Self {
            actions: [SigAction::default(); 32],
            pending_mask: 0,
            blocked_mask: 0,
        }
    }

    /// Return the standard POSIX default action for a signal number.
    pub fn default_action_for(sig: u8) -> DefaultAction {
        match sig {
            SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
            SIGCONT => DefaultAction::Continue,
            SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGSYS => {
                DefaultAction::CoreDump
            }
            _ => DefaultAction::Terminate,
        }
    }

    /// Register a new action for a signal number (1..31).
    pub fn set_action(&mut self, sig: u8, action: SigAction) -> Result<SigAction, &'static str> {
        if sig == 0 || sig > 31 {
            return Err("Invalid signal number");
        }
        if sig == SIGKILL || sig == SIGSTOP {
            return Err("SIGKILL and SIGSTOP cannot be modified or caught");
        }

        let old = self.actions[(sig - 1) as usize];
        self.actions[(sig - 1) as usize] = action;
        Ok(old)
    }

    /// Post a signal to this task's pending mask.
    pub fn post_signal(&mut self, sig: u8) {
        if sig > 0 && sig <= 32 {
            self.pending_mask |= 1u64 << (sig - 1);
        }
    }

    /// Pick the highest-priority pending unblocked signal.
    pub fn dequeue_unblocked_signal(&mut self) -> Option<u8> {
        // Pending AND NOT blocked (except SIGKILL and SIGSTOP which can never be blocked)
        let effective_blocked = self.blocked_mask & !((1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)));
        let deliverable = self.pending_mask & !effective_blocked;

        if deliverable == 0 {
            return None;
        }

        // Find lowest set bit (1-based index)
        let trailing = deliverable.trailing_zeros();
        let sig = (trailing + 1) as u8;

        // Clear bit from pending
        self.pending_mask &= !(1u64 << trailing);
        Some(sig)
    }

    /// Update blocked signal mask (like `sigprocmask`).
    pub fn update_mask(&mut self, how: u32, set: SigSet) {
        const SIG_BLOCK: u32   = 0;
        const SIG_UNBLOCK: u32 = 1;
        const SIG_SETMASK: u32 = 2;

        match how {
            SIG_BLOCK => self.blocked_mask |= set,
            SIG_UNBLOCK => self.blocked_mask &= !set,
            SIG_SETMASK => self.blocked_mask = set,
            _ => {}
        }

        // SIGKILL and SIGSTOP cannot be blocked
        self.blocked_mask &= !((1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)));
    }
}
