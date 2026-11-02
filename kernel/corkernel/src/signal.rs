//! CorOS POSIX Signals Subsystem
//!
//! Provides asynchronous inter-process signals (SIGINT, SIGKILL, SIGTERM, SIGSEGV, etc.),
//! signal masking, and POSIX signal handlers.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::SpinLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
}

impl Signal {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Signal::SIGHUP),
            2 => Some(Signal::SIGINT),
            3 => Some(Signal::SIGQUIT),
            4 => Some(Signal::SIGILL),
            5 => Some(Signal::SIGTRAP),
            6 => Some(Signal::SIGABRT),
            7 => Some(Signal::SIGBUS),
            8 => Some(Signal::SIGFPE),
            9 => Some(Signal::SIGKILL),
            10 => Some(Signal::SIGUSR1),
            11 => Some(Signal::SIGSEGV),
            12 => Some(Signal::SIGUSR2),
            13 => Some(Signal::SIGPIPE),
            14 => Some(Signal::SIGALRM),
            15 => Some(Signal::SIGTERM),
            17 => Some(Signal::SIGCHLD),
            18 => Some(Signal::SIGCONT),
            19 => Some(Signal::SIGSTOP),
            20 => Some(Signal::SIGTSTP),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Signal::SIGHUP => "SIGHUP",
            Signal::SIGINT => "SIGINT",
            Signal::SIGQUIT => "SIGQUIT",
            Signal::SIGILL => "SIGILL",
            Signal::SIGTRAP => "SIGTRAP",
            Signal::SIGABRT => "SIGABRT",
            Signal::SIGBUS => "SIGBUS",
            Signal::SIGFPE => "SIGFPE",
            Signal::SIGKILL => "SIGKILL",
            Signal::SIGUSR1 => "SIGUSR1",
            Signal::SIGSEGV => "SIGSEGV",
            Signal::SIGUSR2 => "SIGUSR2",
            Signal::SIGPIPE => "SIGPIPE",
            Signal::SIGALRM => "SIGALRM",
            Signal::SIGTERM => "SIGTERM",
            Signal::SIGCHLD => "SIGCHLD",
            Signal::SIGCONT => "SIGCONT",
            Signal::SIGSTOP => "SIGSTOP",
            Signal::SIGTSTP => "SIGTSTP",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalAction {
    Default,
    Ignore,
    Handler(u64), // Function pointer address
}

#[derive(Clone)]
pub struct ProcessSignalState {
    pub pending_mask: u32,
    pub blocked_mask: u32,
    pub handlers: BTreeMap<u8, SignalAction>,
}

impl ProcessSignalState {
    pub fn new() -> Self {
        Self {
            pending_mask: 0,
            blocked_mask: 0,
            handlers: BTreeMap::new(),
        }
    }
}

pub struct SignalManager {
    states: BTreeMap<usize, ProcessSignalState>,
}

impl SignalManager {
    pub const fn new() -> Self {
        Self {
            states: BTreeMap::new(),
        }
    }

    /// Send signal to target process PID
    pub fn send_signal(&mut self, target_pid: usize, sig: Signal) -> Result<(), &'static str> {
        let sig_num = sig as u8;
        let sig_bit = 1u32 << sig_num;

        let state = self.states.entry(target_pid).or_insert_with(ProcessSignalState::new);

        // SIGKILL and SIGSTOP cannot be ignored or blocked (POSIX standard)
        if sig == Signal::SIGKILL || sig == Signal::SIGSTOP {
            state.pending_mask |= sig_bit;
            return Ok(());
        }

        // If not blocked, set pending
        if (state.blocked_mask & sig_bit) == 0 {
            state.pending_mask |= sig_bit;
        }

        Ok(())
    }

    /// Check if target process has pending unblocked signal
    pub fn pop_pending_signal(&mut self, pid: usize) -> Option<Signal> {
        if let Some(state) = self.states.get_mut(&pid) {
            let deliverable = state.pending_mask & !state.blocked_mask;
            if deliverable != 0 {
                // Find lowest pending signal bit
                for i in 1..=31 {
                    if (deliverable & (1 << i)) != 0 {
                        state.pending_mask &= !(1 << i);
                        return Signal::from_u8(i);
                    }
                }
            }
        }
        None
    }

    /// Set signal action for PID
    pub fn set_sigaction(&mut self, pid: usize, sig: Signal, action: SignalAction) -> Result<(), &'static str> {
        if sig == Signal::SIGKILL || sig == Signal::SIGSTOP {
            return Err("EINVAL: Cannot catch or ignore SIGKILL / SIGSTOP");
        }

        let state = self.states.entry(pid).or_insert_with(ProcessSignalState::new);
        state.handlers.insert(sig as u8, action);
        Ok(())
    }

    /// List active process signal states for /proc
    pub fn list_signals_proc(&self) -> String {
        let mut out = String::new();
        out.push_str("PID   PENDING     BLOCKED     HANDLERS\n");
        out.push_str("---------------------------------------\n");
        for (pid, st) in &self.states {
            out.push_str(&format!(
                "{:<5} 0x{:08X}  0x{:08X}  {}\n",
                pid,
                st.pending_mask,
                st.blocked_mask,
                st.handlers.len()
            ));
        }
        out
    }
}

pub static SIGNAL_MANAGER: SpinLock<SignalManager> = SpinLock::new(SignalManager::new());
