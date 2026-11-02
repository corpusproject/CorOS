//! CorOS Syscall Domain Module: `posix_signals`
//! POSIX & Real-Time Signal Delivery (`rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigsuspend`, `kill`, `tgkill`, `tkill`, `sigaltstack`, `signalfd4`).

use alloc::collections::VecDeque;

pub const EINVAL: i64 = -22;
pub const ESRCH: i64 = -3;
pub const EAGAIN: i64 = -11;
pub const EPERM: i64 = -1;

pub const SIG_BLOCK: u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const MINSIGSTKSZ: usize = 2048;

pub const SA_NOCLDSTOP: u64 = 0x00000001;
pub const SA_NOCLDWAIT: u64 = 0x00000002;
pub const SA_SIGINFO: u64   = 0x00000004;
pub const SA_RESTORER: u64  = 0x04000000;
pub const SA_ONSTACK: u64   = 0x08000000;
pub const SA_RESTART: u64   = 0x10000000;
pub const SA_NODEFER: u64   = 0x40000000;
pub const SA_RESETHAND: u64 = 0x80000000;

/// Standard POSIX and real-time signal numbers (`1..=64`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalNumber {
    Sighup = 1,
    Sigint = 2,
    Sigquit = 3,
    Sigill = 4,
    Sigtrap = 5,
    Sigabrt = 6,
    Sigbus = 7,
    Sigfpe = 8,
    Sigkill = 9,
    Sigusr1 = 10,
    Sigsegv = 11,
    Sigusr2 = 12,
    Sigpipe = 13,
    Sigalrm = 14,
    Sigterm = 15,
    Sigchld = 17,
    Sigcont = 18,
    Sigstop = 19,
    Sigtstp = 20,
    Sigrtmin = 34,
    Sigrtmax = 64,
}

impl SignalNumber {
    #[inline]
    pub const fn bit(sig: u8) -> u64 {
        if sig >= 1 && sig <= 64 {
            1u64 << (sig - 1)
        } else {
            0
        }
    }

    #[inline]
    pub const fn is_unblockable(sig: u8) -> bool {
        sig == Self::Sigkill as u8 || sig == Self::Sigstop as u8
    }
}

/// 64-bit signal bitmask (`sigset_t`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigSet(pub u64);

impl SigSet {
    pub const EMPTY: Self = Self(0);
    pub const UNBLOCKABLE_MASK: u64 =
        SignalNumber::bit(SignalNumber::Sigkill as u8) | SignalNumber::bit(SignalNumber::Sigstop as u8);

    #[inline]
    pub const fn add(&mut self, sig: u8) {
        self.0 |= SignalNumber::bit(sig);
    }

    #[inline]
    pub const fn remove(&mut self, sig: u8) {
        self.0 &= !SignalNumber::bit(sig);
    }

    #[inline]
    pub const fn contains(&self, sig: u8) -> bool {
        (self.0 & SignalNumber::bit(sig)) != 0
    }

    #[inline]
    pub const fn sanitized(self) -> Self {
        Self(self.0 & !Self::UNBLOCKABLE_MASK)
    }
}

/// Signal disposition configured via `sys_rt_sigaction`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigDisposition {
    Default,
    Ignore,
    Handler(u64), // Function pointer in user space
}

/// Kernel `struct sigaction` representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigAction {
    pub disposition: SigDisposition,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: SigSet,
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            disposition: SigDisposition::Default,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: SigSet::EMPTY,
        }
    }
}

/// Detailed signal metadata (`siginfo_t`) queued for real-time and standard signals.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    pub si_signo: u8,
    pub si_errno: i32,
    pub si_code: i32,
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub sigval_u64: u64,
}

/// Alternate signal stack (`stack_t`) configured via `sys_sigaltstack`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalStack {
    pub ss_sp: u64,
    pub ss_flags: u32,
    pub ss_size: usize,
}

impl Default for SignalStack {
    fn default() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: SS_DISABLE,
            ss_size: 0,
        }
    }
}

pub type StackT = SignalStack;

/// Linux x86_64 machine context structure (`mcontext_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MContextX86_64 {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub __pad0: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
}

impl Default for MContextX86_64 {
    fn default() -> Self {
        Self {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp: 0,
            rip: 0,
            eflags: 0,
            cs: 0,
            gs: 0,
            fs: 0,
            __pad0: 0,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
        }
    }
}

/// Linux x86_64 user context structure (`ucontext_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UContextX86_64 {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: SignalStack,
    pub uc_mcontext: MContextX86_64,
    pub uc_sigmask: SigSet,
    pub __fpregs_mem: [u8; 512],
}

impl Default for UContextX86_64 {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SignalStack::default(),
            uc_mcontext: MContextX86_64::default(),
            uc_sigmask: SigSet::default(),
            __fpregs_mem: [0u8; 512],
        }
    }
}

/// Linux x86_64 real-time signal stack frame (`struct rt_sigframe`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigFrameX86_64 {
    pub pretcode: u64,
    pub uc: UContextX86_64,
    pub info: SigInfo,
}

/// Standard POSIX signal default actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalDefaultAction {
    Terminate,
    CoreDump,
    Ignore,
    Stop,
    Continue,
}

impl SignalDefaultAction {
    pub fn for_signal(sig: u8) -> Self {
        match sig {
            3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31 => Self::CoreDump,
            17 | 18 | 23 | 28 => Self::Ignore,
            19 | 20 | 21 | 22 => Self::Stop,
            _ => Self::Terminate,
        }
    }

    /// Returns the termination status code if terminated, or 0 if ignored/stopped/continued.
    pub fn execute(&self, sig: u8) -> i32 {
        match self {
            Self::Terminate => 128 + sig as i32,
            Self::CoreDump => 128 + sig as i32,
            Self::Ignore => 0,
            Self::Stop => 0,
            Self::Continue => 0,
        }
    }
}

/// Sets up an x86_64 real-time signal frame for user-space signal delivery.
///
/// Returns `(new_sp, handler_addr, rdi_arg, rsi_arg, rdx_arg)` conforming to System V ABI:
/// - RDI: signal number
/// - RSI: pointer to siginfo_t
/// - RDX: pointer to ucontext_t
/// Constructs a genuine `SigFrameX86_64` combining register context, signal info, and blocked mask.
pub fn build_rt_frame(
    info: &SigInfo,
    regs: &MContextX86_64,
    mask: &SigSet,
    altstack: Option<&SignalStack>,
    restorer: u64,
) -> SigFrameX86_64 {
    let mut uc = UContextX86_64::default();
    uc.uc_mcontext = *regs;
    uc.uc_sigmask = *mask;
    if let Some(ss) = altstack {
        uc.uc_stack = *ss;
    }
    SigFrameX86_64 {
        pretcode: restorer,
        uc,
        info: *info,
    }
}

/// Sets up an x86_64 real-time signal frame for user-space signal delivery, serializing
/// a genuine `SigFrameX86_64` onto the target stack at `new_sp`.
///
/// Returns `(new_sp, handler_addr, rdi_arg, rsi_arg, rdx_arg)` conforming to System V ABI:
/// - RDI: signal number
/// - RSI: pointer to siginfo_t
/// - RDX: pointer to ucontext_t
pub fn setup_rt_frame(
    sp: u64,
    altstack: Option<&SignalStack>,
    sa: &SigAction,
    sig: u32,
    info: &SigInfo,
    regs: &MContextX86_64,
    mask: &SigSet,
) -> Result<(u64, u64, u64, u64, u64), i64> {
    let handler = match sa.disposition {
        SigDisposition::Handler(addr) if addr != 0 => addr,
        _ => return Err(EINVAL),
    };

    let mut target_sp = sp;
    if (sa.sa_flags & SA_ONSTACK) != 0 {
        if let Some(ss) = altstack {
            if ss.ss_flags != SS_DISABLE && ss.ss_sp != 0 && ss.ss_size > 0 {
                if !(sp >= ss.ss_sp && sp < ss.ss_sp + ss.ss_size as u64) {
                    target_sp = ss.ss_sp + ss.ss_size as u64;
                }
            }
        }
    }

    let frame_size = core::mem::size_of::<SigFrameX86_64>() as u64;
    let aligned_sp = (target_sp.saturating_sub(frame_size)) & !0xF;
    let new_sp = aligned_sp.saturating_sub(8);

    let frame_base = new_sp;
    let pretcode_offset = 0u64;
    let uc_offset = pretcode_offset + 8;
    let info_offset = uc_offset + core::mem::size_of::<UContextX86_64>() as u64;

    let rdi = sig as u64;
    let rsi = frame_base + info_offset;
    let rdx = frame_base + uc_offset;

    // Construct the genuine SigFrameX86_64
    let frame = build_rt_frame(info, regs, mask, altstack, sa.sa_restorer);

    // Write the frame to memory at new_sp
    if new_sp != 0 {
        unsafe {
            let dest_ptr = new_sp as *mut SigFrameX86_64;
            core::ptr::write_unaligned(dest_ptr, frame);
        }
    }

    Ok((new_sp, handler, rdi, rsi, rdx))
}

/// Prepares real-time frame and returns both stack pointer offsets and the serialized `SigFrameX86_64`.
pub fn setup_rt_frame_full(
    sp: u64,
    altstack: Option<&SignalStack>,
    sa: &SigAction,
    sig: u32,
    info: &SigInfo,
    regs: &MContextX86_64,
    mask: &SigSet,
) -> Result<(u64, u64, u64, u64, u64, SigFrameX86_64), i64> {
    let (new_sp, handler, rdi, rsi, rdx) = setup_rt_frame(sp, altstack, sa, sig, info, regs, mask)?;
    let frame = build_rt_frame(info, regs, mask, altstack, sa.sa_restorer);
    Ok((new_sp, handler, rdi, rsi, rdx, frame))
}

/// Restores register context and blocked signal mask from an x86_64 `SigFrameX86_64`.
pub fn restore_rt_frame(frame: &SigFrameX86_64) -> (MContextX86_64, SigSet) {
    (frame.uc.uc_mcontext, frame.uc.uc_sigmask)
}

/// Per-task signal state machine managing masks, handlers, alternate stack, and queued signals.
pub struct PendingSignals {
    pub tgid: u32,
    pub tid: u32,
    pub blocked: SigSet,
    pub pending_mask: SigSet,
    pub actions: [SigAction; 64],
    pub altstack: SignalStack,
    pub rt_queue: VecDeque<SigInfo>,
    pub signalfd_mask: Option<SigSet>,
}

impl PendingSignals {
    pub fn new(tgid: u32, tid: u32) -> Self {
        Self {
            tgid,
            tid,
            blocked: SigSet::EMPTY,
            pending_mask: SigSet::EMPTY,
            actions: [SigAction::default(); 64],
            altstack: SignalStack::default(),
            rt_queue: VecDeque::new(),
            signalfd_mask: None,
        }
    }

    /// `sys_rt_sigaction`: Queries and/or installs a signal handler for `signum`.
    pub fn sys_rt_sigaction(
        &mut self,
        signum: u8,
        new_act: Option<SigAction>,
        old_act: Option<&mut SigAction>,
    ) -> i64 {
        if signum == 0 || signum > 64 || SignalNumber::is_unblockable(signum) {
            return EINVAL;
        }
        let idx = (signum - 1) as usize;
        if let Some(old) = old_act {
            *old = self.actions[idx];
        }
        if let Some(mut act) = new_act {
            act.sa_mask = act.sa_mask.sanitized();
            self.actions[idx] = act;
            if act.disposition == SigDisposition::Ignore {
                self.pending_mask.remove(signum);
                self.rt_queue.retain(|info| info.si_signo != signum);
            }
        }
        0
    }

    /// `sys_rt_sigprocmask`: Modifies the thread's blocked signal mask.
    pub fn sys_rt_sigprocmask(
        &mut self,
        how: u32,
        set: Option<SigSet>,
        oldset: Option<&mut SigSet>,
    ) -> i64 {
        if let Some(old) = oldset {
            *old = self.blocked;
        }
        if let Some(s) = set {
            let clean = s.sanitized();
            match how {
                SIG_BLOCK => self.blocked.0 |= clean.0,
                SIG_UNBLOCK => self.blocked.0 &= !clean.0,
                SIG_SETMASK => self.blocked = clean,
                _ => return EINVAL,
            }
        }
        0
    }

    /// `sys_rt_sigpending`: Returns the set of signals currently pending and blocked.
    pub fn sys_rt_sigpending(&self) -> SigSet {
        SigSet(self.pending_mask.0 & self.blocked.0)
    }

    /// `sys_kill` / `sys_tgkill` / `sys_tkill`: Enqueues a signal onto the target task.
    pub fn sys_tgkill(&mut self, tgid: u32, tid: u32, signum: u8, sender_pid: u32) -> i64 {
        if tgid != self.tgid || tid != self.tid {
            return ESRCH;
        }
        if signum == 0 {
            return 0; // Existence check only
        }
        if signum > 64 {
            return EINVAL;
        }
        let idx = (signum - 1) as usize;
        if self.actions[idx].disposition == SigDisposition::Ignore && !SignalNumber::is_unblockable(signum) {
            return 0;
        }
        self.pending_mask.add(signum);
        self.rt_queue.push_back(SigInfo {
            si_signo: signum,
            si_errno: 0,
            si_code: 0,
            sender_pid,
            sender_uid: 0,
            sigval_u64: 0,
        });
        0
    }

    /// `sys_sigaltstack`: Configures or queries the alternate signal stack.
    pub fn sys_sigaltstack(
        &mut self,
        new_ss: Option<SignalStack>,
        old_ss: Option<&mut SignalStack>,
    ) -> i64 {
        if let Some(old) = old_ss {
            *old = self.altstack;
        }
        if let Some(ss) = new_ss {
            if ss.ss_flags == SS_DISABLE {
                self.altstack = SignalStack::default();
            } else if ss.ss_size < MINSIGSTKSZ || ss.ss_sp == 0 {
                return EINVAL;
            } else {
                self.altstack = ss;
            }
        }
        0
    }

    /// `sys_signalfd4`: Configures a signalfd mask and reads the next matching pending `SigInfo`.
    pub fn sys_signalfd4_read(&mut self, mask: SigSet) -> Result<SigInfo, i64> {
        self.signalfd_mask = Some(mask);
        let deliverable = self.pending_mask.0 & mask.0;
        if deliverable == 0 {
            return Err(EAGAIN);
        }
        let signum = (deliverable.trailing_zeros() + 1) as u8;
        let pos = self.rt_queue.iter().position(|i| i.si_signo == signum);
        let info = match pos {
            Some(idx) => self.rt_queue.remove(idx).unwrap(),
            None => SigInfo {
                si_signo: signum,
                si_errno: 0,
                si_code: 0,
                sender_pid: 0,
                sender_uid: 0,
                sigval_u64: 0,
            },
        };
        if !self.rt_queue.iter().any(|i| i.si_signo == signum) {
            self.pending_mask.remove(signum);
        }
        Ok(info)
    }

    /// Dequeues the next unblocked signal for user-mode signal frame delivery.
    pub fn dequeue_unblocked(&mut self) -> Option<(SigInfo, SigAction)> {
        let ready = self.pending_mask.0 & !self.blocked.0;
        if ready == 0 {
            return None;
        }
        let signum = (ready.trailing_zeros() + 1) as u8;
        let act = self.actions[(signum - 1) as usize];
        let pos = self.rt_queue.iter().position(|i| i.si_signo == signum);
        let info = pos.and_then(|idx| self.rt_queue.remove(idx)).unwrap_or(SigInfo {
            si_signo: signum,
            si_errno: 0,
            si_code: 0,
            sender_pid: 0,
            sender_uid: 0,
            sigval_u64: 0,
        });
        if !self.rt_queue.iter().any(|i| i.si_signo == signum) {
            self.pending_mask.remove(signum);
        }
        self.blocked.0 |= act.sa_mask.0 | SignalNumber::bit(signum);
        Some((info, act))
    }
}

/// Runs comprehensive self-tests on `posix_signals` structs and signal delivery semantics.
pub fn verify_domain_posix_signals() -> u32 {
    let mut passed = 0u32;
    let mut sigs = PendingSignals::new(100, 100);

    // 1. Cannot install handler for SIGKILL (9)
    let act = SigAction {
        disposition: SigDisposition::Handler(0x40_1000),
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: SigSet::EMPTY,
    };
    if sigs.sys_rt_sigaction(SignalNumber::Sigkill as u8, Some(act), None) == EINVAL {
        passed += 1;
    }

    // 2. Install handler for SIGUSR1 (10)
    if sigs.sys_rt_sigaction(SignalNumber::Sigusr1 as u8, Some(act), None) == 0 {
        passed += 1;
    }

    // 3. Block SIGUSR1 via rt_sigprocmask and send SIGUSR1 via tgkill
    let mut mask = SigSet::EMPTY;
    mask.add(SignalNumber::Sigusr1 as u8);
    if sigs.sys_rt_sigprocmask(SIG_BLOCK, Some(mask), None) == 0
        && sigs.sys_tgkill(100, 100, SignalNumber::Sigusr1 as u8, 1) == 0
    {
        if sigs.sys_rt_sigpending().contains(SignalNumber::Sigusr1 as u8) && sigs.dequeue_unblocked().is_none() {
            passed += 1;
        }
    }

    // 4. Consume blocked signal via signalfd4
    if let Ok(info) = sigs.sys_signalfd4_read(mask) {
        if info.si_signo == SignalNumber::Sigusr1 as u8 && info.sender_pid == 1 {
            passed += 1;
        }
    }

    // 5. Unblock SIGUSR1, send again, and verify user-mode delivery
    if sigs.sys_rt_sigprocmask(SIG_UNBLOCK, Some(mask), None) == 0
        && sigs.sys_tgkill(100, 100, SignalNumber::Sigusr1 as u8, 42) == 0
    {
        if let Some((info, delivered_act)) = sigs.dequeue_unblocked() {
            if info.sender_pid == 42 && delivered_act.disposition == SigDisposition::Handler(0x40_1000) {
                passed += 1;
            }
        }
    }

    // 6. Test sigaltstack validation and installation
    let mut stack_buf = [0u8; 8192];
    let stack_top = stack_buf.as_mut_ptr() as u64 + 8192;
    let valid_ss = SignalStack {
        ss_sp: stack_buf.as_mut_ptr() as u64,
        ss_flags: 0,
        ss_size: 8192,
    };
    if sigs.sys_sigaltstack(Some(valid_ss), None) == 0 {
        passed += 1;
    }

    // 7. Verify setup_rt_frame alignment, ABI argument register setup, and genuine frame serialization
    let mut regs = MContextX86_64::default();
    regs.rip = 0x40_0000;
    regs.rsp = stack_top;
    regs.rdi = 123;
    let sig_info = SigInfo {
        si_signo: SignalNumber::Sigusr1 as u8,
        si_errno: 0,
        si_code: 0,
        sender_pid: 100,
        sender_uid: 0,
        sigval_u64: 999,
    };
    let test_sa = SigAction {
        disposition: SigDisposition::Handler(0x40_2000),
        sa_flags: SA_ONSTACK | SA_SIGINFO,
        sa_restorer: 0x7FFF_FF00,
        sa_mask: SigSet(0x1234),
    };
    if let Ok((new_sp, handler, rdi, rsi, rdx)) = setup_rt_frame(
        stack_top,
        Some(&valid_ss),
        &test_sa,
        SignalNumber::Sigusr1 as u32,
        &sig_info,
        &regs,
        &SigSet(0x1234),
    ) {
        if handler == 0x40_2000
            && rdi == SignalNumber::Sigusr1 as u64
            && (new_sp + 8) % 16 == 0
            && rsi > new_sp
            && rdx > new_sp
        {
            passed += 1;
        }

        // 8. Verify restore_rt_frame directly from the serialized frame written into new_sp
        let frame_on_stack = unsafe { *(new_sp as *const SigFrameX86_64) };
        let (restored_regs, restored_mask) = restore_rt_frame(&frame_on_stack);
        if restored_regs.rip == 0x40_0000 && restored_regs.rdi == 123 && restored_mask.0 == 0x1234 {
            passed += 1;
        }
    }

    // 9. Verify POSIX SignalDefaultAction execution
    let term_int = SignalDefaultAction::for_signal(SignalNumber::Sigint as u8).execute(SignalNumber::Sigint as u8);
    let term_segv = SignalDefaultAction::for_signal(SignalNumber::Sigsegv as u8).execute(SignalNumber::Sigsegv as u8);
    let ign_chld = SignalDefaultAction::for_signal(SignalNumber::Sigchld as u8).execute(SignalNumber::Sigchld as u8);
    let stop_sig = SignalDefaultAction::for_signal(SignalNumber::Sigstop as u8).execute(SignalNumber::Sigstop as u8);
    if term_int == 130 && term_segv == 139 && ign_chld == 0 && stop_sig == 0 {
        passed += 1;
    }

    passed
}
