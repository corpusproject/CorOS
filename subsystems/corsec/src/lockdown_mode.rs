//! Kernel Lockdown enforcement state machine (`lockdown_mode`).
//!
//! Implements `LockdownLevel` (`None`, `Integrity`, `Confidentiality`), irreversible escalation
//! semantics, and a reason-specific gatekeeper (`LockdownReason`: `UnsignedModuleLoad`,
//! `DevMemReadWrite`, `IoPortDirectAccess`, `MsrRawWrite`, `AcpiTableOverride`, `KexecUnsignedImage`,
//! plus confidentiality-tier reasons such as `KernelCoreDumpRead` and `PerfRawKernelTrace`).

/// Monotonically increasing kernel lockdown level.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockdownLevel {
    /// Standard root capabilities are unrestricted.
    None = 0,
    /// Blocks user space from modifying the running kernel image or executing unsigned code in ring 0.
    Integrity = 1,
    /// Blocks user space from extracting confidential material or arbitrary memory from the running kernel.
    Confidentiality = 2,
}

/// Sensitive kernel operations gated by the Kernel Lockdown LSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownReason {
    /// Loading an unsigned or untrusted kernel module (`init_module` / `finit_module`).
    UnsignedModuleLoad,
    /// Reading or writing physical memory through `/dev/mem`, `/dev/kmem`, or `/dev/port`.
    DevMemReadWrite,
    /// Direct x86 hardware I/O port access via `ioperm` or `iopl`.
    IoPortDirectAccess,
    /// Writing raw CPU Model-Specific Registers (`/dev/cpu/*/msr`).
    MsrRawWrite,
    /// Overriding ACPI tables from user space or unverified initrd.
    AcpiTableOverride,
    /// Booting an unsigned kernel image via `kexec_load`.
    KexecUnsignedImage,
    /// Reading `/proc/kcore` or extracting raw kernel memory dumps.
    KernelCoreDumpRead,
    /// Inspecting raw kernel pointers or kernel-mode register state via unredacted perf/ftrace.
    PerfRawKernelTrace,
}

impl LockdownReason {
    /// Returns the minimum `LockdownLevel` at which this operation is forbidden.
    #[inline]
    pub const fn minimum_blocking_level(self) -> LockdownLevel {
        match self {
            Self::UnsignedModuleLoad
            | Self::DevMemReadWrite
            | Self::IoPortDirectAccess
            | Self::MsrRawWrite
            | Self::AcpiTableOverride
            | Self::KexecUnsignedImage => LockdownLevel::Integrity,
            Self::KernelCoreDumpRead | Self::PerfRawKernelTrace => LockdownLevel::Confidentiality,
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::UnsignedModuleLoad => "unsigned module loading",
            Self::DevMemReadWrite => "/dev/mem,kmem,port access",
            Self::IoPortDirectAccess => "direct hardware I/O port access",
            Self::MsrRawWrite => "raw CPU MSR write access",
            Self::AcpiTableOverride => "ACPI table override",
            Self::KexecUnsignedImage => "kexec of unsigned kernel image",
            Self::KernelCoreDumpRead => "/proc/kcore kernel memory extraction",
            Self::PerfRawKernelTrace => "raw kernel pointer trace inspection",
        }
    }
}

/// Errors produced by `KernelLockdownState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownError {
    /// Attempted to downgrade the lockdown level (`None` <- `Integrity` or `Integrity` <- `Confidentiality`).
    CannotDeescalate {
        current: LockdownLevel,
        attempted: LockdownLevel,
    },
    /// Operation was blocked by the active kernel lockdown policy.
    OperationLockedDown {
        active_level: LockdownLevel,
        reason: LockdownReason,
    },
}

/// Irreversible Kernel Lockdown state machine with per-tier denial counters.
pub struct KernelLockdownState {
    level: LockdownLevel,
    pub integrity_denials: u64,
    pub confidentiality_denials: u64,
    pub allowed_checks: u64,
}

impl KernelLockdownState {
    pub const fn new(initial_level: LockdownLevel) -> Self {
        Self {
            level: initial_level,
            integrity_denials: 0,
            confidentiality_denials: 0,
            allowed_checks: 0,
        }
    }

    #[inline]
    pub const fn current_level(&self) -> LockdownLevel {
        self.level
    }

    /// Escalates the lockdown level (`None -> Integrity -> Confidentiality`).
    /// Attempting to lower the level is strictly rejected with `LockdownError::CannotDeescalate`.
    pub fn escalate_to(&mut self, target_level: LockdownLevel) -> Result<LockdownLevel, LockdownError> {
        if target_level < self.level {
            return Err(LockdownError::CannotDeescalate {
                current: self.level,
                attempted: target_level,
            });
        }
        self.level = target_level;
        Ok(self.level)
    }

    /// Evaluates whether a sensitive kernel operation (`reason`) is permitted under the active `LockdownLevel`.
    pub fn is_locked_down(&mut self, reason: LockdownReason) -> Result<(), LockdownError> {
        let required_level = reason.minimum_blocking_level();
        if self.level >= required_level {
            match required_level {
                LockdownLevel::Integrity => self.integrity_denials += 1,
                LockdownLevel::Confidentiality => self.confidentiality_denials += 1,
                LockdownLevel::None => {}
            }
            Err(LockdownError::OperationLockedDown {
                active_level: self.level,
                reason,
            })
        } else {
            self.allowed_checks += 1;
            Ok(())
        }
    }
}
