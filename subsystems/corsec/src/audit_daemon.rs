//! Kernel security audit subsystem (`kauditd`).
//!
//! Provides `AuditRecordType` (`Syscall`, `Execve`, `Path`, `AvcDenial`, `UserAuth`, `SeccompTrap`),
//! structured `type=... msg=audit(sec.ms:serial): ...` formatter, filter rule engine (`AuditFilterAction`),
//! and configurable backlog overflow policy (`Drop`, `OverwriteOldest`, `PanicSystem`).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// Standard Linux audit record classification codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRecordType {
    Syscall = 1300,
    Path = 1302,
    Execve = 1309,
    SeccompTrap = 1326,
    AvcDenial = 1400,
    UserAuth = 1100,
}

impl AuditRecordType {
    pub const fn type_str(self) -> &'static str {
        match self {
            Self::Syscall => "SYSCALL",
            Self::Path => "PATH",
            Self::Execve => "EXECVE",
            Self::SeccompTrap => "SECCOMP",
            Self::AvcDenial => "AVC",
            Self::UserAuth => "USER_AUTH",
        }
    }
}

/// Action taken when an audit filter rule matches an incoming event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFilterAction {
    /// Always emit an audit record for matching events.
    AlwaysLog,
    /// Suppress audit record generation for matching events.
    NeverLog,
}

/// Filter rule matching optional `uid`, `syscall_nr`, and `record_type`.
#[derive(Debug, Clone)]
pub struct AuditFilterRule {
    pub match_uid: Option<u32>,
    pub match_syscall: Option<u32>,
    pub match_record_type: Option<AuditRecordType>,
    pub action: AuditFilterAction,
}

impl AuditFilterRule {
    pub fn matches(&self, uid: u32, syscall_nr: Option<u32>, record_type: AuditRecordType) -> bool {
        if let Some(expected_uid) = self.match_uid {
            if expected_uid != uid {
                return false;
            }
        }
        if let Some(expected_sc) = self.match_syscall {
            if syscall_nr != Some(expected_sc) {
                return false;
            }
        }
        if let Some(expected_rt) = self.match_record_type {
            if expected_rt != record_type {
                return false;
            }
        }
        true
    }
}

/// Policy applied when the in-kernel audit backlog queue reaches capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklogOverflowPolicy {
    /// Drop the newly arriving event and increment `lost_count`.
    DropNewest,
    /// Evict the oldest queued record to make room for the new event.
    OverwriteOldest,
    /// Flag a critical audit panic condition (`AUDIT_FAIL_PANIC`).
    PanicSystem,
}

/// Structured audit event metadata prior to serialization.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub record_type: AuditRecordType,
    pub timestamp_sec: u64,
    pub timestamp_millis: u16,
    pub pid: u32,
    pub uid: u32,
    pub auid: u32,
    pub syscall_nr: Option<u32>,
    pub success: bool,
    pub subject_context: String,
    pub object_name: String,
    pub detail: String,
}

/// Status returned when submitting an event to `AuditDaemon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSubmitStatus {
    Logged(u64),
    FilteredOut,
    DroppedBacklogFull,
    PanickedBacklogFull,
}

/// Kernel security audit engine managing event serial numbers, filter rules, formatting, and backlog queue.
pub struct AuditDaemon {
    backlog: VecDeque<String>,
    filter_rules: Vec<AuditFilterRule>,
    pub max_backlog: usize,
    pub overflow_policy: BacklogOverflowPolicy,
    next_serial: u64,
    pub lost_count: u64,
    pub panic_triggered: bool,
}

impl AuditDaemon {
    pub fn new(max_backlog: usize, overflow_policy: BacklogOverflowPolicy) -> Self {
        let cap = if max_backlog == 0 { 16 } else { max_backlog };
        Self {
            backlog: VecDeque::with_capacity(cap),
            filter_rules: Vec::new(),
            max_backlog: cap,
            overflow_policy,
            next_serial: 1,
            lost_count: 0,
            panic_triggered: false,
        }
    }

    pub fn add_filter_rule(&mut self, rule: AuditFilterRule) {
        self.filter_rules.push(rule);
    }

    pub fn backlog_len(&self) -> usize {
        self.backlog.len()
    }

    /// Pops the oldest formatted audit record from the backlog ring buffer.
    pub fn pop_record(&mut self) -> Option<String> {
        self.backlog.pop_front()
    }

    /// Formats an `AuditEvent` into canonical Linux auditd wire string:
    /// `type=<TYPE> msg=audit(<sec>.<ms>:<serial>): pid=<pid> uid=<uid> auid=<auid> ...`
    pub fn format_record(event: &AuditEvent, serial: u64) -> String {
        let mut line = String::with_capacity(160);
        let ms_clamped = event.timestamp_millis % 1000;
        let _ = write!(
            line,
            "type={} msg=audit({}.{:03}:{}): pid={} uid={} auid={}",
            event.record_type.type_str(),
            event.timestamp_sec,
            ms_clamped,
            serial,
            event.pid,
            event.uid,
            event.auid
        );
        if let Some(sc) = event.syscall_nr {
            let _ = write!(line, " syscall={}", sc);
        }
        let res_str = if event.success { "yes" } else { "no" };
        let _ = write!(
            line,
            " res={} subj=\"{}\" obj=\"{}\" msg=\"{}\"",
            res_str, event.subject_context, event.object_name, event.detail
        );
        line
    }

    /// Evaluates filter rules, assigns a monotonic serial number, formats the record,
    /// and enqueues it according to `overflow_policy`.
    pub fn submit_event(&mut self, event: &AuditEvent) -> AuditSubmitStatus {
        for rule in &self.filter_rules {
            if rule.matches(event.uid, event.syscall_nr, event.record_type) {
                match rule.action {
                    AuditFilterAction::NeverLog => return AuditSubmitStatus::FilteredOut,
                    AuditFilterAction::AlwaysLog => break,
                }
            }
        }

        if self.backlog.len() >= self.max_backlog {
            match self.overflow_policy {
                BacklogOverflowPolicy::DropNewest => {
                    self.lost_count += 1;
                    return AuditSubmitStatus::DroppedBacklogFull;
                }
                BacklogOverflowPolicy::OverwriteOldest => {
                    let _ = self.backlog.pop_front();
                    self.lost_count += 1;
                }
                BacklogOverflowPolicy::PanicSystem => {
                    self.lost_count += 1;
                    self.panic_triggered = true;
                    return AuditSubmitStatus::PanickedBacklogFull;
                }
            }
        }

        let serial = self.next_serial;
        self.next_serial += 1;
        let formatted = Self::format_record(event, serial);
        self.backlog.push_back(formatted);
        AuditSubmitStatus::Logged(serial)
    }
}
