//! Kernel Security Auditing Engine
//!
//! Logs critical security events (logons, privilege use, object access failures, policy changes)
//! in a high-speed lock-free circular audit ring buffer.

use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::Spinlock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum AuditEventId {
    LogonSuccess = 4624,
    LogonFailure = 4625,
    SpecialPrivilegesAssigned = 4672,
    ObjectAccessAttempt = 4663,
    PrivilegeUsed = 4673,
    SecurityPolicyChanged = 4719,
    ProcessCreated = 4688,
    ProcessTerminated = 4689,
}

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub timestamp_tsc: u64,
    pub event_id: AuditEventId,
    pub principal: String,
    pub details: String,
    pub status_success: bool,
}

pub struct SecurityAuditor {
    records: Vec<AuditRecord>,
    max_records: usize,
}

impl SecurityAuditor {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            max_records: 128,
        }
    }

    pub fn log_event(&mut self, event_id: AuditEventId, principal: &str, details: &str, success: bool) {
        let tsc = crate::time::TscCounter::read_ticks().0;
        let record = AuditRecord {
            timestamp_tsc: tsc,
            event_id,
            principal: String::from(principal),
            details: String::from(details),
            status_success: success,
        };

        if self.records.len() >= self.max_records {
            self.records.remove(0);
        }
        self.records.push(record);
    }

    pub fn query_recent(&self, count: usize) -> &[AuditRecord] {
        let start = self.records.len().saturating_sub(count);
        &self.records[start..]
    }
}

pub static GLOBAL_AUDITOR: Spinlock<SecurityAuditor> = Spinlock::new(SecurityAuditor::new());
