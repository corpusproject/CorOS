//! CorOS VFS Module: `quota_tracker`
//!
//! Per-UID and Per-GID disk block and inode quota enforcement (`QuotaLimits`,
//! `QuotaUsage`, `QuotaSubject`, soft-limit grace timer warnings, and hard-limit
//! `EDQUOT` rejection).

use alloc::vec::Vec;

/// Default grace period for exceeding a soft quota limit (7 days in seconds).
pub const DEFAULT_QUOTA_GRACE_SEC: u64 = 7 * 24 * 3600;

/// Identifies whether a quota record applies to a User (`Uid`) or Group (`Gid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QuotaSubject {
    User(u32),
    Group(u32),
}

/// Configured soft and hard limits for 4 KiB disk blocks and inodes (`0` = unlimited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaLimits {
    pub block_soft_limit: u64,
    pub block_hard_limit: u64,
    pub inode_soft_limit: u64,
    pub inode_hard_limit: u64,
    pub grace_period_sec: u64,
}

impl QuotaLimits {
    pub const fn unlimited() -> Self {
        Self {
            block_soft_limit: 0,
            block_hard_limit: 0,
            inode_soft_limit: 0,
            inode_hard_limit: 0,
            grace_period_sec: DEFAULT_QUOTA_GRACE_SEC,
        }
    }
}

/// Live resource consumption and soft-limit deadline state for a `QuotaSubject`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaUsage {
    pub used_blocks: u64,
    pub used_inodes: u64,
    /// Deadline timestamp (seconds) when soft block limit turns into a hard rejection (`0` if below soft limit).
    pub block_grace_deadline_sec: u64,
    /// Deadline timestamp (seconds) when soft inode limit turns into a hard rejection (`0` if below soft limit).
    pub inode_grace_deadline_sec: u64,
}

impl QuotaUsage {
    pub const fn zero() -> Self {
        Self {
            used_blocks: 0,
            used_inodes: 0,
            block_grace_deadline_sec: 0,
            inode_grace_deadline_sec: 0,
        }
    }
}

/// Outcome of a quota allocation check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaVerdict {
    Allowed,
    AllowedWithSoftWarning { deadline_sec: u64 },
    DeniedHardBlockLimit,
    DeniedHardInodeLimit,
    DeniedGracePeriodExpired,
}

#[derive(Clone, Copy, Debug)]
struct QuotaRecord {
    subject: QuotaSubject,
    limits: QuotaLimits,
    usage: QuotaUsage,
}

/// Per-UID and Per-GID Disk Block & Inode Quota Tracker.
pub struct VfsQuotaTracker {
    records: Vec<QuotaRecord>,
}

impl VfsQuotaTracker {
    pub const fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Sets or updates the quota limits for a user (`Uid`) or group (`Gid`).
    pub fn set_limits(&mut self, subject: QuotaSubject, limits: QuotaLimits) {
        if let Some(rec) = self.records.iter_mut().find(|r| r.subject == subject) {
            rec.limits = limits;
        } else {
            self.records.push(QuotaRecord {
                subject,
                limits,
                usage: QuotaUsage::zero(),
            });
        }
    }

    /// Queries the current usage and limits for `subject`.
    pub fn query(&self, subject: QuotaSubject) -> Option<(QuotaLimits, QuotaUsage)> {
        self.records
            .iter()
            .find(|r| r.subject == subject)
            .map(|r| (r.limits, r.usage))
    }

    /// Evaluates and charges `delta_blocks` and `delta_inodes` for `subject` at `now_sec`.
    /// Root (`QuotaSubject::User(0)`) is always exempt from quota enforcement, though usage is still tracked.
    pub fn charge_allocation(
        &mut self,
        subject: QuotaSubject,
        delta_blocks: u64,
        delta_inodes: u64,
        now_sec: u64,
    ) -> QuotaVerdict {
        let Some(rec) = self.records.iter_mut().find(|r| r.subject == subject) else {
            return QuotaVerdict::Allowed;
        };

        let new_blocks = rec.usage.used_blocks.saturating_add(delta_blocks);
        let new_inodes = rec.usage.used_inodes.saturating_add(delta_inodes);

        // Root user (UID 0) is never blocked by quota limits
        if subject == QuotaSubject::User(0) {
            rec.usage.used_blocks = new_blocks;
            rec.usage.used_inodes = new_inodes;
            return QuotaVerdict::Allowed;
        }

        // 1. Check hard limits
        if rec.limits.block_hard_limit > 0 && new_blocks > rec.limits.block_hard_limit {
            return QuotaVerdict::DeniedHardBlockLimit;
        }
        if rec.limits.inode_hard_limit > 0 && new_inodes > rec.limits.inode_hard_limit {
            return QuotaVerdict::DeniedHardInodeLimit;
        }

        // 2. Check expired soft-limit grace timers
        if rec.limits.block_soft_limit > 0 && new_blocks > rec.limits.block_soft_limit {
            if rec.usage.block_grace_deadline_sec != 0 && now_sec >= rec.usage.block_grace_deadline_sec {
                return QuotaVerdict::DeniedGracePeriodExpired;
            }
        }
        if rec.limits.inode_soft_limit > 0 && new_inodes > rec.limits.inode_soft_limit {
            if rec.usage.inode_grace_deadline_sec != 0 && now_sec >= rec.usage.inode_grace_deadline_sec {
                return QuotaVerdict::DeniedGracePeriodExpired;
            }
        }

        // Commit the allocation and arm soft-limit grace timers if crossed for the first time
        rec.usage.used_blocks = new_blocks;
        rec.usage.used_inodes = new_inodes;

        let mut warning_deadline = None;
        if rec.limits.block_soft_limit > 0 && new_blocks > rec.limits.block_soft_limit {
            if rec.usage.block_grace_deadline_sec == 0 {
                rec.usage.block_grace_deadline_sec = now_sec + rec.limits.grace_period_sec;
            }
            warning_deadline = Some(rec.usage.block_grace_deadline_sec);
        }

        if rec.limits.inode_soft_limit > 0 && new_inodes > rec.limits.inode_soft_limit {
            if rec.usage.inode_grace_deadline_sec == 0 {
                rec.usage.inode_grace_deadline_sec = now_sec + rec.limits.grace_period_sec;
            }
            warning_deadline = Some(rec.usage.inode_grace_deadline_sec);
        }

        if let Some(deadline_sec) = warning_deadline {
            QuotaVerdict::AllowedWithSoftWarning { deadline_sec }
        } else {
            QuotaVerdict::Allowed
        }
    }

    /// Releases `freed_blocks` and `freed_inodes` for `subject`, clearing grace timers if usage drops below soft limits.
    pub fn release_allocation(&mut self, subject: QuotaSubject, freed_blocks: u64, freed_inodes: u64) {
        if let Some(rec) = self.records.iter_mut().find(|r| r.subject == subject) {
            rec.usage.used_blocks = rec.usage.used_blocks.saturating_sub(freed_blocks);
            rec.usage.used_inodes = rec.usage.used_inodes.saturating_sub(freed_inodes);

            if rec.limits.block_soft_limit == 0 || rec.usage.used_blocks <= rec.limits.block_soft_limit {
                rec.usage.block_grace_deadline_sec = 0;
            }
            if rec.limits.inode_soft_limit == 0 || rec.usage.used_inodes <= rec.limits.inode_soft_limit {
                rec.usage.inode_grace_deadline_sec = 0;
            }
        }
    }
}

/// Self-test suite for `quota_tracker`.
pub fn verify_vfs_quota_tracker() -> u32 {
    let mut passed = 0u32;
    let mut qt = VfsQuotaTracker::new();
    let user = QuotaSubject::User(1000);

    qt.set_limits(
        user,
        QuotaLimits {
            block_soft_limit: 100,
            block_hard_limit: 150,
            inode_soft_limit: 10,
            inode_hard_limit: 20,
            grace_period_sec: 3600,
        },
    );

    // Allocate within soft limit
    if qt.charge_allocation(user, 80, 5, 1000) == QuotaVerdict::Allowed {
        passed += 1;
    }

    // Cross block soft limit (80 + 40 = 120 > 100) -> AllowedWithSoftWarning (deadline = 1000 + 3600 = 4600)
    if qt.charge_allocation(user, 40, 1, 1000) == (QuotaVerdict::AllowedWithSoftWarning { deadline_sec: 4600 }) {
        passed += 1;
    }

    // Exceed hard block limit (120 + 50 = 170 > 150) -> DeniedHardBlockLimit
    if qt.charge_allocation(user, 50, 0, 2000) == QuotaVerdict::DeniedHardBlockLimit {
        passed += 1;
    }

    // Attempt allocation after soft-limit grace timer has expired (now_sec = 5000 >= 4600)
    if qt.charge_allocation(user, 5, 0, 5000) == QuotaVerdict::DeniedGracePeriodExpired {
        passed += 1;
    }

    // Release 50 blocks (120 - 50 = 70 <= 100), clearing the soft-limit deadline
    qt.release_allocation(user, 50, 0);
    if qt.charge_allocation(user, 10, 0, 6000) == QuotaVerdict::Allowed {
        passed += 1;
    }

    passed
}
