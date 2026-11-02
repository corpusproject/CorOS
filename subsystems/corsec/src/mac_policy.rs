//! Type-Enforcement Mandatory Access Control (`MAC`) engine and Access Vector Cache (`AVC`).
//!
//! Implements `SecurityLabel` (`user:role:type:sensitivity`), `ObjectClass`, `AccessPermission`,
//! a Type Enforcement policy rule table, Multi-Level Security (`MLS`) Bell-LaPadula sensitivity dominance,
//! and an LRU Access Vector Cache (`AvcCache`) with policy sequence number invalidation.

use alloc::string::String;
use alloc::vec::Vec;

/// Four-component security context (`user:role:type:sensitivity`), e.g. `system_u:system_r:sshd_t:s0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLabel {
    pub user: String,
    pub role: String,
    pub domain_type: String,
    pub sensitivity: u8,
}

impl SecurityLabel {
    pub fn new(user: &str, role: &str, domain_type: &str, sensitivity: u8) -> Self {
        Self {
            user: String::from(user),
            role: String::from(role),
            domain_type: String::from(domain_type),
            sensitivity,
        }
    }

    /// Parses a colon-delimited label `user:role:type:s<level>`.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split(':');
        let user = parts.next()?;
        let role = parts.next()?;
        let domain_type = parts.next()?;
        let sens_str = parts.next()?;
        if parts.next().is_some() || user.is_empty() || role.is_empty() || domain_type.is_empty() {
            return None;
        }
        let level_digits = sens_str.strip_prefix('s')?;
        let sensitivity = level_digits.parse::<u8>().ok()?;
        Some(Self::new(user, role, domain_type, sensitivity))
    }

    /// Formats the security context back into canonical `user:role:type:s<N>` notation.
    pub fn to_context_string(&self) -> String {
        let mut out = String::with_capacity(
            self.user.len() + self.role.len() + self.domain_type.len() + 8,
        );
        out.push_str(&self.user);
        out.push(':');
        out.push_str(&self.role);
        out.push(':');
        out.push_str(&self.domain_type);
        out.push_str(":s");
        append_u8_decimal(&mut out, self.sensitivity);
        out
    }
}

fn append_u8_decimal(buf: &mut String, val: u8) {
    if val >= 100 {
        buf.push((b'0' + (val / 100)) as char);
    }
    if val >= 10 {
        buf.push((b'0' + ((val / 10) % 10)) as char);
    }
    buf.push((b'0' + (val % 10)) as char);
}

/// Target kernel object class in a MAC policy rule.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectClass {
    File = 1,
    Dir = 2,
    Process = 3,
    TcpSocket = 4,
    UdpSocket = 5,
    UnixStreamSocket = 6,
    Shm = 7,
    BlockDevice = 8,
}

/// Bitmask of access permissions in an access vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPermission(pub u32);

impl AccessPermission {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const APPEND: Self = Self(1 << 3);
    pub const CREATE: Self = Self(1 << 4);
    pub const UNLINK: Self = Self(1 << 5);
    pub const IOCTL: Self = Self(1 << 6);
    pub const GETATTR: Self = Self(1 << 7);
    pub const SETATTR: Self = Self(1 << 8);
    pub const TRANSITION: Self = Self(1 << 9);
    pub const CONNECT: Self = Self(1 << 10);
    pub const BIND: Self = Self(1 << 11);
    pub const SIGNAL: Self = Self(1 << 12);
    pub const PTRACE: Self = Self(1 << 13);

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Type Enforcement rule entry (`allow` or `neverallow` / explicit deny).
#[derive(Debug, Clone)]
pub struct TePolicyRule {
    pub source_type: String,
    pub target_type: String,
    pub object_class: ObjectClass,
    pub allowed_perms: AccessPermission,
    pub denied_perms: AccessPermission,
}

/// Cached Access Vector entry stored inside `AvcCache`.
#[derive(Debug, Clone)]
struct AvcEntry {
    source_type: String,
    target_type: String,
    source_sensitivity: u8,
    target_sensitivity: u8,
    object_class: ObjectClass,
    allowed_vector: AccessPermission,
    policy_seqno: u64,
    last_used_tick: u64,
}

/// Fixed-capacity Least Recently Used (`LRU`) Access Vector Cache (`AVC`) with sequence invalidation.
pub struct AvcCache {
    entries: Vec<AvcEntry>,
    capacity: usize,
    clock_tick: u64,
    pub hits: u64,
    pub misses: u64,
}

impl AvcCache {
    pub fn new(capacity: usize) -> Self {
        let cap = if capacity == 0 { 16 } else { capacity };
        Self {
            entries: Vec::with_capacity(cap),
            capacity: cap,
            clock_tick: 0,
            hits: 0,
            misses: 0,
        }
    }

    pub fn lookup(
        &mut self,
        source: &SecurityLabel,
        target: &SecurityLabel,
        class: ObjectClass,
        current_seqno: u64,
    ) -> Option<AccessPermission> {
        self.clock_tick += 1;
        let tick = self.clock_tick;
        for entry in self.entries.iter_mut() {
            if entry.policy_seqno == current_seqno
                && entry.object_class == class
                && entry.source_sensitivity == source.sensitivity
                && entry.target_sensitivity == target.sensitivity
                && entry.source_type == source.domain_type
                && entry.target_type == target.domain_type
            {
                entry.last_used_tick = tick;
                self.hits += 1;
                return Some(entry.allowed_vector);
            }
        }
        self.misses += 1;
        None
    }

    pub fn insert(
        &mut self,
        source: &SecurityLabel,
        target: &SecurityLabel,
        class: ObjectClass,
        allowed_vector: AccessPermission,
        current_seqno: u64,
    ) {
        self.clock_tick += 1;
        let tick = self.clock_tick;

        // First try replacing an existing stale or matching slot
        for entry in self.entries.iter_mut() {
            if entry.policy_seqno != current_seqno
                || (entry.object_class == class
                    && entry.source_sensitivity == source.sensitivity
                    && entry.target_sensitivity == target.sensitivity
                    && entry.source_type == source.domain_type
                    && entry.target_type == target.domain_type)
            {
                entry.source_type.clear();
                entry.source_type.push_str(&source.domain_type);
                entry.target_type.clear();
                entry.target_type.push_str(&target.domain_type);
                entry.source_sensitivity = source.sensitivity;
                entry.target_sensitivity = target.sensitivity;
                entry.object_class = class;
                entry.allowed_vector = allowed_vector;
                entry.policy_seqno = current_seqno;
                entry.last_used_tick = tick;
                return;
            }
        }

        if self.entries.len() < self.capacity {
            self.entries.push(AvcEntry {
                source_type: source.domain_type.clone(),
                target_type: target.domain_type.clone(),
                source_sensitivity: source.sensitivity,
                target_sensitivity: target.sensitivity,
                object_class: class,
                allowed_vector,
                policy_seqno: current_seqno,
                last_used_tick: tick,
            });
            return;
        }

        // Evict the least-recently-used entry
        if let Some(lru_slot) = self
            .entries
            .iter_mut()
            .min_by_key(|e| e.last_used_tick)
        {
            lru_slot.source_type.clear();
            lru_slot.source_type.push_str(&source.domain_type);
            lru_slot.target_type.clear();
            lru_slot.target_type.push_str(&target.domain_type);
            lru_slot.source_sensitivity = source.sensitivity;
            lru_slot.target_sensitivity = target.sensitivity;
            lru_slot.object_class = class;
            lru_slot.allowed_vector = allowed_vector;
            lru_slot.policy_seqno = current_seqno;
            lru_slot.last_used_tick = tick;
        }
    }
}

/// Complete Type-Enforcement and Bell-LaPadula MLS Mandatory Access Control policy engine.
pub struct MacPolicyEngine {
    rules: Vec<TePolicyRule>,
    pub avc: AvcCache,
    pub policy_seqno: u64,
    pub enforcing_mode: bool,
    pub mls_enabled: bool,
}

impl MacPolicyEngine {
    pub fn new(avc_capacity: usize, enforcing_mode: bool, mls_enabled: bool) -> Self {
        Self {
            rules: Vec::new(),
            avc: AvcCache::new(avc_capacity),
            policy_seqno: 1,
            enforcing_mode,
            mls_enabled,
        }
    }

    /// Adds or updates a Type Enforcement allow rule and bumps `policy_seqno` to invalidate stale AVC entries.
    pub fn add_allow_rule(
        &mut self,
        source_type: &str,
        target_type: &str,
        object_class: ObjectClass,
        perms: AccessPermission,
    ) {
        self.policy_seqno += 1;
        for rule in self.rules.iter_mut() {
            if rule.object_class == object_class
                && rule.source_type == source_type
                && rule.target_type == target_type
            {
                rule.allowed_perms = rule.allowed_perms.union(perms);
                return;
            }
        }
        self.rules.push(TePolicyRule {
            source_type: String::from(source_type),
            target_type: String::from(target_type),
            object_class,
            allowed_perms: perms,
            denied_perms: AccessPermission::NONE,
        });
    }

    /// Adds an explicit deny (`neverallow`) mask for a `(source, target, class)` triple and bumps `policy_seqno`.
    pub fn add_deny_rule(
        &mut self,
        source_type: &str,
        target_type: &str,
        object_class: ObjectClass,
        denied_perms: AccessPermission,
    ) {
        self.policy_seqno += 1;
        for rule in self.rules.iter_mut() {
            if rule.object_class == object_class
                && rule.source_type == source_type
                && rule.target_type == target_type
            {
                rule.denied_perms = rule.denied_perms.union(denied_perms);
                return;
            }
        }
        self.rules.push(TePolicyRule {
            source_type: String::from(source_type),
            target_type: String::from(target_type),
            object_class,
            allowed_perms: AccessPermission::NONE,
            denied_perms,
        });
    }

    /// Computes the effective access vector for `(source, target, class)`, honoring TE rules and MLS dominance.
    pub fn compute_access_vector(
        &self,
        source: &SecurityLabel,
        target: &SecurityLabel,
        class: ObjectClass,
    ) -> AccessPermission {
        let mut allowed = AccessPermission::NONE;
        let mut denied = AccessPermission::NONE;

        for rule in &self.rules {
            if rule.object_class == class
                && rule.source_type == source.domain_type
                && rule.target_type == target.domain_type
            {
                allowed = allowed.union(rule.allowed_perms);
                denied = denied.union(rule.denied_perms);
            }
        }

        let mut effective = allowed.difference(denied);

        if self.mls_enabled {
            // Bell-LaPadula "no read up" (Simple Security Property): source sensitivity >= target sensitivity
            if source.sensitivity < target.sensitivity {
                effective = effective.difference(AccessPermission::READ.union(AccessPermission::EXECUTE));
            }
            // Bell-LaPadula "no write down" (*-Property): source sensitivity <= target sensitivity
            if source.sensitivity > target.sensitivity {
                effective = effective.difference(
                    AccessPermission::WRITE
                        .union(AccessPermission::APPEND)
                        .union(AccessPermission::CREATE),
                );
            }
        }

        effective
    }

    /// Checks whether `source` is granted `requested` permissions on `target` of `class`.
    /// Consults `AvcCache` first and populates it on cache miss.
    pub fn check_access(
        &mut self,
        source: &SecurityLabel,
        target: &SecurityLabel,
        class: ObjectClass,
        requested: AccessPermission,
    ) -> bool {
        let vector = if let Some(cached) =
            self.avc.lookup(source, target, class, self.policy_seqno)
        {
            cached
        } else {
            let computed = self.compute_access_vector(source, target, class);
            self.avc
                .insert(source, target, class, computed, self.policy_seqno);
            computed
        };

        if vector.contains(requested) {
            true
        } else {
            !self.enforcing_mode
        }
    }
}
