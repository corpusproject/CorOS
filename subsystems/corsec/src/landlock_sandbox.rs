//! Unprivileged path-hierarchy & network port sandboxing (`Landlock`).
//!
//! Provides `LandlockRuleset`, `FsAccessBit`, `NetPortAccessBit`, longest-ancestor path rule
//! inheritance evaluation, and stacked domain intersection across up to 16 sandbox layers.

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum number of stacked Landlock domains per task (matches Linux `LANDLOCK_MAX_NUM_LAYERS`).
pub const MAX_LANDLOCK_LAYERS: usize = 16;

/// Filesystem access rights bitmask handled by a Landlock ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsAccessBit(pub u32);

impl FsAccessBit {
    pub const NONE: Self = Self(0);
    pub const EXECUTE: Self = Self(1 << 0);
    pub const WRITE_FILE: Self = Self(1 << 1);
    pub const READ_FILE: Self = Self(1 << 2);
    pub const READ_DIR: Self = Self(1 << 3);
    pub const REMOVE_DIR: Self = Self(1 << 4);
    pub const REMOVE_FILE: Self = Self(1 << 5);
    pub const MAKE_CHAR: Self = Self(1 << 6);
    pub const MAKE_DIR: Self = Self(1 << 7);
    pub const MAKE_REG: Self = Self(1 << 8);
    pub const MAKE_SOCK: Self = Self(1 << 9);
    pub const MAKE_FIFO: Self = Self(1 << 10);
    pub const MAKE_BLOCK: Self = Self(1 << 11);
    pub const MAKE_SYM: Self = Self(1 << 12);
    pub const REFER: Self = Self(1 << 13);
    pub const TRUNCATE: Self = Self(1 << 14);
    pub const IOCTL_DEV: Self = Self(1 << 15);

    pub const ALL_FS_ACCESS: Self = Self(0xFFFF);

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
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

/// Network TCP port access rights bitmask (`LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetPortAccessBit(pub u8);

impl NetPortAccessBit {
    pub const NONE: Self = Self(0);
    pub const BIND_TCP: Self = Self(1 << 0);
    pub const CONNECT_TCP: Self = Self(1 << 1);
    pub const ALL_NET: Self = Self(0x03);

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
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

/// Path-beneath rule associating an absolute path prefix with allowed `FsAccessBit` rights.
#[derive(Debug, Clone)]
pub struct PathBeneathRule {
    pub parent_path: String,
    pub allowed_access: FsAccessBit,
}

/// Network service port rule associating a TCP port with allowed `NetPortAccessBit` rights.
#[derive(Debug, Clone, Copy)]
pub struct NetPortRule {
    pub port: u16,
    pub allowed_access: NetPortAccessBit,
}

/// Errors produced when configuring or stacking Landlock rulesets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockError {
    UnhandedAccessBit,
    InvalidPath,
    LayerLimitExceeded,
    AccessDenied,
}

/// Single Landlock ruleset layer specifying which filesystem and network rights are handled
/// (denied by default unless explicitly permitted by a matching rule).
#[derive(Debug, Clone)]
pub struct LandlockRuleset {
    pub handled_fs_access: FsAccessBit,
    pub handled_net_access: NetPortAccessBit,
    path_rules: Vec<PathBeneathRule>,
    port_rules: Vec<NetPortRule>,
}

impl LandlockRuleset {
    pub fn new(handled_fs_access: FsAccessBit, handled_net_access: NetPortAccessBit) -> Self {
        Self {
            handled_fs_access,
            handled_net_access,
            path_rules: Vec::new(),
            port_rules: Vec::new(),
        }
    }

    /// Adds a `path_beneath` rule. All `allowed_access` bits must be a subset of `handled_fs_access`.
    pub fn add_path_beneath_rule(
        &mut self,
        path: &str,
        allowed_access: FsAccessBit,
    ) -> Result<(), LandlockError> {
        if !path.starts_with('/') {
            return Err(LandlockError::InvalidPath);
        }
        if !self.handled_fs_access.contains(allowed_access) {
            return Err(LandlockError::UnhandedAccessBit);
        }
        let normalized = normalize_path(path);
        for rule in self.path_rules.iter_mut() {
            if rule.parent_path == normalized {
                rule.allowed_access = rule.allowed_access.union(allowed_access);
                return Ok(());
            }
        }
        self.path_rules.push(PathBeneathRule {
            parent_path: normalized,
            allowed_access,
        });
        Ok(())
    }

    /// Adds a TCP port rule. All `allowed_access` bits must be a subset of `handled_net_access`.
    pub fn add_net_port_rule(
        &mut self,
        port: u16,
        allowed_access: NetPortAccessBit,
    ) -> Result<(), LandlockError> {
        if !self.handled_net_access.contains(allowed_access) {
            return Err(LandlockError::UnhandedAccessBit);
        }
        for rule in self.port_rules.iter_mut() {
            if rule.port == port {
                rule.allowed_access = rule.allowed_access.union(allowed_access);
                return Ok(());
            }
        }
        self.port_rules.push(NetPortRule {
            port,
            allowed_access,
        });
        Ok(())
    }

    /// Evaluates the ruleset for a target path by accumulating permissions along all ancestor prefixes
    /// (including longest-ancestor and parent hierarchy rules) and leaving unhandled bits unrestricted.
    pub fn evaluate_fs_path(&self, target_path: &str) -> FsAccessBit {
        let normalized = normalize_path(target_path);
        let mut granted_handled = FsAccessBit::NONE;

        for rule in &self.path_rules {
            if is_path_ancestor_or_equal(&rule.parent_path, &normalized) {
                granted_handled = granted_handled.union(rule.allowed_access);
            }
        }

        // Unhandled access rights remain implicitly permitted by this layer
        let unhandled = FsAccessBit::ALL_FS_ACCESS.difference(self.handled_fs_access);
        unhandled.union(granted_handled)
    }

    /// Evaluates the ruleset for a TCP port, leaving unhandled network rights unrestricted.
    pub fn evaluate_net_port(&self, port: u16) -> NetPortAccessBit {
        let mut granted_handled = NetPortAccessBit::NONE;
        for rule in &self.port_rules {
            if rule.port == port {
                granted_handled = granted_handled.union(rule.allowed_access);
            }
        }
        let unhandled = NetPortAccessBit::ALL_NET.difference(self.handled_net_access);
        unhandled.union(granted_handled)
    }
}

/// Stacked Landlock sandbox domain enforcing the intersection of up to 16 layers.
#[derive(Debug, Clone, Default)]
pub struct LandlockSandboxDomain {
    layers: Vec<LandlockRuleset>,
}

impl LandlockSandboxDomain {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Stacks a new `LandlockRuleset` onto the current domain (`landlock_restrict_self`).
    pub fn restrict_self(&mut self, ruleset: LandlockRuleset) -> Result<(), LandlockError> {
        if self.layers.len() >= MAX_LANDLOCK_LAYERS {
            return Err(LandlockError::LayerLimitExceeded);
        }
        self.layers.push(ruleset);
        Ok(())
    }

    /// Checks filesystem access across all stacked layers (every layer must permit `requested`).
    pub fn check_fs_access(
        &self,
        target_path: &str,
        requested: FsAccessBit,
    ) -> Result<(), LandlockError> {
        if !target_path.starts_with('/') {
            return Err(LandlockError::InvalidPath);
        }
        let mut effective = FsAccessBit::ALL_FS_ACCESS;
        for layer in &self.layers {
            effective = effective.intersection(layer.evaluate_fs_path(target_path));
        }
        if effective.contains(requested) {
            Ok(())
        } else {
            Err(LandlockError::AccessDenied)
        }
    }

    /// Checks TCP port access across all stacked layers (every layer must permit `requested`).
    pub fn check_net_port_access(
        &self,
        port: u16,
        requested: NetPortAccessBit,
    ) -> Result<(), LandlockError> {
        let mut effective = NetPortAccessBit::ALL_NET;
        for layer in &self.layers {
            effective = effective.intersection(layer.evaluate_net_port(port));
        }
        if effective.contains(requested) {
            Ok(())
        } else {
            Err(LandlockError::AccessDenied)
        }
    }
}

fn normalize_path(path: &str) -> String {
    if path == "/" {
        return String::from("/");
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        String::from("/")
    } else {
        String::from(trimmed)
    }
}

/// Checks if `ancestor` is either equal to `child` or is a directory ancestor of `child`.
fn is_path_ancestor_or_equal(ancestor: &str, child: &str) -> bool {
    if ancestor == "/" {
        return child.starts_with('/');
    }
    if ancestor == child {
        return true;
    }
    if let Some(rest) = child.strip_prefix(ancestor) {
        rest.starts_with('/')
    } else {
        false
    }
}
