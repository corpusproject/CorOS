//! CorOS Userland Coreutil: `chown`
//! POSIX file ownership specification parser (`owner`, `owner:group`, `owner:`, `:group`, numeric `1000:1000`)
//! and recursive (`-R`) VFS inode ownership updater.

use alloc::format;
use alloc::string::String;

#[derive(Clone, Copy, Debug)]
pub struct AccountDatabaseEntry {
    pub name: &'static str,
    pub id: u32,
    pub primary_gid: u32,
}

pub const DEFAULT_USERS: [AccountDatabaseEntry; 4] = [
    AccountDatabaseEntry { name: "root", id: 0, primary_gid: 0 },
    AccountDatabaseEntry { name: "daemon", id: 1, primary_gid: 1 },
    AccountDatabaseEntry { name: "nobody", id: 65534, primary_gid: 65534 },
    AccountDatabaseEntry { name: "coros", id: 1000, primary_gid: 1000 },
];

pub const DEFAULT_GROUPS: [AccountDatabaseEntry; 5] = [
    AccountDatabaseEntry { name: "root", id: 0, primary_gid: 0 },
    AccountDatabaseEntry { name: "wheel", id: 10, primary_gid: 10 },
    AccountDatabaseEntry { name: "daemon", id: 1, primary_gid: 1 },
    AccountDatabaseEntry { name: "nogroup", id: 65534, primary_gid: 65534 },
    AccountDatabaseEntry { name: "coros", id: 1000, primary_gid: 1000 },
];

pub fn resolve_uid(token: &str) -> Option<(u32, u32)> {
    if let Ok(num) = token.parse::<u32>() {
        let primary_gid = DEFAULT_USERS
            .iter()
            .find(|u| u.id == num)
            .map(|u| u.primary_gid)
            .unwrap_or(num);
        return Some((num, primary_gid));
    }
    for u in &DEFAULT_USERS {
        if u.name == token {
            return Some((u.id, u.primary_gid));
        }
    }
    None
}

pub fn resolve_gid(token: &str) -> Option<u32> {
    if let Ok(num) = token.parse::<u32>() {
        return Some(num);
    }
    for g in &DEFAULT_GROUPS {
        if g.name == token {
            return Some(g.id);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnershipChangeSpec {
    pub new_uid: Option<u32>,
    pub new_gid: Option<u32>,
}

impl OwnershipChangeSpec {
    /// Parses POSIX `chown` specs:
    /// - `"user"` -> changes UID only
    /// - `"user:group"` -> changes both UID and GID
    /// - `"user:"` -> changes UID and sets GID to that user's login group
    /// - `":group"` -> changes GID only (equivalent to `chgrp`)
    pub fn parse(spec: &str) -> Result<Self, &'static str> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err("Empty ownership specification");
        }

        if let Some((user_part, group_part)) = trimmed.split_once(':') {
            if user_part.is_empty() && group_part.is_empty() {
                return Err("Invalid ':' spec with neither user nor group");
            }
            if user_part.is_empty() {
                let gid = resolve_gid(group_part).ok_or("Unknown group name or GID")?;
                return Ok(Self {
                    new_uid: None,
                    new_gid: Some(gid),
                });
            }
            let (uid, primary_gid) = resolve_uid(user_part).ok_or("Unknown user name or UID")?;
            if group_part.is_empty() {
                return Ok(Self {
                    new_uid: Some(uid),
                    new_gid: Some(primary_gid),
                });
            }
            let gid = resolve_gid(group_part).ok_or("Unknown group name or GID")?;
            Ok(Self {
                new_uid: Some(uid),
                new_gid: Some(gid),
            })
        } else {
            let (uid, _) = resolve_uid(trimmed).ok_or("Unknown user name or UID")?;
            Ok(Self {
                new_uid: Some(uid),
                new_gid: None,
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChownInodeEntry {
    pub path: &'static str,
    pub depth: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Applies `OwnershipChangeSpec` across matching inodes (honoring `recursive`) and returns an audit log.
pub fn apply_chown_tree(
    inodes: &mut [ChownInodeEntry],
    spec: OwnershipChangeSpec,
    recursive: bool,
) -> String {
    let mut log = String::new();
    for node in inodes.iter_mut() {
        if !recursive && node.depth > 0 {
            continue;
        }
        let old_u = node.uid;
        let old_g = node.gid;
        if let Some(u) = spec.new_uid {
            node.uid = u;
        }
        if let Some(g) = spec.new_gid {
            node.gid = g;
        }
        log.push_str(&format!(
            "changed ownership of '{}' from {}:{} to {}:{}\n",
            node.path, old_u, old_g, node.uid, node.gid
        ));
    }
    log
}

pub fn verify_util_chown() -> u32 {
    let mut passed = 0u32;

    if OwnershipChangeSpec::parse("root:wheel")
        == Ok(OwnershipChangeSpec {
            new_uid: Some(0),
            new_gid: Some(10),
        })
    {
        passed += 1;
    }

    if OwnershipChangeSpec::parse("coros:")
        == Ok(OwnershipChangeSpec {
            new_uid: Some(1000),
            new_gid: Some(1000),
        })
        && OwnershipChangeSpec::parse(":nogroup")
            == Ok(OwnershipChangeSpec {
                new_uid: None,
                new_gid: Some(65534),
            })
    {
        passed += 1;
    }

    let mut tree = [
        ChownInodeEntry { path: "/home/coros", depth: 0, uid: 0, gid: 0 },
        ChownInodeEntry { path: "/home/coros/.profile", depth: 1, uid: 0, gid: 0 },
    ];

    let spec = OwnershipChangeSpec::parse("1000:1000").unwrap();
    let log = apply_chown_tree(&mut tree, spec, true);
    if tree[0].uid == 1000 && tree[1].gid == 1000 && log.lines().count() == 2 {
        passed += 1;
    }

    passed
}
