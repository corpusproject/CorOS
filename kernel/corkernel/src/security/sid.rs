//! Windows NT Security Identifier (SID) Engine for CorOS
//!
//! Represents variable-length security principals (Users, Groups, Computers, Services).
//! Standard format: S-R-I-S-S... (Revision, Identifier Authority, Subauthorities).

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sid {
    pub revision: u8,
    pub authority: u64, // 48-bit identifier authority
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    pub fn new(authority: u64, sub_authorities: &[u32]) -> Self {
        Self {
            revision: 1,
            authority,
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    /// S-1-5-18: NT AUTHORITY\SYSTEM (Local System)
    pub fn local_system() -> Self {
        Self::new(5, &[18])
    }

    /// S-1-5-19: NT AUTHORITY\LOCAL SERVICE
    pub fn local_service() -> Self {
        Self::new(5, &[19])
    }

    /// S-1-5-20: NT AUTHORITY\NETWORK SERVICE
    pub fn network_service() -> Self {
        Self::new(5, &[20])
    }

    /// S-1-5-32-544: BUILTIN\Administrators
    pub fn administrators() -> Self {
        Self::new(5, &[32, 544])
    }

    /// S-1-5-32-545: BUILTIN\Users
    pub fn standard_users() -> Self {
        Self::new(5, &[32, 545])
    }

    /// S-1-1-0: Everyone / World Principal
    pub fn everyone() -> Self {
        Self::new(1, &[0])
    }

    /// S-1-5-21-...-1000: Standard CorOS User Account
    pub fn coros_user(rid: u32) -> Self {
        Self::new(5, &[21, 1001, 2002, 3003, rid])
    }

    /// Converts the SID into its canonical string representation (e.g. "S-1-5-32-544")
    pub fn to_string(&self) -> String {
        let mut s = alloc::format!("S-{}-{}", self.revision, self.authority);
        for sub in &self.sub_authorities {
            s.push_str(&alloc::format!("-{}", sub));
        }
        s
    }

    /// Parses a string representation into a Sid
    pub fn from_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0] != "S" {
            return None;
        }

        let rev = parts[1].parse::<u8>().ok()?;
        let auth = parts[2].parse::<u64>().ok()?;
        let mut subs = Vec::new();

        for &part in &parts[3..] {
            subs.push(part.parse::<u32>().ok()?);
        }

        Some(Self {
            revision: rev,
            authority: auth,
            sub_authorities: subs,
        })
    }
}
