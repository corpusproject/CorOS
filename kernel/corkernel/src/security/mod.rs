//! CorOS Security Reference Monitor (SRM) & Access Control Subsystem
//!
//! Implements enterprise-grade Windows NT / POSIX compatible security models:
//! - Security Identifiers (SIDs)
//! - Access Control Lists (DACL / SACL) and Access Control Entries (ACEs)
//! - Process Access Tokens & Privilege Matrices
//! - Kernel Security Auditing Engine

pub mod sid;
pub mod acl;
pub mod token;
pub mod audit;
pub mod selinux;
pub mod apparmor;
pub mod app_sandbox;
pub mod tpm2;

pub use sid::Sid;
pub use acl::{Acl, Ace, AceType, AccessMask};
pub use token::{SecurityToken, Privilege};
pub use audit::{SecurityAuditor, AuditRecord, AuditEventId, GLOBAL_AUDITOR};
pub use selinux::{SelinuxEngine, SelinuxMode, SecurityClass, SecurityContext, SelinuxSid};
pub use apparmor::{AppArmorManager, AppArmorProfile, AppArmorMode, PathRule};
pub use app_sandbox::{AppContainerProfile, SandboxPathRule, PathAccessLevel, LandlockRuleset, SandboxReferenceMonitor};
pub use tpm2::{Tpm2Device, Tpm2PcrBank, Tpm2CommandHeader, Tpm2ResponseHeader};
