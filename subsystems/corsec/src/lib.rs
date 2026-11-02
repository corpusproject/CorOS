#![no_std]
//! `corsec` — CorOS Linux Security Modules (`LSM`), Mandatory Access Control (`MAC`),
//! Landlock Sandboxing, Keyring, IMA Appraisal, Audit, Yama Ptrace, SYN Cookies,
//! ASLR Entropy & Kernel Lockdown Subsystem.

extern crate alloc;

pub mod aslr_entropy;
pub mod audit_daemon;
pub mod ima_appraisal;
pub mod kernel_keyring;
pub mod landlock_sandbox;
pub mod lockdown_mode;
pub mod lsm_hooks;
pub mod mac_policy;
pub mod syn_cookies;
pub mod yama_ptrace;

use alloc::string::String;

use aslr_entropy::{AslrLayoutGenerator, VmProtFlags, VmRegionDescriptor, WxViolationError};
use audit_daemon::{
    AuditDaemon, AuditEvent, AuditFilterAction, AuditFilterRule, AuditRecordType,
    AuditSubmitStatus, BacklogOverflowPolicy,
};
use ima_appraisal::{ sha256_digest, ImaAppraisalResult, ImaMeasureHook, ImaSubsystem};
use kernel_keyring::{
    KernelKeyringService, KeyCallerContext, KeyPerm, KeyType, KeyringError,
};
use landlock_sandbox::{
    FsAccessBit, LandlockError, LandlockRuleset, LandlockSandboxDomain, NetPortAccessBit,
};
use lockdown_mode::{KernelLockdownState, LockdownError, LockdownLevel, LockdownReason};
use lsm_hooks::{
    Capability, DomainIsolationModule, FilePermMask, InodeSecLabel, LsmError, LsmHookChain,
    SocketSecContext, TaskCreds,
};
use mac_policy::{AccessPermission, MacPolicyEngine, ObjectClass, SecurityLabel};
use syn_cookies::{SynCookieEngine, TcpEndpointTuple};
use yama_ptrace::{YamaError, YamaProcessNode, YamaPtraceEngine, YamaPtraceScope};

/// Executes comprehensive self-tests across all 10 `corsec` security modules and returns the number
/// of verified subsystems (`10` when all pass).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    if test_lsm_hooks() {
        passed += 1;
    }
    if test_mac_policy() {
        passed += 1;
    }
    if test_landlock_sandbox() {
        passed += 1;
    }
    if test_kernel_keyring() {
        passed += 1;
    }
    if test_ima_appraisal() {
        passed += 1;
    }
    if test_audit_daemon() {
        passed += 1;
    }
    if test_yama_ptrace() {
        passed += 1;
    }
    if test_syn_cookies() {
        passed += 1;
    }
    if test_aslr_entropy() {
        passed += 1;
    }
    if test_lockdown_mode() {
        passed += 1;
    }

    passed
}

fn test_lsm_hooks() -> bool {
    let mut iso = DomainIsolationModule::new(false);
    iso.add_restricted_domain("sandbox_app_t");
    iso.add_protected_inode_type("etc_shadow_t");

    let mut chain = LsmHookChain::new(iso);

    let root_creds = TaskCreds::new_root(1, "kernel_t");
    let mut user_creds = TaskCreds::new_unprivileged(42, 1000, 1000, "sandbox_app_t");
    user_creds.no_new_privs = true;

    let shadow_inode = InodeSecLabel::new(10, 0, 0, 0o644, "etc_shadow_t");
    let mut suid_bin = InodeSecLabel::new(20, 0, 0, 0o4755, "bin_t");
    suid_bin.is_suid = true;

    // Restricted domain must be denied access to protected inode even though mode 0644 has world-read
    if chain
        .eval_file_open(&user_creds, &shadow_inode, FilePermMask::MAY_READ)
        != Err(LsmError::PermissionDenied)
    {
        return false;
    }

    // no_new_privs task executing SUID root binary must be rejected by bprm_check_security
    if chain.eval_bprm_check_security(&user_creds, &suid_bin)
        != Err(LsmError::OperationNotPermitted)
    {
        return false;
    }

    // Privileged port bind (<1024) denied for unprivileged user, permitted for root
    let sock = SocketSecContext {
        owner_uid: 1000,
        security_label: String::from("sandbox_app_t"),
        local_port: 443,
        remote_ipv4: 0x0808_0808,
        remote_port: 443,
        is_loopback: false,
    };
    if chain.eval_socket_bind(&user_creds, &sock, 443) != Err(LsmError::PermissionDenied) {
        return false;
    }
    if chain.eval_socket_bind(&root_creds, &sock, 443).is_err() {
        return false;
    }

    // Outbound non-loopback connect blocked for restricted domain
    if chain.eval_socket_connect(&user_creds, &sock, 0x0808_0808, 443) != Err(LsmError::Sandboxed) {
        return false;
    }
    if chain.eval_capable(&root_creds, Capability::SysAdmin).is_err() {
        return false;
    }

    chain.total_evaluations >= 6 && chain.total_denials >= 4
}

fn test_mac_policy() -> bool {
    let Some(subj) = SecurityLabel::parse("system_u:system_r:httpd_t:s1") else {
        return false;
    };
    let Some(obj_same) = SecurityLabel::parse("system_u:object_r:httpd_content_t:s1") else {
        return false;
    };
    let Some(obj_secret) = SecurityLabel::parse("system_u:object_r:httpd_content_t:s2") else {
        return false;
    };

    let mut engine = MacPolicyEngine::new(8, true, true);
    engine.add_allow_rule(
        "httpd_t",
        "httpd_content_t",
        ObjectClass::File,
        AccessPermission::READ
            .union(AccessPermission::WRITE)
            .union(AccessPermission::GETATTR),
    );

    // Same sensitivity s1 -> s1: READ and WRITE allowed; populates AVC cache on first check
    if !engine.check_access(&subj, &obj_same, ObjectClass::File, AccessPermission::READ) {
        return false;
    }
    // Second check hits AVC cache
    if !engine.check_access(&subj, &obj_same, ObjectClass::File, AccessPermission::WRITE) {
        return false;
    }
    if engine.avc.hits == 0 {
        return false;
    }

    // Bell-LaPadula "no read up": s1 subject cannot READ s2 object even though TE allows httpd_t -> httpd_content_t
    if engine.check_access(&subj, &obj_secret, ObjectClass::File, AccessPermission::READ) {
        return false;
    }

    // Adding a deny rule increments policy_seqno, invalidating the cached WRITE grant
    engine.add_deny_rule(
        "httpd_t",
        "httpd_content_t",
        ObjectClass::File,
        AccessPermission::WRITE,
    );
    !engine.check_access(&subj, &obj_same, ObjectClass::File, AccessPermission::WRITE)
}

fn test_landlock_sandbox() -> bool {
    let handled_fs = FsAccessBit::READ_FILE
        .union(FsAccessBit::WRITE_FILE)
        .union(FsAccessBit::EXECUTE);
    let handled_net = NetPortAccessBit::BIND_TCP.union(NetPortAccessBit::CONNECT_TCP);

    let mut layer_one = LandlockRuleset::new(handled_fs, handled_net);
    if layer_one
        .add_path_beneath_rule("/srv/www", FsAccessBit::READ_FILE.union(FsAccessBit::WRITE_FILE))
        .is_err()
    {
        return false;
    }
    if layer_one
        .add_net_port_rule(8080, NetPortAccessBit::BIND_TCP)
        .is_err()
    {
        return false;
    }

    // Second stacked layer restricts /srv/www/public to READ_FILE only (intersecting out WRITE_FILE)
    let mut layer_two = LandlockRuleset::new(handled_fs, NetPortAccessBit::NONE);
    if layer_two
        .add_path_beneath_rule("/srv/www/public", FsAccessBit::READ_FILE)
        .is_err()
    {
        return false;
    }

    let mut domain = LandlockSandboxDomain::new();
    if domain.restrict_self(layer_one).is_err() || domain.restrict_self(layer_two).is_err() {
        return false;
    }

    let read_ok = domain
        .check_fs_access("/srv/www/public/index.html", FsAccessBit::READ_FILE)
        .is_ok();
    let write_blocked = domain
        .check_fs_access("/srv/www/public/index.html", FsAccessBit::WRITE_FILE)
        == Err(LandlockError::AccessDenied);
    let port_ok = domain
        .check_net_port_access(8080, NetPortAccessBit::BIND_TCP)
        .is_ok();
    let port_blocked = domain
        .check_net_port_access(9090, NetPortAccessBit::BIND_TCP)
        == Err(LandlockError::AccessDenied);

    read_ok && write_blocked && port_ok && port_blocked && domain.layer_count() == 2
}

fn test_kernel_keyring() -> bool {
    let mut service = KernelKeyringService::new(256, 8);
    let full_perm = KeyPerm::from_roles(KeyPerm::ALL_SIX, KeyPerm::ALL_SIX, 0, 0);

    let Ok(session_ring) = service.create_keyring("_ses", 1000, 1000, full_perm) else {
        return false;
    };

    let caller = KeyCallerContext {
        uid: 1000,
        gid: 1000,
        process_keyring: None,
        session_keyring: Some(session_ring),
        user_keyring: None,
    };

    let Ok(user_key) = service.add_key(
        &caller,
        KeyType::User,
        "fs_master_key",
        b"super_secret_32_byte_aes_payload",
        full_perm,
        Some(session_ring),
        100,
    ) else {
        return false;
    };

    let Ok(logon_key) = service.add_key(
        &caller,
        KeyType::Logon,
        "cifs:domain_token",
        b"kernel_only_secret",
        full_perm,
        Some(session_ring),
        100,
    ) else {
        return false;
    };

    // Request key through session keyring search
    if service.request_key(&caller, KeyType::User, "fs_master_key", 105) != Ok(user_key) {
        return false;
    }
    // User key payload is readable, whereas Logon key payload is forbidden from user space
    if service.read_key_payload(&caller, user_key, 105).is_err() {
        return false;
    }
    if service.read_key_payload(&caller, logon_key, 105) != Err(KeyringError::LogonKeyUnreadable) {
        return false;
    }

    // Expiration check
    let _ = service.set_key_timeout(&caller, user_key, 200, 110);
    if service.read_key_payload(&caller, user_key, 250) != Err(KeyringError::KeyExpired) {
        return false;
    }

    // Revocation check
    let _ = service.revoke_key(&caller, logon_key, 110);
    service.read_key_payload(&caller, logon_key, 115) == Err(KeyringError::KeyRevoked)
}

fn test_ima_appraisal() -> bool {
    let mut ima = ImaSubsystem::new(true);
    let sshd_elf = b"\x7fELF_coros_sshd_binary_image_v1";
    let golden_hash = sha256_digest(sshd_elf);

    ima.register_golden_digest("/usr/sbin/sshd", golden_hash);

    if ima.measure_and_appraise("/usr/sbin/sshd", sshd_elf, ImaMeasureHook::BprmCheck)
        != ImaAppraisalResult::Verified
    {
        return false;
    }

    // Tampered binary image must fail appraisal and extend PCR-10 with the new measurement
    let tampered_elf = b"\x7fELF_coros_sshd_binary_image_TAMPERED";
    if ima.measure_and_appraise("/usr/sbin/sshd", tampered_elf, ImaMeasureHook::BprmCheck)
        != ImaAppraisalResult::HashMismatch
    {
        return false;
    }

    ima.entries().len() == 2 && ima.verify_log_integrity()
}

fn test_audit_daemon() -> bool {
    let mut daemon = AuditDaemon::new(2, BacklogOverflowPolicy::DropNewest);
    daemon.add_filter_rule(AuditFilterRule {
        match_uid: Some(9999),
        match_syscall: None,
        match_record_type: None,
        action: AuditFilterAction::NeverLog,
    });

    let suppressed_ev = AuditEvent {
        record_type: AuditRecordType::Syscall,
        timestamp_sec: 1700000000,
        timestamp_millis: 42,
        pid: 500,
        uid: 9999,
        auid: 9999,
        syscall_nr: Some(59),
        success: true,
        subject_context: String::from("user_u:user_r:user_t:s0"),
        object_name: String::from("/bin/ls"),
        detail: String::from("filtered_noise"),
    };
    if daemon.submit_event(&suppressed_ev) != AuditSubmitStatus::FilteredOut {
        return false;
    }

    let avc_ev = AuditEvent {
        record_type: AuditRecordType::AvcDenial,
        timestamp_sec: 1700000001,
        timestamp_millis: 7,
        pid: 601,
        uid: 1000,
        auid: 1000,
        syscall_nr: Some(257),
        success: false,
        subject_context: String::from("system_u:system_r:httpd_t:s0"),
        object_name: String::from("/etc/shadow"),
        detail: String::from("avc: denied { read }"),
    };

    if daemon.submit_event(&avc_ev) != AuditSubmitStatus::Logged(1) {
        return false;
    }
    if daemon.submit_event(&avc_ev) != AuditSubmitStatus::Logged(2) {
        return false;
    }
    // Third event overflows max_backlog=2 under DropNewest
    if daemon.submit_event(&avc_ev) != AuditSubmitStatus::DroppedBacklogFull {
        return false;
    }

    let Some(first_record) = daemon.pop_record() else {
        return false;
    };
    first_record.starts_with("type=AVC msg=audit(1700000001.007:1):") && daemon.lost_count == 1
}

fn test_yama_ptrace() -> bool {
    let mut yama = YamaPtraceEngine::new(YamaPtraceScope::RestrictedDescendant);

    // Lineage: parent_shell (100) -> child_worker (200) -> grandchild (300); unrelated_peer (400)
    for (pid, ppid) in [(100, 1), (200, 100), (300, 200), (400, 1)] {
        yama.register_process(YamaProcessNode {
            pid,
            parent_pid: ppid,
            uid: 1000,
            euid: 1000,
            dumpable: true,
            has_cap_sys_ptrace: false,
        });
    }

    // Ancestor 100 can trace descendant 300
    if yama.check_ptrace_access(100, 300).is_err() {
        return false;
    }
    // Unrelated peer 400 cannot trace 300 unless authorized via PR_SET_PTRACER
    if yama.check_ptrace_access(400, 300) != Err(YamaError::NotAncestorOrAuthorized) {
        return false;
    }

    // Tracee 300 grants PR_SET_PTRACER to 400
    yama.set_ptracer_exception(300, 400);
    if yama.check_ptrace_access(400, 300).is_err() {
        return false;
    }

    // Escalate to NoAttach (3) and verify irreversible lock
    if yama.set_scope(YamaPtraceScope::NoAttach).is_err() {
        return false;
    }
    yama.check_ptrace_access(100, 300) == Err(YamaError::PtraceLockedOut)
        && yama.set_scope(YamaPtraceScope::Classic) == Err(YamaError::ScopeLockedIrrevocably)
}

fn test_syn_cookies() -> bool {
    let mut engine = SynCookieEngine::new(
        0x1122_3344_5566_7788,
        0x99AA_BBCC_DDEE_FF00,
        0xCAFE_BABE_DEAD_BEEF,
        0x0123_4567_89AB_CDEF,
    );
    let tuple = TcpEndpointTuple {
        client_ipv4: 0xC0A8_0164,
        server_ipv4: 0x0A00_0001,
        client_port: 54321,
        server_port: 443,
    };
    let client_isn = 0x7654_3210;
    let cookie = engine.generate_syn_cookie(&tuple, client_isn, 1460, 60_000);

    // Validated 30 seconds later -> must recover MSS 1460
    if engine.validate_ack_cookie(&tuple, client_isn, cookie, 60_030) != Some(1460) {
        return false;
    }

    // Expired 300 seconds (5 counter ticks) later -> must reject
    if engine.validate_ack_cookie(&tuple, client_isn, cookie, 60_300).is_some() {
        return false;
    }

    // Forged cookie -> must reject
    engine
        .validate_ack_cookie(&tuple, client_isn, cookie.wrapping_add(0x1337), 60_030)
        .is_none()
}

fn test_aslr_entropy() -> bool {
    let mut rng = AslrLayoutGenerator::new(0xA5A5_5A5A_F0F0_0F0F);
    let layout_first = rng.generate_layout();
    let layout_second = rng.generate_layout();

    if !layout_first.is_valid_layout() || !layout_second.is_valid_layout() {
        return false;
    }
    if layout_first.pie_load_base == layout_second.pie_load_base
        || layout_first.mmap_base == layout_second.mmap_base
    {
        return false;
    }

    let rx_code = VmRegionDescriptor {
        start_va: layout_first.pie_load_base,
        end_va: layout_first.pie_load_base + 0x4000,
        prot: VmProtFlags::READ.union(VmProtFlags::EXEC),
    };
    let rwx_bad = VmRegionDescriptor {
        start_va: layout_first.mmap_base,
        end_va: layout_first.mmap_base + 0x2000,
        prot: VmProtFlags::READ
            .union(VmProtFlags::WRITE)
            .union(VmProtFlags::EXEC),
    };

    AslrLayoutGenerator::verify_wx_region(&rx_code).is_ok()
        && AslrLayoutGenerator::verify_wx_region(&rwx_bad)
            == Err(WxViolationError::SimultaneousWriteAndExec)
}

fn test_lockdown_mode() -> bool {
    let mut lockdown = KernelLockdownState::new(LockdownLevel::None);

    // At None, unsigned module loading is permitted
    if lockdown
        .is_locked_down(LockdownReason::UnsignedModuleLoad)
        .is_err()
    {
        return false;
    }

    // Escalate to Integrity: blocks UnsignedModuleLoad & MsrRawWrite, still permits KernelCoreDumpRead
    if lockdown.escalate_to(LockdownLevel::Integrity).is_err() {
        return false;
    }
    if lockdown
        .is_locked_down(LockdownReason::UnsignedModuleLoad)
        .is_ok()
        || lockdown.is_locked_down(LockdownReason::MsrRawWrite).is_ok()
    {
        return false;
    }
    if lockdown
        .is_locked_down(LockdownReason::KernelCoreDumpRead)
        .is_err()
    {
        return false;
    }

    // De-escalation from Integrity to None must fail
    if !matches!(
        lockdown.escalate_to(LockdownLevel::None),
        Err(LockdownError::CannotDeescalate { .. })
    ) {
        return false;
    }

    // Escalate to Confidentiality: blocks KernelCoreDumpRead and PerfRawKernelTrace
    if lockdown.escalate_to(LockdownLevel::Confidentiality).is_err() {
        return false;
    }
    lockdown
        .is_locked_down(LockdownReason::KernelCoreDumpRead)
        .is_err()
        && lockdown
            .is_locked_down(LockdownReason::PerfRawKernelTrace)
            .is_err()
}
