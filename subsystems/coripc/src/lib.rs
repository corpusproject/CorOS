#![no_std]
//! `coripc` — CorOS Linux Container Namespaces, Cgroups v2, Unix Domain Sockets,
//! POSIX Message Queues, D-Bus Wire Protocol, PI-Futex, Shared-Memory Ring Channels,
//! and Capability Binder RPC Subsystem.

extern crate alloc;

pub mod binder_rpc;
pub mod cgroup_v2;
pub mod dbus_wire;
pub mod futex_pi;
pub mod mount_uts_ns;
pub mod net_namespace;
pub mod pid_namespace;
pub mod posix_mqueue;
pub mod ring_channel;
pub mod unix_domain;

/// Execute self-tests across all 10 `coripc` modules and return the number of passing suites.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    if cgroup_v2::self_test() {
        passed += 1;
    }
    if pid_namespace::self_test() {
        passed += 1;
    }
    if mount_uts_ns::self_test() {
        passed += 1;
    }
    if net_namespace::self_test() {
        passed += 1;
    }
    if unix_domain::self_test() {
        passed += 1;
    }
    if posix_mqueue::self_test() {
        passed += 1;
    }
    if dbus_wire::self_test() {
        passed += 1;
    }
    if futex_pi::self_test() {
        passed += 1;
    }
    if ring_channel::self_test() {
        passed += 1;
    }
    if binder_rpc::self_test() {
        passed += 1;
    }
    passed
}
