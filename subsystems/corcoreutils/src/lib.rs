#![no_std]
//! `corcoreutils` — CorOS 27 Userland Coreutils & Interactive Shell Suite.
//!
//! Every utility module implements genuine `#![no_std]` flag parsing, data processing,
//! and formatted output generation for its respective POSIX/Linux command.

extern crate alloc;

pub mod util_ls;
pub mod util_cat;
pub mod util_grep;
pub mod util_awk;
pub mod util_sed;
pub mod util_tar;
pub mod util_find;
pub mod util_ps;
pub mod util_top;
pub mod util_kill;
pub mod util_mount;
pub mod util_df;
pub mod util_free;
pub mod util_lspci;
pub mod util_lsusb;
pub mod util_lsmod;
pub mod util_dmesg;
pub mod util_ip;
pub mod util_ping;
pub mod util_netstat;
pub mod util_ss;
pub mod util_chmod;
pub mod util_chown;
pub mod util_uname;
pub mod util_sysctl;
pub mod util_syscall_test;
pub mod util_driver_bench;

/// Runs automated self-tests across all 27 userland coreutil modules.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += util_ls::verify_util_ls();
    passed += util_cat::verify_util_cat();
    passed += util_grep::verify_util_grep();
    passed += util_awk::verify_util_awk();
    passed += util_sed::verify_util_sed();
    passed += util_tar::verify_util_tar();
    passed += util_find::verify_util_find();
    passed += util_ps::verify_util_ps();
    passed += util_top::verify_util_top();
    passed += util_kill::verify_util_kill();
    passed += util_mount::verify_util_mount();
    passed += util_df::verify_util_df();
    passed += util_free::verify_util_free();
    passed += util_lspci::verify_util_lspci();
    passed += util_lsusb::verify_util_lsusb();
    passed += util_lsmod::verify_util_lsmod();
    passed += util_dmesg::verify_util_dmesg();
    passed += util_ip::verify_util_ip();
    passed += util_ping::verify_util_ping();
    passed += util_netstat::verify_util_netstat();
    passed += util_ss::verify_util_ss();
    passed += util_chmod::verify_util_chmod();
    passed += util_chown::verify_util_chown();
    passed += util_uname::verify_util_uname();
    passed += util_sysctl::verify_util_sysctl();
    passed += util_syscall_test::verify_util_syscall_test();
    passed += util_driver_bench::verify_util_driver_bench();
    passed
}
