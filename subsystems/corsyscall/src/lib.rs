#![no_std]
//! `corsyscall` — CorOS System Call ABI & Preemptive SMP Dispatch Crate.
//!
//! Contains 18 hand-crafted `#![no_std]` system call domain modules implementing
//! process management, virtual memory areas, VFS file descriptors, directory resolution,
//! BSD sockets, System V / POSIX IPC, real-time signals, timer wheels, CFS/RT SMP scheduling,
//! futex hash buckets, epoll/poll/select multiplexing, capabilities/seccomp, loadable modules,
//! mount namespaces, resource limits, extended attributes, `io_uring`, and native CorOS syscalls.

extern crate alloc;

pub mod process_lifecycle;
pub mod virtual_memory;
pub mod vfs_io;
pub mod directory_ops;
pub mod network_sockets;
pub mod ipc_pipes;
pub mod posix_signals;
pub mod timers_clocks;
pub mod smp_scheduling;
pub mod futex_sync;
pub mod io_multiplex;
pub mod security_caps;
pub mod module_ctl;
pub mod filesystem_ctl;
pub mod resource_limits;
pub mod extended_attrs;
pub mod io_uring_async;
pub mod coros_native;
pub mod syscall_table_x86;
pub mod syscall_table_asm_generic;
pub mod posix_sync_primitives;

pub use syscall_table_x86::X86SyscallFrame;
pub use syscall_table_asm_generic::{GenericSyscallFrame, x86_to_asm_generic, asm_generic_to_x86};
pub use posix_sync_primitives::{PthreadMutex, PthreadRwLock, PthreadCond, PosixSemaphore};

/// Executes comprehensive self-tests across all syscall domain modules.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += process_lifecycle::verify_domain_process_lifecycle();
    passed += virtual_memory::verify_domain_virtual_memory();
    passed += vfs_io::verify_domain_vfs_io();
    passed += directory_ops::verify_domain_directory_ops();
    passed += network_sockets::verify_domain_network_sockets();
    passed += ipc_pipes::verify_domain_ipc_pipes();
    passed += posix_signals::verify_domain_posix_signals();
    passed += timers_clocks::verify_domain_timers_clocks();
    passed += smp_scheduling::verify_domain_smp_scheduling();
    passed += futex_sync::verify_domain_futex_sync();
    passed += io_multiplex::verify_domain_io_multiplex();
    passed += security_caps::verify_domain_security_caps();
    passed += module_ctl::verify_domain_module_ctl();
    passed += filesystem_ctl::verify_domain_filesystem_ctl();
    passed += resource_limits::verify_domain_resource_limits();
    passed += extended_attrs::verify_domain_extended_attrs();
    passed += io_uring_async::verify_domain_io_uring_async();
    passed += coros_native::verify_domain_coros_native();
    passed += syscall_table_asm_generic::verify_domain_syscall_tables();
    passed += posix_sync_primitives::verify_domain_posix_sync_primitives();
    passed
}
