//! Linux & POSIX Binary Compatibility Subsystem for CorOS.
//!
//! Enables native execution of Linux x86_64 ELF userland binaries
//! without emulation or containerization overhead:
//! - POSIX Errno Definitions
//! - 64-bit Linux Syscall Dispatcher
//! - epoll I/O multiplexing event subsystem
//! - futex userspace synchronization subsystem
//! - pty UNIX98 pseudoterminal multiplexer
//! - pipe anonymous and named IPC FIFO subsystem
//! - eBPF 64-bit In-Kernel Virtual Machine, maps, and safety verifier

pub mod errno;
pub mod linux_syscalls;
pub mod epoll;
pub mod futex;
pub mod pty;
pub mod pipe;
pub mod ebpf;
pub mod namespaces;
pub mod cgroups;
pub mod wine_server;
pub mod seccomp;

pub use seccomp::{SeccompManager, SeccompProgram, SeccompData, SockFilter};
pub use errno::*;
pub use linux_syscalls::{LinuxSyscallDispatcher, LinuxStat, LinuxUtsName, LinuxTimespec};
pub use epoll::{EpollInstance, EpollTable, EpollEvent, EpollData};
pub use futex::{FutexManager, FutexWaiter};
pub use pty::{PtyMultiplexer, PtyPair, Termios, WinSize};
pub use pipe::{PipeTable, PipeRingBuffer};
pub use ebpf::{EbpfVm, EbpfInstruction, EbpfMap, EbpfMapRegistry, EbpfVerifier};
pub use namespaces::{ContainerNamespaceContext, UtsNamespace, UserNamespace, PidNamespace, NetNamespace, MountNamespace};
pub use cgroups::{CgroupManager, CgroupNode, CpuController, MemoryController, PidsController};
pub use wine_server::{WineServer, Win32Mutant, Win32Semaphore, Win32Event, EventResetMode, Win32AtomTable, NamedPipeInstance, Win32Mailslot};
