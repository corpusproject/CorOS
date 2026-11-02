//! Multitasking and Scheduling Subsystem for CorOS

pub mod context;
pub mod scheduler;
pub mod elf_loader;
pub mod usermode;
pub mod cfs;
pub mod posix_signals;
pub mod rt_scheduler;
pub mod posix_mq;
pub mod micro_ipc;
pub mod fibers;
pub mod pty;
pub mod security_bridge;
pub mod virt_ebpf_bridge;
pub mod ipc_namespaces_bridge;

pub use security_bridge::{SecurityBridge, GLOBAL_SECURITY_BRIDGE};
pub use virt_ebpf_bridge::{VirtEbpfBridge, GLOBAL_VIRT_EBPF_BRIDGE};
pub use ipc_namespaces_bridge::{IpcNamespacesBridge, GLOBAL_IPC_NAMESPACES_BRIDGE};
pub use crate::acpi::power_thermal_bridge::{PowerThermalBridge, PowerThermalStats, GLOBAL_POWER_THERMAL_BRIDGE};
pub use scheduler::{Task, TaskState, SCHEDULER, PREEMPTION_TICKS};
pub use elf_loader::{ElfLoader, LoadedProgram};
pub use usermode::{UserCrashReport, LAST_USER_CRASH};
pub use cfs::{CfsRunQueue, SchedEntity, TaskSchedState};
pub use posix_signals::{SignalManager, SigAction, SigSet, DefaultAction};
pub use rt_scheduler::{RtRunQueue, RtTaskEntity, RtPolicy, RtMutex, RT_PRIO_MAX};
pub use posix_mq::{PosixMessageQueue, MqRegistry, MqAttr, PosixMessage};
pub use micro_ipc::{Capability, CapabilitySpace, IpcEndpoint, MicroMessage, CAP_RIGHT_SEND, CAP_RIGHT_RECEIVE};
pub use fibers::{FiberManager, FiberControlBlock, FiberState, FiberContext};
pub use pty::{PtyMasterSlavePair, Termios, WinSize, PtySignal};

