//! CorOS Windows NT Executive & Object Manager Subsystem
//!
//! Replicates the architecture of the Windows NT kernel Executive:
//! - Object Manager (Ob): Unified reference counted kernel objects & namespace directory
//! - Handle Tables (Ex): Process-level handle translation & access validation
//! - Executive Resources (Ex): Fast shared-exclusive pushlocks & worker queues
//! - I/O Manager (Io): I/O Request Packets (IRP) & Driver Stack
//! - Process Manager (Ps): EPROCESS, ETHREAD, PEB, TEB
//! - Kernel Dispatcher (Ke): KEVENT, KSEMAPHORE, KMUTANT, KTIMER
//! - Security Subsystem (Se): Security Descriptors, SIDs, DACLs, AccessCheck
//! - Executive Workers (Ex): Critical, Delayed, and HyperCritical worker queues

pub mod object;
pub mod handle;
pub mod executive;
pub mod io_manager;
pub mod process_manager;
pub mod namespace;
pub mod ke_event;
pub mod security_descriptor;
pub mod executive_worker;
pub mod alpc;
pub mod section;
pub mod iocp;

pub use object::{ObjectManager, ObjectHeader, ObjectType, KernelObject};
pub use handle::{HandleTable, HandleEntry, Handle};
pub use executive::{ExecutiveResource, WorkQueue, WorkItem};
pub use io_manager::{IoManager, Irp, DriverObject, DeviceObject, IoStatusBlock, IoParameters};
pub use process_manager::{Eprocess, Ethread, Peb, Teb, ClientId};
pub use namespace::{NtNamespace, NtObjectType, NtHandle};
pub use ke_event::{KeEvent, KeSemaphore, KeMutant, KeTimer, DispatcherHeader, DispatcherRegistry};
pub use security_descriptor::{SecurityDescriptor, Sid, Acl, Ace};
pub use executive_worker::{ExecutiveWorkerManager, WorkQueueItem, WorkQueueType, WorkerRoutine};
pub use alpc::{AlpcManager, AlpcPort, AlpcPortMessage, AlpcMessageType, AlpcPortType};
pub use section::{SectionManager, SectionObject, SectionView, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ};
pub use iocp::{IoCompletionPort, IoCompletionPacket, Kapc, ApcQueue, ApcMode};

