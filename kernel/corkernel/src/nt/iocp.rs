//! Windows NT Asynchronous I/O Completion Ports (IOCP) & APC Architecture
//!
//! Bare-metal no_std pure Rust implementation of Windows NT I/O Completion Ports:
//! - CreateIoCompletionPort / NtCreateIoCompletion
//! - PostQueuedCompletionStatus / NtSetIoCompletion
//! - GetQueuedCompletionStatus / NtRemoveIoCompletion
//! - Thread pool concurrency throttle & queue dispatching
//! - Asynchronous Procedure Calls (APC: Special Kernel APC, Normal Kernel APC, User APC)

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub type NtStatus = i32;
pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_TIMEOUT: NtStatus = 0x00000102;
pub const STATUS_INVALID_HANDLE: NtStatus = -1073741816; // 0xC0000008

/// IO_COMPLETION_PACKET
#[derive(Debug, Clone, Copy)]
pub struct IoCompletionPacket {
    pub completion_key: usize,
    pub overlapped: u64,
    pub status: NtStatus,
    pub bytes_transferred: u32,
}

/// Windows NT I/O Completion Port Object
pub struct IoCompletionPort {
    pub handle: u64,
    pub number_of_concurrent_threads: u32,
    pub current_active_threads: u32,
    pub queue: VecDeque<IoCompletionPacket>,
    pub associated_devices: Vec<u64>,
}

impl IoCompletionPort {
    pub fn new(handle: u64, max_concurrency: u32) -> Self {
        Self {
            handle,
            number_of_concurrent_threads: max_concurrency,
            current_active_threads: 0,
            queue: VecDeque::new(),
            associated_devices: Vec::new(),
        }
    }

    /// Associate a file/device handle with this completion port
    pub fn associate_file(&mut self, file_handle: u64) {
        if !self.associated_devices.contains(&file_handle) {
            self.associated_devices.push(file_handle);
        }
    }

    /// Post completion status into the port queue (PostQueuedCompletionStatus)
    pub fn post_status(
        &mut self,
        completion_key: usize,
        bytes_transferred: u32,
        status: NtStatus,
        overlapped: u64,
    ) {
        self.queue.push_back(IoCompletionPacket {
            completion_key,
            overlapped,
            status,
            bytes_transferred,
        });
    }

    /// Retrieve queued completion status (GetQueuedCompletionStatus)
    pub fn get_status(&mut self) -> Option<IoCompletionPacket> {
        self.queue.pop_front()
    }

    /// Check if queue has pending completion packets
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Number of queued packets
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }
}

/// Asynchronous Procedure Call (APC) Environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcEnvironment {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
}

/// Kernel APC Priority Level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcMode {
    KernelMode,
    UserMode,
}

/// Asynchronous Procedure Call Control Block (KAPC)
pub struct Kapc {
    pub target_thread_id: u64,
    pub mode: ApcMode,
    pub is_special_kernel_apc: bool,
    pub kernel_routine: fn(arg1: usize, arg2: usize),
    pub user_routine: Option<u64>,
    pub normal_context: usize,
    pub system_argument1: usize,
    pub system_argument2: usize,
    pub is_inserted: bool,
}

impl Kapc {
    pub fn new_kernel(
        target_thread_id: u64,
        is_special: bool,
        kernel_routine: fn(usize, usize),
        arg1: usize,
        arg2: usize,
    ) -> Self {
        Self {
            target_thread_id,
            mode: ApcMode::KernelMode,
            is_special_kernel_apc: is_special,
            kernel_routine,
            user_routine: None,
            normal_context: 0,
            system_argument1: arg1,
            system_argument2: arg2,
            is_inserted: true,
        }
    }

    pub fn execute(&self) {
        (self.kernel_routine)(self.system_argument1, self.system_argument2);
    }
}

/// Thread APC Queue
pub struct ApcQueue {
    pub special_kernel_apcs: VecDeque<Kapc>,
    pub normal_kernel_apcs: VecDeque<Kapc>,
    pub user_apcs: VecDeque<Kapc>,
}

impl ApcQueue {
    pub fn new() -> Self {
        Self {
            special_kernel_apcs: VecDeque::new(),
            normal_kernel_apcs: VecDeque::new(),
            user_apcs: VecDeque::new(),
        }
    }

    pub fn queue_apc(&mut self, apc: Kapc) {
        match apc.mode {
            ApcMode::KernelMode => {
                if apc.is_special_kernel_apc {
                    self.special_kernel_apcs.push_back(apc);
                } else {
                    self.normal_kernel_apcs.push_back(apc);
                }
            }
            ApcMode::UserMode => {
                self.user_apcs.push_back(apc);
            }
        }
    }

    /// Deliver next runnable kernel APC
    pub fn deliver_kernel_apc(&mut self) -> bool {
        if let Some(apc) = self.special_kernel_apcs.pop_front() {
            apc.execute();
            return true;
        }
        if let Some(apc) = self.normal_kernel_apcs.pop_front() {
            apc.execute();
            return true;
        }
        false
    }
}
