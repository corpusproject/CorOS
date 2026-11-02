//! Windows NT Driver Model (WDM) I/O Request Packet (IRP) Architecture & IOCP
//!
//! Bare-metal no_std pure Rust implementation of Windows NT I/O subsystem:
//! - I/O Request Packets (IRP) with multi-tiered I/O Stack Locations
//! - NT Major Function Codes (IRP_MJ_CREATE, READ, WRITE, DEVICE_CONTROL, PNP, POWER)
//! - NT Device Objects (DEVICE_OBJECT) and Driver Objects (DRIVER_OBJECT)
//! - Asynchronous I/O Completion Ports (IOCP) for enterprise high-throughput I/O

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::collections::VecDeque;

pub type NtStatus = i32;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_PENDING: NtStatus = 0x00000103;
pub const STATUS_UNSUCCESSFUL: NtStatus = -1073741823; // 0xC0000001
pub const STATUS_NOT_IMPLEMENTED: NtStatus = -1073741822; // 0xC0000002
pub const STATUS_INVALID_PARAMETER: NtStatus = -1073741811; // 0xC000000D
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = -1073741789; // 0xC0000023
pub const STATUS_CANCELLED: NtStatus = -1073741536; // 0xC0000120

/// NT Major Function Codes
pub const IRP_MJ_CREATE: u8 = 0x00;
pub const IRP_MJ_CREATE_NAMED_PIPE: u8 = 0x01;
pub const IRP_MJ_CLOSE: u8 = 0x02;
pub const IRP_MJ_READ: u8 = 0x03;
pub const IRP_MJ_WRITE: u8 = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8 = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
pub const IRP_MJ_SHUTDOWN: u8 = 0x10;
pub const IRP_MJ_CLEANUP: u8 = 0x12;
pub const IRP_MJ_POWER: u8 = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8 = 0x17;
pub const IRP_MJ_PNP: u8 = 0x1B;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1C;

/// I/O Stack Location Completion Control Flags
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;

/// IO_STATUS_BLOCK
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub information: usize,
}

/// Device I/O Control Parameters
#[derive(Debug, Clone, Copy)]
pub struct DeviceIoControlParams {
    pub ioctl_code: u32,
    pub input_buffer_length: u32,
    pub output_buffer_length: u32,
}

/// Read / Write Parameters
#[derive(Debug, Clone, Copy)]
pub struct ReadWriteParams {
    pub length: u32,
    pub key: u32,
    pub byte_offset: u64,
}

/// Parameters for single stack location
#[derive(Debug, Clone, Copy)]
pub enum IoStackParams {
    None,
    Read(ReadWriteParams),
    Write(ReadWriteParams),
    DeviceIoControl(DeviceIoControlParams),
}

/// Single I/O Stack Location (IO_STACK_LOCATION)
#[derive(Debug, Clone)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub params: IoStackParams,
    pub device_id: u32,
    pub file_handle: u64,
}

impl IoStackLocation {
    pub fn empty() -> Self {
        Self {
            major_function: 0,
            minor_function: 0,
            flags: 0,
            control: 0,
            params: IoStackParams::None,
            device_id: 0,
            file_handle: 0,
        }
    }
}

/// Windows NT I/O Request Packet (IRP)
pub struct Irp {
    pub io_status: IoStatusBlock,
    pub flags: u32,
    pub user_buffer: Vec<u8>,
    pub stack_count: u8,
    pub current_location: u8,
    pub stacks: Vec<IoStackLocation>,
    pub cancel: bool,
}

impl Irp {
    pub fn new(stack_count: u8) -> Self {
        let count = stack_count.max(1) as usize;
        let mut stacks = Vec::with_capacity(count);
        for _ in 0..count {
            stacks.push(IoStackLocation::empty());
        }

        Self {
            io_status: IoStatusBlock {
                status: STATUS_PENDING,
                information: 0,
            },
            flags: 0,
            user_buffer: Vec::new(),
            stack_count,
            current_location: stack_count,
            stacks,
            cancel: false,
        }
    }

    /// Get current stack location for processing
    pub fn get_current_stack_location(&mut self) -> Option<&mut IoStackLocation> {
        if self.current_location == 0 || self.current_location as usize > self.stacks.len() {
            None
        } else {
            let idx = (self.current_location - 1) as usize;
            Some(&mut self.stacks[idx])
        }
    }

    /// Advance down device stack (IoSetNextIrpStackLocation)
    pub fn set_next_stack_location(&mut self) -> bool {
        if self.current_location > 0 {
            self.current_location -= 1;
            true
        } else {
            false
        }
    }

    /// Complete IRP with status and bytes transferred
    pub fn complete_request(&mut self, status: NtStatus, information: usize) {
        self.io_status.status = status;
        self.io_status.information = information;
    }
}

/// Windows NT Device Object (DEVICE_OBJECT)
pub struct DeviceObject {
    pub device_id: u32,
    pub driver_id: u32,
    pub device_type: u32,
    pub characteristics: u32,
    pub flags: u32,
    pub attached_device_id: Option<u32>,
}

/// Windows NT Driver Dispatch Table (DRIVER_OBJECT)
pub struct DriverObject {
    pub driver_id: u32,
    pub driver_name: &'static str,
    pub major_functions: [Option<fn(&mut Irp) -> NtStatus>; IRP_MJ_MAXIMUM_FUNCTION],
}

impl DriverObject {
    pub fn new(driver_id: u32, driver_name: &'static str) -> Self {
        Self {
            driver_id,
            driver_name,
            major_functions: [None; IRP_MJ_MAXIMUM_FUNCTION],
        }
    }

    pub fn set_dispatch(&mut self, major_func: u8, handler: fn(&mut Irp) -> NtStatus) {
        if (major_func as usize) < IRP_MJ_MAXIMUM_FUNCTION {
            self.major_functions[major_func as usize] = Some(handler);
        }
    }

    pub fn dispatch(&self, irp: &mut Irp) -> NtStatus {
        let major = if let Some(loc) = irp.get_current_stack_location() {
            loc.major_function as usize
        } else {
            return STATUS_INVALID_PARAMETER;
        };

        if major < IRP_MJ_MAXIMUM_FUNCTION {
            if let Some(handler) = self.major_functions[major] {
                return handler(irp);
            }
        }
        STATUS_NOT_IMPLEMENTED
    }
}

/// I/O Completion Packet
#[derive(Debug, Clone, Copy)]
pub struct CompletionPacket {
    pub completion_key: usize,
    pub bytes_transferred: u32,
    pub status: NtStatus,
    pub overlapped: u64,
}

/// Asynchronous I/O Completion Port (IOCP)
pub struct IoCompletionPort {
    pub port_id: u64,
    queue: VecDeque<CompletionPacket>,
}

impl IoCompletionPort {
    pub fn new(port_id: u64) -> Self {
        Self {
            port_id,
            queue: VecDeque::new(),
        }
    }

    /// Post completion status packet to IOCP queue
    pub fn post_status(&mut self, completion_key: usize, bytes: u32, status: NtStatus, overlapped: u64) {
        self.queue.push_back(CompletionPacket {
            completion_key,
            bytes_transferred: bytes,
            status,
            overlapped,
        });
    }

    /// Retrieve queued completion packet (GetQueuedCompletionStatus)
    pub fn get_status(&mut self) -> Option<CompletionPacket> {
        self.queue.pop_front()
    }
}
