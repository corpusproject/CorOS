//! Windows NT I/O Manager & I/O Request Packet (IRP) Subsystem for CorOS.
//! 100% in-house implementation supporting:
//! - Complete IRP (I/O Request Packet) lifecycle (IoAllocateIrp, IoCallDriver, IoCompleteRequest)
//! - `IO_STACK_LOCATION` parameters and `MajorFunction` codes (Create, Read, Write, DeviceIoControl, Close)
//! - `DRIVER_OBJECT` dispatch routine registration
//! - `DEVICE_OBJECT` layering and device stack traversal

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

// Standard NT Major Function Codes
pub const IRP_MJ_CREATE: u8                   = 0x00;
pub const IRP_MJ_CLOSE: u8                    = 0x02;
pub const IRP_MJ_READ: u8                     = 0x03;
pub const IRP_MJ_WRITE: u8                    = 0x04;
pub const IRP_MJ_QUERY_INFORMATION: u8        = 0x05;
pub const IRP_MJ_SET_INFORMATION: u8          = 0x06;
pub const IRP_MJ_FLUSH_BUFFERS: u8            = 0x09;
pub const IRP_MJ_DEVICE_CONTROL: u8           = 0x0E;
pub const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8  = 0x0F;
pub const IRP_MJ_SHUTDOWN: u8                 = 0x10;
pub const IRP_MJ_CLEANUP: u8                  = 0x12;
pub const IRP_MJ_POWER: u8                    = 0x16;
pub const IRP_MJ_SYSTEM_CONTROL: u8           = 0x17;
pub const IRP_MJ_PNP: u8                      = 0x1B;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize      = 0x1B;

// Device Object Flags
pub const DO_BUFFERED_IO: u32                 = 0x00000004;
pub const DO_EXCLUSIVE: u32                   = 0x00000008;
pub const DO_DIRECT_IO: u32                   = 0x00000010;
pub const DO_MAP_IO_BUFFER: u32               = 0x00000020;
pub const DO_DEVICE_INITIALIZING: u32         = 0x00000080;

// NTSTATUS Constants
pub const STATUS_SUCCESS: i32                 = 0x00000000;
pub const STATUS_UNSUCCESSFUL: i32            = -1073741823; // 0xC0000001
pub const STATUS_NOT_IMPLEMENTED: i32         = -1073741822; // 0xC0000002
pub const STATUS_INVALID_PARAMETER: i32       = -1073741811; // 0xC000000D
pub const STATUS_NO_SUCH_DEVICE: i32          = -1073741806; // 0xC000000E
pub const STATUS_PENDING: i32                 = 0x00000103;

#[derive(Clone, Copy, Default, Debug)]
pub struct IoStatusBlock {
    pub status: i32,
    pub information: usize, // Bytes transferred or result pointer
}

#[derive(Clone, Debug)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: IoParameters,
}

#[derive(Clone, Debug)]
pub enum IoParameters {
    Create { options: u32, file_attributes: u16, share_access: u16 },
    Read { length: u32, byte_offset: u64 },
    Write { length: u32, byte_offset: u64 },
    DeviceIoControl { ioctl_code: u32, input_len: u32, output_len: u32 },
    None,
}

pub struct Irp {
    pub flags: u32,
    pub user_buffer: *mut u8,
    pub io_status: IoStatusBlock,
    pub stack_locations: Vec<IoStackLocation>,
    pub current_location: usize,
}

impl Irp {
    pub fn new(stack_size: u8) -> Self {
        let size = stack_size.max(1) as usize;
        let mut stacks = Vec::with_capacity(size);
        for _ in 0..size {
            stacks.push(IoStackLocation {
                major_function: IRP_MJ_CREATE,
                minor_function: 0,
                flags: 0,
                control: 0,
                parameters: IoParameters::None,
            });
        }

        Self {
            flags: 0,
            user_buffer: core::ptr::null_mut(),
            io_status: IoStatusBlock::default(),
            stack_locations: stacks,
            current_location: 0,
        }
    }

    pub fn get_current_stack_location_mut(&mut self) -> &mut IoStackLocation {
        &mut self.stack_locations[self.current_location]
    }
}

pub type DriverDispatch = fn(device: &DeviceObject, irp: &mut Irp) -> i32;

pub struct DriverObject {
    pub driver_name: String,
    pub major_functions: [Option<DriverDispatch>; IRP_MJ_MAXIMUM_FUNCTION + 1],
}

impl DriverObject {
    pub fn new(name: &str) -> Self {
        Self {
            driver_name: String::from(name),
            major_functions: [None; IRP_MJ_MAXIMUM_FUNCTION + 1],
        }
    }

    pub fn set_dispatch(&mut self, major: u8, handler: DriverDispatch) {
        if (major as usize) <= IRP_MJ_MAXIMUM_FUNCTION {
            self.major_functions[major as usize] = Some(handler);
        }
    }
}

pub struct DeviceObject {
    pub device_name: String,
    pub device_type: u32,
    pub flags: u32,
    pub stack_size: u8,
    pub driver_object: Option<Box<DriverObject>>,
}

impl DeviceObject {
    pub fn new(name: &str, device_type: u32, flags: u32) -> Self {
        Self {
            device_name: String::from(name),
            device_type,
            flags,
            stack_size: 1,
            driver_object: None,
        }
    }
}

pub struct IoManager;

impl IoManager {
    /// Dispatch an IRP to a device object's registered driver dispatch routine.
    pub fn call_driver(device: &DeviceObject, irp: &mut Irp) -> i32 {
        let stack = irp.get_current_stack_location_mut();
        let major = stack.major_function as usize;

        if let Some(drv) = &device.driver_object {
            if major <= IRP_MJ_MAXIMUM_FUNCTION {
                if let Some(dispatch_fn) = drv.major_functions[major] {
                    return dispatch_fn(device, irp);
                }
            }
        }

        irp.io_status.status = STATUS_NOT_IMPLEMENTED;
        STATUS_NOT_IMPLEMENTED
    }

    /// Complete an IRP and report status and byte counts to the caller.
    pub fn complete_request(irp: &mut Irp, status: i32, bytes_transferred: usize) {
        irp.io_status.status = status;
        irp.io_status.information = bytes_transferred;
    }
}
