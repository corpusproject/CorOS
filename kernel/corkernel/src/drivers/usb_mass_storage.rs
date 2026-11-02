//! USB Mass Storage Class (MSC) Bulk-Only Transport (BOT) Driver
//!
//! Implements USB Mass Storage BOT 1.0 & SCSI Transparent Command Set:
//! - Command Block Wrapper (CBW) formatting and validation
//! - Command Status Wrapper (CSW) status checking and residue handling
//! - SCSI INQUIRY (0x12) - Vendor, Product ID, Firmware Revision extraction
//! - SCSI READ CAPACITY 10 (0x25) / 16 (0x9E) - Total LBA and sector size (typically 512 or 4096)
//! - SCSI READ 10 (0x28) - Multi-block sector reading over Bulk-In endpoint
//! - SCSI WRITE 10 (0x2A) - Multi-block sector writing over Bulk-Out endpoint
//! - SCSI TEST UNIT READY (0x00) & REQUEST SENSE (0x03) - Drive readiness and error reporting
//! - Flash drive hotplug enumeration and block device interface integration

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

/// Command Block Wrapper Signature 'USBC' (0x43425355)
pub const CBW_SIGNATURE: u32 = 0x43425355;

/// Command Status Wrapper Signature 'USBS' (0x53425355)
pub const CSW_SIGNATURE: u32 = 0x53425355;

/// CBW Direction Flags
pub const CBW_DIR_HOST_TO_DEVICE: u8 = 0x00;
pub const CBW_DIR_DEVICE_TO_HOST: u8 = 0x80;

/// CSW Status Codes
pub const CSW_STATUS_COMMAND_PASSED: u8 = 0x00;
pub const CSW_STATUS_COMMAND_FAILED: u8 = 0x01;
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

/// SCSI Operation Codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiOpcode {
    TestUnitReady = 0x00,
    RequestSense = 0x03,
    Inquiry = 0x12,
    ModeSense6 = 0x1A,
    StartStopUnit = 0x1B,
    ReadCapacity10 = 0x25,
    Read10 = 0x28,
    Write10 = 0x2A,
    SynchronizeCache10 = 0x35,
    ReadCapacity16 = 0x9E,
}

/// USB Mass Storage Command Block Wrapper (31 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CommandBlockWrapper {
    pub signature: u32,
    pub tag: u32,
    pub data_transfer_length: u32,
    pub flags: u8,
    pub lun: u8,
    pub cb_length: u8,
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    pub fn new(tag: u32, length: u32, dir_in: bool, lun: u8, cmd_bytes: &[u8]) -> Self {
        let mut cb = [0u8; 16];
        let len = cmd_bytes.len().min(16);
        cb[..len].copy_from_slice(&cmd_bytes[..len]);

        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: length,
            flags: if dir_in { CBW_DIR_DEVICE_TO_HOST } else { CBW_DIR_HOST_TO_DEVICE },
            lun: lun & 0x0F,
            cb_length: len as u8,
            cb,
        }
    }

    pub fn to_bytes(&self) -> [u8; 31] {
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// USB Mass Storage Command Status Wrapper (13 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CommandStatusWrapper {
    pub signature: u32,
    pub tag: u32,
    pub data_residue: u32,
    pub status: u8,
}

impl CommandStatusWrapper {
    pub fn parse(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 13 {
            return Err("Buffer too small for CSW");
        }
        let csw: Self = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const _) };
        if csw.signature != CSW_SIGNATURE {
            return Err("Invalid CSW signature");
        }
        Ok(csw)
    }

    pub fn is_success(&self) -> bool {
        self.status == CSW_STATUS_COMMAND_PASSED
    }
}

/// SCSI INQUIRY Response Header and Data (36 bytes minimum)
#[derive(Debug, Clone)]
pub struct ScsiInquiryData {
    pub peripheral_device_type: u8,
    pub is_removable: bool,
    pub version: u8,
    pub vendor_id: String,
    pub product_id: String,
    pub product_rev: String,
}

impl ScsiInquiryData {
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 36 {
            return Err("Inquiry buffer too small");
        }
        let dev_type = data[0] & 0x1F;
        let is_removable = (data[1] & 0x80) != 0;
        let version = data[2];

        let vendor_id = String::from_utf8_lossy(&data[8..16]).trim().into();
        let product_id = String::from_utf8_lossy(&data[16..32]).trim().into();
        let product_rev = String::from_utf8_lossy(&data[32..36]).trim().into();

        Ok(Self {
            peripheral_device_type: dev_type,
            is_removable,
            version,
            vendor_id,
            product_id,
            product_rev,
        })
    }
}

/// SCSI Capacity Structure
#[derive(Debug, Clone, Copy)]
pub struct ScsiCapacity {
    pub last_lba: u64,
    pub block_size: u32,
    pub total_bytes: u64,
}

/// USB Mass Storage BOT Device Driver
pub struct UsbMassStorageDevice {
    pub slot_id: u8,
    pub interface_num: u8,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub max_packet_size: u16,
    pub current_tag: u32,
    pub inquiry: Option<ScsiInquiryData>,
    pub capacity: ScsiCapacity,
    pub is_initialized: bool,
}

impl UsbMassStorageDevice {
    pub fn new(slot_id: u8, interface_num: u8, bulk_in: u8, bulk_out: u8, max_pkt: u16) -> Self {
        Self {
            slot_id,
            interface_num,
            bulk_in_ep: bulk_in,
            bulk_out_ep: bulk_out,
            max_packet_size: max_pkt,
            current_tag: 0x1000,
            inquiry: None,
            capacity: ScsiCapacity {
                last_lba: 0,
                block_size: 512,
                total_bytes: 0,
            },
            is_initialized: false,
        }
    }

    fn next_tag(&mut self) -> u32 {
        self.current_tag = self.current_tag.wrapping_add(1);
        self.current_tag
    }

    /// Build SCSI TEST UNIT READY command
    pub fn build_test_unit_ready(&mut self) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let cmd = [ScsiOpcode::TestUnitReady as u8, 0, 0, 0, 0, 0];
        CommandBlockWrapper::new(tag, 0, false, 0, &cmd)
    }

    /// Build SCSI INQUIRY command
    pub fn build_inquiry(&mut self, alloc_len: u8) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let cmd = [
            ScsiOpcode::Inquiry as u8,
            0,
            0,
            0,
            alloc_len,
            0,
        ];
        CommandBlockWrapper::new(tag, alloc_len as u32, true, 0, &cmd)
    }

    /// Build SCSI READ CAPACITY (10) command
    pub fn build_read_capacity_10(&mut self) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let cmd = [
            ScsiOpcode::ReadCapacity10 as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        CommandBlockWrapper::new(tag, 8, true, 0, &cmd)
    }

    /// Decode READ CAPACITY (10) response buffer (8 bytes: 4 bytes LBA, 4 bytes block size)
    pub fn parse_read_capacity_10(&mut self, buf: &[u8]) -> Result<ScsiCapacity, &'static str> {
        if buf.len() < 8 {
            return Err("Capacity response buffer too small");
        }
        let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let total_bytes = (last_lba + 1) * block_size as u64;
        let cap = ScsiCapacity {
            last_lba,
            block_size,
            total_bytes,
        };
        self.capacity = cap;
        Ok(cap)
    }

    /// Build SCSI READ (10) command for reading consecutive sectors
    pub fn build_read_10(&mut self, lba: u32, block_count: u16) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let transfer_len = (block_count as u32) * self.capacity.block_size;
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();

        let cmd = [
            ScsiOpcode::Read10 as u8,
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0,
            count_bytes[0],
            count_bytes[1],
            0,
        ];

        CommandBlockWrapper::new(tag, transfer_len, true, 0, &cmd)
    }

    /// Build SCSI WRITE (10) command for writing consecutive sectors
    pub fn build_write_10(&mut self, lba: u32, block_count: u16) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let transfer_len = (block_count as u32) * self.capacity.block_size;
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = block_count.to_be_bytes();

        let cmd = [
            ScsiOpcode::Write10 as u8,
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0,
            count_bytes[0],
            count_bytes[1],
            0,
        ];

        CommandBlockWrapper::new(tag, transfer_len, false, 0, &cmd)
    }

    /// Parse SCSI REQUEST SENSE response (18 bytes)
    pub fn parse_sense(&self, buf: &[u8]) -> Result<(u8, u8, u8), &'static str> {
        if buf.len() < 18 {
            return Err("Sense buffer too small");
        }
        let sense_key = buf[2] & 0x0F;
        let asc = buf[12];
        let ascq = buf[13];
        Ok((sense_key, asc, ascq))
    }
}
