//! Unified Block Storage Subsystem for CorOS.
//! Provides hardware-independent storage block device interfaces and driver dispatch.

pub mod ahci;
pub mod ata_pio;
pub mod gpt;
pub mod io_scheduler;
pub mod storage_spaces;
pub mod iscsi;
pub mod nvme_of;

pub use gpt::{GptTable, GptHeader, GptPartition};
pub use io_scheduler::{DeadlineScheduler, BlockRequest, IoDirection};
pub use storage_spaces::{VolumeGroup, PhysicalVolume, LogicalVolume, LvType, ExtentAllocation};
pub use iscsi::{IscsiBlockDevice, IscsiPdu, IscsiBhs};
pub use nvme_of::{NvmeOverFabricsDevice, NvmeTcpCommonPdu, NvmeTcpCapsuleCmd, NvmeTcpCapsuleResp};


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    Timeout,
    DeviceFault,
    BadLba,
    IoError,
    BufferTooSmall,
    NotSupported,
    DeviceNotFound,
}

/// Abstract block device interface (e.g. SATA AHCI, ATA IDE, NVMe)
pub trait BlockDevice: Send + Sync {
    fn read_sectors(&mut self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), StorageError>;
    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), StorageError>;
    fn sector_size(&self) -> usize { 512 }
    fn total_sectors(&self) -> u64;
    fn device_name(&self) -> &str;
}
