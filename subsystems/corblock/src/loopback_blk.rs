//! `loopback_blk.rs` — Virtual Loopback Block Device Driver for CorOS.
//! Mounts regular file images or in-memory backing stores as full block devices,
//! supporting configurable logical sector sizes, read-only guards, and direct I/O dispatch.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use crate::bio::{Bio, BioOp, BioStatus};

/// Error types for loopback device operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopError {
    DeviceBusy,
    DeviceNotBound,
    ReadOnlyDevice,
    InvalidSectorSize(u32),
    InvalidOffsetLimit { offset: u64, limit: u64, file_size: u64 },
    SectorOutOfBounds { requested: u64, max: u64 },
    BufferLengthMismatch,
    IoFailed,
    NoFreeDevices,
    NoSuchDevice(u32),
}

/// Flags modifying loopback device behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoopFlags(pub u32);

impl LoopFlags {
    pub const NONE: Self = Self(0);
    pub const READ_ONLY: Self = Self(1 << 0);
    pub const AUTOCLEAR: Self = Self(1 << 1);
    pub const DIRECT_IO: Self = Self(1 << 2);

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub const fn union(&self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Configuration parameters for binding a file or buffer to a loopback block device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopConfig {
    pub file_path: String,
    pub offset: u64,
    pub size_limit: u64,
    pub sector_size: u32,
    pub flags: LoopFlags,
}

impl LoopConfig {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: String::from(file_path),
            offset: 0,
            size_limit: 0, // 0 = use entire file
            sector_size: 512,
            flags: LoopFlags::NONE,
        }
    }

    pub fn with_read_only(mut self) -> Self {
        self.flags.insert(LoopFlags::READ_ONLY);
        self
    }

    pub fn with_offset_limit(mut self, offset: u64, limit: u64) -> Self {
        self.offset = offset;
        self.size_limit = limit;
        self
    }

    pub fn with_sector_size(mut self, sector_size: u32) -> Result<Self, LoopError> {
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(LoopError::InvalidSectorSize(sector_size));
        }
        self.sector_size = sector_size;
        Ok(self)
    }
}

/// An individual virtual loopback block device (`/dev/loopX`).
#[derive(Debug, Clone)]
pub struct LoopDevice {
    pub id: u32,
    config: Option<LoopConfig>,
    backing_image: Vec<u8>,
    open_count: u32,
}

impl LoopDevice {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            config: None,
            backing_image: Vec::new(),
            open_count: 0,
        }
    }

    pub fn is_bound(&self) -> bool {
        self.config.is_some()
    }

    pub fn config(&self) -> Option<&LoopConfig> {
        self.config.as_ref()
    }

    /// Attaches an in-memory file image to this loop device.
    pub fn attach(&mut self, config: LoopConfig, image_data: Vec<u8>) -> Result<(), LoopError> {
        if self.is_bound() {
            return Err(LoopError::DeviceBusy);
        }

        let file_len = image_data.len() as u64;
        if config.offset > file_len {
            return Err(LoopError::InvalidOffsetLimit {
                offset: config.offset,
                limit: config.size_limit,
                file_size: file_len,
            });
        }

        let effective_size = if config.size_limit == 0 {
            file_len - config.offset
        } else {
            config.size_limit.min(file_len - config.offset)
        };

        if effective_size < config.sector_size as u64 {
            return Err(LoopError::InvalidOffsetLimit {
                offset: config.offset,
                limit: config.size_limit,
                file_size: file_len,
            });
        }

        self.config = Some(config);
        self.backing_image = image_data;
        Ok(())
    }

    /// Detaches the backing image from this loop device.
    pub fn detach(&mut self) -> Result<(), LoopError> {
        if !self.is_bound() {
            return Err(LoopError::DeviceNotBound);
        }
        if self.open_count > 0 {
            return Err(LoopError::DeviceBusy);
        }

        self.config = None;
        self.backing_image.clear();
        Ok(())
    }

    /// Usable capacity in logical sectors.
    pub fn total_sectors(&self) -> u64 {
        let Some(cfg) = &self.config else {
            return 0;
        };
        let file_len = self.backing_image.len() as u64;
        let effective_size = if cfg.size_limit == 0 {
            file_len.saturating_sub(cfg.offset)
        } else {
            cfg.size_limit.min(file_len.saturating_sub(cfg.offset))
        };
        effective_size / (cfg.sector_size as u64)
    }

    /// Reads contiguous sectors from the loop device.
    pub fn read_sectors(&self, start_sector: u64, count: u32, buf: &mut [u8]) -> Result<(), LoopError> {
        let cfg = self.config.as_ref().ok_or(LoopError::DeviceNotBound)?;
        let sec_sz = cfg.sector_size as usize;
        let expected_bytes = (count as usize) * sec_sz;

        if buf.len() < expected_bytes {
            return Err(LoopError::BufferLengthMismatch);
        }

        if start_sector + (count as u64) > self.total_sectors() {
            return Err(LoopError::SectorOutOfBounds {
                requested: start_sector + count as u64,
                max: self.total_sectors(),
            });
        }

        let start_byte = (cfg.offset as usize) + (start_sector as usize) * sec_sz;
        buf[..expected_bytes].copy_from_slice(&self.backing_image[start_byte..start_byte + expected_bytes]);
        Ok(())
    }

    /// Writes contiguous sectors to the loop device.
    pub fn write_sectors(&mut self, start_sector: u64, count: u32, buf: &[u8]) -> Result<(), LoopError> {
        let cfg = self.config.as_ref().ok_or(LoopError::DeviceNotBound)?;
        if cfg.flags.contains(LoopFlags::READ_ONLY) {
            return Err(LoopError::ReadOnlyDevice);
        }

        let sec_sz = cfg.sector_size as usize;
        let expected_bytes = (count as usize) * sec_sz;

        if buf.len() < expected_bytes {
            return Err(LoopError::BufferLengthMismatch);
        }

        if start_sector + (count as u64) > self.total_sectors() {
            return Err(LoopError::SectorOutOfBounds {
                requested: start_sector + count as u64,
                max: self.total_sectors(),
            });
        }

        let start_byte = (cfg.offset as usize) + (start_sector as usize) * sec_sz;
        self.backing_image[start_byte..start_byte + expected_bytes].copy_from_slice(&buf[..expected_bytes]);
        Ok(())
    }

    /// Dispatches a high-level `Bio` request across the loopback block device.
    pub fn submit_bio(&mut self, bio: &mut Bio) -> Result<(), LoopError> {
        let cfg = self.config.as_ref().ok_or(LoopError::DeviceNotBound)?;
        let sec_sz = cfg.sector_size as usize;
        let sector_count = ((bio.bi_size + sec_sz - 1) / sec_sz) as u32;

        match bio.bi_op {
            BioOp::Read => {
                let mut data = vec![0u8; bio.bi_size];
                self.read_sectors(bio.bi_sector, sector_count, &mut data)?;

                let mut offset = 0;
                for bvec in &mut bio.bi_io_vec {
                    let b_len = bvec.length;
                    bvec.slice_mut().copy_from_slice(&data[offset..offset + b_len]);
                    offset += b_len;
                }
                bio.complete(BioStatus::Success);
                Ok(())
            }
            BioOp::Write => {
                if cfg.flags.contains(LoopFlags::READ_ONLY) {
                    bio.complete(BioStatus::NotSupported);
                    return Err(LoopError::ReadOnlyDevice);
                }
                let data = bio.flatten_data();
                self.write_sectors(bio.bi_sector, sector_count, &data)?;
                bio.complete(BioStatus::Success);
                Ok(())
            }
            BioOp::Flush => {
                bio.complete(BioStatus::Success);
                Ok(())
            }
            BioOp::Discard => {
                if cfg.flags.contains(LoopFlags::READ_ONLY) {
                    bio.complete(BioStatus::NotSupported);
                    return Err(LoopError::ReadOnlyDevice);
                }
                let zero_buf = vec![0u8; bio.bi_size];
                self.write_sectors(bio.bi_sector, sector_count, &zero_buf)?;
                bio.complete(BioStatus::Success);
                Ok(())
            }
            _ => {
                bio.complete(BioStatus::NotSupported);
                Ok(())
            }
        }
    }
}

/// Loopback device subsystem manager overseeing `/dev/loop*` pool.
#[derive(Debug, Clone)]
pub struct LoopController {
    devices: Vec<LoopDevice>,
}

impl LoopController {
    pub fn new(max_devices: usize) -> Self {
        let mut devices = Vec::with_capacity(max_devices);
        for i in 0..max_devices {
            devices.push(LoopDevice::new(i as u32));
        }
        Self { devices }
    }

    pub fn find_free_device(&self) -> Option<u32> {
        self.devices.iter().find(|d| !d.is_bound()).map(|d| d.id)
    }

    pub fn attach(
        &mut self,
        device_id: u32,
        config: LoopConfig,
        image_data: Vec<u8>,
    ) -> Result<(), LoopError> {
        let dev = self.devices.iter_mut().find(|d| d.id == device_id).ok_or(LoopError::NoSuchDevice(device_id))?;
        dev.attach(config, image_data)
    }

    pub fn detach(&mut self, device_id: u32) -> Result<(), LoopError> {
        let dev = self.devices.iter_mut().find(|d| d.id == device_id).ok_or(LoopError::NoSuchDevice(device_id))?;
        dev.detach()
    }

    pub fn get_device(&self, device_id: u32) -> Option<&LoopDevice> {
        self.devices.iter().find(|d| d.id == device_id)
    }

    pub fn get_device_mut(&mut self, device_id: u32) -> Option<&mut LoopDevice> {
        self.devices.iter_mut().find(|d| d.id == device_id)
    }

    pub fn count(&self) -> usize {
        self.devices.len()
    }
}
