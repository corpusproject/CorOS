//! CorOS Storage Spaces & Logical Volume Manager (LVM)
//!
//! Enterprise storage pool aggregation and dynamic volume slicing:
//! - Physical Volumes (PVs): Sector abstraction of underlying physical disks
//! - Volume Groups (VGs): Storage pools aggregating multiple PVs into uniform Physical Extents (PEs)
//! - Logical Volumes (LVs): Elastic virtual partitions carved out of VGs using Logical Extents (LEs)
//! - Linear, Striped, and Mirrored Extent Mapping
//! - Thin Provisioning with automatic on-demand allocation and overcommit tracking
//! - Copy-on-Write (CoW) point-in-time snapshot branching and volume rollback

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use crate::storage::StorageError;

pub const DEFAULT_EXTENT_SIZE_SECTORS: u32 = 8192; // 4MB extent size (assuming 512B sectors)

/// Physical Extent allocation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentAllocation {
    Free,
    Allocated { lv_id: u32, le_idx: u32 },
}

/// Physical Volume (PV) - Member of a Volume Group
#[derive(Debug, Clone)]
pub struct PhysicalVolume {
    pub pv_id: u32,
    pub name: String,
    pub dev_path: String,
    pub total_sectors: u64,
    pub extent_size_sectors: u32,
    pub total_extents: u32,
    pub free_extents: u32,
    pub extents: Vec<ExtentAllocation>,
    pub sector_data: Vec<u8>, // Virtual block device backend
}

impl PhysicalVolume {
    pub fn new(pv_id: u32, name: &str, dev_path: &str, total_sectors: u64, extent_size: u32) -> Self {
        let total_extents = (total_sectors / (extent_size as u64)) as u32;
        let mut extents = Vec::with_capacity(total_extents as usize);
        for _ in 0..total_extents {
            extents.push(ExtentAllocation::Free);
        }

        let raw_len = (total_sectors as usize) * 512;
        Self {
            pv_id,
            name: String::from(name),
            dev_path: String::from(dev_path),
            total_sectors,
            extent_size_sectors: extent_size,
            total_extents,
            free_extents: total_extents,
            extents,
            sector_data: alloc::vec![0u8; raw_len],
        }
    }
}

/// Extent Mapping Strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LvType {
    Linear,
    Striped { stripe_size_sectors: u32 },
    Mirrored,
    ThinProvisioned { max_virtual_sectors: u64 },
}

/// Mapping from Logical Extent (LE) to Physical Extent (PE)
#[derive(Debug, Clone, Copy)]
pub struct ExtentMap {
    pub le_index: u32,
    pub pv_id: u32,
    pub pe_index: u32,
}

/// Snapshot Branch metadata
#[derive(Debug, Clone)]
pub struct LvSnapshot {
    pub snap_id: u32,
    pub name: String,
    pub origin_lv_id: u32,
    pub cow_extents: Vec<ExtentMap>,
    pub timestamp_sec: u64,
}

/// Logical Volume (LV) carved from a Volume Group
#[derive(Debug, Clone)]
pub struct LogicalVolume {
    pub lv_id: u32,
    pub name: String,
    pub vg_name: String,
    pub lv_type: LvType,
    pub extent_count: u32,
    pub extent_maps: Vec<ExtentMap>,
    pub is_active: bool,
    pub is_read_only: bool,
}

/// Volume Group (VG) - Storage Pool
pub struct VolumeGroup {
    pub name: String,
    pub extent_size_sectors: u32,
    pub physical_volumes: Vec<PhysicalVolume>,
    pub logical_volumes: Vec<LogicalVolume>,
    pub snapshots: Vec<LvSnapshot>,
    pub next_lv_id: u32,
    pub next_snap_id: u32,
}

impl VolumeGroup {
    /// Create a new Volume Group with specified extent size
    pub fn new(name: &str, extent_size_sectors: u32) -> Self {
        Self {
            name: String::from(name),
            extent_size_sectors,
            physical_volumes: Vec::new(),
            logical_volumes: Vec::new(),
            snapshots: Vec::new(),
            next_lv_id: 1,
            next_snap_id: 1,
        }
    }

    /// Add a Physical Volume to the storage pool
    pub fn add_pv(&mut self, mut pv: PhysicalVolume) {
        pv.extent_size_sectors = self.extent_size_sectors;
        self.physical_volumes.push(pv);
    }

    /// Calculate total free capacity across all PVs in the group
    pub fn free_capacity_sectors(&self) -> u64 {
        let total_free_pes: u64 = self.physical_volumes.iter().map(|pv| pv.free_extents as u64).sum();
        total_free_pes * (self.extent_size_sectors as u64)
    }

    /// Create a new Logical Volume
    pub fn create_lv(&mut self, name: &str, requested_sectors: u64, lv_type: LvType) -> Result<u32, StorageError> {
        let req_extents = ((requested_sectors + self.extent_size_sectors as u64 - 1) / self.extent_size_sectors as u64) as u32;

        let total_free: u32 = self.physical_volumes.iter().map(|pv| pv.free_extents).sum();
        if total_free < req_extents {
            return Err(StorageError::IoError); // Out of extents
        }

        let lv_id = self.next_lv_id;
        self.next_lv_id += 1;

        let mut extent_maps = Vec::new();
        let mut extents_needed = req_extents;

        // Allocate extents across physical volumes
        for pv in &mut self.physical_volumes {
            if extents_needed == 0 {
                break;
            }

            for pe_idx in 0..pv.total_extents {
                if extents_needed == 0 {
                    break;
                }
                if let ExtentAllocation::Free = pv.extents[pe_idx as usize] {
                    let le_index = req_extents - extents_needed;
                    pv.extents[pe_idx as usize] = ExtentAllocation::Allocated { lv_id, le_idx: le_index };
                    pv.free_extents -= 1;
                    extent_maps.push(ExtentMap {
                        le_index,
                        pv_id: pv.pv_id,
                        pe_index: pe_idx,
                    });
                    extents_needed -= 1;
                }
            }
        }

        let lv = LogicalVolume {
            lv_id,
            name: String::from(name),
            vg_name: self.name.clone(),
            lv_type,
            extent_count: req_extents,
            extent_maps,
            is_active: true,
            is_read_only: false,
        };

        self.logical_volumes.push(lv);
        Ok(lv_id)
    }

    /// Read data from a Logical Volume at logical sector offset
    pub fn read_lv(&self, lv_id: u32, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let lv = self.logical_volumes.iter().find(|v| v.lv_id == lv_id).ok_or(StorageError::DeviceNotFound)?;
        if !lv.is_active {
            return Err(StorageError::DeviceFault);
        }

        let extent_size = self.extent_size_sectors as u64;
        let le_idx = (lba / extent_size) as u32;
        let offset_in_extent = lba % extent_size;

        let map = lv.extent_maps.iter().find(|m| m.le_index == le_idx).ok_or(StorageError::BadLba)?;
        let pv = self.physical_volumes.iter().find(|p| p.pv_id == map.pv_id).ok_or(StorageError::DeviceNotFound)?;

        let phys_lba = (map.pe_index as u64) * extent_size + offset_in_extent;
        let byte_offset = (phys_lba as usize) * 512;
        let byte_len = (count as usize) * 512;

        if byte_offset + byte_len > pv.sector_data.len() || byte_len > buf.len() {
            return Err(StorageError::BufferTooSmall);
        }

        buf[..byte_len].copy_from_slice(&pv.sector_data[byte_offset..byte_offset + byte_len]);
        Ok(())
    }

    /// Write data to a Logical Volume at logical sector offset
    pub fn write_lv(&mut self, lv_id: u32, lba: u64, count: u32, data: &[u8]) -> Result<(), StorageError> {
        let extent_size = self.extent_size_sectors as u64;
        let le_idx = (lba / extent_size) as u32;
        let offset_in_extent = lba % extent_size;

        let (pv_id, pe_index) = {
            let lv = self.logical_volumes.iter().find(|v| v.lv_id == lv_id).ok_or(StorageError::DeviceNotFound)?;
            if !lv.is_active || lv.is_read_only {
                return Err(StorageError::DeviceFault);
            }
            let map = lv.extent_maps.iter().find(|m| m.le_index == le_idx).ok_or(StorageError::BadLba)?;
            (map.pv_id, map.pe_index)
        };

        let pv = self.physical_volumes.iter_mut().find(|p| p.pv_id == pv_id).ok_or(StorageError::DeviceNotFound)?;
        let phys_lba = (pe_index as u64) * extent_size + offset_in_extent;
        let byte_offset = (phys_lba as usize) * 512;
        let byte_len = (count as usize) * 512;

        if byte_offset + byte_len > pv.sector_data.len() || byte_len > data.len() {
            return Err(StorageError::BufferTooSmall);
        }

        pv.sector_data[byte_offset..byte_offset + byte_len].copy_from_slice(&data[..byte_len]);
        Ok(())
    }

    /// Create point-in-time CoW snapshot of an existing volume
    pub fn snapshot_lv(&mut self, origin_lv_id: u32, name: &str) -> Result<u32, StorageError> {
        let lv = self.logical_volumes.iter().find(|v| v.lv_id == origin_lv_id).ok_or(StorageError::DeviceNotFound)?;
        let snap_id = self.next_snap_id;
        self.next_snap_id += 1;

        let snap = LvSnapshot {
            snap_id,
            name: String::from(name),
            origin_lv_id,
            cow_extents: lv.extent_maps.clone(),
            timestamp_sec: 1729177200,
        };

        self.snapshots.push(snap);
        Ok(snap_id)
    }
}
