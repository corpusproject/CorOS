//! CorOS VFS & Block Storage Pipeline Bridge (`block_pipeline.rs`)
//!
//! Unifies:
//! - `corvfs::mount_table::MountTable` (CorFS on `/`, FAT32 ESP on `/boot/efi`, Ext4 on `/data`)
//! - `corblock::bio::{Bio, BioOp, BioFlags, BioStatus, SECTOR_SIZE}`
//! - Storage Driver Adapters: `NvmeBlockAdapter`, `AhciBlockAdapter`, `VirtioBlkAdapter`

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use corblock::bio::{Bio, BioFlags, BioOp, BioStatus, SECTOR_SIZE};
use cordrivers::universal_device::{AhciBlockAdapter, BlockDeviceDriver, NvmeBlockAdapter, VirtioBlkAdapter};
use corvfs::mount_table::{FsType, MountFlags, MountResolution, MountTable};

pub struct BlockDeviceEntry {
    pub name: String,
    pub driver: Box<dyn BlockDeviceDriver>,
}

pub struct VfsBlockPipeline {
    mount_table: SpinLock<Option<MountTable>>,
    devices: SpinLock<Vec<BlockDeviceEntry>>,
}

unsafe impl Send for VfsBlockPipeline {}
unsafe impl Sync for VfsBlockPipeline {}

impl VfsBlockPipeline {
    pub const fn uninit() -> Self {
        Self {
            mount_table: SpinLock::new(None),
            devices: SpinLock::new(Vec::new()),
        }
    }

    /// Initializes the VFS mount table hierarchy and attaches default hardware block adapters.
    pub fn initialize(&self) {
        let mut mt = self.mount_table.lock_irqsave();
        if mt.is_none() {
            let mut table = MountTable::with_coros_defaults();
            // Mount Ext4 data volume on /data
            let _ = table.mount("/dev/sda1", "/data", FsType::CorFs, MountFlags::RW_DEFAULT, 108);
            *mt = Some(table);
        }
        drop(mt);

        let mut devs = self.devices.lock_irqsave();
        if devs.is_empty() {
            // Attach Primary NVMe 1.4 system drive (256 MiB simulated capacity)
            let nvme = NvmeBlockAdapter::new("nvme0n1", 524_288, 512);
            devs.push(BlockDeviceEntry {
                name: String::from("/dev/nvme0n1"),
                driver: Box::new(nvme),
            });

            // Attach AHCI SATA secondary drive (64 MiB capacity)
            let ahci = AhciBlockAdapter::new("sda", 0, 131_072);
            devs.push(BlockDeviceEntry {
                name: String::from("/dev/sda"),
                driver: Box::new(ahci),
            });

            // Attach VirtIO-Blk ephemeral drive (32 MiB capacity)
            let virtio = VirtioBlkAdapter::new("vda", 65_536);
            devs.push(BlockDeviceEntry {
                name: String::from("/dev/vda"),
                driver: Box::new(virtio),
            });
        }
    }

    /// Resolves an absolute VFS path against the active mount table.
    pub fn resolve_path(&self, path: &str) -> Result<MountResolution, &'static str> {
        self.initialize();
        let mt = self.mount_table.lock_irqsave();
        if let Some(ref table) = *mt {
            table.resolve_path(path).map_err(|_| "VFS path resolution failed")
        } else {
            Err("Mount table uninitialized")
        }
    }

    /// Submits an atomic block I/O request through the storage driver adapter.
    pub fn submit_bio(&self, dev_path: &str, bio: &mut Bio) -> Result<(), &'static str> {
        self.initialize();
        let mut devs = self.devices.lock_irqsave();
        let entry = devs
            .iter_mut()
            .find(|d| d.name == dev_path || dev_path.starts_with(&d.name))
            .ok_or("Block device driver adapter not found for target path")?;

        let sector = bio.bi_sector;
        let count = bio.sector_count() as u32;

        match bio.bi_op {
            BioOp::Read => {
                let total_bytes = (count as usize) * SECTOR_SIZE;
                let mut temp_buf = alloc::vec![0u8; total_bytes];
                entry.driver.read_sectors(sector, count, &mut temp_buf)?;
                let mut written = 0;
                for bvec in &mut bio.bi_io_vec {
                    let len = bvec.len().min(total_bytes.saturating_sub(written));
                    bvec.slice_mut()[..len].copy_from_slice(&temp_buf[written..written + len]);
                    written += len;
                }
                bio.bi_status = BioStatus::Success;
            }
            BioOp::Write => {
                let mut flat_data = Vec::with_capacity(bio.bi_size);
                for bvec in &bio.bi_io_vec {
                    flat_data.extend_from_slice(bvec.slice());
                }
                entry.driver.write_sectors(sector, count, &flat_data)?;
                bio.bi_status = BioStatus::Success;
            }
            BioOp::Flush => {
                entry.driver.flush()?;
                bio.bi_status = BioStatus::Success;
            }
            _ => {
                bio.bi_status = BioStatus::NotSupported;
                return Err("Unsupported BIO operation on block driver");
            }
        }

        Ok(())
    }

    /// Reads data from a block device via the BIO pipeline.
    pub fn read_sectors(&self, dev_path: &str, lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        let mut bio = Bio::with_flags(BioOp::Read, lba, BioFlags::SYNC);
        bio.add_buffer(buf);
        self.submit_bio(dev_path, &mut bio)?;
        if bio.bi_status == BioStatus::Success {
            if let Some(bvec) = bio.bi_io_vec.first() {
                buf.copy_from_slice(bvec.slice());
            }
            Ok(())
        } else {
            Err("BIO read transaction failed")
        }
    }

    /// Writes data to a block device via the BIO pipeline.
    pub fn write_sectors(&self, dev_path: &str, lba: u64, buf: &[u8]) -> Result<(), &'static str> {
        let mut bio = Bio::with_flags(BioOp::Write, lba, BioFlags::SYNC);
        bio.add_buffer(buf);
        self.submit_bio(dev_path, &mut bio)?;
        if bio.bi_status == BioStatus::Success {
            Ok(())
        } else {
            Err("BIO write transaction failed")
        }
    }

    /// Flushes all pending writes on the target block device.
    pub fn flush_device(&self, dev_path: &str) -> Result<(), &'static str> {
        let mut bio = Bio::with_flags(BioOp::Flush, 0, BioFlags::SYNC);
        self.submit_bio(dev_path, &mut bio)
    }

    /// Returns the number of registered block device adapters.
    pub fn device_count(&self) -> usize {
        self.initialize();
        self.devices.lock_irqsave().len()
    }
}

pub static GLOBAL_BLOCK_PIPELINE: VfsBlockPipeline = VfsBlockPipeline::uninit();
