//! `software_raid.rs` — Software RAID 0 (striping), RAID 1 (mirroring),
//! and RAID 5 (left-symmetric distributed parity with XOR reconstruction) for CorOS.

use alloc::vec;
use alloc::vec::Vec;

pub const DEFAULT_CHUNK_SECTORS: u32 = 128; // 64 KiB stripes with 512-byte sectors
pub const SECTOR_SIZE: usize = 512;

/// RAID subsystem error conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaidError {
    NotEnoughDisks { needed: usize, provided: usize },
    DiskOffline(usize),
    ArrayFailed,
    DegradedArray,
    InvalidSector { requested: u64, total: u64 },
    BufferLengthMismatch,
    DiskWriteError(usize),
    DiskReadError(usize),
    RebuildTargetOnline,
}

/// RAID operational levels supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidLevel {
    Raid0,
    Raid1,
    Raid5,
}

/// Operational health state of the RAID array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidState {
    Optimal,
    Degraded,
    Failed,
    Rebuilding,
}

/// In-memory virtual disk representing a physical drive partition or block device.
#[derive(Debug, Clone)]
pub struct VirtualDisk {
    pub storage: Vec<u8>,
    pub sector_count: u64,
    pub is_online: bool,
}

impl VirtualDisk {
    pub fn new(sector_count: u64) -> Self {
        Self {
            storage: vec![0u8; (sector_count as usize) * SECTOR_SIZE],
            sector_count,
            is_online: true,
        }
    }

    pub fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<(), RaidError> {
        if !self.is_online {
            return Err(RaidError::DiskOffline(0));
        }
        if sector >= self.sector_count {
            return Err(RaidError::InvalidSector {
                requested: sector,
                total: self.sector_count,
            });
        }
        let offset = (sector as usize) * SECTOR_SIZE;
        buf[..SECTOR_SIZE].copy_from_slice(&self.storage[offset..offset + SECTOR_SIZE]);
        Ok(())
    }

    pub fn write_sector(&mut self, sector: u64, buf: &[u8]) -> Result<(), RaidError> {
        if !self.is_online {
            return Err(RaidError::DiskOffline(0));
        }
        if sector >= self.sector_count {
            return Err(RaidError::InvalidSector {
                requested: sector,
                total: self.sector_count,
            });
        }
        let offset = (sector as usize) * SECTOR_SIZE;
        self.storage[offset..offset + SECTOR_SIZE].copy_from_slice(&buf[..SECTOR_SIZE]);
        Ok(())
    }
}

/// Bitwise XOR computation between two sector buffers.
pub fn xor_buffers(dest: &mut [u8], src: &[u8]) {
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Software RAID Array manager.
#[derive(Debug, Clone)]
pub struct SoftwareRaidArray {
    pub level: RaidLevel,
    pub chunk_sectors: u32,
    pub disks: Vec<VirtualDisk>,
    pub state: RaidState,
    pub read_balance_counter: usize,
}

impl SoftwareRaidArray {
    /// Creates a new RAID array with the given level and member disks.
    pub fn new(
        level: RaidLevel,
        chunk_sectors: u32,
        disks: Vec<VirtualDisk>,
    ) -> Result<Self, RaidError> {
        let count = disks.len();
        match level {
            RaidLevel::Raid0 => {
                if count < 2 {
                    return Err(RaidError::NotEnoughDisks { needed: 2, provided: count });
                }
            }
            RaidLevel::Raid1 => {
                if count < 2 {
                    return Err(RaidError::NotEnoughDisks { needed: 2, provided: count });
                }
            }
            RaidLevel::Raid5 => {
                if count < 3 {
                    return Err(RaidError::NotEnoughDisks { needed: 3, provided: count });
                }
            }
        }

        let chunk = if chunk_sectors == 0 { DEFAULT_CHUNK_SECTORS } else { chunk_sectors };
        let mut array = Self {
            level,
            chunk_sectors: chunk,
            disks,
            state: RaidState::Optimal,
            read_balance_counter: 0,
        };
        array.update_state();
        Ok(array)
    }

    /// Evaluates current health state based on online disks.
    pub fn update_state(&mut self) {
        let online_count = self.disks.iter().filter(|d| d.is_online).count();
        let total = self.disks.len();

        match self.level {
            RaidLevel::Raid0 => {
                if online_count == total {
                    self.state = RaidState::Optimal;
                } else {
                    self.state = RaidState::Failed;
                }
            }
            RaidLevel::Raid1 => {
                if online_count == total {
                    self.state = RaidState::Optimal;
                } else if online_count > 0 {
                    self.state = RaidState::Degraded;
                } else {
                    self.state = RaidState::Failed;
                }
            }
            RaidLevel::Raid5 => {
                if online_count == total {
                    self.state = RaidState::Optimal;
                } else if online_count == total - 1 {
                    self.state = RaidState::Degraded;
                } else {
                    self.state = RaidState::Failed;
                }
            }
        }
    }

    /// Total usable capacity in sectors.
    pub fn usable_sectors(&self) -> u64 {
        let min_disk_sectors = self.disks.iter().map(|d| d.sector_count).min().unwrap_or(0);
        let n = self.disks.len() as u64;

        match self.level {
            RaidLevel::Raid0 => min_disk_sectors * n,
            RaidLevel::Raid1 => min_disk_sectors,
            RaidLevel::Raid5 => min_disk_sectors * (n - 1),
        }
    }

    /// Fails a member disk simulating hardware fault.
    pub fn fail_disk(&mut self, disk_idx: usize) -> Result<(), RaidError> {
        if disk_idx >= self.disks.len() {
            return Err(RaidError::DiskOffline(disk_idx));
        }
        self.disks[disk_idx].is_online = false;
        self.update_state();
        Ok(())
    }

    /// Replaces and rebuilds a failed disk in a RAID 1 or RAID 5 array.
    pub fn rebuild_disk(&mut self, disk_idx: usize) -> Result<(), RaidError> {
        if disk_idx >= self.disks.len() {
            return Err(RaidError::DiskOffline(disk_idx));
        }
        if self.disks[disk_idx].is_online {
            return Err(RaidError::RebuildTargetOnline);
        }

        self.state = RaidState::Rebuilding;
        let disk_sectors = self.disks[disk_idx].sector_count;

        // Reset the disk storage and bring online
        self.disks[disk_idx].storage = vec![0u8; (disk_sectors as usize) * SECTOR_SIZE];

        match self.level {
            RaidLevel::Raid0 => {
                return Err(RaidError::ArrayFailed);
            }
            RaidLevel::Raid1 => {
                // Find an online mirror source
                let source_idx = self.disks.iter().position(|d| d.is_online).ok_or(RaidError::ArrayFailed)?;
                let mut sector_buf = [0u8; SECTOR_SIZE];
                for s in 0..disk_sectors {
                    self.disks[source_idx].read_sector(s, &mut sector_buf).map_err(|_| RaidError::DiskReadError(source_idx))?;
                    let offset = (s as usize) * SECTOR_SIZE;
                    self.disks[disk_idx].storage[offset..offset + SECTOR_SIZE].copy_from_slice(&sector_buf);
                }
            }
            RaidLevel::Raid5 => {
                // Reconstruct data sector by sector by XORing all surviving disks
                let mut xor_buf = [0u8; SECTOR_SIZE];
                let mut temp_buf = [0u8; SECTOR_SIZE];

                for s in 0..disk_sectors {
                    xor_buf.fill(0);
                    for i in 0..self.disks.len() {
                        if i == disk_idx {
                            continue;
                        }
                        self.disks[i].read_sector(s, &mut temp_buf).map_err(|_| RaidError::DiskReadError(i))?;
                        xor_buffers(&mut xor_buf, &temp_buf);
                    }
                    let offset = (s as usize) * SECTOR_SIZE;
                    self.disks[disk_idx].storage[offset..offset + SECTOR_SIZE].copy_from_slice(&xor_buf);
                }
            }
        }

        self.disks[disk_idx].is_online = true;
        self.update_state();
        Ok(())
    }

    /// Reads a single 512-byte sector from the RAID array.
    pub fn read_sector(&mut self, logical_sector: u64, buf: &mut [u8]) -> Result<(), RaidError> {
        if logical_sector >= self.usable_sectors() {
            return Err(RaidError::InvalidSector {
                requested: logical_sector,
                total: self.usable_sectors(),
            });
        }

        match self.level {
            RaidLevel::Raid0 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }
                let stripe = logical_sector / self.chunk_sectors as u64;
                let chunk_offset = logical_sector % self.chunk_sectors as u64;
                let disk_idx = (stripe % self.disks.len() as u64) as usize;
                let disk_stripe = stripe / self.disks.len() as u64;
                let phys_sector = (disk_stripe * self.chunk_sectors as u64) + chunk_offset;

                self.disks[disk_idx].read_sector(phys_sector, buf)
            }
            RaidLevel::Raid1 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }
                // Balanced read: cycle through online disks
                let total = self.disks.len();
                let mut attempts = 0;
                while attempts < total {
                    let idx = self.read_balance_counter % total;
                    self.read_balance_counter = (self.read_balance_counter + 1) % total;
                    if self.disks[idx].is_online {
                        return self.disks[idx].read_sector(logical_sector, buf);
                    }
                    attempts += 1;
                }
                Err(RaidError::ArrayFailed)
            }
            RaidLevel::Raid5 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }

                let num_disks = self.disks.len() as u64;
                let data_disks = num_disks - 1;

                let stripe = logical_sector / (self.chunk_sectors as u64 * data_disks);
                let stripe_offset = logical_sector % (self.chunk_sectors as u64 * data_disks);
                let data_col = stripe_offset / self.chunk_sectors as u64;
                let chunk_offset = stripe_offset % self.chunk_sectors as u64;

                // Left-Symmetric Parity calculation:
                // Parity disk P = (num_disks - 1 - (stripe % num_disks))
                let parity_disk = (num_disks - 1 - (stripe % num_disks)) as usize;
                let target_disk = ((parity_disk as u64 + 1 + data_col) % num_disks) as usize;
                let phys_sector = (stripe * self.chunk_sectors as u64) + chunk_offset;

                if self.disks[target_disk].is_online {
                    self.disks[target_disk].read_sector(phys_sector, buf)
                } else {
                    // Degraded Read: target disk is offline!
                    // Reconstruct missing chunk by XORing all other disks in this stripe
                    let mut xor_acc = [0u8; SECTOR_SIZE];
                    let mut temp = [0u8; SECTOR_SIZE];

                    for i in 0..self.disks.len() {
                        if i == target_disk {
                            continue;
                        }
                        if !self.disks[i].is_online {
                            return Err(RaidError::ArrayFailed);
                        }
                        self.disks[i].read_sector(phys_sector, &mut temp)?;
                        xor_buffers(&mut xor_acc, &temp);
                    }

                    buf[..SECTOR_SIZE].copy_from_slice(&xor_acc);
                    Ok(())
                }
            }
        }
    }

    /// Writes a single 512-byte sector to the RAID array.
    pub fn write_sector(&mut self, logical_sector: u64, buf: &[u8]) -> Result<(), RaidError> {
        if logical_sector >= self.usable_sectors() {
            return Err(RaidError::InvalidSector {
                requested: logical_sector,
                total: self.usable_sectors(),
            });
        }

        match self.level {
            RaidLevel::Raid0 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }
                let stripe = logical_sector / self.chunk_sectors as u64;
                let chunk_offset = logical_sector % self.chunk_sectors as u64;
                let disk_idx = (stripe % self.disks.len() as u64) as usize;
                let disk_stripe = stripe / self.disks.len() as u64;
                let phys_sector = (disk_stripe * self.chunk_sectors as u64) + chunk_offset;

                self.disks[disk_idx].write_sector(phys_sector, buf)
            }
            RaidLevel::Raid1 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }
                let mut written = 0;
                for i in 0..self.disks.len() {
                    if self.disks[i].is_online {
                        if self.disks[i].write_sector(logical_sector, buf).is_ok() {
                            written += 1;
                        }
                    }
                }
                if written > 0 {
                    Ok(())
                } else {
                    Err(RaidError::ArrayFailed)
                }
            }
            RaidLevel::Raid5 => {
                if self.state == RaidState::Failed {
                    return Err(RaidError::ArrayFailed);
                }

                let num_disks = self.disks.len() as u64;
                let data_disks = num_disks - 1;

                let stripe = logical_sector / (self.chunk_sectors as u64 * data_disks);
                let stripe_offset = logical_sector % (self.chunk_sectors as u64 * data_disks);
                let data_col = stripe_offset / self.chunk_sectors as u64;
                let chunk_offset = stripe_offset % self.chunk_sectors as u64;

                let parity_disk = (num_disks - 1 - (stripe % num_disks)) as usize;
                let target_disk = ((parity_disk as u64 + 1 + data_col) % num_disks) as usize;
                let phys_sector = (stripe * self.chunk_sectors as u64) + chunk_offset;

                // Read-Modify-Write Parity Update:
                // NewParity = OldParity XOR OldData XOR NewData
                let mut old_data = [0u8; SECTOR_SIZE];
                let mut old_parity = [0u8; SECTOR_SIZE];

                let target_online = self.disks[target_disk].is_online;
                let parity_online = self.disks[parity_disk].is_online;

                if target_online && parity_online {
                    self.disks[target_disk].read_sector(phys_sector, &mut old_data)?;
                    self.disks[parity_disk].read_sector(phys_sector, &mut old_parity)?;

                    let mut new_parity = old_parity;
                    xor_buffers(&mut new_parity, &old_data);
                    xor_buffers(&mut new_parity, buf);

                    self.disks[target_disk].write_sector(phys_sector, buf)?;
                    self.disks[parity_disk].write_sector(phys_sector, &new_parity)?;
                    Ok(())
                } else if !target_online && parity_online {
                    // Target disk is down, but parity is up: compute and update parity directly
                    // NewParity = XOR of all other online data disks XOR NewData
                    let mut parity_acc = [0u8; SECTOR_SIZE];
                    parity_acc.copy_from_slice(buf);

                    let mut temp = [0u8; SECTOR_SIZE];
                    for col in 0..data_disks {
                        let disk = ((parity_disk as u64 + 1 + col) % num_disks) as usize;
                        if disk != target_disk {
                            self.disks[disk].read_sector(phys_sector, &mut temp)?;
                            xor_buffers(&mut parity_acc, &temp);
                        }
                    }

                    self.disks[parity_disk].write_sector(phys_sector, &parity_acc)?;
                    Ok(())
                } else if target_online && !parity_online {
                    // Parity is down, just write data
                    self.disks[target_disk].write_sector(phys_sector, buf)?;
                    Ok(())
                } else {
                    Err(RaidError::ArrayFailed)
                }
            }
        }
    }
}
