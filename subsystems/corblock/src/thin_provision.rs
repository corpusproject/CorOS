//! `thin_provision.rs` — Thin provisioning copy-on-write (`COW`) snapshot manager
//! and chunk allocation metadata mapping engine for CorOS.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KiB chunks (128 sectors)

/// Errors occurring in the thin provisioning subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThinError {
    PoolExhausted,
    InvalidChunkSize,
    VolumeNotFound(u32),
    VolumeAlreadyExists(u32),
    InvalidLogicalAddress { offset: u64, virtual_size: u64 },
    BufferLengthMismatch,
    ChunkIndexOutOfBounds(u32),
}

/// Metadata tracking for physical chunks within the storage pool.
#[derive(Debug, Clone, Default)]
pub struct PhysicalChunkMeta {
    pub refcount: u32,
    pub is_allocated: bool,
}

/// Thin Provisioning Pool managing physical storage blocks and reference counts.
#[derive(Debug, Clone)]
pub struct ThinPool {
    chunk_size: usize,
    total_chunks: u32,
    free_chunk_indices: Vec<u32>,
    chunk_metadata: Vec<PhysicalChunkMeta>,
    storage: Vec<u8>,
}

impl ThinPool {
    pub fn new(total_chunks: u32, chunk_size: usize) -> Result<Self, ThinError> {
        if chunk_size == 0 || chunk_size % SECTOR_SIZE != 0 {
            return Err(ThinError::InvalidChunkSize);
        }

        let mut free_indices = Vec::with_capacity(total_chunks as usize);
        for i in (0..total_chunks).rev() {
            free_indices.push(i);
        }

        let total_bytes = (total_chunks as usize) * chunk_size;

        Ok(Self {
            chunk_size,
            total_chunks,
            free_chunk_indices: free_indices,
            chunk_metadata: vec![PhysicalChunkMeta::default(); total_chunks as usize],
            storage: vec![0u8; total_bytes],
        })
    }

    pub fn alloc_chunk(&mut self) -> Result<u32, ThinError> {
        let chunk_idx = self.free_chunk_indices.pop().ok_or(ThinError::PoolExhausted)?;
        let meta = &mut self.chunk_metadata[chunk_idx as usize];
        meta.refcount = 1;
        meta.is_allocated = true;

        // Zero out freshly allocated chunk
        let offset = (chunk_idx as usize) * self.chunk_size;
        self.storage[offset..offset + self.chunk_size].fill(0);

        Ok(chunk_idx)
    }

    pub fn inc_ref(&mut self, chunk_idx: u32) -> Result<(), ThinError> {
        if (chunk_idx as usize) >= self.chunk_metadata.len() {
            return Err(ThinError::ChunkIndexOutOfBounds(chunk_idx));
        }
        self.chunk_metadata[chunk_idx as usize].refcount += 1;
        Ok(())
    }

    pub fn dec_ref(&mut self, chunk_idx: u32) -> Result<(), ThinError> {
        if (chunk_idx as usize) >= self.chunk_metadata.len() {
            return Err(ThinError::ChunkIndexOutOfBounds(chunk_idx));
        }

        let meta = &mut self.chunk_metadata[chunk_idx as usize];
        if meta.refcount > 0 {
            meta.refcount -= 1;
            if meta.refcount == 0 {
                meta.is_allocated = false;
                self.free_chunk_indices.push(chunk_idx);
            }
        }
        Ok(())
    }

    pub fn get_refcount(&self, chunk_idx: u32) -> u32 {
        if (chunk_idx as usize) < self.chunk_metadata.len() {
            self.chunk_metadata[chunk_idx as usize].refcount
        } else {
            0
        }
    }

    pub fn read_chunk(&self, chunk_idx: u32, offset_in_chunk: usize, buf: &mut [u8]) -> Result<(), ThinError> {
        if (chunk_idx as usize) >= self.total_chunks as usize {
            return Err(ThinError::ChunkIndexOutOfBounds(chunk_idx));
        }
        let start = (chunk_idx as usize) * self.chunk_size + offset_in_chunk;
        let end = start + buf.len();
        if offset_in_chunk + buf.len() > self.chunk_size {
            return Err(ThinError::BufferLengthMismatch);
        }
        buf.copy_from_slice(&self.storage[start..end]);
        Ok(())
    }

    pub fn write_chunk(&mut self, chunk_idx: u32, offset_in_chunk: usize, buf: &[u8]) -> Result<(), ThinError> {
        if (chunk_idx as usize) >= self.total_chunks as usize {
            return Err(ThinError::ChunkIndexOutOfBounds(chunk_idx));
        }
        let start = (chunk_idx as usize) * self.chunk_size + offset_in_chunk;
        let end = start + buf.len();
        if offset_in_chunk + buf.len() > self.chunk_size {
            return Err(ThinError::BufferLengthMismatch);
        }
        self.storage[start..end].copy_from_slice(buf);
        Ok(())
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub fn free_chunks(&self) -> u32 {
        self.free_chunk_indices.len() as u32
    }

    pub fn allocated_chunks(&self) -> u32 {
        self.total_chunks - self.free_chunks()
    }
}

/// A thin provisioned volume mapping logical chunk indices to physical pool chunks.
#[derive(Debug, Clone)]
pub struct ThinVolume {
    pub volume_id: u32,
    pub virtual_size_bytes: u64,
    pub chunk_map: BTreeMap<u64, u32>,
}

impl ThinVolume {
    pub fn new(volume_id: u32, virtual_size_bytes: u64) -> Self {
        Self {
            volume_id,
            virtual_size_bytes,
            chunk_map: BTreeMap::new(),
        }
    }

    pub fn mapped_chunks_count(&self) -> usize {
        self.chunk_map.len()
    }
}

/// Thin Provisioning COW Snapshot Manager.
#[derive(Debug, Clone)]
pub struct ThinProvisioningManager {
    pool: ThinPool,
    volumes: BTreeMap<u32, ThinVolume>,
    next_vol_id: u32,
}

impl ThinProvisioningManager {
    pub fn new(total_pool_chunks: u32, chunk_size: usize) -> Result<Self, ThinError> {
        Ok(Self {
            pool: ThinPool::new(total_pool_chunks, chunk_size)?,
            volumes: BTreeMap::new(),
            next_vol_id: 1,
        })
    }

    /// Creates a new empty thin provisioned volume with a given virtual capacity.
    pub fn create_volume(&mut self, virtual_size_bytes: u64) -> u32 {
        let vol_id = self.next_vol_id;
        self.next_vol_id += 1;
        self.volumes.insert(vol_id, ThinVolume::new(vol_id, virtual_size_bytes));
        vol_id
    }

    /// Takes a point-in-time Copy-On-Write snapshot of an existing volume.
    pub fn create_snapshot(&mut self, origin_vol_id: u32) -> Result<u32, ThinError> {
        let origin = self.volumes.get(&origin_vol_id).ok_or(ThinError::VolumeNotFound(origin_vol_id))?;
        let snap_id = self.next_vol_id;
        self.next_vol_id += 1;

        let mut snap_vol = ThinVolume::new(snap_id, origin.virtual_size_bytes);
        snap_vol.chunk_map = origin.chunk_map.clone();

        // Increment reference counts for all shared chunks
        for &phys_idx in snap_vol.chunk_map.values() {
            self.pool.inc_ref(phys_idx)?;
        }

        self.volumes.insert(snap_id, snap_vol);
        Ok(snap_id)
    }

    /// Reads data from a thin volume. Unmapped chunks return zeros.
    pub fn read(&self, vol_id: u32, byte_offset: u64, buf: &mut [u8]) -> Result<(), ThinError> {
        let vol = self.volumes.get(&vol_id).ok_or(ThinError::VolumeNotFound(vol_id))?;
        let len = buf.len() as u64;

        if byte_offset.saturating_add(len) > vol.virtual_size_bytes {
            return Err(ThinError::InvalidLogicalAddress {
                offset: byte_offset,
                virtual_size: vol.virtual_size_bytes,
            });
        }

        let chunk_sz = self.pool.chunk_size() as u64;
        let mut read_done = 0usize;

        while read_done < buf.len() {
            let cur_offset = byte_offset + read_done as u64;
            let logical_chunk = cur_offset / chunk_sz;
            let offset_in_chunk = (cur_offset % chunk_sz) as usize;
            let bytes_in_chunk = (chunk_sz as usize - offset_in_chunk).min(buf.len() - read_done);

            if let Some(&phys_idx) = vol.chunk_map.get(&logical_chunk) {
                self.pool.read_chunk(
                    phys_idx,
                    offset_in_chunk,
                    &mut buf[read_done..read_done + bytes_in_chunk],
                )?;
            } else {
                // Thin unallocated block: return zeroes
                buf[read_done..read_done + bytes_in_chunk].fill(0);
            }

            read_done += bytes_in_chunk;
        }

        Ok(())
    }

    /// Writes data to a thin volume, triggering Copy-On-Write if chunks are shared.
    pub fn write(&mut self, vol_id: u32, byte_offset: u64, buf: &[u8]) -> Result<(), ThinError> {
        let chunk_sz = self.pool.chunk_size() as u64;
        let virtual_size = {
            let vol = self.volumes.get(&vol_id).ok_or(ThinError::VolumeNotFound(vol_id))?;
            vol.virtual_size_bytes
        };

        let len = buf.len() as u64;
        if byte_offset.saturating_add(len) > virtual_size {
            return Err(ThinError::InvalidLogicalAddress {
                offset: byte_offset,
                virtual_size,
            });
        }

        let mut write_done = 0usize;

        while write_done < buf.len() {
            let cur_offset = byte_offset + write_done as u64;
            let logical_chunk = cur_offset / chunk_sz;
            let offset_in_chunk = (cur_offset % chunk_sz) as usize;
            let bytes_in_chunk = (chunk_sz as usize - offset_in_chunk).min(buf.len() - write_done);

            let mapped_phys = {
                let vol = self.volumes.get(&vol_id).unwrap();
                vol.chunk_map.get(&logical_chunk).copied()
            };

            let target_phys = match mapped_phys {
                None => {
                    // Fresh allocation
                    let fresh_idx = self.pool.alloc_chunk()?;
                    let vol = self.volumes.get_mut(&vol_id).unwrap();
                    vol.chunk_map.insert(logical_chunk, fresh_idx);
                    fresh_idx
                }
                Some(phys_idx) => {
                    if self.pool.get_refcount(phys_idx) > 1 {
                        // Copy-on-Write branch: allocate new chunk, copy existing content, apply write
                        let fresh_idx = self.pool.alloc_chunk()?;
                        let mut copy_buf = vec![0u8; self.pool.chunk_size()];
                        self.pool.read_chunk(phys_idx, 0, &mut copy_buf)?;
                        self.pool.write_chunk(fresh_idx, 0, &copy_buf)?;

                        self.pool.dec_ref(phys_idx)?;
                        let vol = self.volumes.get_mut(&vol_id).unwrap();
                        vol.chunk_map.insert(logical_chunk, fresh_idx);
                        fresh_idx
                    } else {
                        // Exclusive ownership: write directly in place
                        phys_idx
                    }
                }
            };

            self.pool.write_chunk(
                target_phys,
                offset_in_chunk,
                &buf[write_done..write_done + bytes_in_chunk],
            )?;

            write_done += bytes_in_chunk;
        }

        Ok(())
    }

    /// Discards (TRIM) a logical chunk, reclaiming physical storage if refcount drops to 0.
    pub fn discard_chunk(&mut self, vol_id: u32, logical_chunk: u64) -> Result<(), ThinError> {
        let vol = self.volumes.get_mut(&vol_id).ok_or(ThinError::VolumeNotFound(vol_id))?;
        if let Some(phys_idx) = vol.chunk_map.remove(&logical_chunk) {
            self.pool.dec_ref(phys_idx)?;
        }
        Ok(())
    }

    pub fn pool(&self) -> &ThinPool {
        &self.pool
    }

    pub fn get_volume(&self, vol_id: u32) -> Option<&ThinVolume> {
        self.volumes.get(&vol_id)
    }
}
