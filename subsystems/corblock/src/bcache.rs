//! `bcache.rs` — SSD Block Caching Layer for CorOS.
//! Implements Write-Back, Write-Through, and Write-Around caching modes,
//! Least-Recently-Used (LRU) bucket replacement, dirty block writeback, and hit telemetry.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;
pub const BUCKET_SECTORS: usize = 8; // 4 KiB bucket size (8 x 512 bytes)
pub const BUCKET_BYTES: usize = BUCKET_SECTORS * SECTOR_SIZE;

/// Caching policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    WriteBack,
    WriteThrough,
    WriteAround,
}

/// Errors occurring within the bcache layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BcacheError {
    InvalidSector { sector: u64, max: u64 },
    BufferLengthMismatch,
    BackingDeviceOffline,
    CacheFullNoCleanBuckets,
}

/// Metadata and storage for an individual SSD cache bucket.
#[derive(Debug, Clone)]
pub struct CacheBucket {
    pub backing_lba: u64,
    pub is_valid: bool,
    pub is_dirty: bool,
    pub lru_tick: u64,
    pub data: Vec<u8>,
}

impl CacheBucket {
    pub fn new() -> Self {
        Self {
            backing_lba: 0,
            is_valid: false,
            is_dirty: false,
            lru_tick: 0,
            data: vec![0u8; BUCKET_BYTES],
        }
    }
}

impl Default for CacheBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Telemetry metrics for cache performance evaluation.
#[derive(Debug, Clone, Copy, Default)]
pub struct BcacheStats {
    pub read_hits: u64,
    pub read_misses: u64,
    pub write_hits: u64,
    pub write_misses: u64,
    pub flushes: u64,
    pub evictions: u64,
}

/// Unified Bcache Tiered Storage Device.
#[derive(Debug, Clone)]
pub struct BcacheDevice {
    mode: CacheMode,
    backing_storage: Vec<u8>,
    backing_total_sectors: u64,
    buckets: Vec<CacheBucket>,
    sector_to_bucket: BTreeMap<u64, usize>,
    current_tick: u64,
    stats: BcacheStats,
}

impl BcacheDevice {
    pub fn new(
        backing_total_sectors: u64,
        cache_bucket_count: usize,
        mode: CacheMode,
    ) -> Self {
        let mut buckets = Vec::with_capacity(cache_bucket_count);
        for _ in 0..cache_bucket_count {
            buckets.push(CacheBucket::new());
        }

        Self {
            mode,
            backing_storage: vec![0u8; (backing_total_sectors as usize) * SECTOR_SIZE],
            backing_total_sectors,
            buckets,
            sector_to_bucket: BTreeMap::new(),
            current_tick: 1,
            stats: BcacheStats::default(),
        }
    }

    pub fn set_mode(&mut self, mode: CacheMode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> CacheMode {
        self.mode
    }

    pub fn stats(&self) -> BcacheStats {
        self.stats
    }

    fn advance_tick(&mut self) -> u64 {
        self.current_tick = self.current_tick.wrapping_add(1);
        self.current_tick
    }

    /// Finds or allocates a bucket using LRU eviction.
    fn allocate_bucket(&mut self, _base_lba: u64) -> Result<usize, BcacheError> {
        // Step 1: Look for an invalid (free) bucket
        for (idx, b) in self.buckets.iter().enumerate() {
            if !b.is_valid {
                return Ok(idx);
            }
        }

        // Step 2: All buckets valid -> Find LRU victim
        let mut victim_idx = 0usize;
        let mut min_tick = u64::MAX;

        for (idx, b) in self.buckets.iter().enumerate() {
            if b.lru_tick < min_tick {
                min_tick = b.lru_tick;
                victim_idx = idx;
            }
        }

        // Step 3: Evict victim; flush to backing store if dirty
        let victim = &mut self.buckets[victim_idx];
        if victim.is_dirty {
            let offset = (victim.backing_lba as usize) * SECTOR_SIZE;
            self.backing_storage[offset..offset + BUCKET_BYTES].copy_from_slice(&victim.data);
            victim.is_dirty = false;
            self.stats.flushes += 1;
        }

        self.sector_to_bucket.remove(&victim.backing_lba);
        victim.is_valid = false;
        self.stats.evictions += 1;

        Ok(victim_idx)
    }

    /// Reads a 512-byte sector through the cache layer.
    pub fn read_sector(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BcacheError> {
        if sector >= self.backing_total_sectors {
            return Err(BcacheError::InvalidSector {
                sector,
                max: self.backing_total_sectors,
            });
        }
        if buf.len() != SECTOR_SIZE {
            return Err(BcacheError::BufferLengthMismatch);
        }

        let base_lba = (sector / BUCKET_SECTORS as u64) * BUCKET_SECTORS as u64;
        let offset_in_bucket = ((sector % BUCKET_SECTORS as u64) as usize) * SECTOR_SIZE;
        let tick = self.advance_tick();

        if let Some(&bucket_idx) = self.sector_to_bucket.get(&base_lba) {
            // Cache Hit
            self.stats.read_hits += 1;
            let bucket = &mut self.buckets[bucket_idx];
            bucket.lru_tick = tick;
            buf.copy_from_slice(&bucket.data[offset_in_bucket..offset_in_bucket + SECTOR_SIZE]);
            return Ok(());
        }

        // Cache Miss: fetch from backing storage into a new bucket
        self.stats.read_misses += 1;
        let bucket_idx = self.allocate_bucket(base_lba)?;

        let backing_offset = (base_lba as usize) * SECTOR_SIZE;
        let mut bucket_data = vec![0u8; BUCKET_BYTES];
        let bytes_to_copy = BUCKET_BYTES.min(self.backing_storage.len().saturating_sub(backing_offset));
        bucket_data[..bytes_to_copy].copy_from_slice(&self.backing_storage[backing_offset..backing_offset + bytes_to_copy]);

        let bucket = &mut self.buckets[bucket_idx];
        bucket.backing_lba = base_lba;
        bucket.is_valid = true;
        bucket.is_dirty = false;
        bucket.lru_tick = tick;
        bucket.data = bucket_data;

        buf.copy_from_slice(&bucket.data[offset_in_bucket..offset_in_bucket + SECTOR_SIZE]);
        self.sector_to_bucket.insert(base_lba, bucket_idx);
        Ok(())
    }

    /// Writes a 512-byte sector through the cache layer.
    pub fn write_sector(&mut self, sector: u64, buf: &[u8]) -> Result<(), BcacheError> {
        if sector >= self.backing_total_sectors {
            return Err(BcacheError::InvalidSector {
                sector,
                max: self.backing_total_sectors,
            });
        }
        if buf.len() != SECTOR_SIZE {
            return Err(BcacheError::BufferLengthMismatch);
        }

        let base_lba = (sector / BUCKET_SECTORS as u64) * BUCKET_SECTORS as u64;
        let offset_in_bucket = ((sector % BUCKET_SECTORS as u64) as usize) * SECTOR_SIZE;
        let tick = self.advance_tick();

        match self.mode {
            CacheMode::WriteAround => {
                // Bypass cache completely on writes
                self.stats.write_misses += 1;
                let offset = (sector as usize) * SECTOR_SIZE;
                self.backing_storage[offset..offset + SECTOR_SIZE].copy_from_slice(buf);

                // If cached, invalidate to avoid stale reads
                if let Some(bucket_idx) = self.sector_to_bucket.remove(&base_lba) {
                    self.buckets[bucket_idx].is_valid = false;
                }
                Ok(())
            }
            CacheMode::WriteThrough => {
                // Write to backing storage AND cache
                let offset = (sector as usize) * SECTOR_SIZE;
                self.backing_storage[offset..offset + SECTOR_SIZE].copy_from_slice(buf);

                if let Some(&bucket_idx) = self.sector_to_bucket.get(&base_lba) {
                    self.stats.write_hits += 1;
                    let bucket = &mut self.buckets[bucket_idx];
                    bucket.lru_tick = tick;
                    bucket.data[offset_in_bucket..offset_in_bucket + SECTOR_SIZE].copy_from_slice(buf);
                    bucket.is_dirty = false;
                } else {
                    self.stats.write_misses += 1;
                }
                Ok(())
            }
            CacheMode::WriteBack => {
                // Write to cache only and mark dirty
                let bucket_idx = if let Some(&idx) = self.sector_to_bucket.get(&base_lba) {
                    self.stats.write_hits += 1;
                    idx
                } else {
                    self.stats.write_misses += 1;
                    // Populate bucket from backing first so partial writes don't corrupt the rest of bucket
                    let idx = self.allocate_bucket(base_lba)?;
                    let backing_offset = (base_lba as usize) * SECTOR_SIZE;
                    let mut bucket_data = vec![0u8; BUCKET_BYTES];
                    let bytes_to_copy = BUCKET_BYTES.min(self.backing_storage.len().saturating_sub(backing_offset));
                    bucket_data[..bytes_to_copy].copy_from_slice(&self.backing_storage[backing_offset..backing_offset + bytes_to_copy]);

                    let bucket = &mut self.buckets[idx];
                    bucket.backing_lba = base_lba;
                    bucket.is_valid = true;
                    bucket.data = bucket_data;

                    self.sector_to_bucket.insert(base_lba, idx);
                    idx
                };

                let bucket = &mut self.buckets[bucket_idx];
                bucket.lru_tick = tick;
                bucket.is_dirty = true;
                bucket.data[offset_in_bucket..offset_in_bucket + SECTOR_SIZE].copy_from_slice(buf);
                Ok(())
            }
        }
    }

    /// Explicitly flushes all dirty buckets to the backing storage.
    pub fn flush(&mut self) -> usize {
        let mut flushed_count = 0usize;
        for bucket in self.buckets.iter_mut() {
            if bucket.is_valid && bucket.is_dirty {
                let offset = (bucket.backing_lba as usize) * SECTOR_SIZE;
                self.backing_storage[offset..offset + BUCKET_BYTES].copy_from_slice(&bucket.data);
                bucket.is_dirty = false;
                flushed_count += 1;
            }
        }
        self.stats.flushes += flushed_count as u64;
        flushed_count
    }

    /// Read directly from backing storage (used for test verification).
    pub fn read_backing_direct(&self, sector: u64, buf: &mut [u8]) -> Result<(), BcacheError> {
        if sector >= self.backing_total_sectors {
            return Err(BcacheError::InvalidSector {
                sector,
                max: self.backing_total_sectors,
            });
        }
        let offset = (sector as usize) * SECTOR_SIZE;
        buf.copy_from_slice(&self.backing_storage[offset..offset + SECTOR_SIZE]);
        Ok(())
    }
}
