//! Generic Extended BPF (`eBPF`) Map Subsystem (`ARRAY`, `HASH`, `LRU_HASH`).
//!
//! Provides kernel-space key-value storage accessible from both eBPF programs
//! and user/kernel control planes with `BPF_ANY`, `BPF_NOEXIST`, and `BPF_EXIST` semantics.

use alloc::vec;
use alloc::vec::Vec;

/// Map update flags matching `<linux/bpf.h>`.
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

/// eBPF map type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfMapType {
    Array = 1,
    Hash = 2,
    LruHash = 9,
}

/// Metadata definition for creating an eBPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfMapDef {
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Error returned by eBPF map operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    KeySizeMismatch,
    ValueSizeMismatch,
    KeyNotFound,
    KeyAlreadyExists,
    MapFull,
    IndexOutOfBounds,
    InvalidUpdateFlags,
}

/// Fixed-capacity `BPF_MAP_TYPE_ARRAY` backed by a contiguous flat byte buffer.
/// Keys are 4-byte unsigned 32-bit array indices (`0..max_entries`).
pub struct BpfArrayMap {
    def: BpfMapDef,
    storage: Vec<u8>,
}

impl BpfArrayMap {
    pub fn new(value_size: u32, max_entries: u32) -> Self {
        let total_bytes = (value_size as usize).saturating_mul(max_entries as usize);
        Self {
            def: BpfMapDef {
                map_type: BpfMapType::Array,
                key_size: 4,
                value_size,
                max_entries,
            },
            storage: vec![0u8; total_bytes],
        }
    }

    pub const fn def(&self) -> BpfMapDef {
        self.def
    }

    fn decode_index(&self, key: &[u8]) -> Result<usize, MapError> {
        if key.len() != 4 {
            return Err(MapError::KeySizeMismatch);
        }
        let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        if idx >= self.def.max_entries {
            return Err(MapError::IndexOutOfBounds);
        }
        Ok(idx as usize)
    }

    pub fn lookup_elem(&self, key: &[u8]) -> Option<&[u8]> {
        let idx = self.decode_index(key).ok()?;
        let val_sz = self.def.value_size as usize;
        let start = idx * val_sz;
        Some(&self.storage[start..start + val_sz])
    }

    pub fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        if flags == BPF_NOEXIST {
            // Array map elements always exist from creation.
            return Err(MapError::KeyAlreadyExists);
        }
        if flags != BPF_ANY && flags != BPF_EXIST {
            return Err(MapError::InvalidUpdateFlags);
        }
        if value.len() != self.def.value_size as usize {
            return Err(MapError::ValueSizeMismatch);
        }
        let idx = self.decode_index(key)?;
        let val_sz = self.def.value_size as usize;
        let start = idx * val_sz;
        self.storage[start..start + val_sz].copy_from_slice(value);
        Ok(())
    }

    pub fn get_next_key(&self, current_key: Option<&[u8]>, next_key_out: &mut [u8]) -> Result<(), MapError> {
        if next_key_out.len() != 4 {
            return Err(MapError::KeySizeMismatch);
        }
        if self.def.max_entries == 0 {
            return Err(MapError::KeyNotFound);
        }
        let next_idx = match current_key {
            None => 0u32,
            Some(k) => {
                if k.len() != 4 {
                    return Err(MapError::KeySizeMismatch);
                }
                let idx = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
                if idx + 1 >= self.def.max_entries {
                    return Err(MapError::KeyNotFound);
                }
                idx + 1
            }
        };
        next_key_out.copy_from_slice(&next_idx.to_le_bytes());
        Ok(())
    }
}

/// Entry stored inside a `BpfHashMap` or `BpfLruHashMap`.
#[derive(Clone)]
struct HashBucket {
    occupied: bool,
    hash: u64,
    key: Vec<u8>,
    value: Vec<u8>,
    last_access_tick: u64,
}

/// FNV-1a 64-bit hash function for arbitrary byte keys.
fn fnv1a_hash64(key: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// `BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_LRU_HASH` implementation with monotonic LRU clock.
pub struct BpfHashMap {
    def: BpfMapDef,
    buckets: Vec<HashBucket>,
    active_count: usize,
    access_clock: u64,
}

impl BpfHashMap {
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self::with_type(BpfMapType::Hash, key_size, value_size, max_entries)
    }

    pub fn new_lru(key_size: u32, value_size: u32, max_entries: u32) -> Self {
        Self::with_type(BpfMapType::LruHash, key_size, value_size, max_entries)
    }

    fn with_type(map_type: BpfMapType, key_size: u32, value_size: u32, max_entries: u32) -> Self {
        let mut buckets = Vec::with_capacity(max_entries as usize);
        for _ in 0..max_entries {
            buckets.push(HashBucket {
                occupied: false,
                hash: 0,
                key: vec![0u8; key_size as usize],
                value: vec![0u8; value_size as usize],
                last_access_tick: 0,
            });
        }
        Self {
            def: BpfMapDef {
                map_type,
                key_size,
                value_size,
                max_entries,
            },
            buckets,
            active_count: 0,
            access_clock: 1,
        }
    }

    pub const fn len(&self) -> usize {
        self.active_count
    }

    pub const fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    fn find_slot(&self, key: &[u8], hash: u64) -> Option<usize> {
        if self.buckets.is_empty() {
            return None;
        }
        let cap = self.buckets.len();
        let start = (hash as usize) % cap;
        for step in 0..cap {
            let idx = (start + step) % cap;
            let b = &self.buckets[idx];
            if b.occupied && b.hash == hash && b.key.as_slice() == key {
                return Some(idx);
            }
        }
        None
    }

    pub fn lookup_elem(&mut self, key: &[u8]) -> Option<&[u8]> {
        if key.len() != self.def.key_size as usize {
            return None;
        }
        let hash = fnv1a_hash64(key);
        let idx = self.find_slot(key, hash)?;
        self.access_clock = self.access_clock.wrapping_add(1);
        self.buckets[idx].last_access_tick = self.access_clock;
        Some(self.buckets[idx].value.as_slice())
    }

    pub fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<(), MapError> {
        if key.len() != self.def.key_size as usize {
            return Err(MapError::KeySizeMismatch);
        }
        if value.len() != self.def.value_size as usize {
            return Err(MapError::ValueSizeMismatch);
        }
        if flags != BPF_ANY && flags != BPF_NOEXIST && flags != BPF_EXIST {
            return Err(MapError::InvalidUpdateFlags);
        }

        let hash = fnv1a_hash64(key);
        if let Some(existing_idx) = self.find_slot(key, hash) {
            if flags == BPF_NOEXIST {
                return Err(MapError::KeyAlreadyExists);
            }
            self.access_clock = self.access_clock.wrapping_add(1);
            let slot = &mut self.buckets[existing_idx];
            slot.value.copy_from_slice(value);
            slot.last_access_tick = self.access_clock;
            return Ok(());
        }

        if flags == BPF_EXIST {
            return Err(MapError::KeyNotFound);
        }

        // Need to allocate a free slot or evict LRU slot if `LruHash`.
        let cap = self.buckets.len();
        if cap == 0 {
            return Err(MapError::MapFull);
        }

        let target_idx = if self.active_count < cap {
            let start = (hash as usize) % cap;
            let mut chosen = 0;
            for step in 0..cap {
                let idx = (start + step) % cap;
                if !self.buckets[idx].occupied {
                    chosen = idx;
                    break;
                }
            }
            self.active_count += 1;
            chosen
        } else if self.def.map_type == BpfMapType::LruHash {
            // Find occupied bucket with minimum `last_access_tick`.
            let mut oldest_idx = 0usize;
            let mut oldest_tick = u64::MAX;
            for (idx, bucket) in self.buckets.iter().enumerate() {
                if bucket.occupied && bucket.last_access_tick < oldest_tick {
                    oldest_tick = bucket.last_access_tick;
                    oldest_idx = idx;
                }
            }
            oldest_idx
        } else {
            return Err(MapError::MapFull);
        };

        self.access_clock = self.access_clock.wrapping_add(1);
        let slot = &mut self.buckets[target_idx];
        slot.occupied = true;
        slot.hash = hash;
        slot.key.copy_from_slice(key);
        slot.value.copy_from_slice(value);
        slot.last_access_tick = self.access_clock;
        Ok(())
    }

    pub fn delete_elem(&mut self, key: &[u8]) -> Result<(), MapError> {
        if key.len() != self.def.key_size as usize {
            return Err(MapError::KeySizeMismatch);
        }
        let hash = fnv1a_hash64(key);
        let idx = self.find_slot(key, hash).ok_or(MapError::KeyNotFound)?;
        self.buckets[idx].occupied = false;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    pub fn get_next_key(&self, current_key: Option<&[u8]>, next_key_out: &mut [u8]) -> Result<(), MapError> {
        if next_key_out.len() != self.def.key_size as usize {
            return Err(MapError::KeySizeMismatch);
        }
        let start_search = match current_key {
            None => 0usize,
            Some(k) => {
                if k.len() != self.def.key_size as usize {
                    return Err(MapError::KeySizeMismatch);
                }
                let hash = fnv1a_hash64(k);
                match self.find_slot(k, hash) {
                    Some(idx) => idx + 1,
                    None => 0,
                }
            }
        };

        for idx in start_search..self.buckets.len() {
            if self.buckets[idx].occupied {
                next_key_out.copy_from_slice(&self.buckets[idx].key);
                return Ok(());
            }
        }
        Err(MapError::KeyNotFound)
    }
}
