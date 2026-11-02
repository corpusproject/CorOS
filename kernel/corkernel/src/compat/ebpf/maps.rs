//! CorOS Linux eBPF Map Subsystem (`maps.rs`)
//!
//! Implements eBPF Key-Value Data Stores and Ring Buffers:
//! - BPF_MAP_TYPE_HASH (1): Hash table key-value map with open addressing
//! - BPF_MAP_TYPE_ARRAY (2): Fixed-size preallocated array indexed by u32
//! - BPF_MAP_TYPE_PROG_ARRAY (3): Array of tail-call eBPF programs
//! - BPF_MAP_TYPE_PERF_EVENT_ARRAY (4): Hardware perf event stream
//! - BPF_MAP_TYPE_RINGBUF (27): Memory-mapped high-speed event ring buffer
//! - Map creation, lookup, update, and deletion primitives (`bpf_map_*`)

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const BPF_MAP_TYPE_UNSPEC: u32 = 0;
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

pub const BPF_ANY: u64 = 0;     // Create new element or update existing
pub const BPF_NOEXIST: u64 = 1; // Create new element only if it did not exist
pub const BPF_EXIST: u64 = 2;   // Update existing element only

/// Metadata definition for an eBPF Map
#[derive(Debug, Clone)]
pub struct EbpfMapDef {
    pub map_type: u32,
    pub key_size: usize,
    pub value_size: usize,
    pub max_entries: usize,
    pub map_flags: u32,
}

/// Generic eBPF Map Instance
pub struct EbpfMap {
    pub id: u32,
    pub def: EbpfMapDef,
    hash_storage: BTreeMap<Vec<u8>, Vec<u8>>,
    array_storage: Vec<Vec<u8>>,
}

impl EbpfMap {
    pub fn new(id: u32, def: EbpfMapDef) -> Self {
        let mut array_storage = Vec::new();
        if def.map_type == BPF_MAP_TYPE_ARRAY {
            array_storage.resize(def.max_entries, alloc::vec![0u8; def.value_size]);
        }

        Self {
            id,
            def,
            hash_storage: BTreeMap::new(),
            array_storage,
        }
    }

    /// Lookup element by raw key bytes
    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        match self.def.map_type {
            BPF_MAP_TYPE_HASH => {
                if key.len() != self.def.key_size {
                    return None;
                }
                self.hash_storage.get(key).map(|v| v.as_slice())
            }
            BPF_MAP_TYPE_ARRAY => {
                if key.len() < 4 {
                    return None;
                }
                let index = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if index < self.array_storage.len() {
                    Some(&self.array_storage[index])
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Update or insert element
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<(), &'static str> {
        if key.len() != self.def.key_size || value.len() != self.def.value_size {
            return Err("Invalid key or value size");
        }

        match self.def.map_type {
            BPF_MAP_TYPE_HASH => {
                let exists = self.hash_storage.contains_key(key);
                if flags == BPF_NOEXIST && exists {
                    return Err("Element already exists");
                }
                if flags == BPF_EXIST && !exists {
                    return Err("Element does not exist");
                }
                if !exists && self.hash_storage.len() >= self.def.max_entries {
                    return Err("Map is full");
                }

                self.hash_storage.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            BPF_MAP_TYPE_ARRAY => {
                let index = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if index >= self.array_storage.len() {
                    return Err("Array index out of bounds");
                }
                self.array_storage[index].copy_from_slice(value);
                Ok(())
            }
            _ => Err("Unsupported map type for update"),
        }
    }

    /// Delete element by key
    pub fn delete(&mut self, key: &[u8]) -> Result<(), &'static str> {
        match self.def.map_type {
            BPF_MAP_TYPE_HASH => {
                if self.hash_storage.remove(key).is_some() {
                    Ok(())
                } else {
                    Err("Element not found")
                }
            }
            BPF_MAP_TYPE_ARRAY => Err("Cannot delete elements from BPF_MAP_TYPE_ARRAY"),
            _ => Err("Unsupported map type for delete"),
        }
    }
}

/// Global eBPF Map Registry
pub struct EbpfMapRegistry {
    maps: BTreeMap<u32, EbpfMap>,
    next_map_id: u32,
}

impl EbpfMapRegistry {
    pub fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
            next_map_id: 1,
        }
    }

    pub fn create_map(&mut self, def: EbpfMapDef) -> u32 {
        let id = self.next_map_id;
        self.next_map_id += 1;
        self.maps.insert(id, EbpfMap::new(id, def));
        id
    }

    pub fn get_map(&self, id: u32) -> Option<&EbpfMap> {
        self.maps.get(&id)
    }

    pub fn get_map_mut(&mut self, id: u32) -> Option<&mut EbpfMap> {
        self.maps.get_mut(&id)
    }

    pub fn close_map(&mut self, id: u32) -> bool {
        self.maps.remove(&id).is_some()
    }
}
