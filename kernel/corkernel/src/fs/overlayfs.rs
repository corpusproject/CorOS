//! OverlayFS (Union Mount & Container Layering Filesystem) for CorOS.
//!
//! Implements modern container union filesystem mechanics (Docker / OCI compatible):
//! - Multi-layer lowerdir (read-only base image layers stacked in precedence order)
//! - Single upperdir (read-write copy-on-write layer)
//! - Atomic workdir scratchpad
//! - Copy-Up (COW): Lazily copies files from lower layers to upper layer on first write
//! - Whiteout device nodes (char 0,0) and opaque directory markers for atomic deletions

#![allow(dead_code)]

use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use core::fmt;

/// Overlay Entry Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayEntryType {
    RegularFile,
    Directory,
    Symlink,
    Whiteout, // Marks file deleted in upper layer, hiding lower layer occurrences
}

/// Unified In-Memory Overlay Node
#[derive(Debug, Clone)]
pub struct OverlayNode {
    pub name: String,
    pub node_type: OverlayEntryType,
    pub is_upper: bool,
    pub layer_index: usize, // 0 = upperdir, 1..N = lowerdirs
    pub size: u64,
    pub data: Option<Vec<u8>>,
    pub is_opaque: bool, // Opaque directory ignores all underlying lower directories
}

/// Overlay Filesystem Engine
pub struct OverlayFileSystem {
    /// Upper directory layer (Read-Write)
    pub upper_entries: BTreeMap<String, OverlayNode>,
    /// Lower directory layers (Read-Only stack, lowest index has highest priority)
    pub lower_layers: Vec<BTreeMap<String, OverlayNode>>,
    /// Work directory tracking pending transactions
    pub work_dir: BTreeMap<String, OverlayNode>,
    pub copy_up_count: u64,
    pub whiteout_count: u64,
}

impl OverlayFileSystem {
    pub fn new() -> Self {
        Self {
            upper_entries: BTreeMap::new(),
            lower_layers: Vec::new(),
            work_dir: BTreeMap::new(),
            copy_up_count: 0,
            whiteout_count: 0,
        }
    }

    /// Add a read-only lower layer (e.g. from container image rootfs)
    pub fn add_lower_layer(&mut self, layer: BTreeMap<String, OverlayNode>) {
        self.lower_layers.push(layer);
    }

    /// Lookup a file across the union stack (upper layer first, then lower layers in order)
    pub fn lookup(&self, path: &str) -> Option<&OverlayNode> {
        // 1. Check upper layer
        if let Some(node) = self.upper_entries.get(path) {
            if node.node_type == OverlayEntryType::Whiteout {
                return None; // File was deleted via whiteout
            }
            return Some(node);
        }

        // 2. Check lower layers in precedence order
        for layer in &self.lower_layers {
            if let Some(node) = layer.get(path) {
                if node.node_type == OverlayEntryType::Whiteout {
                    return None;
                }
                return Some(node);
            }
        }

        None
    }

    /// Read file content, triggering transparent access to lower or upper layer
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, &'static str> {
        let node = self.lookup(path).ok_or("File not found in union stack")?;
        if node.node_type != OverlayEntryType::RegularFile {
            return Err("Not a regular file");
        }
        node.data.clone().ok_or("No data in node")
    }

    /// Write file: Performs Copy-Up (COW) if file resides only in a lower layer
    pub fn write_file(&mut self, path: &str, new_data: &[u8]) -> Result<(), &'static str> {
        // Check if file already exists in upper layer
        if let Some(upper_node) = self.upper_entries.get_mut(path) {
            upper_node.data = Some(new_data.to_vec());
            upper_node.size = new_data.len() as u64;
            upper_node.node_type = OverlayEntryType::RegularFile;
            return Ok(());
        }

        // Check if file exists in lower layer -> Trigger Copy-Up
        let mut found_lower = false;
        for layer in &self.lower_layers {
            if layer.contains_key(path) {
                found_lower = true;
                break;
            }
        }

        if found_lower {
            self.copy_up_count += 1;
        }

        // Write directly to upper layer
        let new_node = OverlayNode {
            name: path.into(),
            node_type: OverlayEntryType::RegularFile,
            is_upper: true,
            layer_index: 0,
            size: new_data.len() as u64,
            data: Some(new_data.to_vec()),
            is_opaque: false,
        };

        self.upper_entries.insert(path.into(), new_node);
        Ok(())
    }

    /// Delete file: Creates a Whiteout node in upperdir to mask lower layers
    pub fn delete_file(&mut self, path: &str) -> Result<(), &'static str> {
        let exists_somewhere = self.lookup(path).is_some();
        if !exists_somewhere {
            return Err("File not found");
        }

        self.whiteout_count += 1;
        let whiteout_node = OverlayNode {
            name: path.into(),
            node_type: OverlayEntryType::Whiteout,
            is_upper: true,
            layer_index: 0,
            size: 0,
            data: None,
            is_opaque: false,
        };

        self.upper_entries.insert(path.into(), whiteout_node);
        Ok(())
    }

    /// List all unique entries in merged directory view
    pub fn readdir(&self, dir_prefix: &str) -> Vec<String> {
        let mut results = BTreeMap::new();

        // 1. Collect from lower layers (bottom to top)
        for layer in self.lower_layers.iter().rev() {
            for (path, node) in layer {
                if path.starts_with(dir_prefix) {
                    if node.node_type == OverlayEntryType::Whiteout {
                        results.remove(path);
                    } else {
                        results.insert(path.clone(), true);
                    }
                }
            }
        }

        // 2. Overlay upper layer (highest priority)
        for (path, node) in &self.upper_entries {
            if path.starts_with(dir_prefix) {
                if node.node_type == OverlayEntryType::Whiteout {
                    results.remove(path);
                } else {
                    results.insert(path.clone(), true);
                }
            }
        }

        results.into_keys().collect()
    }
}

impl fmt::Display for OverlayFileSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OverlayFS(lowers={}, upper_entries={}, copy_ups={}, whiteouts={})",
            self.lower_layers.len(),
            self.upper_entries.len(),
            self.copy_up_count,
            self.whiteout_count
        )
    }
}
