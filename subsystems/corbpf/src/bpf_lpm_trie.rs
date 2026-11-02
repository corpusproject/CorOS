//! `BPF_MAP_TYPE_LPM_TRIE` Longest-Prefix Match Bitwise Radix Trie.
//!
//! Supports arbitrary key byte widths (e.g., 4 bytes for IPv4 `/0..=/32` or
//! 16 bytes for IPv6 `/0..=/128`) with longest-prefix match lookup, prefix
//! insertion/update, and automatic leaf pruning on deletion.

use alloc::vec;
use alloc::vec::Vec;

/// Error returned by `BpfLpmTrie` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LpmError {
    KeySizeMismatch,
    ValueSizeMismatch,
    PrefixLenOutOfBounds,
    PrefixNotFound,
    TrieCapacityExceeded,
}

#[derive(Clone)]
struct LpmNode {
    left_child: Option<usize>,
    right_child: Option<usize>,
    value: Option<Vec<u8>>,
    active: bool,
}

/// Bitwise radix trie implementing `BPF_MAP_TYPE_LPM_TRIE`.
pub struct BpfLpmTrie {
    key_bytes: usize,
    value_bytes: usize,
    max_prefixes: usize,
    active_prefixes: usize,
    nodes: Vec<LpmNode>,
}

impl BpfLpmTrie {
    pub fn new(key_bytes: usize, value_bytes: usize, max_prefixes: usize) -> Self {
        let root = LpmNode {
            left_child: None,
            right_child: None,
            value: None,
            active: true,
        };
        Self {
            key_bytes,
            value_bytes,
            max_prefixes,
            active_prefixes: 0,
            nodes: vec![root],
        }
    }

    pub const fn max_prefix_bits(&self) -> u32 {
        (self.key_bytes * 8) as u32
    }

    pub const fn len(&self) -> usize {
        self.active_prefixes
    }

    pub const fn is_empty(&self) -> bool {
        self.active_prefixes == 0
    }

    /// Extract bit `bit_idx` (`0` = MSB of `key[0]`) from `key`.
    #[inline]
    fn extract_bit(key: &[u8], bit_idx: u32) -> u8 {
        let byte_idx = (bit_idx / 8) as usize;
        let bit_in_byte = 7 - (bit_idx % 8);
        (key[byte_idx] >> bit_in_byte) & 1
    }

    fn alloc_node(&mut self) -> usize {
        for (idx, node) in self.nodes.iter_mut().enumerate().skip(1) {
            if !node.active {
                node.left_child = None;
                node.right_child = None;
                node.value = None;
                node.active = true;
                return idx;
            }
        }
        let idx = self.nodes.len();
        self.nodes.push(LpmNode {
            left_child: None,
            right_child: None,
            value: None,
            active: true,
        });
        idx
    }

    /// Insert or update a `(prefix_len, key) -> value` route in the trie.
    pub fn update_prefix(
        &mut self,
        prefix_len: u32,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), LpmError> {
        if key.len() != self.key_bytes {
            return Err(LpmError::KeySizeMismatch);
        }
        if value.len() != self.value_bytes {
            return Err(LpmError::ValueSizeMismatch);
        }
        if prefix_len > self.max_prefix_bits() {
            return Err(LpmError::PrefixLenOutOfBounds);
        }

        let mut curr = 0usize;
        for bit_idx in 0..prefix_len {
            let bit = Self::extract_bit(key, bit_idx);
            let next_opt = if bit == 0 {
                self.nodes[curr].left_child
            } else {
                self.nodes[curr].right_child
            };
            let next_idx = match next_opt {
                Some(idx) => idx,
                None => {
                    if self.active_prefixes >= self.max_prefixes {
                        return Err(LpmError::TrieCapacityExceeded);
                    }
                    let new_idx = self.alloc_node();
                    if bit == 0 {
                        self.nodes[curr].left_child = Some(new_idx);
                    } else {
                        self.nodes[curr].right_child = Some(new_idx);
                    }
                    new_idx
                }
            };
            curr = next_idx;
        }

        if self.nodes[curr].value.is_none() {
            if self.active_prefixes >= self.max_prefixes {
                return Err(LpmError::TrieCapacityExceeded);
            }
            self.active_prefixes += 1;
        }
        self.nodes[curr].value = Some(value.to_vec());
        Ok(())
    }

    /// Perform longest-prefix match (`LPM`) for `key`, returning the matched `(prefix_len, value_slice)`.
    pub fn lookup_lpm(&self, key: &[u8]) -> Result<Option<(u32, &[u8])>, LpmError> {
        if key.len() != self.key_bytes {
            return Err(LpmError::KeySizeMismatch);
        }

        let mut curr = 0usize;
        let mut best_match: Option<(u32, usize)> = self.nodes[0].value.as_ref().map(|_| (0, 0));

        let total_bits = self.max_prefix_bits();
        for bit_idx in 0..total_bits {
            let bit = Self::extract_bit(key, bit_idx);
            let next_opt = if bit == 0 {
                self.nodes[curr].left_child
            } else {
                self.nodes[curr].right_child
            };
            let Some(next_idx) = next_opt else {
                break;
            };
            curr = next_idx;
            if self.nodes[curr].value.is_some() {
                best_match = Some((bit_idx + 1, curr));
            }
        }

        Ok(best_match.and_then(|(plen, node_idx)| {
            self.nodes[node_idx]
                .value
                .as_deref()
                .map(|val_slice| (plen, val_slice))
        }))
    }

    /// Delete an exact `(prefix_len, key)` entry and prune any childless intermediate nodes.
    pub fn delete_prefix(&mut self, prefix_len: u32, key: &[u8]) -> Result<(), LpmError> {
        if key.len() != self.key_bytes {
            return Err(LpmError::KeySizeMismatch);
        }
        if prefix_len > self.max_prefix_bits() {
            return Err(LpmError::PrefixLenOutOfBounds);
        }

        let mut path: Vec<(usize, u8)> = Vec::with_capacity(prefix_len as usize);
        let mut curr = 0usize;
        for bit_idx in 0..prefix_len {
            let bit = Self::extract_bit(key, bit_idx);
            let next_opt = if bit == 0 {
                self.nodes[curr].left_child
            } else {
                self.nodes[curr].right_child
            };
            let Some(next_idx) = next_opt else {
                return Err(LpmError::PrefixNotFound);
            };
            path.push((curr, bit));
            curr = next_idx;
        }

        if self.nodes[curr].value.take().is_none() {
            return Err(LpmError::PrefixNotFound);
        }
        self.active_prefixes = self.active_prefixes.saturating_sub(1);

        // Walk bottom-up along `path` to prune empty leaf nodes.
        let mut child_idx = curr;
        while let Some((parent_idx, bit)) = path.pop() {
            let child = &self.nodes[child_idx];
            if child.value.is_none() && child.left_child.is_none() && child.right_child.is_none() {
                self.nodes[child_idx].active = false;
                if bit == 0 {
                    self.nodes[parent_idx].left_child = None;
                } else {
                    self.nodes[parent_idx].right_child = None;
                }
                child_idx = parent_idx;
            } else {
                break;
            }
        }

        Ok(())
    }
}
