//! Kernel Samepage Merging (`ksmd`) Deduplication Engine.
//!
//! Computes 64-bit FNV-1a content digests over 4 KiB pages, manages the two-tree
//! (`UnstableTreeNode` and `StableTreeNode`) KSM state machine, and tracks
//! read-only Copy-On-Write (CoW) shared physical frames (`ksm_pages_sharing`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// 64-bit FNV-1a offset basis constant.
pub const FNV1A_64_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;

/// 64-bit FNV-1a prime multiplier.
pub const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01B3;

/// Computes the 64-bit FNV-1a content hash of a page buffer.
pub fn fnv1a_hash_page(page_bytes: &[u8]) -> u64 {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    for &byte in page_bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

/// Virtual page descriptor registered for KSM scanning (`rmap_item`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KsmRmapItem {
    pub pid: u32,
    pub vaddr: u64,
    pub current_pfn: usize,
}

/// Node in the KSM Unstable Tree representing a candidate page whose content
/// has not yet been matched twice or write-protected into a KSM stable page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnstableTreeNode {
    pub content_hash: u64,
    pub owner: KsmRmapItem,
}

/// Node in the KSM Stable Tree representing a write-protected (Read-Only CoW)
/// deduplicated physical page shared by one or more `KsmRmapItem` mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableTreeNode {
    pub content_hash: u64,
    pub canonical_ksm_pfn: usize,
    pub sharers: Vec<KsmRmapItem>,
}

/// Outcome of scanning a single candidate page in `KsmScanner::scan_page`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KsmScanOutcome {
    /// Page matched an existing `StableTreeNode` and was remapped Read-Only CoW to `ksm_pfn`.
    MergedIntoStable { ksm_pfn: usize, total_sharers: usize },
    /// Page matched an `UnstableTreeNode`, promoting both into a new `StableTreeNode`.
    PromotedToStable { ksm_pfn: usize },
    /// Page was not found in either tree and was inserted into the Unstable Tree.
    InsertedIntoUnstable { content_hash: u64 },
}

/// Kernel Samepage Merging (`ksmd`) scanner and CoW break manager.
#[derive(Debug, Clone)]
pub struct KsmScanner {
    stable_tree: BTreeMap<u64, StableTreeNode>,
    unstable_tree: BTreeMap<u64, UnstableTreeNode>,
    scan_pass_generation: u64,
    cow_breaks: u64,
}

impl KsmScanner {
    /// Creates an empty `KsmScanner`.
    pub fn new() -> Self {
        Self {
            stable_tree: BTreeMap::new(),
            unstable_tree: BTreeMap::new(),
            scan_pass_generation: 0,
            cow_breaks: 0,
        }
    }

    /// Scans `page_bytes` belonging to `candidate` and performs KSM stable/unstable
    /// tree lookup and deduplication.
    pub fn scan_page(&mut self, candidate: KsmRmapItem, page_bytes: &[u8]) -> KsmScanOutcome {
        let digest = fnv1a_hash_page(page_bytes);

        // 1. Check the Stable Tree first
        if let Some(stable_node) = self.stable_tree.get_mut(&digest) {
            if !stable_node
                .sharers
                .iter()
                .any(|s| s.pid == candidate.pid && s.vaddr == candidate.vaddr)
            {
                let mut updated_candidate = candidate;
                updated_candidate.current_pfn = stable_node.canonical_ksm_pfn;
                stable_node.sharers.push(updated_candidate);
            }
            return KsmScanOutcome::MergedIntoStable {
                ksm_pfn: stable_node.canonical_ksm_pfn,
                total_sharers: stable_node.sharers.len(),
            };
        }

        // 2. Check the Unstable Tree
        if let Some(unstable_node) = self.unstable_tree.remove(&digest) {
            let ksm_pfn = unstable_node.owner.current_pfn;
            let mut remapped_candidate = candidate;
            remapped_candidate.current_pfn = ksm_pfn;

            let stable_node = StableTreeNode {
                content_hash: digest,
                canonical_ksm_pfn: ksm_pfn,
                sharers: alloc::vec![unstable_node.owner, remapped_candidate],
            };
            self.stable_tree.insert(digest, stable_node);
            return KsmScanOutcome::PromotedToStable { ksm_pfn };
        }

        // 3. Insert into the Unstable Tree
        self.unstable_tree.insert(
            digest,
            UnstableTreeNode {
                content_hash: digest,
                owner: candidate,
            },
        );
        KsmScanOutcome::InsertedIntoUnstable {
            content_hash: digest,
        }
    }

    /// Handles a Write Fault (Copy-On-Write break) on a KSM-shared page (`pid`, `vaddr`),
    /// detaching that mapping onto `private_copy_pfn`.
    pub fn break_cow_on_write(
        &mut self,
        content_hash: u64,
        pid: u32,
        vaddr: u64,
        private_copy_pfn: usize,
    ) -> Option<KsmRmapItem> {
        let node = self.stable_tree.get_mut(&content_hash)?;
        let pos = node
            .sharers
            .iter()
            .position(|s| s.pid == pid && s.vaddr == vaddr)?;
        let mut detached = node.sharers.remove(pos);
        detached.current_pfn = private_copy_pfn;
        self.cow_breaks += 1;

        if node.sharers.is_empty() {
            self.stable_tree.remove(&content_hash);
        }
        Some(detached)
    }

    /// Completes a full KSM scan pass, flushing the Unstable Tree as Linux `ksmd` does.
    pub fn finish_scan_sweep(&mut self) {
        self.unstable_tree.clear();
        self.scan_pass_generation += 1;
    }

    /// Number of unique canonical KSM pages in the Stable Tree (`pages_shared`).
    pub fn pages_shared(&self) -> usize {
        self.stable_tree.len()
    }

    /// Number of additional virtual mappings saved by sharing (`pages_sharing`).
    pub fn pages_sharing(&self) -> usize {
        self.stable_tree
            .values()
            .map(|n| n.sharers.len().saturating_sub(1))
            .sum()
    }

    /// Number of volatile candidate entries currently in the Unstable Tree (`pages_unshared`).
    pub fn pages_unshared(&self) -> usize {
        self.unstable_tree.len()
    }

    /// Total Copy-On-Write breaks recorded on KSM stable pages.
    pub const fn cow_breaks(&self) -> u64 {
        self.cow_breaks
    }
}
