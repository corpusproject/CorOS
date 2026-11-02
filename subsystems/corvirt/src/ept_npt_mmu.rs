//! Second-Level Address Translation (`SLAT`) for Intel EPT and AMD NPT,
//! 4-level `GPA -> HPA` page table walker/mapper, memory typing, MMIO trap regions,
//! and dirty page logging bitmap.

use alloc::vec::Vec;

/// EPT/SLAT Memory Caching Type (`MTRR`/`PAT` effective encoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EptMemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

/// Permission flags for a Second-Level Address Translation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlatPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SlatPermissions {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const READ_WRITE_EXEC: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// Encodes permissions into Intel EPT low bits `[2:0]`.
    pub const fn to_ept_bits(self) -> u64 {
        let mut bits = 0u64;
        if self.read {
            bits |= 1 << 0;
        }
        if self.write {
            bits |= 1 << 1;
        }
        if self.execute {
            bits |= 1 << 2;
        }
        bits
    }

    /// Decodes permissions from Intel EPT low bits `[2:0]`.
    pub const fn from_ept_bits(raw: u64) -> Self {
        Self {
            read: (raw & (1 << 0)) != 0,
            write: (raw & (1 << 1)) != 0,
            execute: (raw & (1 << 2)) != 0,
        }
    }
}

/// Bitmask constants for Intel EPT / AMD NPT 64-bit page table entries.
pub mod slat_entry_flags {
    pub const EPT_READ: u64 = 1 << 0;
    pub const EPT_WRITE: u64 = 1 << 1;
    pub const EPT_EXEC: u64 = 1 << 2;
    pub const EPT_MEM_TYPE_SHIFT: u64 = 3;
    pub const EPT_IGNORE_PAT: u64 = 1 << 6;
    pub const EPT_LARGE_PAGE: u64 = 1 << 7;
    pub const EPT_ACCESSED: u64 = 1 << 8;
    pub const EPT_DIRTY: u64 = 1 << 9;
    pub const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
}

/// A 512-entry 4 KiB page table node used at PML4, PDPT, PD, or PT level.
#[derive(Clone)]
pub struct SlatTableNode {
    pub entries: [u64; 512],
}

impl SlatTableNode {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }
}

/// Registered Guest-Physical MMIO trap aperture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioTrapRegion {
    pub base_gpa: u64,
    pub length_bytes: u64,
    pub device_id: u32,
    pub write_coalescing_enabled: bool,
}

/// Outcome of walking a Guest-Physical Address (`GPA`) through the SLAT hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlatTranslationResult {
    Mapped {
        hpa: u64,
        permissions: SlatPermissions,
        memory_type: EptMemoryType,
        accessed: bool,
        dirty: bool,
    },
    MmioIntercept {
        device_id: u32,
        offset: u64,
    },
    UnmappedGpa {
        failed_level: u8,
    },
    PermissionViolation {
        hpa: u64,
        granted: SlatPermissions,
    },
}

/// 4-Level Second-Level Address Translation (`SlatPageTable`) supporting EPT and NPT.
pub struct SlatPageTable {
    nodes: Vec<SlatTableNode>,
    mmio_regions: Vec<MmioTrapRegion>,
    dirty_bitmap: Vec<u64>,
    tracked_ram_pages: usize,
    enable_ad_bits: bool,
}

impl SlatPageTable {
    /// Creates a new SLAT 4-level hierarchy with an allocated root PML4 node (index 0)
    /// and a dirty-page tracking bitmap covering `tracked_ram_pages` 4 KiB pages.
    pub fn new(tracked_ram_pages: usize, enable_ad_bits: bool) -> Self {
        let mut nodes = Vec::new();
        nodes.push(SlatTableNode::new()); // Root PML4 at node index 0
        let bitmap_words = (tracked_ram_pages + 63) / 64;
        let mut dirty_bitmap = Vec::with_capacity(bitmap_words);
        dirty_bitmap.resize(bitmap_words, 0);

        Self {
            nodes,
            mmio_regions: Vec::new(),
            dirty_bitmap,
            tracked_ram_pages,
            enable_ad_bits,
        }
    }

    /// Constructs the 64-bit Intel `EPTP` (Extended Page Table Pointer) value for VMCS.
    pub fn build_eptp(&self, root_hpa: u64) -> u64 {
        let wb_type = EptMemoryType::WriteBack as u64; // bits [2:0] = 6 (Write-Back)
        let page_walk_len_minus_one = 3u64 << 3; // 4-level walk -> value 3 in bits [5:3]
        let ad_flag = if self.enable_ad_bits { 1u64 << 6 } else { 0 };
        (root_hpa & slat_entry_flags::PHYS_ADDR_MASK) | wb_type | page_walk_len_minus_one | ad_flag
    }

    /// Registers a guest-physical MMIO aperture that intercepts guest reads/writes.
    pub fn register_mmio_region(
        &mut self,
        base_gpa: u64,
        length_bytes: u64,
        device_id: u32,
        write_coalescing_enabled: bool,
    ) -> Result<(), &'static str> {
        if length_bytes == 0 || (base_gpa & 0xFFF) != 0 {
            return Err("MMIO region must be 4 KiB aligned and non-empty");
        }
        let new_end = base_gpa.saturating_add(length_bytes);
        for existing in &self.mmio_regions {
            let ex_end = existing.base_gpa.saturating_add(existing.length_bytes);
            if base_gpa < ex_end && new_end > existing.base_gpa {
                return Err("Overlapping MMIO trap region");
            }
        }
        self.mmio_regions.push(MmioTrapRegion {
            base_gpa,
            length_bytes,
            device_id,
            write_coalescing_enabled,
        });
        Ok(())
    }

    /// Allocates a new internal page table node and returns its node index.
    fn alloc_node(&mut self) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(SlatTableNode::new());
        idx
    }

    /// Maps a 4 KiB Guest-Physical Page (`gpa`) to a Host-Physical Page (`hpa`) across the 4-level tree.
    pub fn map_4k_page(
        &mut self,
        gpa: u64,
        hpa: u64,
        perms: SlatPermissions,
        mem_type: EptMemoryType,
    ) -> Result<(), &'static str> {
        if !perms.read && perms.write {
            return Err("EPT misconfiguration: write-only without read permission is invalid");
        }

        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx = ((gpa >> 12) & 0x1FF) as usize;

        let non_leaf_perms = SlatPermissions::READ_WRITE_EXEC.to_ept_bits();

        // Level 4: PML4 -> PDPT
        let pdpt_node_idx = if self.nodes[0].entries[pml4_idx] == 0 {
            let new_idx = self.alloc_node();
            self.nodes[0].entries[pml4_idx] =
                ((new_idx as u64) << 12) | non_leaf_perms;
            new_idx
        } else {
            ((self.nodes[0].entries[pml4_idx] & slat_entry_flags::PHYS_ADDR_MASK) >> 12) as usize
        };

        // Level 3: PDPT -> PD
        let pd_node_idx = if self.nodes[pdpt_node_idx].entries[pdpt_idx] == 0 {
            let new_idx = self.alloc_node();
            self.nodes[pdpt_node_idx].entries[pdpt_idx] =
                ((new_idx as u64) << 12) | non_leaf_perms;
            new_idx
        } else {
            ((self.nodes[pdpt_node_idx].entries[pdpt_idx] & slat_entry_flags::PHYS_ADDR_MASK) >> 12)
                as usize
        };

        // Level 2: PD -> PT
        let pt_node_idx = if self.nodes[pd_node_idx].entries[pd_idx] == 0 {
            let new_idx = self.alloc_node();
            self.nodes[pd_node_idx].entries[pd_idx] =
                ((new_idx as u64) << 12) | non_leaf_perms;
            new_idx
        } else {
            ((self.nodes[pd_node_idx].entries[pd_idx] & slat_entry_flags::PHYS_ADDR_MASK) >> 12)
                as usize
        };

        // Level 1: Leaf PT Entry
        let mem_bits = (mem_type as u64) << slat_entry_flags::EPT_MEM_TYPE_SHIFT;
        let leaf_entry = (hpa & slat_entry_flags::PHYS_ADDR_MASK)
            | perms.to_ept_bits()
            | mem_bits;
        self.nodes[pt_node_idx].entries[pt_idx] = leaf_entry;
        Ok(())
    }

    /// Walks the 4-level SLAT page table for `gpa` with requested access permissions,
    /// updating hardware Accessed/Dirty bits and dirty page bitmap on write accesses.
    pub fn translate_gpa(
        &mut self,
        gpa: u64,
        req_read: bool,
        req_write: bool,
        req_exec: bool,
    ) -> SlatTranslationResult {
        // First check MMIO trap apertures
        for region in &self.mmio_regions {
            let end = region.base_gpa.saturating_add(region.length_bytes);
            if gpa >= region.base_gpa && gpa < end {
                return SlatTranslationResult::MmioIntercept {
                    device_id: region.device_id,
                    offset: gpa - region.base_gpa,
                };
            }
        }

        let indices = [
            ((gpa >> 39) & 0x1FF) as usize,
            ((gpa >> 30) & 0x1FF) as usize,
            ((gpa >> 21) & 0x1FF) as usize,
            ((gpa >> 12) & 0x1FF) as usize,
        ];

        let mut current_node = 0usize;
        for level in 0..3 {
            let entry = self.nodes[current_node].entries[indices[level]];
            if (entry & 0x7) == 0 {
                return SlatTranslationResult::UnmappedGpa {
                    failed_level: (4 - level) as u8,
                };
            }
            if self.enable_ad_bits {
                self.nodes[current_node].entries[indices[level]] |= slat_entry_flags::EPT_ACCESSED;
            }
            current_node = ((entry & slat_entry_flags::PHYS_ADDR_MASK) >> 12) as usize;
        }

        let leaf_idx = indices[3];
        let mut leaf = self.nodes[current_node].entries[leaf_idx];
        if (leaf & 0x7) == 0 {
            return SlatTranslationResult::UnmappedGpa { failed_level: 1 };
        }

        let granted = SlatPermissions::from_ept_bits(leaf);
        let page_hpa = leaf & slat_entry_flags::PHYS_ADDR_MASK;
        let final_hpa = page_hpa | (gpa & 0xFFF);

        if (req_read && !granted.read)
            || (req_write && !granted.write)
            || (req_exec && !granted.execute)
        {
            return SlatTranslationResult::PermissionViolation {
                hpa: final_hpa,
                granted,
            };
        }

        if self.enable_ad_bits {
            leaf |= slat_entry_flags::EPT_ACCESSED;
            if req_write {
                leaf |= slat_entry_flags::EPT_DIRTY;
                self.mark_gfn_dirty((gpa >> 12) as usize);
            }
            self.nodes[current_node].entries[leaf_idx] = leaf;
        } else if req_write {
            self.mark_gfn_dirty((gpa >> 12) as usize);
        }

        let raw_mem = ((leaf >> slat_entry_flags::EPT_MEM_TYPE_SHIFT) & 0x7) as u8;
        let memory_type = match raw_mem {
            1 => EptMemoryType::WriteCombining,
            4 => EptMemoryType::WriteThrough,
            5 => EptMemoryType::WriteProtected,
            6 => EptMemoryType::WriteBack,
            _ => EptMemoryType::Uncacheable,
        };

        SlatTranslationResult::Mapped {
            hpa: final_hpa,
            permissions: granted,
            memory_type,
            accessed: (leaf & slat_entry_flags::EPT_ACCESSED) != 0,
            dirty: (leaf & slat_entry_flags::EPT_DIRTY) != 0,
        }
    }

    /// Marks a Guest Frame Number (`gfn`) as dirty in the dirty logging bitmap.
    pub fn mark_gfn_dirty(&mut self, gfn: usize) {
        if gfn < self.tracked_ram_pages {
            let word = gfn / 64;
            let bit = gfn % 64;
            self.dirty_bitmap[word] |= 1u64 << bit;
        }
    }

    /// Atomically harvests all dirty Guest Frame Numbers (`GFN`s) and clears the dirty bitmap.
    pub fn harvest_and_clear_dirty_gfns(&mut self) -> Vec<u64> {
        let mut dirty_list = Vec::new();
        for (word_idx, word_ref) in self.dirty_bitmap.iter_mut().enumerate() {
            let mut word = *word_ref;
            if word != 0 {
                *word_ref = 0;
                while word != 0 {
                    let bit = word.trailing_zeros() as usize;
                    let gfn = word_idx * 64 + bit;
                    if gfn < self.tracked_ram_pages {
                        dirty_list.push(gfn as u64);
                    }
                    word &= word - 1;
                }
            }
        }
        dirty_list
    }
}
