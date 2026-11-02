//! Translation Table Manager (TTM) multi-domain VRAM, GTT & System RAM memory placement engine.

use alloc::vec::Vec;

/// TTM Memory Domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtmMemoryDomain {
    SystemRam,
    GttAperture,
    VramDedicated,
}

/// Buffer Object placement flags and preferences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtmPlacementRule {
    pub preferred_domain: TtmMemoryDomain,
    pub allowed_domains: u8,
    pub pinned: bool,
    pub contiguous: bool,
}

impl TtmPlacementRule {
    pub const MASK_SYSTEM: u8 = 1 << 0;
    pub const MASK_GTT: u8 = 1 << 1;
    pub const MASK_VRAM: u8 = 1 << 2;

    pub fn new_vram(pinned: bool) -> Self {
        Self {
            preferred_domain: TtmMemoryDomain::VramDedicated,
            allowed_domains: Self::MASK_VRAM | Self::MASK_GTT | Self::MASK_SYSTEM,
            pinned,
            contiguous: true,
        }
    }
}

/// TTM Managed Buffer Object descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TtmBufferObject {
    pub id: u32,
    pub size_bytes: usize,
    pub current_domain: TtmMemoryDomain,
    pub placement: TtmPlacementRule,
    pub lru_counter: u64,
    pub offset: u64,
}

/// TTM Memory Pool and LRU Eviction Manager.
pub struct TtmPoolManager {
    pub vram_capacity_bytes: usize,
    pub vram_used_bytes: usize,
    pub gtt_capacity_bytes: usize,
    pub gtt_used_bytes: usize,
    pub bo_list: Vec<TtmBufferObject>,
    pub eviction_clock: u64,
}

impl TtmPoolManager {
    pub fn new(vram_capacity_bytes: usize, gtt_capacity_bytes: usize) -> Self {
        Self {
            vram_capacity_bytes,
            vram_used_bytes: 0,
            gtt_capacity_bytes,
            gtt_used_bytes: 0,
            bo_list: Vec::new(),
            eviction_clock: 1,
        }
    }

    /// Allocates or places a buffer object. If VRAM is full, evicts cold unpinned BOs to GTT.
    pub fn place_buffer(&mut self, id: u32, size_bytes: usize, rule: TtmPlacementRule) -> Result<TtmMemoryDomain, &'static str> {
        self.eviction_clock += 1;
        if rule.preferred_domain == TtmMemoryDomain::VramDedicated {
            if self.vram_used_bytes + size_bytes <= self.vram_capacity_bytes {
                let offset = self.vram_used_bytes as u64;
                self.vram_used_bytes += size_bytes;
                self.bo_list.push(TtmBufferObject {
                    id,
                    size_bytes,
                    current_domain: TtmMemoryDomain::VramDedicated,
                    placement: rule,
                    lru_counter: self.eviction_clock,
                    offset,
                });
                return Ok(TtmMemoryDomain::VramDedicated);
            }

            // Attempt LRU eviction
            let mut evicted_id = None;
            for bo in &self.bo_list {
                if bo.current_domain == TtmMemoryDomain::VramDedicated && !bo.placement.pinned {
                    evicted_id = Some(bo.id);
                    break;
                }
            }

            if let Some(eid) = evicted_id {
                self.migrate_bo_domain(eid, TtmMemoryDomain::GttAperture)?;
                return self.place_buffer(id, size_bytes, rule);
            }
        }

        // Fallback to GTT
        if self.gtt_used_bytes + size_bytes <= self.gtt_capacity_bytes {
            let offset = self.gtt_used_bytes as u64;
            self.gtt_used_bytes += size_bytes;
            self.bo_list.push(TtmBufferObject {
                id,
                size_bytes,
                current_domain: TtmMemoryDomain::GttAperture,
                placement: rule,
                lru_counter: self.eviction_clock,
                offset,
            });
            Ok(TtmMemoryDomain::GttAperture)
        } else {
            Ok(TtmMemoryDomain::SystemRam)
        }
    }

    pub fn migrate_bo_domain(&mut self, bo_id: u32, target_domain: TtmMemoryDomain) -> Result<(), &'static str> {
        let bo = self.bo_list.iter_mut().find(|b| b.id == bo_id).ok_or("BO not found")?;
        if bo.placement.pinned {
            return Err("Cannot evict pinned BO");
        }
        match (bo.current_domain, target_domain) {
            (TtmMemoryDomain::VramDedicated, TtmMemoryDomain::GttAperture) => {
                self.vram_used_bytes = self.vram_used_bytes.saturating_sub(bo.size_bytes);
                self.gtt_used_bytes += bo.size_bytes;
                bo.current_domain = TtmMemoryDomain::GttAperture;
            }
            (TtmMemoryDomain::GttAperture, TtmMemoryDomain::VramDedicated) => {
                self.gtt_used_bytes = self.gtt_used_bytes.saturating_sub(bo.size_bytes);
                self.vram_used_bytes += bo.size_bytes;
                bo.current_domain = TtmMemoryDomain::VramDedicated;
            }
            _ => bo.current_domain = target_domain,
        }
        Ok(())
    }
}
