#![no_std]
//! `cormm` — CorOS Linux-Grade Virtual & Physical Memory Management Subsystem.
//!
//! Provides 12 cohesive kernel memory management components:
//! 1. `buddy_allocator`: Physical page frame Buddy Allocator (`MAX_ORDER = 11`) & `MemoryZone` watermarks.
//! 2. `slub_cache`: Linux SLUB-style object slab allocator (`KmemCache`, `SlabPage`, `KmallocSizeClass`).
//! 3. `page_table_x86`: x86_64 4-level & 5-level (`LA57`) page table manager and PCID TLB shootdown tracker.
//! 4. `vma_interval`: Virtual Memory Area (`VmArea`) interval tree with merge, split, and stack guard enforcement.
//! 5. `zram_swap`: In-RAM RLE+LZ77 compressed swap block device (`ZramDevice`) with zero-page elimination.
//! 6. `huge_pages`: Transparent HugePage (`THP`) 2 MiB (`PMD`) and 1 GiB (`PUD`) collapse and CoW split engine.
//! 7. `ksm_dedup`: Kernel Samepage Merging (`ksmd`) FNV-1a 64-bit page deduplication and CoW tracker.
//! 8. `oom_killer`: Linux Out-Of-Memory (`OomVictimSelector`) badness heuristic and immunity evaluator.
//! 9. `memcg_cgroup`: Cgroup v2 (`MemCgroup`) hierarchical memory accounting and `high`/`max` enforcement.
//! 10. `numa_topology`: ACPI SRAT/SLIT NUMA node distance matrix, zonelists, and `NumaPolicy` allocator.
//! 11. `page_reclaim`: Two-list Active/Inactive LRU (`kswapd`) scanner and working-set shadow refault detector.
//! 12. `dma_pool`: Coherent DMA page pool & `SwiotlbAperture` software IOMMU bounce buffer allocator.

extern crate alloc;

pub mod buddy_allocator;
pub mod dma_pool;
pub mod huge_pages;
pub mod ksm_dedup;
pub mod memcg_cgroup;
pub mod numa_topology;
pub mod oom_killer;
pub mod page_reclaim;
pub mod page_table_mapper;
pub mod page_table_x86;
pub mod page_table_aarch64;
pub mod page_table_riscv64;
pub mod slub_cache;
pub mod vma_interval;
pub mod zram_swap;
pub mod swap_entry;

pub use page_table_mapper::PageTableMapper;
pub use page_table_aarch64::{AArch64AddressSpacePageTable, AArch64PageTableFlags, AArch64Pte};
pub use page_table_riscv64::{Riscv64AddressSpacePageTable, Riscv64PteFlags, Riscv64Pte, RiscvPagingMode};
pub use swap_entry::{encode_swap_entry, decode_swap_entry, is_swap_entry};

use alloc::vec;
use alloc::vec::Vec;

use buddy_allocator::{MemoryZoneKind, PhysicalBuddyAllocator, buddy_pfn};
use dma_pool::{DmaDirection, DmaMask, SwiotlbAperture};
use huge_pages::{CollapseEligibility, HPAGE_PMD_NR, HPAGE_PMD_SIZE, KhugepagedScanner};
use ksm_dedup::{KsmRmapItem, KsmScanOutcome, KsmScanner, fnv1a_hash_page};
use memcg_cgroup::{ChargeOutcome, MemCgLimits, MemCgStatKind, MemCgroupHierarchy};
use numa_topology::{NumaNode, NumaPolicy, NumaTopology};
use oom_killer::{OOM_SCORE_ADJ_MIN, OomVictimSelector, TaskOomProfile};
use page_reclaim::{LruListKind, LruPageFrame, PageReclaimScanner};
use page_table_x86::{
    AddressSpacePageTable, PageTableEntry, PageTableFlags, PagingMode, is_canonical_vaddr,
};
use slub_cache::{KmallocSizeClass, SlubAllocator};
use vma_interval::{VmArea, VmaFlags, VmaIntervalTree, VmaType};
use zram_swap::{ZRAM_PAGE_SIZE, ZramDevice};

/// Executes self-verification tests across all 12 `cormm` memory management modules
/// and returns the count of verified subsystems (`12`).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Buddy Allocator: split, XOR buddy calculation, and coalesce back to order 10
    {
        let mut buddy = PhysicalBuddyAllocator::new_standard_layout(1024, 2048, 0);
        let initial_free = buddy.total_free_pages();
        if let Some((zone, pfn_a)) = buddy.alloc_from_zone(MemoryZoneKind::ZoneNormal, 2, false) {
            let expected_xor = buddy_pfn(pfn_a, 2);
            if zone == MemoryZoneKind::ZoneNormal
                && expected_xor == (pfn_a ^ 4)
                && buddy.free_to_owning_zone(pfn_a, 2)
                && buddy.total_free_pages() == initial_free
            {
                passed += 1;
            }
        }
    }

    // 2. SLUB Cache: allocate and free across size classes
    {
        let mut slub = SlubAllocator::new(0xFFFF_8880_0000_0000);
        if let Some(alloc_receipt) = slub.kmalloc(96) {
            if alloc_receipt.size_class == KmallocSizeClass::Bytes128
                && slub.cache(KmallocSizeClass::Bytes128).active_objects() == 1
                && slub.kfree(alloc_receipt)
                && slub.cache(KmallocSizeClass::Bytes128).active_objects() == 0
            {
                passed += 1;
            }
        }
    }

    // 3. Multi-Arch Page Tables: x86_64, AArch64, and RISC-V PageTableMapper implementations
    {
        let mut pt = AddressSpacePageTable::new(PagingMode::FourLevel, 42);
        let user_vaddr = 0x0000_7FFF_1234_5678u64;
        let non_canonical = 0x0001_0000_0000_0000u64;
        let flags = PageTableFlags::WRITABLE.union(PageTableFlags::USER);
        let mut x86_ok = false;
        if is_canonical_vaddr(user_vaddr, PagingMode::FourLevel)
            && !is_canonical_vaddr(non_canonical, PagingMode::FourLevel)
            && pt.map_page(user_vaddr, 0x0020_0000, flags).is_ok()
        {
            if let Some((phys, _)) = pt.translate(user_vaddr) {
                let _ = pt.unmap_page(user_vaddr);
                let flushed = pt.tlb_tracker_mut().drain_and_acknowledge();
                if phys == 0x0020_0678 && flushed == 1 {
                    x86_ok = true;
                }
            }
        }

        let mut aarch_ok = false;
        let mut aarch_pt = AArch64AddressSpacePageTable::new(7);
        let aarch_flags = AArch64PageTableFlags::AP_USER_RW.union(AArch64PageTableFlags::ATTR_NORMAL_WB);
        if aarch_pt.map_page(user_vaddr, 0x0040_0000, aarch_flags).is_ok() {
            if let Some((phys, _)) = aarch_pt.translate(user_vaddr) {
                let _ = aarch_pt.unmap_page(user_vaddr);
                let flushed = aarch_pt.tlb_tracker_mut().drain_and_acknowledge();
                if phys == 0x0040_0678 && flushed == 1 {
                    aarch_ok = true;
                }
            }
        }

        let mut riscv_ok = false;
        let mut riscv_pt = Riscv64AddressSpacePageTable::new(RiscvPagingMode::Sv39, 15);
        let riscv_flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE).union(Riscv64PteFlags::USER);
        if riscv_pt.map_page(user_vaddr, 0x0060_0000, riscv_flags).is_ok() {
            if let Some((phys, _)) = riscv_pt.translate(user_vaddr) {
                let _ = riscv_pt.unmap_page(user_vaddr);
                let flushed = riscv_pt.tlb_tracker_mut().drain_and_acknowledge();
                if phys == 0x0060_0678 && flushed == 1 {
                    riscv_ok = true;
                }
            }
        }

        if x86_ok && aarch_ok && riscv_ok {
            passed += 1;
        }
    }

    // 4. VMA Interval Manager: adjacent merge, mprotect split, and stack guard check
    {
        let mut vma_tree = VmaIntervalTree::new(0x0001_0000, 0x0000_7FFF_FFFF_F000);
        let rw = VmaFlags::READ.union(VmaFlags::WRITE);
        let first = VmArea::new(0x0010_0000, 0x0010_4000, rw, VmaType::Anonymous, 0, 0);
        let second = VmArea::new(0x0010_4000, 0x0010_8000, rw, VmaType::Anonymous, 0, 0);
        if vma_tree.insert_and_merge(first).is_ok() && vma_tree.insert_and_merge(second).is_ok() {
            let merged_count = vma_tree.vma_count();
            let removed = vma_tree.munmap_range(0x0010_2000, 0x0010_6000);
            if merged_count == 1 && removed == 1 && vma_tree.vma_count() == 2 {
                passed += 1;
            }
        }
    }

    // 5. Zram Compressed Swap: RLE+LZ77 roundtrip and zero-page detection
    {
        let mut zram = ZramDevice::new(64);
        let zero_page = [0u8; ZRAM_PAGE_SIZE];
        let mut structured_page = [0u8; ZRAM_PAGE_SIZE];
        for (idx, b) in structured_page.iter_mut().enumerate() {
            *b = ((idx / 16) & 0xFF) as u8;
        }
        if zram.store_page(0, &zero_page).is_ok() && zram.store_page(1, &structured_page).is_ok() {
            if let Ok(restored) = zram.load_page(1) {
                let stats = zram.telemetry();
                if restored.as_slice() == structured_page.as_slice()
                    && stats.zero_pages_stored == 1
                    && stats.compressed_bytes < ZRAM_PAGE_SIZE
                {
                    passed += 1;
                }
            }
        }
    }

    // 6. Transparent HugePages: collapse 512 4 KiB PTEs into 2 MiB PMD and split back
    {
        let mut thp = KhugepagedScanner::new(8);
        let pte_flags = PageTableFlags::PRESENT
            .union(PageTableFlags::WRITABLE)
            .union(PageTableFlags::USER);
        let mut base_ptes = Vec::with_capacity(HPAGE_PMD_NR);
        for idx in 0..HPAGE_PMD_NR {
            base_ptes.push(PageTableEntry::encode(((0x1000 + idx) as u64) << 12, pte_flags));
        }
        let vaddr_2m = 2 * HPAGE_PMD_SIZE;
        if matches!(
            thp.evaluate_pmd_window(vaddr_2m, &base_ptes),
            CollapseEligibility::Eligible { .. }
        ) && thp
            .collapse_into_pmd_hugepage(vaddr_2m, &base_ptes, 0x2000)
            .is_ok()
        {
            if let Some(split_ptes) = thp.split_huge_pmd(vaddr_2m) {
                if split_ptes.len() == HPAGE_PMD_NR && thp.collapsed_total() == 1 {
                    passed += 1;
                }
            }
        }
    }

    // 7. KSM Deduplication: unstable -> stable promotion and CoW break
    {
        let mut ksm = KsmScanner::new();
        let page_content = [0x5Au8; 256];
        let digest = fnv1a_hash_page(&page_content);
        let item_one = KsmRmapItem {
            pid: 101,
            vaddr: 0x4000_0000,
            current_pfn: 500,
        };
        let item_two = KsmRmapItem {
            pid: 202,
            vaddr: 0x5000_0000,
            current_pfn: 600,
        };
        let step_one = ksm.scan_page(item_one, &page_content);
        let step_two = ksm.scan_page(item_two, &page_content);
        if matches!(step_one, KsmScanOutcome::InsertedIntoUnstable { .. })
            && matches!(step_two, KsmScanOutcome::PromotedToStable { ksm_pfn: 500 })
            && ksm.pages_sharing() == 1
            && ksm.break_cow_on_write(digest, 202, 0x5000_0000, 700).is_some()
        {
            passed += 1;
        }
    }

    // 8. OOM Killer: PID 1 & OOM_SCORE_ADJ_MIN immunity and highest badness victim selection
    {
        let mut oom = OomVictimSelector::new(100_000);
        let tasks = [
            TaskOomProfile::new(1, "init", false, 50_000, 0, 65536, 0),
            TaskOomProfile::new(55, "sshd", false, 20_000, 0, 65536, OOM_SCORE_ADJ_MIN),
            TaskOomProfile::new(120, "worker-small", false, 4_000, 500, 32768, 0),
            TaskOomProfile::new(199, "runaway-hog", false, 45_000, 5_000, 131_072, 200),
        ];
        if let Some(decision) = oom.select_victim(&tasks) {
            if decision.victim_pid == 199 && decision.badness_points > 500 {
                passed += 1;
            }
        }
    }

    // 9. MemCgroup Hierarchy: parent propagation, high throttle, and max OOM rejection
    {
        let mut memcg = MemCgroupHierarchy::new(10_000);
        let limits = MemCgLimits {
            min_pages: 64,
            low_pages: 128,
            high_pages: 500,
            max_pages: 600,
        };
        if memcg.create_cgroup(10, 0, "container-app", limits).is_ok() {
            let ok_step = memcg.try_charge(10, MemCgStatKind::Anon, 400);
            let throttle_step = memcg.try_charge(10, MemCgStatKind::File, 150);
            let oom_step = memcg.try_charge(10, MemCgStatKind::Slab, 100);
            if matches!(ok_step, ChargeOutcome::Allowed { .. })
                && matches!(
                    throttle_step,
                    ChargeOutcome::ThrottledHigh {
                        throttled_cgroup_id: 10,
                        reclaim_target_pages: 50
                    }
                )
                && matches!(
                    oom_step,
                    ChargeOutcome::RejectedMaxOom {
                        limiting_cgroup_id: 10
                    }
                )
            {
                passed += 1;
            }
        }
    }

    // 10. NUMA Topology: SLIT distance zonelist ordering and Interleave policy
    {
        let nodes = vec![
            NumaNode::new(0, 0, 1024, 512, 0x0F),
            NumaNode::new(1, 1024, 2048, 512, 0xF0),
        ];
        let mut numa = NumaTopology::new(nodes);
        let _ = numa.set_distance(0, 1, 21);
        let zonelist = numa.build_zonelist(1);
        let policy = NumaPolicy::Interleave { nodemask: 0b11 };
        let first_node = numa.allocate_on_policy(&policy, 0, 16);
        let second_node = numa.allocate_on_policy(&policy, 0, 16);
        if zonelist == vec![1, 0] && first_node == Some(0) && second_node == Some(1) {
            passed += 1;
        }
    }

    // 11. Page Reclaim (`kswapd`): clock sweep eviction and working-set shadow refault promotion
    {
        let mut reclaim = PageReclaimScanner::new(16);
        reclaim.add_new_page(LruPageFrame {
            pfn: 900,
            is_anon: false,
            referenced: false,
            dirty: false,
        });
        let report = reclaim.shrink_lists(1);
        let refault_promoted = reclaim.handle_page_refault(LruPageFrame {
            pfn: 900,
            is_anon: false,
            referenced: true,
            dirty: false,
        });
        if report.reclaimed_pages == 1
            && refault_promoted
            && reclaim.list_len(LruListKind::ActiveFile) == 1
        {
            passed += 1;
        }
    }

    // 12. DMA Pool & SWIOTLB: 32-bit direct zero-copy vs >4 GiB bounce buffer allocation
    {
        let mut swiotlb = SwiotlbAperture::new(0x0010_0000, 32);
        let low_phys = 0x0040_0000u64;
        let high_phys = 0x0002_0000_0000u64; // 8 GiB (above 32-bit PCI DMA mask)
        if let (Ok(direct_map), Ok(bounced_map)) = (
            swiotlb.map_single(low_phys, 4096, DmaMask::Bit32, DmaDirection::ToDevice),
            swiotlb.map_single(high_phys, 4096, DmaMask::Bit32, DmaDirection::Bidirectional),
        ) {
            if !direct_map.is_bounced()
                && bounced_map.is_bounced()
                && bounced_map.bounce_slot_count == 2
                && swiotlb.unmap_single(bounced_map)
                && swiotlb.free_slots() == 32
            {
                passed += 1;
            }
        }
    }

    // 13. Swap Entry PTE encoding and decoding
    passed += swap_entry::verify_swap_entries();

    passed
}
