//! Transparent HugePage (`THP`) 2 MiB (`PMD`) and 1 GiB (`PUD`) Compound Page Manager.
//!
//! Implements `KhugepagedScanner` eligibility scanning (promoting 512 contiguous
//! 4 KiB base PTEs into a single 2 MiB PMD huge page) and splitting a 2 MiB huge
//! page back into 512 individual 4 KiB PTEs upon partial Copy-On-Write or `munmap`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::page_table_x86::{PageTableEntry, PageTableFlags};

/// Number of 4 KiB base pages inside one 2 MiB PMD HugePage (`2^9 = 512`).
pub const HPAGE_PMD_NR: usize = 512;

/// Size in bytes of a 2 MiB PMD HugePage.
pub const HPAGE_PMD_SIZE: u64 = 2 * 1024 * 1024;

/// Size in bytes of a 1 GiB PUD Giant Page (`512 * 2 MiB`).
pub const HPAGE_PUD_SIZE: u64 = 1024 * 1024 * 1024;

/// Granularity of a compound huge page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageLevel {
    /// 2 MiB PMD-level compound page (`Order 9` = 512 base pages).
    Pmd2MiB,
    /// 1 GiB PUD-level giant page (`Order 18` = 262,144 base pages).
    Pud1GiB,
}

impl HugePageLevel {
    /// Returns the size in bytes of this huge page level.
    pub const fn size_bytes(self) -> u64 {
        match self {
            Self::Pmd2MiB => HPAGE_PMD_SIZE,
            Self::Pud1GiB => HPAGE_PUD_SIZE,
        }
    }
}

/// Compound HugePage metadata tracking head PFN, reference count, and mapcount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundHugePage {
    pub head_pfn: usize,
    pub vaddr_base: u64,
    pub level: HugePageLevel,
    pub flags: PageTableFlags,
    pub refcount: u32,
}

/// Result of scanning a 2 MiB virtual region with `KhugepagedScanner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollapseEligibility {
    /// Region can be collapsed into a 2 MiB PMD huge page (`present_count` pages will be copied).
    Eligible {
        present_base_pages: usize,
        uniform_writable: bool,
    },
    /// Virtual address is not 2 MiB aligned.
    UnalignedBaseAddress,
    /// Too few present 4 KiB pages (`< min_ptes_none` threshold).
    InsufficientPresentPages { present_base_pages: usize },
    /// Base PTEs have conflicting protection flags (`USER` / `NO_EXECUTE` mismatch).
    IncompatiblePteFlags,
}

/// Background `khugepaged` collapse scanner and huge page lifecycle manager.
#[derive(Debug, Clone)]
pub struct KhugepagedScanner {
    /// Minimum number of present 4 KiB PTEs out of 512 required before collapsing.
    pub max_ptes_none: usize,
    compound_pages: BTreeMap<u64, CompoundHugePage>,
    collapsed_total: u64,
    split_total: u64,
}

impl KhugepagedScanner {
    /// Creates a new `KhugepagedScanner` (Linux default `max_ptes_none = 511`, or stricter).
    pub fn new(max_ptes_none: usize) -> Self {
        Self {
            max_ptes_none: max_ptes_none.min(HPAGE_PMD_NR),
            compound_pages: BTreeMap::new(),
            collapsed_total: 0,
            split_total: 0,
        }
    }

    /// Evaluates whether a 512-entry slice of 4 KiB PTEs at `pmd_vaddr_base` is eligible
    /// for promotion into a single 2 MiB PMD huge page.
    pub fn evaluate_pmd_window(
        &self,
        pmd_vaddr_base: u64,
        ptes: &[PageTableEntry],
    ) -> CollapseEligibility {
        if (pmd_vaddr_base & (HPAGE_PMD_SIZE - 1)) != 0 || ptes.len() != HPAGE_PMD_NR {
            return CollapseEligibility::UnalignedBaseAddress;
        }

        let min_present = HPAGE_PMD_NR.saturating_sub(self.max_ptes_none);
        let mut present_base_pages = 0usize;
        let mut reference_flags: Option<PageTableFlags> = None;

        for pte in ptes {
            if pte.is_present() {
                present_base_pages += 1;
                let relevant = PageTableFlags::from_bits_truncate(
                    pte.flags().bits()
                        & (PageTableFlags::WRITABLE.bits()
                            | PageTableFlags::USER.bits()
                            | PageTableFlags::NO_EXECUTE.bits()),
                );
                if let Some(expected) = reference_flags {
                    if expected != relevant {
                        return CollapseEligibility::IncompatiblePteFlags;
                    }
                } else {
                    reference_flags = Some(relevant);
                }
            }
        }

        if present_base_pages < min_present || present_base_pages == 0 {
            return CollapseEligibility::InsufficientPresentPages { present_base_pages };
        }

        let uniform_writable = reference_flags
            .map(|f| f.contains(PageTableFlags::WRITABLE))
            .unwrap_or(false);

        CollapseEligibility::Eligible {
            present_base_pages,
            uniform_writable,
        }
    }

    /// Collapses 512 4 KiB PTEs at `pmd_vaddr_base` into a newly allocated 2 MiB
    /// compound page at `new_huge_head_pfn`.
    pub fn collapse_into_pmd_hugepage(
        &mut self,
        pmd_vaddr_base: u64,
        ptes: &[PageTableEntry],
        new_huge_head_pfn: usize,
    ) -> Result<PageTableEntry, CollapseEligibility> {
        match self.evaluate_pmd_window(pmd_vaddr_base, ptes) {
            CollapseEligibility::Eligible {
                uniform_writable, ..
            } => {
                let mut pmd_flags = PageTableFlags::PRESENT
                    .union(PageTableFlags::HUGE_PAGE)
                    .union(PageTableFlags::ACCESSED)
                    .union(PageTableFlags::DIRTY);
                if uniform_writable {
                    pmd_flags = pmd_flags.union(PageTableFlags::WRITABLE);
                }
                let compound = CompoundHugePage {
                    head_pfn: new_huge_head_pfn,
                    vaddr_base: pmd_vaddr_base,
                    level: HugePageLevel::Pmd2MiB,
                    flags: pmd_flags,
                    refcount: 1,
                };
                self.compound_pages.insert(pmd_vaddr_base, compound);
                self.collapsed_total += 1;
                let phys_addr = (new_huge_head_pfn as u64) << 12;
                Ok(PageTableEntry::encode(phys_addr, pmd_flags))
            }
            ineligible => Err(ineligible),
        }
    }

    /// Splits a 2 MiB PMD HugePage at `pmd_vaddr_base` back into 512 contiguous 4 KiB
    /// base `PageTableEntry` descriptors (e.g. on partial CoW fault or partial `munmap`).
    pub fn split_huge_pmd(&mut self, pmd_vaddr_base: u64) -> Option<Vec<PageTableEntry>> {
        let compound = self.compound_pages.remove(&pmd_vaddr_base)?;
        if compound.level != HugePageLevel::Pmd2MiB {
            return None;
        }

        let base_flags = compound.flags.difference(PageTableFlags::HUGE_PAGE);
        let mut base_ptes = Vec::with_capacity(HPAGE_PMD_NR);

        for offset_idx in 0..HPAGE_PMD_NR {
            let sub_pfn = compound.head_pfn + offset_idx;
            let phys_addr = (sub_pfn as u64) << 12;
            base_ptes.push(PageTableEntry::encode(phys_addr, base_flags));
        }

        self.split_total += 1;
        Some(base_ptes)
    }

    /// Registers an explicit 1 GiB PUD Giant Page at `pud_vaddr_base`.
    pub fn register_pud_giant_page(
        &mut self,
        pud_vaddr_base: u64,
        head_pfn: usize,
        flags: PageTableFlags,
    ) -> Result<PageTableEntry, &'static str> {
        if (pud_vaddr_base & (HPAGE_PUD_SIZE - 1)) != 0 {
            return Err("PUD giant page virtual address is not 1 GiB aligned");
        }
        let pud_flags = flags
            .union(PageTableFlags::PRESENT)
            .union(PageTableFlags::HUGE_PAGE);
        self.compound_pages.insert(
            pud_vaddr_base,
            CompoundHugePage {
                head_pfn,
                vaddr_base: pud_vaddr_base,
                level: HugePageLevel::Pud1GiB,
                flags: pud_flags,
                refcount: 1,
            },
        );
        Ok(PageTableEntry::encode((head_pfn as u64) << 12, pud_flags))
    }

    /// Returns total number of collapsed 2 MiB huge pages.
    pub const fn collapsed_total(&self) -> u64 {
        self.collapsed_total
    }

    /// Returns total number of split 2 MiB huge pages.
    pub const fn split_total(&self) -> u64 {
        self.split_total
    }
}
