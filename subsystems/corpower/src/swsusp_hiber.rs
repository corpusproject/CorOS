//! Software Suspend to Disk (swsusp / S4 Hibernation) header, saveable page bitmap & CRC-32 verification.

use alloc::vec::Vec;

/// Standard Hibernation Image Header (e.g. stored in `HIBER.DAT` or Swap partition).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwsuspHeader {
    pub magic: [u8; 8], // b"COROS_S4"
    pub version: u32,
    pub total_pages: u32,
    pub image_crc32: u32,
    pub resume_lba: u64,
}

impl SwsuspHeader {
    pub const MAGIC: [u8; 8] = *b"COROS_S4";

    pub fn new(total_pages: u32, image_crc32: u32, resume_lba: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            total_pages,
            image_crc32,
            resume_lba,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == 1 && self.total_pages > 0
    }
}

/// Bitfield representing saveable memory pages during hibernation snapshot creation.
pub struct SaveablePageBitmap {
    pub max_pfn: usize,
    pub bits: Vec<u64>,
}

impl SaveablePageBitmap {
    pub fn new(max_pfn: usize) -> Self {
        let num_words = (max_pfn + 63) / 64;
        Self {
            max_pfn,
            bits: alloc::vec![0u64; num_words],
        }
    }

    #[inline]
    pub fn set_saveable(&mut self, pfn: usize) {
        if pfn < self.max_pfn {
            self.bits[pfn / 64] |= 1 << (pfn % 64);
        }
    }

    #[inline]
    pub fn is_saveable(&self, pfn: usize) -> bool {
        if pfn < self.max_pfn {
            (self.bits[pfn / 64] & (1 << (pfn % 64))) != 0
        } else {
            false
        }
    }

    pub fn count_saveable_pages(&self) -> usize {
        let mut count = 0;
        for &w in &self.bits {
            count += w.count_ones() as usize;
        }
        count
    }
}
