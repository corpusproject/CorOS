//! Graphics Execution Manager (GEM) buffer objects & PRIME DMA-BUF cross-device sharing.

use alloc::vec::Vec;

/// GEM memory domain caching policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GemCacheDomain {
    CpuRead,
    CpuWrite,
    GpuRead,
    GpuWrite,
}

/// GEM Buffer Object holding physical backing pages and pitch metadata.
#[derive(Clone, Debug)]
pub struct GemBufferObject {
    pub handle: u32,
    pub size: usize,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub refcount: usize,
    pub dma_address: u64,
    pub physical_pages: Vec<u64>,
}

impl GemBufferObject {
    /// Computes aligned pitch (must align to 64 bytes for hardware burst alignment).
    #[inline]
    pub fn compute_aligned_pitch(width: u32, bpp: u8) -> u32 {
        let bytes_per_pixel = (bpp as u32 + 7) / 8;
        let raw_pitch = width.saturating_mul(bytes_per_pixel);
        (raw_pitch + 63) & !63
    }

    /// Allocates dumb buffer tracking structures with power-of-two page alignment.
    pub fn new_dumb(handle: u32, width: u32, height: u32, bpp: u8, base_pfn: u64) -> Self {
        let pitch = Self::compute_aligned_pitch(width, bpp);
        let raw_size = (pitch as usize).saturating_mul(height as usize);
        let aligned_size = (raw_size + 4095) & !4095;
        let num_pages = aligned_size / 4096;

        let mut physical_pages = Vec::with_capacity(num_pages);
        for i in 0..num_pages {
            physical_pages.push((base_pfn + i as u64) * 4096);
        }

        Self {
            handle,
            size: aligned_size,
            pitch,
            width,
            height,
            bpp,
            refcount: 1,
            dma_address: base_pfn * 4096,
            physical_pages,
        }
    }
}

/// PRIME DMA-BUF export record for sharing GPU buffers between render and scanout devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimeExportEntry {
    pub dma_buf_fd: i32,
    pub source_gem_handle: u32,
    pub size: usize,
    pub is_exported: bool,
}

/// Global GEM & PRIME DMA-BUF table.
pub struct GemManager {
    pub next_handle: u32,
    pub next_fd: i32,
    pub buffers: Vec<GemBufferObject>,
    pub prime_exports: Vec<PrimeExportEntry>,
}

impl GemManager {
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            next_fd: 100,
            buffers: Vec::new(),
            prime_exports: Vec::new(),
        }
    }

    pub fn allocate_dumb(&mut self, width: u32, height: u32, bpp: u8, base_pfn: u64) -> u32 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        let bo = GemBufferObject::new_dumb(handle, width, height, bpp, base_pfn);
        self.buffers.push(bo);
        handle
    }

    pub fn export_prime_dma_buf(&mut self, gem_handle: u32) -> Option<i32> {
        let bo = self.buffers.iter_mut().find(|b| b.handle == gem_handle)?;
        bo.refcount += 1;
        let fd = self.next_fd;
        self.next_fd += 1;
        self.prime_exports.push(PrimeExportEntry {
            dma_buf_fd: fd,
            source_gem_handle: gem_handle,
            size: bo.size,
            is_exported: true,
        });
        Some(fd)
    }

    pub fn import_prime_dma_buf(&mut self, dma_buf_fd: i32) -> Option<u32> {
        let entry = self.prime_exports.iter().find(|e| e.dma_buf_fd == dma_buf_fd)?;
        let bo = self.buffers.iter_mut().find(|b| b.handle == entry.source_gem_handle)?;
        bo.refcount += 1;
        Some(bo.handle)
    }
}
