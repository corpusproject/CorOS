//! CorOS Hardware Driver Module: `virtio_blk`
//!
//! VirtIO 1.2 Split Virtqueue layout (`VirtqDesc`, `VirtqAvailHeader`, `VirtqUsedElem`),
//! VirtIO Block Device configuration space (`VirtioBlkConfig`), 16-byte Block Request
//! Header (`VIRTIO_BLK_T_IN`, `VIRTIO_BLK_T_OUT`, `VIRTIO_BLK_T_FLUSH`, `VIRTIO_BLK_T_DISCARD`),
//! and 3-descriptor chain allocator (`Header -> Data -> Status`).

/// VirtIO Device Status bitflags.
pub mod virtio_status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Virtqueue Descriptor flags (`VirtqDesc::flags`).
pub mod virtq_desc_flags {
    /// Buffer continues via the `next` field.
    pub const NEXT: u16 = 1 << 0;
    /// Buffer is device-writable (vs device-readable).
    pub const WRITE: u16 = 1 << 1;
    /// Buffer contains a list of indirect descriptors.
    pub const INDIRECT: u16 = 1 << 2;
}

/// VirtIO Block Feature bits.
pub mod virtio_blk_features {
    pub const SIZE_MAX: u64 = 1 << 1;
    pub const SEG_MAX: u64 = 1 << 2;
    pub const GEOMETRY: u64 = 1 << 4;
    pub const RO: u64 = 1 << 5;
    pub const BLK_SIZE: u64 = 1 << 6;
    pub const FLUSH: u64 = 1 << 9;
    pub const TOPOLOGY: u64 = 1 << 10;
    pub const MQ: u64 = 1 << 12;
    pub const DISCARD: u64 = 1 << 13;
    pub const WRITE_ZEROES: u64 = 1 << 14;
}

/// VirtIO Block Request Type codes (`VirtioBlkReqHeader::req_type`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkReqType {
    In = 0,
    Out = 1,
    Flush = 4,
    GetId = 8,
    Discard = 11,
    WriteZeroes = 13,
}

/// VirtIO Block Status byte values written by the device into the final 1-byte descriptor.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkStatus {
    Ok = 0,
    IoErr = 1,
    Unsupported = 2,
    Pending = 0xFF,
}

/// 16-byte Split Virtqueue Descriptor (`VirtqDesc`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqDesc {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// `virtq_desc_flags` (`NEXT`, `WRITE`, `INDIRECT`).
    pub flags: u16,
    /// Index of the next chained descriptor if `NEXT` is set.
    pub next: u16,
}

impl VirtqDesc {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }
}

/// 8-byte Split Virtqueue Used Ring Element (`VirtqUsedElem`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqUsedElem {
    /// Index of start of used descriptor chain.
    pub id: u32,
    /// Total length of the descriptor chain written to by the device.
    pub len: u32,
}

/// 16-byte VirtIO Block Request Header (`VirtioBlkReqHeader`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

impl VirtioBlkReqHeader {
    #[inline]
    pub const fn new(req_type: VirtioBlkReqType, sector: u64) -> Self {
        Self {
            req_type: req_type as u32,
            reserved: 0,
            sector,
        }
    }
}

/// VirtIO Block Device Configuration Space layout (`VirtioBlkConfig`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioBlkConfig {
    /// Total capacity in 512-byte sectors.
    pub capacity_sectors: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
    /// Logical block size in bytes (typically 512 or 4096).
    pub blk_size: u32,
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: u16,
    pub opt_io_size: u32,
}

impl VirtioBlkConfig {
    #[inline]
    pub const fn total_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(512)
    }
}

/// Free-list descriptor allocator and 3-stage block request chain builder for a Split Virtqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqDescriptorChainAllocator {
    pub queue_size: u16,
    pub free_head: u16,
    pub free_count: u16,
    pub avail_idx: u16,
    pub last_used_idx: u16,
}

impl VirtqDescriptorChainAllocator {
    /// Initializes the descriptor table free-list linked chain (`0 -> 1 -> 2 ... -> queue_size - 1`).
    pub fn init(desc_table: &mut [VirtqDesc]) -> Self {
        let qsize = desc_table.len() as u16;
        let mut i = 0usize;
        while i < desc_table.len() {
            desc_table[i] = VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: if i + 1 < desc_table.len() {
                    (i + 1) as u16
                } else {
                    0xFFFF
                },
            };
            i += 1;
        }
        Self {
            queue_size: qsize,
            free_head: 0,
            free_count: qsize,
            avail_idx: 0,
            last_used_idx: 0,
        }
    }

    /// Allocates a single descriptor from the free list.
    pub fn alloc_desc(&mut self, desc_table: &mut [VirtqDesc]) -> Option<u16> {
        if self.free_count == 0 || self.free_head == 0xFFFF {
            return None;
        }
        let idx = self.free_head;
        self.free_head = desc_table[idx as usize].next;
        self.free_count -= 1;
        desc_table[idx as usize].next = 0;
        desc_table[idx as usize].flags = 0;
        Some(idx)
    }

    /// Releases a descriptor chain starting at `head_idx` back to the free list.
    pub fn free_chain(&mut self, desc_table: &mut [VirtqDesc], head_idx: u16) {
        let mut curr = head_idx;
        let mut guard = 0u16;
        while (curr as usize) < desc_table.len() && guard < self.queue_size {
            guard += 1;
            let flags = desc_table[curr as usize].flags;
            let next = desc_table[curr as usize].next;
            desc_table[curr as usize].flags = 0;
            desc_table[curr as usize].next = self.free_head;
            self.free_head = curr;
            self.free_count += 1;
            if (flags & virtq_desc_flags::NEXT) == 0 {
                break;
            }
            curr = next;
        }
    }

    /// Builds a 3-descriptor VirtIO Block request chain (`Header -> Data -> 1B Status`)
    /// and returns the head descriptor index.
    pub fn build_block_io_chain(
        &mut self,
        desc_table: &mut [VirtqDesc],
        avail_ring: &mut [u16],
        header_phys: u64,
        data_phys: u64,
        data_len: u32,
        is_write_to_disk: bool,
        status_byte_phys: u64,
    ) -> Option<u16> {
        if self.free_count < 3 {
            return None;
        }
        let d_hdr = self.alloc_desc(desc_table)?;
        let d_dat = self.alloc_desc(desc_table)?;
        let d_sts = self.alloc_desc(desc_table)?;

        // 1. Device-readable 16-byte request header
        desc_table[d_hdr as usize] = VirtqDesc {
            addr: header_phys,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: virtq_desc_flags::NEXT,
            next: d_dat,
        };

        // 2. Data buffer: device-writable for READ (`VIRTIO_BLK_T_IN`), device-readable for WRITE (`VIRTIO_BLK_T_OUT`)
        let data_flags = if is_write_to_disk {
            virtq_desc_flags::NEXT
        } else {
            virtq_desc_flags::NEXT | virtq_desc_flags::WRITE
        };
        desc_table[d_dat as usize] = VirtqDesc {
            addr: data_phys,
            len: data_len,
            flags: data_flags,
            next: d_sts,
        };

        // 3. Device-writable 1-byte completion status
        desc_table[d_sts as usize] = VirtqDesc {
            addr: status_byte_phys,
            len: 1,
            flags: virtq_desc_flags::WRITE,
            next: 0,
        };

        let avail_slot = (self.avail_idx % self.queue_size) as usize;
        if avail_slot < avail_ring.len() {
            avail_ring[avail_slot] = d_hdr;
        }
        self.avail_idx = self.avail_idx.wrapping_add(1);
        Some(d_hdr)
    }
}

/// Self-test for `virtio_blk` Split Virtqueue descriptor chaining, free list reuse, and block request headers.
pub fn verify_driver_module_virtio_blk() -> u32 {
    let mut passed = 0u32;

    // 1. Verify VirtqDesc (16B) and VirtioBlkReqHeader (16B) sizes
    if core::mem::size_of::<VirtqDesc>() == 16
        && core::mem::size_of::<VirtioBlkReqHeader>() == 16
    {
        passed += 1;
    }

    // 2. Verify 3-descriptor chain allocation for a Read (`VIRTIO_BLK_T_IN`) operation
    let mut desc_table = [VirtqDesc::empty(); 8];
    let mut avail_ring = [0u16; 8];
    let mut alloc = VirtqDescriptorChainAllocator::init(&mut desc_table);

    let head = alloc.build_block_io_chain(
        &mut desc_table,
        &mut avail_ring,
        0x1000_0000,
        0x1000_1000,
        4096,
        false, // Read from disk -> device writes to buffer
        0x1000_2000,
    );
    if head == Some(0)
        && alloc.free_count == 5
        && (desc_table[1].flags & virtq_desc_flags::WRITE) != 0
        && desc_table[2].len == 1
    {
        passed += 1;
    }

    // 3. Verify freeing the 3-descriptor chain restores all 8 descriptors
    alloc.free_chain(&mut desc_table, 0);
    if alloc.free_count == 8 {
        passed += 1;
    }

    // 4. Verify VirtioBlkConfig capacity calculation
    let cfg = VirtioBlkConfig {
        capacity_sectors: 2_097_152, // 1 GiB in 512-byte sectors
        size_max: 65536,
        seg_max: 126,
        cylinders: 1024,
        heads: 16,
        sectors_per_track: 63,
        blk_size: 4096,
        physical_block_exp: 3,
        alignment_offset: 0,
        min_io_size: 1,
        opt_io_size: 8,
    };
    if cfg.total_bytes() == 1024 * 1024 * 1024 {
        passed += 1;
    }

    passed
}
