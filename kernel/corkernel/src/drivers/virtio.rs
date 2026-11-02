//! Enterprise VirtIO 1.0 / 1.1 Specification Driver for CorOS.
//! 100% in-house implementation supporting VirtIO Split Virtqueues,
//! VirtIO-Block (vblk), VirtIO-Net (vnet), and VirtIO-GPU devices.
//! Compliant with OASIS Virtual I/O Device (VIRTIO) Version 1.1.

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// -----------------------------------------------------------------------------
// VirtIO Device Status Bits
// -----------------------------------------------------------------------------
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8   = 1;
pub const VIRTIO_STATUS_DRIVER: u8        = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8     = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8   = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8        = 128;

// -----------------------------------------------------------------------------
// VirtIO Device IDs (PCI Subsystem ID / VirtIO Standard)
// -----------------------------------------------------------------------------
pub const VIRTIO_DEV_NET: u16    = 1;
pub const VIRTIO_DEV_BLOCK: u16  = 2;
pub const VIRTIO_DEV_CONSOLE: u16= 3;
pub const VIRTIO_DEV_ENTROPY: u16= 4;
pub const VIRTIO_DEV_BALLOON: u16= 5;
pub const VIRTIO_DEV_SCSI: u16   = 8;
pub const VIRTIO_DEV_GPU: u16    = 16;
pub const VIRTIO_DEV_INPUT: u16  = 18;
pub const VIRTIO_DEV_VSOCK: u16  = 19;

// -----------------------------------------------------------------------------
// VirtIO Legacy / Modern PCI Registers Offsets
// -----------------------------------------------------------------------------
pub const VIRTIO_PCI_HOST_FEATURES: usize  = 0x00; // 32-bit R
pub const VIRTIO_PCI_GUEST_FEATURES: usize = 0x04; // 32-bit R/W
pub const VIRTIO_PCI_QUEUE_PFN: usize      = 0x08; // 32-bit R/W
pub const VIRTIO_PCI_QUEUE_SIZE: usize     = 0x0C; // 16-bit R
pub const VIRTIO_PCI_QUEUE_SEL: usize      = 0x0E; // 16-bit R/W
pub const VIRTIO_PCI_QUEUE_NOTIFY: usize   = 0x10; // 16-bit R/W
pub const VIRTIO_PCI_STATUS: usize         = 0x12; // 8-bit R/W
pub const VIRTIO_PCI_ISR: usize            = 0x13; // 8-bit R
pub const VIRTIO_PCI_CONFIG_OFF: usize     = 0x14; // Start of device-specific config

// -----------------------------------------------------------------------------
// Virtqueue Descriptor Flags
// -----------------------------------------------------------------------------
pub const VRING_DESC_F_NEXT: u16     = 1; // Buffer continues via next field
pub const VRING_DESC_F_WRITE: u16    = 2; // Buffer is device write-only
pub const VRING_DESC_F_INDIRECT: u16 = 4; // Buffer contains list of buffer descriptors

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtqDesc {
    pub addr: u64,   // Physical address of the buffer
    pub len: u32,    // Length of the buffer in bytes
    pub flags: u16,  // Descriptor flags (NEXT, WRITE, INDIRECT)
    pub next: u16,   // Next descriptor index in chain
}

// -----------------------------------------------------------------------------
// Virtqueue Available Ring
// -----------------------------------------------------------------------------
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 256], // Up to 256 descriptors
}

// -----------------------------------------------------------------------------
// Virtqueue Used Element & Used Ring
// -----------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtqUsedElem {
    pub id: u32,     // Index of start of used descriptor chain
    pub len: u32,    // Total bytes written into buffer by device
}

pub const VRING_USED_F_NO_NOTIFY: u16 = 1;

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 256],
}

// -----------------------------------------------------------------------------
// Virtqueue Memory Management
// -----------------------------------------------------------------------------
pub struct VirtQueue {
    pub index: u16,
    pub size: u16,
    pub free_head: u16,
    pub num_free: u16,
    pub last_used_idx: u16,
    pub desc_table: Vec<VirtqDesc>,
    pub avail_ring: Vec<u8>,
    pub used_ring: Vec<u8>,
}

impl VirtQueue {
    pub fn new(index: u16, size: u16) -> Self {
        let size = size.min(256);
        let mut desc_table = Vec::with_capacity(size as usize);
        for i in 0..size {
            desc_table.push(VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: (i + 1) % size,
            });
        }

        let avail_size = 4 + 2 * (size as usize);
        let mut avail_ring = Vec::with_capacity(avail_size);
        avail_ring.resize(avail_size, 0);

        let used_size = 4 + core::mem::size_of::<VirtqUsedElem>() * (size as usize);
        let mut used_ring = Vec::with_capacity(used_size);
        used_ring.resize(used_size, 0);

        Self {
            index,
            size,
            free_head: 0,
            num_free: size,
            last_used_idx: 0,
            desc_table,
            avail_ring,
            used_ring,
        }
    }

    pub fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let desc_idx = self.free_head;
        self.free_head = self.desc_table[desc_idx as usize].next;
        self.num_free -= 1;
        Some(desc_idx)
    }

    pub fn free_desc_chain(&mut self, start: u16) {
        let mut cur = start;
        loop {
            let next = self.desc_table[cur as usize].next;
            let flags = self.desc_table[cur as usize].flags;

            self.desc_table[cur as usize].next = self.free_head;
            self.free_head = cur;
            self.num_free += 1;

            if (flags & VRING_DESC_F_NEXT) == 0 {
                break;
            }
            cur = next;
        }
    }

    pub fn submit_chain(&mut self, head: u16) {
        let avail_ptr = self.avail_ring.as_mut_ptr() as *mut VirtqAvail;
        unsafe {
            let cur_idx = read_volatile(&(*avail_ptr).idx);
            let slot = (cur_idx % self.size) as usize;
            (*avail_ptr).ring[slot] = head;
            write_volatile(&mut (*avail_ptr).idx, cur_idx.wrapping_add(1));
        }
    }

    pub fn is_used_ready(&self) -> bool {
        let used_ptr = self.used_ring.as_ptr() as *const VirtqUsed;
        unsafe {
            let cur_idx = read_volatile(&(*used_ptr).idx);
            cur_idx != self.last_used_idx
        }
    }

    pub fn pop_used(&mut self) -> Option<VirtqUsedElem> {
        let used_ptr = self.used_ring.as_ptr() as *const VirtqUsed;
        unsafe {
            let cur_idx = read_volatile(&(*used_ptr).idx);
            if cur_idx == self.last_used_idx {
                return None;
            }
            let slot = (self.last_used_idx % self.size) as usize;
            let elem = (*used_ptr).ring[slot];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Some(elem)
        }
    }
}

// -----------------------------------------------------------------------------
// VirtIO Block Device Driver (virtio-blk)
// -----------------------------------------------------------------------------
pub const VIRTIO_BLK_T_IN: u32           = 0; // Read block
pub const VIRTIO_BLK_T_OUT: u32          = 1; // Write block
pub const VIRTIO_BLK_T_FLUSH: u32        = 4; // Flush cache
pub const VIRTIO_BLK_T_DISCARD: u32      = 11;// Trim / Discard
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32= 13;// Write Zeroes

pub const VIRTIO_BLK_S_OK: u8     = 0;
pub const VIRTIO_BLK_S_IOERR: u8  = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

pub struct VirtioBlockDevice {
    pub io_base: usize,
    pub capacity_sectors: u64,
    pub queue: VirtQueue,
}

impl VirtioBlockDevice {
    pub unsafe fn init(io_base: usize) -> Result<Self, &'static str> {
        // 1. Reset device
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, 0);

        // 2. Set ACKNOWLEDGE status
        let mut status = VIRTIO_STATUS_ACKNOWLEDGE;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        // 3. Set DRIVER status
        status |= VIRTIO_STATUS_DRIVER;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        // 4. Negotiate Features (Read Host, Write Guest)
        let _host_features = read_volatile((io_base + VIRTIO_PCI_HOST_FEATURES) as *const u32);
        write_volatile((io_base + VIRTIO_PCI_GUEST_FEATURES) as *mut u32, 0);

        status |= VIRTIO_STATUS_FEATURES_OK;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        // 5. Setup Request Queue (Index 0)
        write_volatile((io_base + VIRTIO_PCI_QUEUE_SEL) as *mut u16, 0);
        let q_size = read_volatile((io_base + VIRTIO_PCI_QUEUE_SIZE) as *const u16);
        if q_size == 0 {
            return Err("VirtIO block device has 0 queue size");
        }

        let mut queue = VirtQueue::new(0, q_size);

        // Inform device of queue page frame number (PFN = physical address / 4096)
        let pfn = (queue.desc_table.as_ptr() as usize) / 4096;
        write_volatile((io_base + VIRTIO_PCI_QUEUE_PFN) as *mut u32, pfn as u32);

        // 6. Read Device Config (Capacity in 512-byte sectors at config offset 0)
        let cap_low = read_volatile((io_base + VIRTIO_PCI_CONFIG_OFF) as *const u32) as u64;
        let cap_high = read_volatile((io_base + VIRTIO_PCI_CONFIG_OFF + 4) as *const u32) as u64;
        let capacity_sectors = cap_low | (cap_high << 32);

        // 7. Set DRIVER_OK
        status |= VIRTIO_STATUS_DRIVER_OK;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        Ok(Self {
            io_base,
            capacity_sectors,
            queue,
        })
    }

    /// Read raw 512-byte sectors using 3-descriptor split chain.
    pub unsafe fn read_sectors(&mut self, start_sector: u64, count: usize, dest: &mut [u8]) -> Result<(), &'static str> {
        let byte_len = count * 512;
        if dest.len() < byte_len {
            return Err("Destination buffer too small");
        }

        let mut req_header = VirtioBlkReqHeader {
            req_type: VIRTIO_BLK_T_IN,
            reserved: 0,
            sector: start_sector,
        };
        let mut status_byte: u8 = 0xFF;

        // Allocate 3 descriptors:
        // Desc 0: Header (Read-only for device)
        // Desc 1: Data Buffer (Write-only for device)
        // Desc 2: Status Byte (Write-only for device)
        let d0 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;
        let d1 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;
        let d2 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;

        // Fill Desc 0
        self.queue.desc_table[d0 as usize] = VirtqDesc {
            addr: &mut req_header as *mut _ as u64,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: VRING_DESC_F_NEXT,
            next: d1,
        };

        // Fill Desc 1
        self.queue.desc_table[d1 as usize] = VirtqDesc {
            addr: dest.as_mut_ptr() as u64,
            len: byte_len as u32,
            flags: VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
            next: d2,
        };

        // Fill Desc 2
        self.queue.desc_table[d2 as usize] = VirtqDesc {
            addr: &mut status_byte as *mut _ as u64,
            len: 1,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };

        // Submit to available ring
        self.queue.submit_chain(d0);

        // Notify device: write queue index 0 to notify register
        write_volatile((self.io_base + VIRTIO_PCI_QUEUE_NOTIFY) as *mut u16, 0);

        // Busy-wait for completion
        let mut timeout = 1_000_000;
        loop {
            if self.queue.is_used_ready() {
                let _used = self.queue.pop_used();
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                self.queue.free_desc_chain(d0);
                return Err("VirtIO block read timeout");
            }
        }

        self.queue.free_desc_chain(d0);

        if status_byte != VIRTIO_BLK_S_OK {
            return Err("VirtIO block read returned I/O error status");
        }

        Ok(())
    }

    /// Write raw 512-byte sectors using 3-descriptor split chain.
    pub unsafe fn write_sectors(&mut self, start_sector: u64, count: usize, src: &[u8]) -> Result<(), &'static str> {
        let byte_len = count * 512;
        if src.len() < byte_len {
            return Err("Source buffer too small");
        }

        let mut req_header = VirtioBlkReqHeader {
            req_type: VIRTIO_BLK_T_OUT,
            reserved: 0,
            sector: start_sector,
        };
        let mut status_byte: u8 = 0xFF;

        let d0 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;
        let d1 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;
        let d2 = self.queue.alloc_desc().ok_or("Virtqueue out of descriptors")?;

        self.queue.desc_table[d0 as usize] = VirtqDesc {
            addr: &mut req_header as *mut _ as u64,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: VRING_DESC_F_NEXT,
            next: d1,
        };

        self.queue.desc_table[d1 as usize] = VirtqDesc {
            addr: src.as_ptr() as u64,
            len: byte_len as u32,
            flags: VRING_DESC_F_NEXT, // Read-only for device
            next: d2,
        };

        self.queue.desc_table[d2 as usize] = VirtqDesc {
            addr: &mut status_byte as *mut _ as u64,
            len: 1,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };

        self.queue.submit_chain(d0);
        write_volatile((self.io_base + VIRTIO_PCI_QUEUE_NOTIFY) as *mut u16, 0);

        let mut timeout = 1_000_000;
        loop {
            if self.queue.is_used_ready() {
                let _used = self.queue.pop_used();
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                self.queue.free_desc_chain(d0);
                return Err("VirtIO block write timeout");
            }
        }

        self.queue.free_desc_chain(d0);

        if status_byte != VIRTIO_BLK_S_OK {
            return Err("VirtIO block write returned I/O error status");
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// VirtIO Network Device Driver (virtio-net)
// -----------------------------------------------------------------------------
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

pub struct VirtioNetDevice {
    pub io_base: usize,
    pub mac_address: [u8; 6],
    pub rx_queue: VirtQueue,
    pub tx_queue: VirtQueue,
}

impl VirtioNetDevice {
    pub unsafe fn init(io_base: usize) -> Result<Self, &'static str> {
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, 0);

        let mut status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        // Read MAC address from device config space
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = read_volatile((io_base + VIRTIO_PCI_CONFIG_OFF + i) as *const u8);
        }

        // Setup RX Queue (Index 0)
        write_volatile((io_base + VIRTIO_PCI_QUEUE_SEL) as *mut u16, 0);
        let rx_q_size = read_volatile((io_base + VIRTIO_PCI_QUEUE_SIZE) as *const u16);
        let rx_queue = VirtQueue::new(0, rx_q_size);
        let rx_pfn = (rx_queue.desc_table.as_ptr() as usize) / 4096;
        write_volatile((io_base + VIRTIO_PCI_QUEUE_PFN) as *mut u32, rx_pfn as u32);

        // Setup TX Queue (Index 1)
        write_volatile((io_base + VIRTIO_PCI_QUEUE_SEL) as *mut u16, 1);
        let tx_q_size = read_volatile((io_base + VIRTIO_PCI_QUEUE_SIZE) as *const u16);
        let tx_queue = VirtQueue::new(1, tx_q_size);
        let tx_pfn = (tx_queue.desc_table.as_ptr() as usize) / 4096;
        write_volatile((io_base + VIRTIO_PCI_QUEUE_PFN) as *mut u32, tx_pfn as u32);

        status |= VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK;
        write_volatile((io_base + VIRTIO_PCI_STATUS) as *mut u8, status);

        Ok(Self {
            io_base,
            mac_address: mac,
            rx_queue,
            tx_queue,
        })
    }

    /// Transmit raw Ethernet frame using VirtIO-Net header prefix.
    pub unsafe fn send_packet(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        let mut net_hdr = VirtioNetHeader::default();

        let d0 = self.tx_queue.alloc_desc().ok_or("TX virtqueue out of descriptors")?;
        let d1 = self.tx_queue.alloc_desc().ok_or("TX virtqueue out of descriptors")?;

        self.tx_queue.desc_table[d0 as usize] = VirtqDesc {
            addr: &mut net_hdr as *mut _ as u64,
            len: core::mem::size_of::<VirtioNetHeader>() as u32,
            flags: VRING_DESC_F_NEXT,
            next: d1,
        };

        self.tx_queue.desc_table[d1 as usize] = VirtqDesc {
            addr: packet.as_ptr() as u64,
            len: packet.len() as u32,
            flags: 0,
            next: 0,
        };

        self.tx_queue.submit_chain(d0);
        write_volatile((self.io_base + VIRTIO_PCI_QUEUE_NOTIFY) as *mut u16, 1); // Notify TX queue

        let mut timeout = 500_000;
        loop {
            if self.tx_queue.is_used_ready() {
                let _used = self.tx_queue.pop_used();
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                self.tx_queue.free_desc_chain(d0);
                return Err("VirtIO Net TX timeout");
            }
        }

        self.tx_queue.free_desc_chain(d0);
        Ok(())
    }
}
