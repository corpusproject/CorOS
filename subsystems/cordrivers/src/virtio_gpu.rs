//! CorOS Hardware Driver Module: `virtio_gpu`
//!
//! VirtIO 1.2 GPU Device (`virtio-gpu`) 24-byte Control Header (`VirtioGpuCtrlHdr`),
//! 2D scanout & resource management commands (`GetDisplayInfo`, `ResourceCreate2d`,
//! `ResourceAttachBacking`, `SetScanout`, `TransferToHost2d`, `ResourceFlush`),
//! and hardware cursor commands (`UpdateCursor`, `MoveCursor`).

/// VirtIO GPU Control & Cursor Command Types (`VirtioGpuCtrlHdr::cmd_type`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioGpuCtrlType {
    // 2D commands
    GetDisplayInfo = 0x0100,
    ResourceCreate2d = 0x0101,
    ResourceUnref = 0x0102,
    SetScanout = 0x0103,
    ResourceFlush = 0x0104,
    TransferToHost2d = 0x0105,
    ResourceAttachBacking = 0x0106,
    ResourceDetachBacking = 0x0107,
    GetCapsetInfo = 0x0108,
    GetCapset = 0x0109,
    GetEdid = 0x010A,
    // Cursor commands
    UpdateCursor = 0x0300,
    MoveCursor = 0x0301,
    // Success responses
    RespOkNodata = 0x1100,
    RespOkDisplayInfo = 0x1101,
    RespOkCapsetInfo = 0x1102,
    RespOkCapset = 0x1103,
    RespOkEdid = 0x1104,
    // Error responses
    RespErrUnspec = 0x1200,
    RespErrOutOfMemory = 0x1201,
    RespErrInvalidScanoutId = 0x1202,
    RespErrInvalidResourceId = 0x1203,
    RespErrInvalidContextId = 0x1204,
    RespErrInvalidParameter = 0x1205,
}

/// VirtIO GPU 2D Pixel Formats (`virtio_gpu_formats`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioGpuFormat {
    B8G8R8A8Unorm = 1,
    B8G8R8X8Unorm = 2,
    A8R8G8B8Unorm = 3,
    X8R8G8B8Unorm = 4,
    R8G8B8A8Unorm = 67,
    X8B8G8R8Unorm = 68,
    A8B8G8R8Unorm = 121,
    R8G8B8X8Unorm = 134,
}

/// `VirtioGpuCtrlHdr::flags` bit definitions.
pub const VIRTIO_GPU_FLAG_FENCE: u32 = 1 << 0;

/// 24-byte VirtIO GPU Common Control Header (`virtio_gpu_ctrl_hdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub padding: u32,
}

impl VirtioGpuCtrlHdr {
    #[inline]
    pub const fn new(cmd_type: VirtioGpuCtrlType, fence_id: Option<u64>) -> Self {
        match fence_id {
            Some(fid) => Self {
                cmd_type: cmd_type as u32,
                flags: VIRTIO_GPU_FLAG_FENCE,
                fence_id: fid,
                ctx_id: 0,
                padding: 0,
            },
            None => Self {
                cmd_type: cmd_type as u32,
                flags: 0,
                fence_id: 0,
                ctx_id: 0,
                padding: 0,
            },
        }
    }
}

/// 16-byte 2D rectangle (`virtio_gpu_rect`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl VirtioGpuRect {
    #[inline]
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` (40 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

impl VirtioGpuResourceCreate2d {
    #[inline]
    pub const fn new(
        resource_id: u32,
        format: VirtioGpuFormat,
        width: u32,
        height: u32,
        fence_id: Option<u64>,
    ) -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::new(VirtioGpuCtrlType::ResourceCreate2d, fence_id),
            resource_id,
            format: format as u32,
            width,
            height,
        }
    }
}

/// `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING` header (32 bytes) followed by `nr_entries` of `VirtioGpuMemEntry`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuResourceAttachBacking {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

/// 16-byte Scatter-Gather Guest Physical Page Entry (`virtio_gpu_mem_entry`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuMemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

/// `VIRTIO_GPU_CMD_SET_SCANOUT` (48 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuSetScanout {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

impl VirtioGpuSetScanout {
    #[inline]
    pub const fn new(
        scanout_id: u32,
        resource_id: u32,
        rect: VirtioGpuRect,
        fence_id: Option<u64>,
    ) -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::new(VirtioGpuCtrlType::SetScanout, fence_id),
            rect,
            scanout_id,
            resource_id,
        }
    }
}

/// `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D` (56 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuTransferToHost2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuTransferToHost2d {
    #[inline]
    pub const fn new(
        resource_id: u32,
        rect: VirtioGpuRect,
        byte_offset: u64,
        fence_id: Option<u64>,
    ) -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::new(VirtioGpuCtrlType::TransferToHost2d, fence_id),
            rect,
            offset: byte_offset,
            resource_id,
            padding: 0,
        }
    }
}

/// `VIRTIO_GPU_CMD_RESOURCE_FLUSH` (48 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuResourceFlush {
    pub hdr: VirtioGpuCtrlHdr,
    pub rect: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

impl VirtioGpuResourceFlush {
    #[inline]
    pub const fn new(resource_id: u32, rect: VirtioGpuRect, fence_id: Option<u64>) -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::new(VirtioGpuCtrlType::ResourceFlush, fence_id),
            rect,
            resource_id,
            padding: 0,
        }
    }
}

/// 16-byte Cursor Position descriptor (`virtio_gpu_cursor_pos`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuCursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub padding: u32,
}

/// 56-byte Hardware Cursor Update / Move command (`virtio_gpu_update_cursor`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuUpdateCursor {
    pub hdr: VirtioGpuCtrlHdr,
    pub pos: VirtioGpuCursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub padding: u32,
}

impl VirtioGpuUpdateCursor {
    #[inline]
    pub const fn move_cursor(scanout_id: u32, x: u32, y: u32) -> Self {
        Self {
            hdr: VirtioGpuCtrlHdr::new(VirtioGpuCtrlType::MoveCursor, None),
            pos: VirtioGpuCursorPos {
                scanout_id,
                x,
                y,
                padding: 0,
            },
            resource_id: 0,
            hot_x: 0,
            hot_y: 0,
            padding: 0,
        }
    }
}

/// Self-test for `virtio_gpu` 2D scanout & cursor command packet layouts and fence encoding.
pub fn verify_driver_module_virtio_gpu() -> u32 {
    let mut passed = 0u32;

    // 1. Verify VirtIO GPU wire protocol struct sizes
    if core::mem::size_of::<VirtioGpuCtrlHdr>() == 24
        && core::mem::size_of::<VirtioGpuResourceCreate2d>() == 40
        && core::mem::size_of::<VirtioGpuSetScanout>() == 48
        && core::mem::size_of::<VirtioGpuTransferToHost2d>() == 56
        && core::mem::size_of::<VirtioGpuUpdateCursor>() == 56
    {
        passed += 1;
    }

    // 2. Verify ResourceCreate2d and SetScanout packet generation for 1920x1080 BGRA8
    let create = VirtioGpuResourceCreate2d::new(
        1,
        VirtioGpuFormat::B8G8R8A8Unorm,
        1920,
        1080,
        Some(101),
    );
    let rect = VirtioGpuRect::new(0, 0, 1920, 1080);
    let scanout = VirtioGpuSetScanout::new(0, 1, rect, Some(102));

    if create.hdr.cmd_type == 0x0101
        && create.hdr.flags == VIRTIO_GPU_FLAG_FENCE
        && create.hdr.fence_id == 101
        && scanout.hdr.cmd_type == 0x0103
        && scanout.rect.width == 1920
    {
        passed += 1;
    }

    // 3. Verify TransferToHost2d and ResourceFlush for dirty damage rectangle
    let dirty = VirtioGpuRect::new(100, 50, 400, 300);
    let byte_off = ((50 * 1920 + 100) * 4) as u64;
    let xfer = VirtioGpuTransferToHost2d::new(1, dirty, byte_off, Some(103));
    let flush = VirtioGpuResourceFlush::new(1, dirty, Some(104));
    if xfer.offset == byte_off && flush.hdr.cmd_type == 0x0104 {
        passed += 1;
    }

    // 4. Verify Hardware Cursor move command
    let cursor = VirtioGpuUpdateCursor::move_cursor(0, 960, 540);
    if cursor.hdr.cmd_type == 0x0301 && cursor.pos.x == 960 && cursor.pos.y == 540 {
        passed += 1;
    }

    passed
}
