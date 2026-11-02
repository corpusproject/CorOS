//! CorOS Syscall Domain Module: `io_uring_async`
//! High-Performance Asynchronous I/O Ring Buffers (`io_uring_setup`, `io_uring_enter`, `io_uring_register`).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EBADF: i64 = -9;
pub const EBUSY: i64 = -16;
pub const EAGAIN: i64 = -11;

pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;

pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;

/// `io_uring` submission queue opcodes (`IORING_OP_*`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SendMsg = 9,
    RecvMsg = 10,
    Timeout = 11,
    Accept = 13,
    Connect = 16,
    Close = 19,
    Read = 22,
    Write = 23,
}

impl IoUringOp {
    pub const fn from_raw(op: u8) -> Option<Self> {
        match op {
            0 => Some(Self::Nop),
            1 => Some(Self::Readv),
            2 => Some(Self::Writev),
            3 => Some(Self::Fsync),
            4 => Some(Self::ReadFixed),
            5 => Some(Self::WriteFixed),
            6 => Some(Self::PollAdd),
            7 => Some(Self::PollRemove),
            9 => Some(Self::SendMsg),
            10 => Some(Self::RecvMsg),
            11 => Some(Self::Timeout),
            13 => Some(Self::Accept),
            16 => Some(Self::Connect),
            19 => Some(Self::Close),
            22 => Some(Self::Read),
            23 => Some(Self::Write),
            _ => None,
        }
    }
}

/// Submission Queue Entry (`struct io_uring_sqe`, 64-byte ABI).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub rw_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub file_index: i32,
    pub pad2: [u64; 2],
}

impl IoUringSqe {
    pub const fn nop(user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Nop as u8,
            flags: 0,
            ioprio: 0,
            fd: -1,
            off: 0,
            addr: 0,
            len: 0,
            rw_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            file_index: 0,
            pad2: [0; 2],
        }
    }
}

/// Completion Queue Entry (`struct io_uring_cqe`, 16-byte ABI).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// Ring setup parameters populated by `sys_io_uring_setup`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
}

/// Kernel `io_uring` instance managing SQ/CQ ring buffers and registered fixed buffers/files.
pub struct IoUringInstance {
    pub params: IoUringParams,
    sq_ring: VecDeque<IoUringSqe>,
    cq_ring: VecDeque<IoUringCqe>,
    pub cq_overflow: u64,
    pub registered_buffers: Vec<(u64, u32)>,
    pub registered_files: Vec<i32>,
}

impl IoUringInstance {
    /// `sys_io_uring_setup`: Initializes a new `IoUringInstance` with power-of-two SQ and CQ rings.
    pub fn sys_io_uring_setup(entries: u32, mut params: IoUringParams) -> Result<Self, i64> {
        if entries == 0 || entries > 4096 {
            return Err(EINVAL);
        }
        let sq_sz = entries.next_power_of_two();
        let cq_sz = sq_sz * 2;
        params.sq_entries = sq_sz;
        params.cq_entries = cq_sz;
        params.features = 0x0000_00FF; // SINGLE_MMAP | NODROP | SUBMIT_STABLE | RW_CUR_POS

        Ok(Self {
            params,
            sq_ring: VecDeque::with_capacity(sq_sz as usize),
            cq_ring: VecDeque::with_capacity(cq_sz as usize),
            cq_overflow: 0,
            registered_buffers: Vec::new(),
            registered_files: Vec::new(),
        })
    }

    /// Enqueues an SQE into the submission ring prior to `sys_io_uring_enter`.
    pub fn push_sqe(&mut self, sqe: IoUringSqe) -> bool {
        if self.sq_ring.len() >= self.params.sq_entries as usize {
            return false;
        }
        self.sq_ring.push_back(sqe);
        true
    }

    /// Pops a completed CQE from the completion ring.
    pub fn pop_cqe(&mut self) -> Option<IoUringCqe> {
        self.cq_ring.pop_front()
    }

    fn execute_sqe(&self, sqe: &IoUringSqe) -> i32 {
        let op = match IoUringOp::from_raw(sqe.opcode) {
            Some(o) => o,
            None => return EINVAL as i32,
        };
        match op {
            IoUringOp::Nop => 0,
            IoUringOp::Read | IoUringOp::Write | IoUringOp::Readv | IoUringOp::Writev => {
                if sqe.fd < 0 {
                    EBADF as i32
                } else {
                    sqe.len as i32
                }
            }
            IoUringOp::ReadFixed | IoUringOp::WriteFixed => {
                match self.registered_buffers.get(sqe.buf_index as usize) {
                    Some(&(_, cap)) if sqe.len <= cap => sqe.len as i32,
                    _ => EINVAL as i32,
                }
            }
            IoUringOp::Fsync | IoUringOp::Close => {
                if sqe.fd < 0 {
                    EBADF as i32
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// `sys_io_uring_enter`: Submits up to `to_submit` SQEs and optionally waits for `min_complete` CQEs.
    pub fn sys_io_uring_enter(&mut self, to_submit: u32, min_complete: u32, flags: u32) -> i64 {
        let mut submitted = 0u32;
        while submitted < to_submit {
            let sqe = match self.sq_ring.pop_front() {
                Some(s) => s,
                None => break,
            };
            let res = self.execute_sqe(&sqe);
            if self.cq_ring.len() < self.params.cq_entries as usize {
                self.cq_ring.push_back(IoUringCqe {
                    user_data: sqe.user_data,
                    res,
                    flags: 0,
                });
            } else {
                self.cq_overflow += 1;
            }
            submitted += 1;
        }

        if (flags & IORING_ENTER_GETEVENTS) != 0 && (self.cq_ring.len() as u32) < min_complete {
            return EAGAIN;
        }
        submitted as i64
    }

    /// `sys_io_uring_register`: Registers or unregisters fixed buffers or fixed file descriptor tables.
    pub fn sys_io_uring_register(
        &mut self,
        opcode: u32,
        buffers: &[(u64, u32)],
        files: &[i32],
    ) -> i64 {
        match opcode {
            IORING_REGISTER_BUFFERS => {
                if !self.registered_buffers.is_empty() {
                    return EBUSY;
                }
                if buffers.is_empty() {
                    return EINVAL;
                }
                self.registered_buffers = buffers.to_vec();
                0
            }
            IORING_UNREGISTER_BUFFERS => {
                self.registered_buffers.clear();
                0
            }
            IORING_REGISTER_FILES => {
                if !self.registered_files.is_empty() {
                    return EBUSY;
                }
                if files.is_empty() {
                    return EINVAL;
                }
                self.registered_files = files.to_vec();
                0
            }
            IORING_UNREGISTER_FILES => {
                self.registered_files.clear();
                0
            }
            _ => EINVAL,
        }
    }
}

/// Runs comprehensive self-tests on `io_uring_async` structs and SQ/CQ ring processing.
pub fn verify_domain_io_uring_async() -> u32 {
    let mut passed = 0u32;
    let params = IoUringParams {
        sq_entries: 0,
        cq_entries: 0,
        flags: 0,
        sq_thread_cpu: 0,
        sq_thread_idle: 0,
        features: 0,
    };

    // 1. Setup io_uring with 12 entries -> rounds up to 16 SQ, 32 CQ
    let mut ring = IoUringInstance::sys_io_uring_setup(12, params).unwrap();
    if ring.params.sq_entries == 16 && ring.params.cq_entries == 32 {
        passed += 1;
    }

    // 2. Register fixed I/O buffer and fixed file descriptors
    if ring.sys_io_uring_register(IORING_REGISTER_BUFFERS, &[(0x7000_0000, 4096)], &[]) == 0
        && ring.sys_io_uring_register(IORING_REGISTER_FILES, &[], &[3, 4]) == 0
    {
        passed += 1;
    }

    // 3. Enqueue a NOP SQE and a READ_FIXED SQE
    let sqe_nop = IoUringSqe::nop(0xAA01);
    let mut sqe_read = IoUringSqe::nop(0xBB02);
    sqe_read.opcode = IoUringOp::ReadFixed as u8;
    sqe_read.fd = 3;
    sqe_read.buf_index = 0;
    sqe_read.len = 1024;

    if ring.push_sqe(sqe_nop) && ring.push_sqe(sqe_read) {
        passed += 1;
    }

    // 4. Submit both SQEs via io_uring_enter and verify CQEs
    if ring.sys_io_uring_enter(2, 2, IORING_ENTER_GETEVENTS) == 2 {
        let cqe1 = ring.pop_cqe().unwrap();
        let cqe2 = ring.pop_cqe().unwrap();
        if cqe1.user_data == 0xAA01 && cqe1.res == 0 && cqe2.user_data == 0xBB02 && cqe2.res == 1024 {
            passed += 1;
        }
    }

    // 5. Unregister fixed buffers and files cleanly
    if ring.sys_io_uring_register(IORING_UNREGISTER_BUFFERS, &[], &[]) == 0
        && ring.sys_io_uring_register(IORING_UNREGISTER_FILES, &[], &[]) == 0
    {
        passed += 1;
    }

    passed
}
