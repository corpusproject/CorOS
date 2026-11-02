//! CorOS Syscall Domain Module: `ipc_pipes`
//! Inter-Process Communication: Anonymous pipes (`pipe2`), event counters (`eventfd2`), System V shared memory (`shmget`, `shmat`, `shmctl`), semaphores (`semget`, `semop`), and message queues (`msgget`, `msgsnd`, `msgrcv`).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ENXIO: i64 = -6;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const EINVAL: i64 = -22;
pub const EPIPE: i64 = -32;
pub const ENOMSG: i64 = -42;
pub const EMSGSIZE: i64 = -90;

pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_EXCL: u32 = 0o2000;
pub const IPC_RMID: u32 = 0;

pub const EFD_SEMAPHORE: u32 = 1 << 0;
pub const EFD_NONBLOCK: u32 = 1 << 11;

/// Circular ring buffer backing a POSIX unidirectional pipe (`sys_pipe2`).
pub struct PipeBuffer {
    ring: VecDeque<u8>,
    capacity: usize,
    pub readers: u32,
    pub writers: u32,
    pub nonblock: bool,
}

impl PipeBuffer {
    pub fn new(capacity: usize, nonblock: bool) -> Self {
        Self {
            ring: VecDeque::with_capacity(capacity),
            capacity,
            readers: 1,
            writers: 1,
            nonblock,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> i64 {
        if self.readers == 0 {
            return EPIPE;
        }
        let space = self.capacity - self.ring.len();
        if space == 0 {
            return if self.nonblock { EAGAIN } else { 0 };
        }
        let to_write = space.min(data.len());
        for &b in &data[..to_write] {
            self.ring.push_back(b);
        }
        to_write as i64
    }

    pub fn read(&mut self, buf: &mut [u8]) -> i64 {
        if self.ring.is_empty() {
            if self.writers == 0 {
                return 0; // EOF
            }
            return EAGAIN;
        }
        let to_read = self.ring.len().min(buf.len());
        for slot in &mut buf[..to_read] {
            *slot = self.ring.pop_front().unwrap_or(0);
        }
        to_read as i64
    }
}

/// Kernel `eventfd2` 64-bit counter descriptor.
#[derive(Clone, Copy, Debug)]
pub struct EventFdCounter {
    pub counter: u64,
    pub flags: u32,
}

impl EventFdCounter {
    pub const fn new(initval: u32, flags: u32) -> Self {
        Self {
            counter: initval as u64,
            flags,
        }
    }

    pub fn write(&mut self, val: u64) -> i64 {
        if val == u64::MAX || u64::MAX - 1 - self.counter < val {
            return EAGAIN;
        }
        self.counter += val;
        8
    }

    pub fn read(&mut self) -> Result<u64, i64> {
        if self.counter == 0 {
            return Err(EAGAIN);
        }
        if (self.flags & EFD_SEMAPHORE) != 0 {
            self.counter -= 1;
            Ok(1)
        } else {
            let v = self.counter;
            self.counter = 0;
            Ok(v)
        }
    }
}

/// System V Shared Memory segment descriptor (`shmget`, `shmat`, `shmctl`).
#[derive(Clone, Debug)]
pub struct ShmSegment {
    pub shmid: i32,
    pub key: i32,
    pub size: usize,
    pub nattch: u32,
    pub marked_destroy: bool,
    pub pages: Vec<u8>,
    pub attached_addrs: Vec<u64>,
}

/// POSIX Shared Memory named object descriptor (`shm_open`, `shm_unlink`, `ftruncate`, `mmap`).
#[derive(Clone, Debug)]
pub struct PosixShmObject {
    pub name: alloc::string::String,
    pub buffer: Vec<u8>,
    pub size: usize,
}

/// POSIX Message Queue descriptor entry.
pub struct PosixMqEntry {
    pub name: alloc::string::String,
    pub mq: coripc::posix_mqueue::PosixMessageQueue,
}

/// System V Semaphore operation (`struct sembuf`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemBuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: u16,
}

/// System V Semaphore array (`semget`, `semop`).
#[derive(Clone, Debug)]
pub struct SemArray {
    pub semid: i32,
    pub key: i32,
    pub values: Vec<i32>,
}

/// Typed message stored in a System V `MsgQueue`.
#[derive(Clone, Debug)]
pub struct SysvMessage {
    pub mtype: i64,
    pub mtext: Vec<u8>,
}

/// System V Message Queue (`msgget`, `msgsnd`, `msgrcv`).
#[derive(Clone, Debug)]
pub struct MsgQueue {
    pub msqid: i32,
    pub key: i32,
    pub max_bytes: usize,
    pub current_bytes: usize,
    pub messages: VecDeque<SysvMessage>,
}

/// Isolated IPC namespace holding pipes, eventfds, shared memory, semaphores, and message queues.
pub struct IpcNamespace {
    pipes: Vec<PipeBuffer>,
    eventfds: Vec<EventFdCounter>,
    shm_segments: Vec<ShmSegment>,
    sem_arrays: Vec<SemArray>,
    msg_queues: Vec<MsgQueue>,
    posix_shms: Vec<PosixShmObject>,
    posix_mqs: Vec<Option<PosixMqEntry>>,
    next_ipc_id: i32,
}

impl IpcNamespace {
    pub fn new() -> Self {
        Self {
            pipes: Vec::new(),
            eventfds: Vec::new(),
            shm_segments: Vec::new(),
            sem_arrays: Vec::new(),
            msg_queues: Vec::new(),
            posix_shms: Vec::new(),
            posix_mqs: Vec::new(),
            next_ipc_id: 1,
        }
    }

    /// `sys_pipe2`: Allocates a new pipe buffer and returns its pipe index.
    pub fn sys_pipe2(&mut self, flags: u32) -> i64 {
        let nonblock = (flags & EFD_NONBLOCK) != 0;
        let id = self.pipes.len();
        self.pipes.push(PipeBuffer::new(65536, nonblock));
        id as i64
    }

    pub fn pipe_write(&mut self, pipe_id: usize, data: &[u8]) -> i64 {
        match self.pipes.get_mut(pipe_id) {
            Some(p) => p.write(data),
            None => EINVAL,
        }
    }

    pub fn pipe_read(&mut self, pipe_id: usize, buf: &mut [u8]) -> i64 {
        match self.pipes.get_mut(pipe_id) {
            Some(p) => p.read(buf),
            None => EINVAL,
        }
    }

    /// `sys_eventfd2`: Creates an eventfd counter object.
    pub fn sys_eventfd2(&mut self, initval: u32, flags: u32) -> i64 {
        let id = self.eventfds.len();
        self.eventfds.push(EventFdCounter::new(initval, flags));
        id as i64
    }

    pub fn eventfd_write(&mut self, id: usize, val: u64) -> i64 {
        match self.eventfds.get_mut(id) {
            Some(e) => e.write(val),
            None => EINVAL,
        }
    }

    pub fn eventfd_read(&mut self, id: usize) -> Result<u64, i64> {
        match self.eventfds.get_mut(id) {
            Some(e) => e.read(),
            None => Err(EINVAL),
        }
    }

    /// `sys_shmget`: Allocates or looks up a System V shared memory segment.
    pub fn sys_shmget(&mut self, key: i32, size: usize, shmflg: u32) -> i64 {
        if size == 0 {
            return EINVAL;
        }
        if key != 0 {
            if let Some(seg) = self.shm_segments.iter().find(|s| s.key == key) {
                if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                    return EEXIST;
                }
                return seg.shmid as i64;
            }
            if (shmflg & IPC_CREAT) == 0 {
                return ENOENT;
            }
        }
        let shmid = self.next_ipc_id;
        self.next_ipc_id += 1;
        self.shm_segments.push(ShmSegment {
            shmid,
            key,
            size,
            nattch: 0,
            marked_destroy: false,
            pages: alloc::vec![0u8; size],
            attached_addrs: Vec::new(),
        });
        shmid as i64
    }

    /// `sys_shmat`: Attaches to a shared memory segment and returns a synthetic virtual address.
    pub fn sys_shmat(&mut self, shmid: i32) -> i64 {
        match self.shm_segments.iter_mut().find(|s| s.shmid == shmid) {
            Some(seg) => {
                seg.nattch += 1;
                let addr = 0x0000_7F00_0000_0000 + (shmid as u64) * 0x10_0000;
                seg.attached_addrs.push(addr);
                addr as i64
            }
            None => EINVAL,
        }
    }

    /// `sys_shmat_vma`: Attaches to a shared memory segment and maps a genuine `VmArea` in `vma_tree`.
    pub fn sys_shmat_vma(
        &mut self,
        shmid: i32,
        vma_tree: &mut cormm::vma_interval::VmaIntervalTree,
    ) -> Result<u64, i64> {
        let seg = self.shm_segments.iter_mut().find(|s| s.shmid == shmid).ok_or(EINVAL)?;
        let size = seg.size as u64;
        let aligned_size = (size + cormm::vma_interval::VMA_PAGE_SIZE - 1) & !(cormm::vma_interval::VMA_PAGE_SIZE - 1);
        let hint = 0x0000_7F00_0000_0000 + (shmid as u64) * 0x10_0000;
        let addr = vma_tree.find_unmapped_area_bottom_up(hint, aligned_size).ok_or(ENOMEM)?;
        let vma = cormm::vma_interval::VmArea::new(
            addr,
            addr + aligned_size,
            cormm::vma_interval::VmaFlags::SHARED
                .union(cormm::vma_interval::VmaFlags::READ)
                .union(cormm::vma_interval::VmaFlags::WRITE),
            cormm::vma_interval::VmaType::SharedMemory,
            0,
            0,
        );
        if vma_tree.insert_and_merge(vma).is_err() {
            return Err(ENOMEM);
        }
        seg.nattch += 1;
        seg.attached_addrs.push(addr);
        Ok(addr)
    }

    /// `sys_shmdt`: Detaches from a shared memory segment by attached virtual address or shmid.
    pub fn sys_shmdt(&mut self, shmaddr: u64) -> i64 {
        let mut found_idx = None;
        for (idx, seg) in self.shm_segments.iter_mut().enumerate() {
            if let Some(pos) = seg.attached_addrs.iter().position(|&a| a == shmaddr) {
                seg.attached_addrs.remove(pos);
                seg.nattch = seg.nattch.saturating_sub(1);
                found_idx = Some((idx, seg.marked_destroy && seg.nattch == 0));
                break;
            }
        }
        if let Some((idx, should_destroy)) = found_idx {
            if should_destroy {
                self.shm_segments.remove(idx);
            }
            return 0;
        }

        // Also fallback to match by shmid directly
        if let Some(idx) = self.shm_segments.iter().position(|s| s.shmid as u64 == shmaddr) {
            let seg = &mut self.shm_segments[idx];
            seg.nattch = seg.nattch.saturating_sub(1);
            if !seg.attached_addrs.is_empty() {
                seg.attached_addrs.pop();
            }
            if seg.marked_destroy && seg.nattch == 0 {
                self.shm_segments.remove(idx);
            }
            return 0;
        }

        EINVAL
    }

    /// `sys_shmdt_vma`: Detaches from a shared memory segment and unmaps its `VmArea` range from `vma_tree`.
    pub fn sys_shmdt_vma(
        &mut self,
        shmaddr: u64,
        vma_tree: &mut cormm::vma_interval::VmaIntervalTree,
    ) -> i64 {
        let mut seg_size = None;
        for seg in &self.shm_segments {
            if seg.attached_addrs.contains(&shmaddr) {
                seg_size = Some(seg.size);
                break;
            }
        }
        if let Some(size) = seg_size {
            let aligned_size = (size as u64 + cormm::vma_interval::VMA_PAGE_SIZE - 1) & !(cormm::vma_interval::VMA_PAGE_SIZE - 1);
            vma_tree.munmap_range(shmaddr, shmaddr + aligned_size);
        }
        self.sys_shmdt(shmaddr)
    }

    /// `sys_shmctl`: Controls a shared memory segment (`IPC_RMID`), deferring deletion if `nattch > 0`.
    pub fn sys_shmctl(&mut self, shmid: i32, cmd: u32) -> i64 {
        if cmd != IPC_RMID {
            return EINVAL;
        }
        match self.shm_segments.iter_mut().position(|s| s.shmid == shmid) {
            Some(idx) => {
                let seg = &mut self.shm_segments[idx];
                if seg.nattch > 0 {
                    seg.marked_destroy = true;
                    0
                } else {
                    self.shm_segments.remove(idx);
                    0
                }
            }
            None => EINVAL,
        }
    }

    /// `sys_posix_shm_open`: Creates or opens a named POSIX shared memory object (`/dev/shm/*`).
    pub fn sys_posix_shm_open(&mut self, name: &str, oflag: i32, size: usize) -> Result<i32, i64> {
        if let Some(pos) = self.posix_shms.iter().position(|s| s.name == name) {
            if (oflag & (IPC_CREAT as i32)) != 0 && (oflag & (IPC_EXCL as i32)) != 0 {
                return Err(EEXIST);
            }
            return Ok(pos as i32);
        }
        let shm = PosixShmObject {
            name: alloc::string::String::from(name),
            buffer: alloc::vec![0u8; size],
            size,
        };
        let id = self.posix_shms.len() as i32;
        self.posix_shms.push(shm);
        Ok(id)
    }

    /// `sys_posix_shm_unlink`: Unlinks a named POSIX shared memory object.
    pub fn sys_posix_shm_unlink(&mut self, name: &str) -> i64 {
        if let Some(pos) = self.posix_shms.iter().position(|s| s.name == name) {
            self.posix_shms.remove(pos);
            0
        } else {
            ENOENT
        }
    }

    /// Retrieves an immutable slice of a POSIX shared memory object's buffer.
    pub fn posix_shm_get_slice(&self, id: i32) -> Result<&[u8], i64> {
        if id < 0 {
            return Err(EINVAL);
        }
        self.posix_shms
            .get(id as usize)
            .map(|s| s.buffer.as_slice())
            .ok_or(ENOENT)
    }

    /// Retrieves a mutable slice of a POSIX shared memory object's buffer.
    pub fn posix_shm_get_slice_mut(&mut self, id: i32) -> Result<&mut [u8], i64> {
        if id < 0 {
            return Err(EINVAL);
        }
        self.posix_shms
            .get_mut(id as usize)
            .map(|s| s.buffer.as_mut_slice())
            .ok_or(ENOENT)
    }

    /// `posix_shm_ftruncate`: Adjusts the byte size of a POSIX shared memory buffer.
    pub fn posix_shm_ftruncate(&mut self, id: i32, length: usize) -> i64 {
        if id < 0 {
            return EINVAL;
        }
        if let Some(shm) = self.posix_shms.get_mut(id as usize) {
            shm.buffer.resize(length, 0);
            shm.size = length;
            0
        } else {
            ENOENT
        }
    }

    /// `sys_mq_open`: Creates or opens a POSIX message queue by name.
    pub fn sys_mq_open(&mut self, name: &str, oflag: i32, maxmsg: usize, msgsize: usize) -> Result<i32, i64> {
        for (idx, entry_opt) in self.posix_mqs.iter().enumerate() {
            if let Some(entry) = entry_opt {
                if entry.name == name {
                    if (oflag & (IPC_CREAT as i32)) != 0 && (oflag & (IPC_EXCL as i32)) != 0 {
                        return Err(EEXIST);
                    }
                    return Ok(idx as i32);
                }
            }
        }
        if (oflag & (IPC_CREAT as i32)) == 0 && oflag != 0 {
            return Err(ENOENT);
        }
        let q = coripc::posix_mqueue::PosixMessageQueue::new(maxmsg, msgsize, oflag as u32);
        let entry = PosixMqEntry {
            name: alloc::string::String::from(name),
            mq: q,
        };
        let idx = self.posix_mqs.len();
        self.posix_mqs.push(Some(entry));
        Ok(idx as i32)
    }

    /// `sys_mq_unlink`: Removes a POSIX message queue by name.
    pub fn sys_mq_unlink(&mut self, name: &str) -> i64 {
        for entry_opt in self.posix_mqs.iter_mut() {
            if let Some(entry) = entry_opt {
                if entry.name == name {
                    *entry_opt = None;
                    return 0;
                }
            }
        }
        ENOENT
    }

    /// `sys_mq_timedsend`: Sends a message to a POSIX message queue with priority `0..32768`.
    pub fn sys_mq_timedsend(&mut self, mqdes: i32, msg: &[u8], prio: u32) -> i64 {
        if mqdes < 0 {
            return EBADF;
        }
        let entry = match self.posix_mqs.get_mut(mqdes as usize).and_then(|e| e.as_mut()) {
            Some(e) => e,
            None => return EBADF,
        };
        match entry.mq.mq_send(msg, prio) {
            Ok(()) => 0,
            Err(coripc::posix_mqueue::MqError::InvalidPriority) => EINVAL,
            Err(coripc::posix_mqueue::MqError::MessageTooLarge) => EMSGSIZE,
            Err(coripc::posix_mqueue::MqError::QueueFull) => EAGAIN,
            Err(_) => EINVAL,
        }
    }

    /// `sys_mq_timedreceive`: Receives the highest priority message from a POSIX message queue.
    pub fn sys_mq_timedreceive(&mut self, mqdes: i32, buf: &mut [u8]) -> Result<(usize, u32), i64> {
        if mqdes < 0 {
            return Err(EBADF);
        }
        let entry = match self.posix_mqs.get_mut(mqdes as usize).and_then(|e| e.as_mut()) {
            Some(e) => e,
            None => return Err(EBADF),
        };
        match entry.mq.mq_receive(buf.len()) {
            Ok((payload, prio)) => {
                let to_copy = payload.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&payload[..to_copy]);
                Ok((to_copy, prio))
            }
            Err(coripc::posix_mqueue::MqError::BufferTooSmall) => Err(EMSGSIZE),
            Err(coripc::posix_mqueue::MqError::QueueEmpty) => Err(EAGAIN),
            Err(_) => Err(EINVAL),
        }
    }

    /// `sys_mq_notify`: Registers or unregisters single-shot notification for when an empty queue receives a message.
    pub fn sys_mq_notify(&mut self, mqdes: i32, subscriber_pid: u32, signo: u32, sigval_u64: u64) -> i64 {
        if mqdes < 0 {
            return EBADF;
        }
        let entry = match self.posix_mqs.get_mut(mqdes as usize).and_then(|e| e.as_mut()) {
            Some(e) => e,
            None => return EBADF,
        };
        let reg = if subscriber_pid == 0 || signo == 0 {
            None
        } else {
            Some(coripc::posix_mqueue::MqNotificationReg {
                subscriber_pid,
                signo,
                sigval_u64,
            })
        };
        match entry.mq.mq_notify(reg) {
            Ok(()) => 0,
            Err(coripc::posix_mqueue::MqError::NotifyBusy) => EBUSY,
            Err(_) => EINVAL,
        }
    }

    /// `sys_mq_getsetattr`: Retrieves current attributes for a POSIX message queue.
    pub fn sys_mq_getsetattr(&mut self, mqdes: i32, _new_flags: Option<u32>) -> Result<coripc::posix_mqueue::MqAttr, i64> {
        if mqdes < 0 {
            return Err(EBADF);
        }
        let entry = match self.posix_mqs.get_mut(mqdes as usize).and_then(|e| e.as_mut()) {
            Some(e) => e,
            None => return Err(EBADF),
        };
        Ok(entry.mq.getattr())
    }

    /// `sys_semget`: Creates or retrieves a System V semaphore set with `nsems` elements.
    pub fn sys_semget(&mut self, key: i32, nsems: usize, semflg: u32) -> i64 {
        if nsems == 0 || nsems > 256 {
            return EINVAL;
        }
        if key != 0 {
            if let Some(arr) = self.sem_arrays.iter().find(|a| a.key == key) {
                if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
                    return EEXIST;
                }
                return arr.semid as i64;
            }
        }
        let semid = self.next_ipc_id;
        self.next_ipc_id += 1;
        self.sem_arrays.push(SemArray {
            semid,
            key,
            values: alloc::vec![0i32; nsems],
        });
        semid as i64
    }

    /// `sys_semop`: Atomically applies an array of `SemBuf` operations to `semid`.
    pub fn sys_semop(&mut self, semid: i32, ops: &[SemBuf]) -> i64 {
        let arr = match self.sem_arrays.iter_mut().find(|a| a.semid == semid) {
            Some(a) => a,
            None => return EINVAL,
        };
        // Pre-validate atomic feasibility
        let mut staged = arr.values.clone();
        for op in ops {
            let idx = op.sem_num as usize;
            if idx >= staged.len() {
                return EINVAL;
            }
            if op.sem_op == 0 {
                if staged[idx] != 0 {
                    return EAGAIN;
                }
            } else {
                let next = staged[idx] + (op.sem_op as i32);
                if next < 0 {
                    return EAGAIN;
                }
                staged[idx] = next;
            }
        }
        arr.values = staged;
        0
    }

    /// `sys_msgget`: Creates or opens a System V message queue.
    pub fn sys_msgget(&mut self, key: i32, msgflg: u32) -> i64 {
        if key != 0 {
            if let Some(q) = self.msg_queues.iter().find(|q| q.key == key) {
                if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                    return EEXIST;
                }
                return q.msqid as i64;
            }
        }
        let msqid = self.next_ipc_id;
        self.next_ipc_id += 1;
        self.msg_queues.push(MsgQueue {
            msqid,
            key,
            max_bytes: 65536,
            current_bytes: 0,
            messages: VecDeque::new(),
        });
        msqid as i64
    }

    /// `sys_msgsnd`: Appends a typed message to `msqid`.
    pub fn sys_msgsnd(&mut self, msqid: i32, mtype: i64, mtext: &[u8]) -> i64 {
        if mtype <= 0 {
            return EINVAL;
        }
        let q = match self.msg_queues.iter_mut().find(|q| q.msqid == msqid) {
            Some(q) => q,
            None => return EINVAL,
        };
        if q.current_bytes + mtext.len() > q.max_bytes {
            return EAGAIN;
        }
        q.current_bytes += mtext.len();
        q.messages.push_back(SysvMessage {
            mtype,
            mtext: mtext.to_vec(),
        });
        0
    }

    /// `sys_msgrcv`: Dequeues a message matching `msgtyp` (0 = any, >0 = exact type, <0 = lowest <= |msgtyp|).
    pub fn sys_msgrcv(&mut self, msqid: i32, msgtyp: i64, buf: &mut [u8]) -> Result<(i64, usize), i64> {
        let q = self.msg_queues.iter_mut().find(|q| q.msqid == msqid).ok_or(EINVAL)?;
        let pos = if msgtyp == 0 {
            if q.messages.is_empty() { None } else { Some(0) }
        } else if msgtyp > 0 {
            q.messages.iter().position(|m| m.mtype == msgtyp)
        } else {
            let max_type = -msgtyp;
            q.messages
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= max_type)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(idx, _)| idx)
        };

        match pos {
            Some(idx) => {
                let msg = q.messages.remove(idx).unwrap();
                q.current_bytes = q.current_bytes.saturating_sub(msg.mtext.len());
                let copy_len = msg.mtext.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.mtext[..copy_len]);
                Ok((msg.mtype, copy_len))
            }
            None => Err(ENOMSG),
        }
    }
}

/// Runs comprehensive self-tests on `ipc_pipes` structs and IPC namespace operations.
pub fn verify_domain_ipc_pipes() -> u32 {
    let mut passed = 0u32;
    let mut ipc = IpcNamespace::new();

    // 1. Test pipe2 write and read
    let pid = ipc.sys_pipe2(0) as usize;
    let mut pbuf = [0u8; 16];
    if ipc.pipe_write(pid, b"coros_ipc") == 9 && ipc.pipe_read(pid, &mut pbuf) == 9 && &pbuf[..9] == b"coros_ipc" {
        passed += 1;
    }

    // 2. Test eventfd2 in semaphore mode
    let efd = ipc.sys_eventfd2(0, EFD_SEMAPHORE) as usize;
    if ipc.eventfd_write(efd, 3) == 8 && ipc.eventfd_read(efd) == Ok(1) && ipc.eventfd_read(efd) == Ok(1) {
        passed += 1;
    }

    // 3. Test shmget, shmat, and shmctl
    let shmid = ipc.sys_shmget(0x1234, 4096, IPC_CREAT) as i32;
    if shmid > 0 && ipc.sys_shmat(shmid) > 0 && ipc.sys_shmctl(shmid, IPC_RMID) == 0 {
        passed += 1;
    }

    // 4. Test semget and atomic semop V (+2) followed by P (-1)
    let semid = ipc.sys_semget(0x5678, 2, IPC_CREAT) as i32;
    let ops = [
        SemBuf { sem_num: 0, sem_op: 2, sem_flg: 0 },
        SemBuf { sem_num: 0, sem_op: -1, sem_flg: 0 },
    ];
    if ipc.sys_semop(semid, &ops) == 0 {
        passed += 1;
    }

    // 5. Test msgget, msgsnd, and typed msgrcv
    let msqid = ipc.sys_msgget(0x9ABC, IPC_CREAT) as i32;
    if ipc.sys_msgsnd(msqid, 10, b"low_prio") == 0 && ipc.sys_msgsnd(msqid, 2, b"high_prio") == 0 {
        let mut mbuf = [0u8; 16];
        // Receive type 2 specifically
        if let Ok((mtype, len)) = ipc.sys_msgrcv(msqid, 2, &mut mbuf) {
            if mtype == 2 && len == 9 && &mbuf[..9] == b"high_prio" {
                passed += 1;
            }
        }
    }

    // 6. Test sys_shmdt and deferred IPC_RMID destruction
    let shmid2 = ipc.sys_shmget(0xFEED, 4096, IPC_CREAT) as i32;
    let shmaddr = ipc.sys_shmat(shmid2) as u64;
    // Mark for destruction while attached (nattch == 1)
    if ipc.sys_shmctl(shmid2, IPC_RMID) == 0 {
        // Must still be present
        if ipc.shm_segments.iter().any(|s| s.shmid == shmid2) {
            // Detach: nattch reaches 0, triggering removal
            if ipc.sys_shmdt(shmaddr) == 0 && !ipc.shm_segments.iter().any(|s| s.shmid == shmid2) {
                passed += 1;
            }
        }
    }

    // 7. Test sys_shmat_vma and sys_shmdt_vma with genuine VmaIntervalTree
    let mut vma_tree = cormm::vma_interval::VmaIntervalTree::new(0x0000_7000_0000_0000, 0x0000_8000_0000_0000);
    let shmid3 = ipc.sys_shmget(0xCAFE, 8192, IPC_CREAT) as i32;
    if let Ok(vaddr) = ipc.sys_shmat_vma(shmid3, &mut vma_tree) {
        if vaddr >= 0x0000_7000_0000_0000 && ipc.sys_shmdt_vma(vaddr, &mut vma_tree) == 0 {
            passed += 1;
        }
    }

    // 8. Test POSIX shared memory (open, ftruncate, write, slice, unlink)
    if let Ok(shm_id) = ipc.sys_posix_shm_open("/coros_test_shm", IPC_CREAT as i32, 4096) {
        if let Ok(slice) = ipc.posix_shm_get_slice_mut(shm_id) {
            slice[0..4].copy_from_slice(b"CORO");
        }
        if ipc.posix_shm_ftruncate(shm_id, 8192) == 0 {
            if let Ok(slice) = ipc.posix_shm_get_slice(shm_id) {
                if slice.len() == 8192 && &slice[0..4] == b"CORO" {
                    if ipc.sys_posix_shm_unlink("/coros_test_shm") == 0 {
                        passed += 1;
                    }
                }
            }
        }
    }

    // 9. Test POSIX message queue (open, send priority, timedreceive, unlink)
    if let Ok(mqdes) = ipc.sys_mq_open("/coros_mq", IPC_CREAT as i32, 10, 128) {
        if ipc.sys_mq_timedsend(mqdes, b"LOW", 1) == 0
            && ipc.sys_mq_timedsend(mqdes, b"HIGH", 10) == 0
        {
            let mut rcv_buf = [0u8; 128];
            // High priority message must arrive first
            if let Ok((len, prio)) = ipc.sys_mq_timedreceive(mqdes, &mut rcv_buf) {
                if prio == 10 && &rcv_buf[..len] == b"HIGH" {
                    if ipc.sys_mq_unlink("/coros_mq") == 0 {
                        passed += 1;
                    }
                }
            }
        }
    }

    passed
}
