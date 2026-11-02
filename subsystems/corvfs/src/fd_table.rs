//! CorOS VFS Module: `fd_table`
//!
//! Per-process file descriptor table (`FileDescriptor`, `OpenFileHandle`, `FdFlags`,
//! `OpenMode`, `SeekWhence`, `allocate_fd`, `dup_fd`, `dup2_fd`, `close_fd`, `seek_fd`,
//! and `close_on_exec` purging).

use alloc::vec::Vec;

/// Strongly-typed process-local file descriptor number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileDescriptor(pub u32);

/// Per-descriptor flags (`FD_CLOEXEC`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdFlags(pub u32);

impl FdFlags {
    pub const NONE: Self = Self(0);
    pub const CLOEXEC: Self = Self(1 << 0);

    #[inline]
    pub const fn is_cloexec(self) -> bool {
        (self.0 & Self::CLOEXEC.0) != 0
    }
}

/// File status and access mode flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_NONBLOCK`, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenMode(pub u32);

impl OpenMode {
    pub const O_RDONLY: Self = Self(0x0000);
    pub const O_WRONLY: Self = Self(0x0001);
    pub const O_RDWR: Self = Self(0x0002);
    pub const O_ACCMODE: u32 = 0x0003;

    pub const O_CREAT: Self = Self(0x0040);
    pub const O_EXCL: Self = Self(0x0080);
    pub const O_TRUNC: Self = Self(0x0200);
    pub const O_APPEND: Self = Self(0x0400);
    pub const O_NONBLOCK: Self = Self(0x0800);
    pub const O_DIRECTORY: Self = Self(0x10000);

    #[inline]
    pub const fn can_read(self) -> bool {
        let acc = self.0 & Self::O_ACCMODE;
        acc == Self::O_RDONLY.0 || acc == Self::O_RDWR.0
    }

    #[inline]
    pub const fn can_write(self) -> bool {
        let acc = self.0 & Self::O_ACCMODE;
        acc == Self::O_WRONLY.0 || acc == Self::O_RDWR.0
    }

    #[inline]
    pub const fn is_append(self) -> bool {
        (self.0 & Self::O_APPEND.0) != 0
    }
}

/// Anchor mode for `lseek` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    SeekSet(u64),
    SeekCur(i64),
    SeekEnd(i64),
}

/// Errors returned by file descriptor table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdError {
    BadFileDescriptor,
    TooManyOpenFiles,
    PermissionDenied,
    InvalidSeekOffset,
    IllegalSeekOnPipeOrTty,
}

/// Kernel open file description (shared across `dup`/`dup2` descriptors).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFileHandle {
    pub handle_id: u32,
    pub superblock_id: u64,
    pub inode_num: u64,
    pub mode: OpenMode,
    pub offset: u64,
    pub file_size: u64,
    pub seekable: bool,
    pub ref_count: u32,
}

/// Slot inside the per-process FD array pointing to an `OpenFileHandle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdSlot {
    pub handle_id: u32,
    pub fd_flags: FdFlags,
}

/// Per-process File Descriptor Table managing FD indices and shared open file descriptions.
pub struct ProcessFdTable {
    slots: Vec<Option<FdSlot>>,
    handles: Vec<OpenFileHandle>,
    next_handle_id: u32,
    max_fds: usize,
}

impl ProcessFdTable {
    pub const DEFAULT_MAX_FDS: usize = 256;

    /// Creates a new FD table pre-populated with standard streams (`0: stdin`, `1: stdout`, `2: stderr`).
    pub fn with_stdio() -> Self {
        let mut table = Self {
            slots: Vec::with_capacity(16),
            handles: Vec::with_capacity(16),
            next_handle_id: 1,
            max_fds: Self::DEFAULT_MAX_FDS,
        };
        // fd 0: stdin (/dev/tty0, read-only, non-seekable)
        let _ = table.allocate_fd(104, 1, OpenMode::O_RDONLY, 0, false, FdFlags::NONE);
        // fd 1: stdout (/dev/tty0, write-only, non-seekable)
        let _ = table.allocate_fd(104, 1, OpenMode::O_WRONLY, 0, false, FdFlags::NONE);
        // fd 2: stderr (/dev/tty0, write-only, non-seekable)
        let _ = table.allocate_fd(104, 1, OpenMode::O_WRONLY, 0, false, FdFlags::NONE);
        table
    }

    /// Allocates the lowest-numbered free file descriptor at or above `min_fd`.
    fn alloc_lowest_slot(&mut self, min_fd: usize, slot: FdSlot) -> Result<FileDescriptor, FdError> {
        if min_fd >= self.max_fds {
            return Err(FdError::TooManyOpenFiles);
        }
        while self.slots.len() <= min_fd {
            self.slots.push(None);
        }

        for idx in min_fd..self.slots.len() {
            if self.slots[idx].is_none() {
                self.slots[idx] = Some(slot);
                return Ok(FileDescriptor(idx as u32));
            }
        }

        if self.slots.len() >= self.max_fds {
            return Err(FdError::TooManyOpenFiles);
        }

        let new_fd = self.slots.len();
        self.slots.push(Some(slot));
        Ok(FileDescriptor(new_fd as u32))
    }

    /// Allocates a brand-new `OpenFileHandle` and binds it to the lowest available `FileDescriptor`.
    pub fn allocate_fd(
        &mut self,
        superblock_id: u64,
        inode_num: u64,
        mode: OpenMode,
        file_size: u64,
        seekable: bool,
        fd_flags: FdFlags,
    ) -> Result<FileDescriptor, FdError> {
        let handle_id = self.next_handle_id;
        self.next_handle_id += 1;

        let initial_offset = if mode.is_append() { file_size } else { 0 };
        self.handles.push(OpenFileHandle {
            handle_id,
            superblock_id,
            inode_num,
            mode,
            offset: initial_offset,
            file_size,
            seekable,
            ref_count: 1,
        });

        self.alloc_lowest_slot(0, FdSlot { handle_id, fd_flags })
    }

    /// Duplicates `old_fd` into the lowest available descriptor (`dup`), clearing `FD_CLOEXEC`.
    pub fn dup_fd(&mut self, old_fd: FileDescriptor) -> Result<FileDescriptor, FdError> {
        let slot = self
            .slots
            .get(old_fd.0 as usize)
            .and_then(|s| *s)
            .ok_or(FdError::BadFileDescriptor)?;

        let handle = self
            .handles
            .iter_mut()
            .find(|h| h.handle_id == slot.handle_id)
            .ok_or(FdError::BadFileDescriptor)?;
        handle.ref_count += 1;

        self.alloc_lowest_slot(
            0,
            FdSlot {
                handle_id: slot.handle_id,
                fd_flags: FdFlags::NONE,
            },
        )
    }

    /// Duplicates `old_fd` onto `new_fd` (`dup2`), closing `new_fd` first if it was open.
    pub fn dup2_fd(&mut self, old_fd: FileDescriptor, new_fd: FileDescriptor) -> Result<FileDescriptor, FdError> {
        let new_idx = new_fd.0 as usize;
        if new_idx >= self.max_fds {
            return Err(FdError::TooManyOpenFiles);
        }

        let old_slot = self
            .slots
            .get(old_fd.0 as usize)
            .and_then(|s| *s)
            .ok_or(FdError::BadFileDescriptor)?;

        if old_fd == new_fd {
            return Ok(new_fd);
        }

        if new_idx < self.slots.len() && self.slots[new_idx].is_some() {
            let _ = self.close_fd(new_fd);
        }

        while self.slots.len() <= new_idx {
            self.slots.push(None);
        }

        if let Some(handle) = self.handles.iter_mut().find(|h| h.handle_id == old_slot.handle_id) {
            handle.ref_count += 1;
        }

        self.slots[new_idx] = Some(FdSlot {
            handle_id: old_slot.handle_id,
            fd_flags: FdFlags::NONE,
        });
        Ok(new_fd)
    }

    /// Closes `fd` and decrements the reference count of its underlying `OpenFileHandle`.
    pub fn close_fd(&mut self, fd: FileDescriptor) -> Result<(), FdError> {
        let idx = fd.0 as usize;
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(|s| s.take())
            .ok_or(FdError::BadFileDescriptor)?;

        if let Some(pos) = self.handles.iter().position(|h| h.handle_id == slot.handle_id) {
            if self.handles[pos].ref_count <= 1 {
                self.handles.swap_remove(pos);
            } else {
                self.handles[pos].ref_count -= 1;
            }
        }
        Ok(())
    }

    /// Repositions the byte offset of the open file description associated with `fd`.
    pub fn seek_fd(&mut self, fd: FileDescriptor, whence: SeekWhence) -> Result<u64, FdError> {
        let slot = self
            .slots
            .get(fd.0 as usize)
            .and_then(|s| *s)
            .ok_or(FdError::BadFileDescriptor)?;

        let handle = self
            .handles
            .iter_mut()
            .find(|h| h.handle_id == slot.handle_id)
            .ok_or(FdError::BadFileDescriptor)?;

        if !handle.seekable {
            return Err(FdError::IllegalSeekOnPipeOrTty);
        }

        let new_offset: i128 = match whence {
            SeekWhence::SeekSet(abs) => abs as i128,
            SeekWhence::SeekCur(rel) => (handle.offset as i128) + (rel as i128),
            SeekWhence::SeekEnd(rel) => (handle.file_size as i128) + (rel as i128),
        };

        if new_offset < 0 {
            return Err(FdError::InvalidSeekOffset);
        }

        handle.offset = new_offset as u64;
        Ok(handle.offset)
    }

    /// Advances the file offset after a read or write operation.
    pub fn advance_offset(&mut self, fd: FileDescriptor, bytes: u64, is_write: bool) -> Result<u64, FdError> {
        let slot = self
            .slots
            .get(fd.0 as usize)
            .and_then(|s| *s)
            .ok_or(FdError::BadFileDescriptor)?;

        let handle = self
            .handles
            .iter_mut()
            .find(|h| h.handle_id == slot.handle_id)
            .ok_or(FdError::BadFileDescriptor)?;

        if is_write && !handle.mode.can_write() {
            return Err(FdError::PermissionDenied);
        }
        if !is_write && !handle.mode.can_read() {
            return Err(FdError::PermissionDenied);
        }

        if is_write && handle.mode.is_append() {
            handle.offset = handle.file_size;
        }

        handle.offset = handle.offset.saturating_add(bytes);
        if is_write && handle.offset > handle.file_size {
            handle.file_size = handle.offset;
        }
        Ok(handle.offset)
    }

    /// Closes all descriptors marked with `FD_CLOEXEC` across an `execve` boundary.
    pub fn purge_cloexec(&mut self) -> u32 {
        let mut closed = 0u32;
        for idx in 0..self.slots.len() {
            if let Some(slot) = self.slots[idx] {
                if slot.fd_flags.is_cloexec() && self.close_fd(FileDescriptor(idx as u32)).is_ok() {
                    closed += 1;
                }
            }
        }
        closed
    }

    /// Inspects the underlying `OpenFileHandle` for `fd`.
    pub fn inspect_handle(&self, fd: FileDescriptor) -> Result<OpenFileHandle, FdError> {
        let slot = self
            .slots
            .get(fd.0 as usize)
            .and_then(|s| *s)
            .ok_or(FdError::BadFileDescriptor)?;

        self.handles
            .iter()
            .copied()
            .find(|h| h.handle_id == slot.handle_id)
            .ok_or(FdError::BadFileDescriptor)
    }
}

/// Self-test suite for `fd_table`.
pub fn verify_vfs_fd_table() -> u32 {
    let mut passed = 0u32;
    let mut table = ProcessFdTable::with_stdio();

    // Seeking on TTY fd 0 must fail with IllegalSeekOnPipeOrTty
    if table.seek_fd(FileDescriptor(0), SeekWhence::SeekSet(0)) == Err(FdError::IllegalSeekOnPipeOrTty) {
        passed += 1;
    }

    // Allocate a regular file at fd 3
    let fd3 = table
        .allocate_fd(100, 42, OpenMode::O_RDWR, 1024, true, FdFlags::CLOEXEC)
        .unwrap_or(FileDescriptor(999));
    if fd3 == FileDescriptor(3) {
        passed += 1;
    }

    // Duplicate fd 3 -> fd 4 and verify shared offset across dup'd descriptors
    if let Ok(fd4) = table.dup_fd(fd3) {
        let _ = table.seek_fd(fd3, SeekWhence::SeekEnd(-124));
        if let Ok(handle4) = table.inspect_handle(fd4) {
            if fd4 == FileDescriptor(4) && handle4.offset == 900 && handle4.ref_count == 2 {
                passed += 1;
            }
        }
    }

    // dup2 onto fd 10
    if table.dup2_fd(fd3, FileDescriptor(10)) == Ok(FileDescriptor(10)) {
        passed += 1;
    }

    // Purge CLOEXEC should close fd 3 (which had CLOEXEC), leaving fd 4 and fd 10 open
    if table.purge_cloexec() == 1
        && table.inspect_handle(fd3).is_err()
        && table.inspect_handle(FileDescriptor(4)).is_ok()
    {
        passed += 1;
    }

    passed
}
