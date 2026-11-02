//! CorOS Syscall Domain Module: `vfs_io`
//! Virtual File System I/O & File Descriptor Table (`openat`, `close`, `read`, `write`, `pread64`, `pwrite64`, `readv`, `writev`, `lseek`, `dup`, `dup2`, `dup3`, `sendfile`).

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

pub const EBADF: i64 = -9;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ESPIPE: i64 = -29;
pub const EACCES: i64 = -13;

/// File open mode and status flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_APPEND`, `O_CLOEXEC`, etc.).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    pub const RDONLY: Self = Self(0x0000);
    pub const WRONLY: Self = Self(0x0001);
    pub const RDWR: Self = Self(0x0002);
    pub const ACCMODE: Self = Self(0x0003);
    pub const CREAT: Self = Self(0x0040);
    pub const EXCL: Self = Self(0x0080);
    pub const TRUNC: Self = Self(0x0200);
    pub const APPEND: Self = Self(0x0400);
    pub const NONBLOCK: Self = Self(0x0800);
    pub const DIRECTORY: Self = Self(0x0001_0000);
    pub const CLOEXEC: Self = Self(0x0008_0000);

    #[inline]
    pub const fn can_read(self) -> bool {
        let mode = self.0 & Self::ACCMODE.0;
        mode == Self::RDONLY.0 || mode == Self::RDWR.0
    }

    #[inline]
    pub const fn can_write(self) -> bool {
        let mode = self.0 & Self::ACCMODE.0;
        mode == Self::WRONLY.0 || mode == Self::RDWR.0
    }

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// `lseek` origin directives (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    Set = 0,
    Cur = 1,
    End = 2,
}

impl SeekWhence {
    pub const fn from_raw(w: u32) -> Option<Self> {
        match w {
            0 => Some(Self::Set),
            1 => Some(Self::Cur),
            2 => Some(Self::End),
            _ => None,
        }
    }
}

/// Scatter/gather I/O vector descriptor used by `readv` and `writev`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoVec {
    pub base_addr: u64,
    pub len: usize,
}

/// Kernel open file description shared across `dup()`ed file descriptors and forked tasks.
#[derive(Debug)]
pub struct OpenFileDescription {
    pub inode_id: u64,
    pub flags: OpenFlags,
    pub offset: u64,
    pub data: Vec<u8>,
    pub seekable: bool,
}

impl OpenFileDescription {
    pub fn new(inode_id: u64, flags: OpenFlags, initial_data: &[u8], seekable: bool) -> Self {
        let data = if flags.contains(OpenFlags::TRUNC) && flags.can_write() {
            Vec::new()
        } else {
            initial_data.to_vec()
        };
        Self {
            inode_id,
            flags,
            offset: 0,
            data,
            seekable,
        }
    }
}

/// Per-FD entry in the process `FdTable` holding a reference to an `OpenFileDescription` and `FD_CLOEXEC`.
#[derive(Clone)]
pub struct FdEntry {
    pub file: Rc<RefCell<OpenFileDescription>>,
    pub cloexec: bool,
}

/// Per-process File Descriptor Table managing open files and I/O system calls.
pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
    max_fds: usize,
}

impl FdTable {
    pub fn new(max_fds: usize) -> Self {
        let mut table = Self {
            entries: Vec::new(),
            max_fds,
        };
        // Initialize standard streams: 0 (stdin), 1 (stdout), 2 (stderr)
        let _ = table.sys_openat(-100, "/dev/stdin", OpenFlags::RDONLY, &[], false);
        let _ = table.sys_openat(-100, "/dev/stdout", OpenFlags::WRONLY, &[], false);
        let _ = table.sys_openat(-100, "/dev/stderr", OpenFlags::WRONLY, &[], false);
        table
    }

    fn alloc_lowest_fd(&mut self, min_fd: usize, entry: FdEntry) -> Result<i32, i64> {
        if min_fd >= self.max_fds {
            return Err(EMFILE);
        }
        for fd in min_fd..self.entries.len() {
            if self.entries[fd].is_none() {
                self.entries[fd] = Some(entry);
                return Ok(fd as i32);
            }
        }
        if self.entries.len() >= self.max_fds {
            return Err(EMFILE);
        }
        while self.entries.len() < min_fd {
            self.entries.push(None);
        }
        let fd = self.entries.len();
        self.entries.push(Some(entry));
        Ok(fd as i32)
    }

    fn get_entry(&self, fd: i32) -> Result<&FdEntry, i64> {
        if fd < 0 {
            return Err(EBADF);
        }
        self.entries
            .get(fd as usize)
            .and_then(|e| e.as_ref())
            .ok_or(EBADF)
    }

    /// `sys_openat`: Allocates a new file descriptor and backing `OpenFileDescription`.
    pub fn sys_openat(
        &mut self,
        _dirfd: i32,
        path: &str,
        flags: OpenFlags,
        initial_content: &[u8],
        seekable: bool,
    ) -> i64 {
        if path.is_empty() {
            return EINVAL;
        }
        let mut inode_hash = 0xCBF2_9CE4_8422_2325u64;
        for b in path.as_bytes() {
            inode_hash ^= *b as u64;
            inode_hash = inode_hash.wrapping_mul(0x0100_0000_01B3);
        }
        let ofd = OpenFileDescription::new(inode_hash, flags, initial_content, seekable);
        let entry = FdEntry {
            file: Rc::new(RefCell::new(ofd)),
            cloexec: flags.contains(OpenFlags::CLOEXEC),
        };
        match self.alloc_lowest_fd(0, entry) {
            Ok(fd) => fd as i64,
            Err(e) => e,
        }
    }

    /// `sys_close`: Closes a file descriptor slot.
    pub fn sys_close(&mut self, fd: i32) -> i64 {
        if fd < 0 || (fd as usize) >= self.entries.len() {
            return EBADF;
        }
        if self.entries[fd as usize].take().is_some() {
            0
        } else {
            EBADF
        }
    }

    /// `sys_read`: Reads up to `buf.len()` bytes from `fd` at its current offset and advances offset.
    pub fn sys_read(&mut self, fd: i32, buf: &mut [u8]) -> i64 {
        let entry = match self.get_entry(fd) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let mut ofd = entry.file.borrow_mut();
        if !ofd.flags.can_read() {
            return EBADF;
        }
        let pos = ofd.offset as usize;
        if pos >= ofd.data.len() {
            return 0;
        }
        let available = ofd.data.len() - pos;
        let to_read = available.min(buf.len());
        buf[..to_read].copy_from_slice(&ofd.data[pos..pos + to_read]);
        ofd.offset += to_read as u64;
        to_read as i64
    }

    /// `sys_write`: Writes `buf` to `fd`, honoring `O_APPEND` and extending file size as needed.
    pub fn sys_write(&mut self, fd: i32, buf: &[u8]) -> i64 {
        let entry = match self.get_entry(fd) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let mut ofd = entry.file.borrow_mut();
        if !ofd.flags.can_write() {
            return EBADF;
        }
        if ofd.flags.contains(OpenFlags::APPEND) {
            ofd.offset = ofd.data.len() as u64;
        }
        let pos = ofd.offset as usize;
        let end = pos + buf.len();
        if end > ofd.data.len() {
            ofd.data.resize(end, 0);
        }
        ofd.data[pos..end].copy_from_slice(buf);
        ofd.offset = end as u64;
        buf.len() as i64
    }

    /// `sys_pread64`: Reads from `fd` at an explicit `offset` without mutating the file offset.
    pub fn sys_pread64(&self, fd: i32, buf: &mut [u8], offset: u64) -> i64 {
        let entry = match self.get_entry(fd) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let ofd = entry.file.borrow();
        if !ofd.seekable {
            return ESPIPE;
        }
        if !ofd.flags.can_read() {
            return EBADF;
        }
        let pos = offset as usize;
        if pos >= ofd.data.len() {
            return 0;
        }
        let to_read = (ofd.data.len() - pos).min(buf.len());
        buf[..to_read].copy_from_slice(&ofd.data[pos..pos + to_read]);
        to_read as i64
    }

    /// `sys_pwrite64`: Writes to `fd` at an explicit `offset` without mutating the file offset.
    pub fn sys_pwrite64(&mut self, fd: i32, buf: &[u8], offset: u64) -> i64 {
        let entry = match self.get_entry(fd) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let mut ofd = entry.file.borrow_mut();
        if !ofd.seekable {
            return ESPIPE;
        }
        if !ofd.flags.can_write() {
            return EBADF;
        }
        let pos = offset as usize;
        let end = pos + buf.len();
        if end > ofd.data.len() {
            ofd.data.resize(end, 0);
        }
        ofd.data[pos..end].copy_from_slice(buf);
        buf.len() as i64
    }

    /// `sys_readv`: Scatter read across multiple slice buffers.
    pub fn sys_readv(&mut self, fd: i32, iovecs: &mut [&mut [u8]]) -> i64 {
        let mut total = 0i64;
        for slice in iovecs.iter_mut() {
            let n = self.sys_read(fd, slice);
            if n < 0 {
                return if total > 0 { total } else { n };
            }
            total += n;
            if (n as usize) < slice.len() {
                break;
            }
        }
        total
    }

    /// `sys_writev`: Gather write across multiple slice buffers.
    pub fn sys_writev(&mut self, fd: i32, iovecs: &[&[u8]]) -> i64 {
        let mut total = 0i64;
        for slice in iovecs {
            let n = self.sys_write(fd, slice);
            if n < 0 {
                return if total > 0 { total } else { n };
            }
            total += n;
        }
        total
    }

    /// `sys_lseek`: Repositions the file offset of `fd`.
    pub fn sys_lseek(&mut self, fd: i32, offset: i64, whence: SeekWhence) -> i64 {
        let entry = match self.get_entry(fd) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let mut ofd = entry.file.borrow_mut();
        if !ofd.seekable {
            return ESPIPE;
        }
        let base: i64 = match whence {
            SeekWhence::Set => 0,
            SeekWhence::Cur => ofd.offset as i64,
            SeekWhence::End => ofd.data.len() as i64,
        };
        let new_pos = match base.checked_add(offset) {
            Some(p) if p >= 0 => p as u64,
            _ => return EINVAL,
        };
        ofd.offset = new_pos;
        new_pos as i64
    }

    /// `sys_dup`: Duplicates `oldfd` into the lowest available descriptor slot.
    pub fn sys_dup(&mut self, oldfd: i32) -> i64 {
        let cloned = match self.get_entry(oldfd) {
            Ok(e) => FdEntry {
                file: Rc::clone(&e.file),
                cloexec: false,
            },
            Err(e) => return e,
        };
        match self.alloc_lowest_fd(0, cloned) {
            Ok(fd) => fd as i64,
            Err(e) => e,
        }
    }

    /// `sys_dup2`: Duplicates `oldfd` into `newfd`, closing `newfd` first if open.
    pub fn sys_dup2(&mut self, oldfd: i32, newfd: i32) -> i64 {
        if oldfd == newfd {
            return if self.get_entry(oldfd).is_ok() { newfd as i64 } else { EBADF };
        }
        self.sys_dup3(oldfd, newfd, OpenFlags(0))
    }

    /// `sys_dup3`: Duplicates `oldfd` into `newfd` with explicit `O_CLOEXEC` flag support.
    pub fn sys_dup3(&mut self, oldfd: i32, newfd: i32, flags: OpenFlags) -> i64 {
        if oldfd == newfd || newfd < 0 || (newfd as usize) >= self.max_fds {
            return EINVAL;
        }
        if (flags.0 & !OpenFlags::CLOEXEC.0) != 0 {
            return EINVAL;
        }
        let cloned = match self.get_entry(oldfd) {
            Ok(e) => FdEntry {
                file: Rc::clone(&e.file),
                cloexec: flags.contains(OpenFlags::CLOEXEC),
            },
            Err(e) => return e,
        };
        while self.entries.len() <= newfd as usize {
            self.entries.push(None);
        }
        self.entries[newfd as usize] = Some(cloned);
        newfd as i64
    }

    /// `sys_sendfile`: Zero-copy kernel transfer between `in_fd` and `out_fd`.
    pub fn sys_sendfile(&mut self, out_fd: i32, in_fd: i32, offset: Option<&mut u64>, count: usize) -> i64 {
        let mut temp = alloc::vec![0u8; count];
        let n_read = match offset {
            Some(off_ref) => {
                let n = self.sys_pread64(in_fd, &mut temp, *off_ref);
                if n > 0 {
                    *off_ref += n as u64;
                }
                n
            }
            None => self.sys_read(in_fd, &mut temp),
        };
        if n_read <= 0 {
            return n_read;
        }
        self.sys_write(out_fd, &temp[..n_read as usize])
    }
}

/// Runs comprehensive self-tests on `vfs_io` structs and file descriptor table operations.
pub fn verify_domain_vfs_io() -> u32 {
    let mut passed = 0u32;
    let mut fds = FdTable::new(64);

    // 1. Open a read-write seekable file (should allocate FD 3 after 0, 1, 2)
    let fd = fds.sys_openat(-100, "/var/log/coros.log", OpenFlags::RDWR.union(OpenFlags::CREAT), b"CorOS:", true) as i32;
    if fd == 3 {
        passed += 1;
    }

    // 2. Seek to end and writev two slices
    if fds.sys_lseek(fd, 0, SeekWhence::End) == 6 {
        passed += 1;
    }
    if fds.sys_writev(fd, &[b"boot", b"_ok"]) == 7 {
        passed += 1;
    }

    // 3. Test pread64 without altering file offset
    let mut pread_buf = [0u8; 5];
    if fds.sys_pread64(fd, &mut pread_buf, 0) == 5 && &pread_buf == b"CorOS" {
        passed += 1;
    }

    // 4. Test dup3 and verify shared offset semantics between fd 3 and fd 10
    if fds.sys_dup3(fd, 10, OpenFlags::CLOEXEC) == 10 {
        passed += 1;
    }
    if fds.sys_lseek(10, 0, SeekWhence::Set) == 0 {
        passed += 1;
    }
    let mut read_buf = [0u8; 13];
    if fds.sys_read(fd, &mut read_buf) == 13 && &read_buf == b"CorOS:boot_ok" {
        passed += 1;
    }

    // 5. Test sendfile from FD 3 to a new destination FD
    let dest_fd = fds.sys_openat(-100, "/tmp/copy.log", OpenFlags::RDWR.union(OpenFlags::CREAT), &[], true) as i32;
    let mut off = 6u64;
    if fds.sys_sendfile(dest_fd, fd, Some(&mut off), 7) == 7 && off == 13 {
        passed += 1;
    }

    // 6. Close descriptors and verify EBADF on closed FD
    if fds.sys_close(fd) == 0 && fds.sys_close(fd) == EBADF {
        passed += 1;
    }

    passed
}
