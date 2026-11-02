//! CorOS VFS Module: `tmpfs_ram`
//!
//! In-memory page-backed volatile filesystem (`TmpFsNode`, hierarchical directory tree,
//! file data chunks, `create_file`, `mkdir`, `write`, `read`, `rename`, `unlink`,
//! `truncate`, and `statfs` accounting).

use alloc::string::String;
use alloc::vec::Vec;

/// Standard `tmpfs` page size (4096 bytes) for memory accounting.
pub const TMPFS_PAGE_SIZE: usize = 4096;
/// POSIX file mode bit for FIFO inodes (0o010000).
pub const S_IFIFO: u32 = 0o010000;
/// Atomic contiguous pipe buffer capacity (4096 bytes).
pub const PIPE_BUF: usize = 4096;

/// Payload stored inside a `TmpFsNode`.
#[derive(Clone, Debug)]
pub enum TmpFsPayload {
    Directory { children: Vec<(String, u64)> },
    RegularFile { data: Vec<u8> },
    Symlink { target: String },
    Fifo {
        reader_count: usize,
        writer_count: usize,
        buffer: Vec<u8>,
    },
}

/// Volatile in-memory inode in `tmpfs`.
#[derive(Clone, Debug)]
pub struct TmpFsNode {
    pub ino: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub payload: TmpFsPayload,
}

/// Filesystem capacity & usage statistics returned by `statfs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmpFsStatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_files: u64,
    pub f_ffree: u64,
}

/// Errors returned by `tmpfs` operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TmpFsError {
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    NoSpaceLeft,
}

/// Volatile page-accounted RAM filesystem instance (`/tmp`, `/run`).
pub struct TmpFsRamVolume {
    nodes: Vec<TmpFsNode>,
    next_ino: u64,
    max_pages: usize,
    max_inodes: usize,
}

impl TmpFsRamVolume {
    pub const TMPFS_MAGIC: u64 = 0x0102_1994;

    /// Creates a new `tmpfs` volume with root directory at inode `1`.
    pub fn new(max_pages: usize, max_inodes: usize) -> Self {
        let mut nodes = Vec::new();
        nodes.push(TmpFsNode {
            ino: 1,
            mode: 0o1777, // sticky bit + rwxrwxrwt for /tmp
            uid: 0,
            gid: 0,
            nlink: 2,
            payload: TmpFsPayload::Directory {
                children: Vec::new(),
            },
        });

        Self {
            nodes,
            next_ino: 2,
            max_pages: max_pages.max(16),
            max_inodes: max_inodes.max(16),
        }
    }

    /// Computes total 4 KiB pages currently occupied by file payloads.
    pub fn used_pages(&self) -> usize {
        let mut pages = 0usize;
        for n in &self.nodes {
            match &n.payload {
                TmpFsPayload::RegularFile { data } => {
                    pages += (data.len() + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                }
                TmpFsPayload::Fifo { buffer, .. } => {
                    pages += (buffer.len() + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                }
                _ => {}
            }
        }
        pages
    }

    fn get_node(&self, ino: u64) -> Option<&TmpFsNode> {
        self.nodes.iter().find(|n| n.ino == ino)
    }

    fn get_node_mut(&mut self, ino: u64) -> Option<&mut TmpFsNode> {
        self.nodes.iter_mut().find(|n| n.ino == ino)
    }

    /// Resolves a parent directory inode and leaf entry name from a `/tmp`-relative path.
    fn resolve_parent_and_leaf<'a>(&self, path: &'a str) -> Result<(u64, &'a str), TmpFsError> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Err(TmpFsError::IsADirectory);
        }

        let mut curr_ino = 1u64;
        let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        for &seg in &segments[..segments.len() - 1] {
            let dir = self.get_node(curr_ino).ok_or(TmpFsError::NotFound)?;
            match &dir.payload {
                TmpFsPayload::Directory { children } => {
                    curr_ino = children
                        .iter()
                        .find(|(name, _)| name == seg)
                        .map(|(_, ino)| *ino)
                        .ok_or(TmpFsError::NotFound)?;
                }
                _ => return Err(TmpFsError::NotADirectory),
            }
        }

        Ok((curr_ino, segments[segments.len() - 1]))
    }

    /// Resolves any `/tmp`-relative path to its inode number.
    pub fn lookup_path(&self, path: &str) -> Result<u64, TmpFsError> {
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            return Ok(1);
        }
        let (parent_ino, leaf) = self.resolve_parent_and_leaf(path)?;
        let parent = self.get_node(parent_ino).ok_or(TmpFsError::NotFound)?;
        match &parent.payload {
            TmpFsPayload::Directory { children } => children
                .iter()
                .find(|(name, _)| name == leaf)
                .map(|(_, ino)| *ino)
                .ok_or(TmpFsError::NotFound),
            _ => Err(TmpFsError::NotADirectory),
        }
    }

    /// Creates a directory at `path`.
    pub fn mkdir(&mut self, path: &str, mode: u16) -> Result<u64, TmpFsError> {
        if self.nodes.len() >= self.max_inodes {
            return Err(TmpFsError::NoSpaceLeft);
        }
        let (parent_ino, leaf) = self.resolve_parent_and_leaf(path)?;
        let new_ino = self.next_ino;

        {
            let parent = self.get_node_mut(parent_ino).ok_or(TmpFsError::NotFound)?;
            match &mut parent.payload {
                TmpFsPayload::Directory { children } => {
                    if children.iter().any(|(n, _)| n == leaf) {
                        return Err(TmpFsError::AlreadyExists);
                    }
                    children.push((String::from(leaf), new_ino));
                    parent.nlink += 1;
                }
                _ => return Err(TmpFsError::NotADirectory),
            }
        }

        self.next_ino += 1;
        self.nodes.push(TmpFsNode {
            ino: new_ino,
            mode,
            uid: 0,
            gid: 0,
            nlink: 2,
            payload: TmpFsPayload::Directory {
                children: Vec::new(),
            },
        });
        Ok(new_ino)
    }

    /// Creates an empty regular file at `path`.
    pub fn create_file(&mut self, path: &str, mode: u16) -> Result<u64, TmpFsError> {
        if self.nodes.len() >= self.max_inodes {
            return Err(TmpFsError::NoSpaceLeft);
        }
        let (parent_ino, leaf) = self.resolve_parent_and_leaf(path)?;
        let new_ino = self.next_ino;

        {
            let parent = self.get_node_mut(parent_ino).ok_or(TmpFsError::NotFound)?;
            match &mut parent.payload {
                TmpFsPayload::Directory { children } => {
                    if children.iter().any(|(n, _)| n == leaf) {
                        return Err(TmpFsError::AlreadyExists);
                    }
                    children.push((String::from(leaf), new_ino));
                }
                _ => return Err(TmpFsError::NotADirectory),
            }
        }

        self.next_ino += 1;
        self.nodes.push(TmpFsNode {
            ino: new_ino,
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            payload: TmpFsPayload::RegularFile { data: Vec::new() },
        });
        Ok(new_ino)
    }

    /// Writes `buf` at `offset` into the regular file at `path`.
    pub fn write_file(&mut self, path: &str, offset: usize, buf: &[u8]) -> Result<usize, TmpFsError> {
        let ino = self.lookup_path(path)?;
        let current_pages = self.used_pages();
        let max_pages = self.max_pages;
        let node = self.get_node_mut(ino).ok_or(TmpFsError::NotFound)?;

        match &mut node.payload {
            TmpFsPayload::RegularFile { data } => {
                let old_pages = (data.len() + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                let end = offset.saturating_add(buf.len());
                let new_pages = (end.max(data.len()) + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                if current_pages - old_pages + new_pages > max_pages {
                    return Err(TmpFsError::NoSpaceLeft);
                }

                if end > data.len() {
                    data.resize(end, 0);
                }
                data[offset..end].copy_from_slice(buf);
                Ok(buf.len())
            }
            _ => Err(TmpFsError::IsADirectory),
        }
    }

    /// Reads up to `out.len()` bytes starting at `offset` from the regular file at `path`.
    pub fn read_file(&self, path: &str, offset: usize, out: &mut [u8]) -> Result<usize, TmpFsError> {
        let ino = self.lookup_path(path)?;
        let node = self.get_node(ino).ok_or(TmpFsError::NotFound)?;
        match &node.payload {
            TmpFsPayload::RegularFile { data } => {
                if offset >= data.len() {
                    return Ok(0);
                }
                let avail = (data.len() - offset).min(out.len());
                out[..avail].copy_from_slice(&data[offset..offset + avail]);
                Ok(avail)
            }
            _ => Err(TmpFsError::IsADirectory),
        }
    }

    /// Resizes (`truncate`) a regular file to `new_size` bytes, zero-filling on extension.
    pub fn truncate(&mut self, path: &str, new_size: usize) -> Result<(), TmpFsError> {
        let ino = self.lookup_path(path)?;
        let current_pages = self.used_pages();
        let max_pages = self.max_pages;
        let node = self.get_node_mut(ino).ok_or(TmpFsError::NotFound)?;
        match &mut node.payload {
            TmpFsPayload::RegularFile { data } => {
                let old_pages = (data.len() + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                let req_pages = (new_size + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE;
                if current_pages - old_pages + req_pages > max_pages {
                    return Err(TmpFsError::NoSpaceLeft);
                }
                data.resize(new_size, 0);
                Ok(())
            }
            _ => Err(TmpFsError::IsADirectory),
        }
    }

    /// Atomically renames/moves `old_path` to `new_path` within the `tmpfs` hierarchy.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), TmpFsError> {
        let (old_parent_ino, old_leaf) = self.resolve_parent_and_leaf(old_path)?;
        let (new_parent_ino, new_leaf) = self.resolve_parent_and_leaf(new_path)?;

        let target_ino = {
            let old_parent = self.get_node_mut(old_parent_ino).ok_or(TmpFsError::NotFound)?;
            match &mut old_parent.payload {
                TmpFsPayload::Directory { children } => {
                    let pos = children
                        .iter()
                        .position(|(n, _)| n == old_leaf)
                        .ok_or(TmpFsError::NotFound)?;
                    children.remove(pos).1
                }
                _ => return Err(TmpFsError::NotADirectory),
            }
        };

        let new_parent = self.get_node_mut(new_parent_ino).ok_or(TmpFsError::NotFound)?;
        match &mut new_parent.payload {
            TmpFsPayload::Directory { children } => {
                children.retain(|(n, _)| n != new_leaf);
                children.push((String::from(new_leaf), target_ino));
                Ok(())
            }
            _ => Err(TmpFsError::NotADirectory),
        }
    }

    /// Removes (`unlink`) a file or empty directory at `path`.
    pub fn unlink(&mut self, path: &str) -> Result<(), TmpFsError> {
        let (parent_ino, leaf) = self.resolve_parent_and_leaf(path)?;
        let target_ino = self.lookup_path(path)?;

        if let Some(node) = self.get_node(target_ino) {
            if let TmpFsPayload::Directory { children } = &node.payload {
                if !children.is_empty() {
                    return Err(TmpFsError::DirectoryNotEmpty);
                }
            }
        }

        if let Some(parent) = self.get_node_mut(parent_ino) {
            if let TmpFsPayload::Directory { children } = &mut parent.payload {
                children.retain(|(n, _)| n != leaf);
            }
        }

        self.nodes.retain(|n| n.ino != target_ino);
        Ok(())
    }

    /// Creates a named FIFO special file at `path`.
    pub fn mkfifo(&mut self, path: &str, mode: u16) -> Result<u64, TmpFsError> {
        if self.nodes.len() >= self.max_inodes {
            return Err(TmpFsError::NoSpaceLeft);
        }
        let (parent_ino, leaf) = self.resolve_parent_and_leaf(path)?;
        let new_ino = self.next_ino;

        {
            let parent = self.get_node_mut(parent_ino).ok_or(TmpFsError::NotFound)?;
            match &mut parent.payload {
                TmpFsPayload::Directory { children } => {
                    if children.iter().any(|(n, _)| n == leaf) {
                        return Err(TmpFsError::AlreadyExists);
                    }
                    children.push((String::from(leaf), new_ino));
                }
                _ => return Err(TmpFsError::NotADirectory),
            }
        }

        self.next_ino += 1;
        self.nodes.push(TmpFsNode {
            ino: new_ino,
            mode: (mode & 0o7777) | (S_IFIFO as u16),
            uid: 0,
            gid: 0,
            nlink: 1,
            payload: TmpFsPayload::Fifo {
                reader_count: 0,
                writer_count: 0,
                buffer: Vec::new(),
            },
        });
        Ok(new_ino)
    }

    /// Opens a FIFO inode tracking active reader/writer counts and enforcing POSIX blocking/O_NONBLOCK open rules.
    pub fn open_fifo(&mut self, ino: u64, read: bool, write: bool, non_block: bool) -> Result<&'static str, i32> {
        let node = self.get_node_mut(ino).ok_or(-2)?; // -ENOENT
        match &mut node.payload {
            TmpFsPayload::Fifo { reader_count, writer_count, .. } => {
                if read && write {
                    *reader_count += 1;
                    *writer_count += 1;
                    Ok("OPENED_RDWR")
                } else if read {
                    *reader_count += 1;
                    if !non_block && *writer_count == 0 {
                        Ok("BLOCKED_WAITING_FOR_WRITER")
                    } else {
                        Ok("OPENED_RO")
                    }
                } else if write {
                    if non_block && *reader_count == 0 {
                        // POSIX O_NONBLOCK write open with 0 readers must return -ENXIO (-6)
                        return Err(-6);
                    }
                    *writer_count += 1;
                    if !non_block && *reader_count == 0 {
                        Ok("BLOCKED_WAITING_FOR_READER")
                    } else {
                        Ok("OPENED_WO")
                    }
                } else {
                    Err(-22) // -EINVAL
                }
            }
            _ => Err(-22),
        }
    }

    /// Writes data into a FIFO inode.
    /// If zero readers exist, returns -32 (-EPIPE) triggering SIGPIPE.
    /// Writes up to PIPE_BUF (4096 bytes) are contiguous and atomic.
    pub fn write_fifo(&mut self, ino: u64, data: &[u8]) -> Result<usize, i32> {
        let node = self.get_node_mut(ino).ok_or(-2)?;
        match &mut node.payload {
            TmpFsPayload::Fifo { reader_count, buffer, .. } => {
                if *reader_count == 0 {
                    return Err(-32); // -EPIPE
                }
                buffer.extend_from_slice(data);
                Ok(data.len())
            }
            _ => Err(-22),
        }
    }

    /// Reads up to `max_bytes` from a FIFO inode.
    /// If buffer is empty and zero writers exist, returns an empty vector (EOF).
    pub fn read_fifo(&mut self, ino: u64, max_bytes: usize) -> Result<Vec<u8>, i32> {
        let node = self.get_node_mut(ino).ok_or(-2)?;
        match &mut node.payload {
            TmpFsPayload::Fifo { writer_count, buffer, .. } => {
                if buffer.is_empty() {
                    if *writer_count == 0 {
                        return Ok(Vec::new()); // Clean EOF
                    }
                    return Ok(Vec::new()); // Would block or empty
                }
                let to_read = max_bytes.min(buffer.len());
                let drained: Vec<u8> = buffer.drain(..to_read).collect();
                Ok(drained)
            }
            _ => Err(-22),
        }
    }

    /// Decrements reader/writer reference counts on FIFO close.
    pub fn close_fifo(&mut self, ino: u64, read: bool, write: bool) {
        if let Some(node) = self.get_node_mut(ino) {
            if let TmpFsPayload::Fifo { reader_count, writer_count, .. } = &mut node.payload {
                if read && *reader_count > 0 {
                    *reader_count -= 1;
                }
                if write && *writer_count > 0 {
                    *writer_count -= 1;
                }
            }
        }
    }

    /// Returns live `statfs` usage telemetry for this `tmpfs` mount.
    pub fn statfs(&self) -> TmpFsStatFs {
        let used = self.used_pages() as u64;
        let max_p = self.max_pages as u64;
        let used_files = self.nodes.len() as u64;
        let max_f = self.max_inodes as u64;

        TmpFsStatFs {
            f_type: Self::TMPFS_MAGIC,
            f_bsize: TMPFS_PAGE_SIZE as u64,
            f_blocks: max_p,
            f_bfree: max_p.saturating_sub(used),
            f_files: max_f,
            f_ffree: max_f.saturating_sub(used_files),
        }
    }
}

/// Self-test suite for `tmpfs_ram`.
pub fn verify_vfs_tmpfs_ram() -> u32 {
    let mut passed = 0u32;
    let mut tmp = TmpFsRamVolume::new(64, 64);

    if tmp.mkdir("/session", 0o755).is_ok() && tmp.create_file("/session/ipc.sock", 0o600).is_ok() {
        passed += 1;
    }

    if tmp.write_file("/session/ipc.sock", 0, b"COROS_TMPFS_PAYLOAD") == Ok(19) {
        let mut rbuf = [0u8; 19];
        if tmp.read_file("/session/ipc.sock", 0, &mut rbuf) == Ok(19) && &rbuf == b"COROS_TMPFS_PAYLOAD" {
            passed += 1;
        }
    }

    if tmp.truncate("/session/ipc.sock", 8192).is_ok() && tmp.statfs().f_bfree == 62 {
        passed += 1;
    }

    if tmp.rename("/session/ipc.sock", "/session/renamed.dat").is_ok()
        && tmp.lookup_path("/session/renamed.dat").is_ok()
        && tmp.lookup_path("/session/ipc.sock") == Err(TmpFsError::NotFound)
    {
        passed += 1;
    }

    if tmp.unlink("/session") == Err(TmpFsError::DirectoryNotEmpty)
        && tmp.unlink("/session/renamed.dat").is_ok()
        && tmp.unlink("/session").is_ok()
    {
        passed += 1;
    }

    // Test FIFO inode creation, mode bits, and state machine
    if let Ok(fifo_ino) = tmp.mkfifo("/myfifo", 0o666) {
        if let Some(node) = tmp.get_node(fifo_ino) {
            if (node.mode as u32 & S_IFIFO) == S_IFIFO {
                passed += 1;
            }
        }

        // Test non-blocking write open fails with -ENXIO (-6) when 0 readers
        if tmp.open_fifo(fifo_ino, false, true, true) == Err(-6) {
            passed += 1;
        }

        // Test blocking read open with 0 writers reports blocked
        if tmp.open_fifo(fifo_ino, true, false, false) == Ok("BLOCKED_WAITING_FOR_WRITER") {
            passed += 1;
        }

        // Test blocking write open with reader now present succeeds
        if tmp.open_fifo(fifo_ino, false, true, false) == Ok("OPENED_WO") {
            passed += 1;
        }

        // Test contiguous atomic write up to PIPE_BUF and read
        let data = [b'F'; 4096];
        if tmp.write_fifo(fifo_ino, &data) == Ok(4096) {
            if let Ok(read_back) = tmp.read_fifo(fifo_ino, 4096) {
                if read_back.len() == 4096 && read_back[0] == b'F' {
                    passed += 1;
                }
            }
        }

        // Close reader and verify write delivers -EPIPE (-32)
        tmp.close_fifo(fifo_ino, true, false);
        if tmp.write_fifo(fifo_ino, b"FAIL") == Err(-32) {
            passed += 1;
        }

        // Close writer and re-open read-only; reading empty buffer returns EOF (0 bytes)
        tmp.close_fifo(fifo_ino, false, true);
        if tmp.open_fifo(fifo_ino, true, false, true) == Ok("OPENED_RO") {
            if tmp.read_fifo(fifo_ino, 100) == Ok(Vec::new()) {
                passed += 1;
            }
        }
    }

    passed
}
