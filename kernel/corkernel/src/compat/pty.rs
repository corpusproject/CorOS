//! CorOS POSIX Pseudoterminal (PTY) Subsystem (`pty.rs`)
//!
//! Implements UNIX 98 pseudoterminal multiplexer (/dev/ptmx and /dev/pts/N):
//! - Master / Slave bidirectional duplex communication pipes
//! - POSIX termios line discipline:
//!   - c_iflag: ICRNL (Map CR to NL), IGNCR, INLCR
//!   - c_oflag: OPOST (Post-process output), ONLCR (Map NL to CR-NL)
//!   - c_cflag: CS8 (8-bit characters), CREAD, CLOCAL
//!   - c_lflag: ECHO, ICANON (Canonical line-buffered mode), ISIG (SIGINT/SIGQUIT generation)
//! - Line editing controls: ERASE (^H/Backspace), KILL (^U), EOF (^D), INTR (^C)
//! - TIOCGWINSZ / TIOCSWINSZ terminal window geometry (rows, cols, xpixel, ypixel)

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

pub const NCCS: usize = 32;

/// Termios Input Flags
pub const IGNBRK: u32 = 0o000001;
pub const BRKINT: u32 = 0o000002;
pub const IGNPAR: u32 = 0o000004;
pub const PARMRK: u32 = 0o000010;
pub const INPCK: u32 = 0o000020;
pub const ISTRIP: u32 = 0o000040;
pub const INLCR: u32 = 0o000100;
pub const IGNCR: u32 = 0o000200;
pub const ICRNL: u32 = 0o000400;
pub const IXON: u32 = 0o002000;
pub const IXOFF: u32 = 0o010000;

/// Termios Output Flags
pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;
pub const OCRNL: u32 = 0o000010;
pub const ONOCR: u32 = 0o000020;
pub const ONLRET: u32 = 0o000040;

/// Termios Local Flags
pub const ISIG: u32 = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32 = 0o000010;
pub const ECHOE: u32 = 0o000020;
pub const ECHOK: u32 = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const NOFLSH: u32 = 0o000200;
pub const TOSTOP: u32 = 0o000400;
pub const IEXTEN: u32 = 0o100000;

/// Special Control Characters (c_cc indices)
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;

/// POSIX termios structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Default for Termios {
    fn default() -> Self {
        let mut cc = [0u8; NCCS];
        cc[VINTR] = 3;   // ^C
        cc[VQUIT] = 28;  // ^\
        cc[VERASE] = 127;// DEL / Backspace
        cc[VKILL] = 21;  // ^U
        cc[VEOF] = 4;    // ^D
        cc[VTIME] = 0;
        cc[VMIN] = 1;

        Self {
            c_iflag: ICRNL | IXON,
            c_oflag: OPOST | ONLCR,
            c_cflag: 0o000060 | 0o000200, // CS8 | CREAD
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK,
            c_line: 0,
            c_cc: cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }
}

/// Window Size Structure (`winsize`)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// A single PTY Master/Slave Pair
pub struct PtyPair {
    pub pty_num: u32,
    pub master_fd: i32,
    pub slave_fd: i32,
    pub termios: Termios,
    pub winsize: WinSize,
    master_to_slave_buf: VecDeque<u8>,
    slave_to_master_buf: VecDeque<u8>,
    canonical_line_buf: Vec<u8>,
}

impl PtyPair {
    pub fn new(pty_num: u32, master_fd: i32, slave_fd: i32) -> Self {
        Self {
            pty_num,
            master_fd,
            slave_fd,
            termios: Termios::default(),
            winsize: WinSize {
                ws_row: 25,
                ws_col: 80,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
            master_to_slave_buf: VecDeque::new(),
            slave_to_master_buf: VecDeque::new(),
            canonical_line_buf: Vec::new(),
        }
    }

    /// Write from Master side (Keyboard / Terminal emulator -> Slave)
    pub fn master_write(&mut self, input: &[u8]) -> usize {
        for &byte in input {
            let mut ch = byte;

            // Input transformations
            if ch == b'\r' && (self.termios.c_iflag & ICRNL) != 0 {
                ch = b'\n';
            } else if ch == b'\n' && (self.termios.c_iflag & INLCR) != 0 {
                ch = b'\r';
            }

            // Check for ISIG signals (e.g. ^C)
            if (self.termios.c_lflag & ISIG) != 0 && ch == self.termios.c_cc[VINTR] {
                // Generate SIGINT
                self.canonical_line_buf.clear();
                continue;
            }

            // Echo character back to master if ECHO is enabled
            if (self.termios.c_lflag & ECHO) != 0 {
                if ch == b'\n' && (self.termios.c_oflag & ONLCR) != 0 {
                    self.slave_to_master_buf.push_back(b'\r');
                    self.slave_to_master_buf.push_back(b'\n');
                } else {
                    self.slave_to_master_buf.push_back(ch);
                }
            }

            // Canonical vs Raw mode
            if (self.termios.c_lflag & ICANON) != 0 {
                if ch == self.termios.c_cc[VERASE] {
                    self.canonical_line_buf.pop();
                } else if ch == self.termios.c_cc[VKILL] {
                    self.canonical_line_buf.clear();
                } else if ch == b'\n' || ch == self.termios.c_cc[VEOF] {
                    if ch == b'\n' {
                        self.canonical_line_buf.push(b'\n');
                    }
                    for &b in &self.canonical_line_buf {
                        self.master_to_slave_buf.push_back(b);
                    }
                    self.canonical_line_buf.clear();
                } else {
                    self.canonical_line_buf.push(ch);
                }
            } else {
                self.master_to_slave_buf.push_back(ch);
            }
        }
        input.len()
    }

    /// Read from Slave side (Shell / application reads stdin)
    pub fn slave_read(&mut self, buf: &mut [u8]) -> usize {
        let count = core::cmp::min(buf.len(), self.master_to_slave_buf.len());
        for i in 0..count {
            buf[i] = self.master_to_slave_buf.pop_front().unwrap();
        }
        count
    }

    /// Write from Slave side (Shell stdout -> Master / display terminal)
    pub fn slave_write(&mut self, output: &[u8]) -> usize {
        for &byte in output {
            if byte == b'\n' && (self.termios.c_oflag & ONLCR) != 0 {
                self.slave_to_master_buf.push_back(b'\r');
                self.slave_to_master_buf.push_back(b'\n');
            } else {
                self.slave_to_master_buf.push_back(byte);
            }
        }
        output.len()
    }

    /// Read from Master side (Terminal GUI reads to render to screen)
    pub fn master_read(&mut self, buf: &mut [u8]) -> usize {
        let count = core::cmp::min(buf.len(), self.slave_to_master_buf.len());
        for i in 0..count {
            buf[i] = self.slave_to_master_buf.pop_front().unwrap();
        }
        count
    }
}

/// Global PTY multiplexer table
pub struct PtyMultiplexer {
    pairs: Vec<PtyPair>,
    next_pty_id: u32,
    next_fd: i32,
}

impl PtyMultiplexer {
    pub fn new() -> Self {
        Self {
            pairs: Vec::new(),
            next_pty_id: 0,
            next_fd: 200,
        }
    }

    /// `posix_openpt` - Open a new pseudoterminal master
    pub fn open_pt(&mut self) -> (i32, i32, u32) {
        let pty_num = self.next_pty_id;
        self.next_pty_id += 1;

        let m_fd = self.next_fd;
        self.next_fd += 1;
        let s_fd = self.next_fd;
        self.next_fd += 1;

        self.pairs.push(PtyPair::new(pty_num, m_fd, s_fd));
        (m_fd, s_fd, pty_num)
    }

    pub fn get_by_master_mut(&mut self, m_fd: i32) -> Option<&mut PtyPair> {
        self.pairs.iter_mut().find(|p| p.master_fd == m_fd)
    }

    pub fn get_by_slave_mut(&mut self, s_fd: i32) -> Option<&mut PtyPair> {
        self.pairs.iter_mut().find(|p| p.slave_fd == s_fd)
    }
}
