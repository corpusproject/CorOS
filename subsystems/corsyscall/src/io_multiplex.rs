//! CorOS Syscall Domain Module: `io_multiplex`
//! Scalable I/O Event Multiplexing (`epoll_create1`, `epoll_ctl`, `epoll_pwait`, `poll`, `ppoll`, `pselect6`).

use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const ENOENT: i64 = -2;
pub const EEXIST: i64 = -17;
pub const EBADF: i64 = -9;

/// `epoll_ctl` operation codes (`EPOLL_CTL_ADD`, `EPOLL_CTL_DEL`, `EPOLL_CTL_MOD`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpollCtlOp {
    Add = 1,
    Del = 2,
    Mod = 3,
}

impl EpollCtlOp {
    pub const fn from_raw(op: u32) -> Option<Self> {
        match op {
            1 => Some(Self::Add),
            2 => Some(Self::Del),
            3 => Some(Self::Mod),
            _ => None,
        }
    }
}

/// Event bitmask flags for `epoll` and `poll` (`EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLET`, `EPOLLONESHOT`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollFlags(pub u32);

impl EpollFlags {
    pub const IN: Self = Self(0x0001);
    pub const PRI: Self = Self(0x0002);
    pub const OUT: Self = Self(0x0004);
    pub const ERR: Self = Self(0x0008);
    pub const HUP: Self = Self(0x0010);
    pub const RDHUP: Self = Self(0x2000);
    pub const ONESHOT: Self = Self(1 << 30);
    pub const ET: Self = Self(1 << 31); // Edge-Triggered

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Userspace `struct epoll_event` containing event flags and 64-bit user data token.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollEvent {
    pub events: EpollFlags,
    pub u64_data: u64,
}

/// Descriptor entry for `sys_poll` and `sys_ppoll` (`struct pollfd`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

/// 1024-bit file descriptor bitset (`fd_set`) used by `sys_pselect6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdSet {
    pub bits: [u64; 16],
}

impl FdSet {
    pub const fn new() -> Self {
        Self { bits: [0; 16] }
    }

    #[inline]
    pub fn set(&mut self, fd: usize) {
        if fd < 1024 {
            self.bits[fd / 64] |= 1u64 << (fd % 64);
        }
    }

    #[inline]
    pub fn clear(&mut self, fd: usize) {
        if fd < 1024 {
            self.bits[fd / 64] &= !(1u64 << (fd % 64));
        }
    }

    #[inline]
    pub const fn is_set(&self, fd: usize) -> bool {
        if fd < 1024 {
            (self.bits[fd / 64] & (1u64 << (fd % 64))) != 0
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MonitoredFd {
    fd: i32,
    reg_event: EpollEvent,
    readiness: u32,
    edge_pending: bool,
    disabled_oneshot: bool,
}

/// Kernel `epoll` interest list and readiness notification engine.
pub struct EpollInstance {
    pub cloexec: bool,
    interest_list: Vec<MonitoredFd>,
}

impl EpollInstance {
    /// `sys_epoll_create1`: Allocates a new `EpollInstance`.
    pub fn sys_epoll_create1(flags: u32) -> Result<Self, i64> {
        if (flags & !0x0008_0000) != 0 {
            return Err(EINVAL);
        }
        Ok(Self {
            cloexec: (flags & 0x0008_0000) != 0,
            interest_list: Vec::new(),
        })
    }

    /// `sys_epoll_ctl`: Adds, modifies, or deletes an FD in the epoll interest list.
    pub fn sys_epoll_ctl(&mut self, raw_op: u32, fd: i32, event: Option<EpollEvent>) -> i64 {
        if fd < 0 {
            return EBADF;
        }
        let op = match EpollCtlOp::from_raw(raw_op) {
            Some(o) => o,
            None => return EINVAL,
        };
        let pos = self.interest_list.iter().position(|m| m.fd == fd);

        match op {
            EpollCtlOp::Add => {
                if pos.is_some() {
                    return EEXIST;
                }
                let ev = match event {
                    Some(e) => e,
                    None => return EINVAL,
                };
                self.interest_list.push(MonitoredFd {
                    fd,
                    reg_event: ev,
                    readiness: 0,
                    edge_pending: false,
                    disabled_oneshot: false,
                });
                0
            }
            EpollCtlOp::Mod => {
                let idx = match pos {
                    Some(i) => i,
                    None => return ENOENT,
                };
                let ev = match event {
                    Some(e) => e,
                    None => return EINVAL,
                };
                self.interest_list[idx].reg_event = ev;
                self.interest_list[idx].disabled_oneshot = false;
                self.interest_list[idx].edge_pending = true;
                0
            }
            EpollCtlOp::Del => match pos {
                Some(i) => {
                    self.interest_list.remove(i);
                    0
                }
                None => ENOENT,
            },
        }
    }

    /// Signals I/O readiness transitions from an underlying device/socket/pipe.
    pub fn notify_fd_readiness(&mut self, fd: i32, new_ready_mask: u32) {
        if let Some(m) = self.interest_list.iter_mut().find(|m| m.fd == fd) {
            if (new_ready_mask & !m.readiness) != 0 {
                m.edge_pending = true;
            }
            m.readiness = new_ready_mask;
        }
    }

    /// `sys_epoll_pwait`: Harvests ready events honoring Level-Triggered, Edge-Triggered (`EPOLLET`), and `EPOLLONESHOT` semantics.
    pub fn sys_epoll_pwait(&mut self, out_events: &mut [EpollEvent]) -> i64 {
        if out_events.is_empty() {
            return EINVAL;
        }
        let mut count = 0usize;
        for m in &mut self.interest_list {
            if count >= out_events.len() {
                break;
            }
            if m.disabled_oneshot {
                continue;
            }
            let mask = (m.reg_event.events.0 | EpollFlags::ERR.0 | EpollFlags::HUP.0) & m.readiness;
            if mask == 0 {
                continue;
            }
            let is_et = m.reg_event.events.contains(EpollFlags::ET);
            if is_et && !m.edge_pending {
                continue;
            }

            out_events[count] = EpollEvent {
                events: EpollFlags(mask),
                u64_data: m.reg_event.u64_data,
            };
            count += 1;

            if is_et {
                m.edge_pending = false;
            }
            if m.reg_event.events.contains(EpollFlags::ONESHOT) {
                m.disabled_oneshot = true;
            }
        }
        count as i64
    }

    /// `sys_poll` / `sys_ppoll`: Synchronous readiness scan across an array of `PollFd`s.
    pub fn sys_ppoll(&self, pfds: &mut [PollFd]) -> i64 {
        let mut ready_fds = 0i64;
        for pfd in pfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            if let Some(m) = self.interest_list.iter().find(|m| m.fd == pfd.fd) {
                let matched = (m.readiness as u16) & (pfd.events | 0x0018);
                pfd.revents = matched;
                if matched != 0 {
                    ready_fds += 1;
                }
            }
        }
        ready_fds
    }

    /// `sys_pselect6`: Evaluates read, write, and exception `FdSet` bitmasks up to `nfds`.
    pub fn sys_pselect6(
        &self,
        nfds: usize,
        readfds: Option<&mut FdSet>,
        writefds: Option<&mut FdSet>,
    ) -> i64 {
        if nfds > 1024 {
            return EINVAL;
        }
        let mut total_bits = 0i64;
        if let Some(rfds) = readfds {
            for fd in 0..nfds {
                if rfds.is_set(fd) {
                    let ready = self
                        .interest_list
                        .iter()
                        .any(|m| m.fd == fd as i32 && (m.readiness & EpollFlags::IN.0) != 0);
                    if ready {
                        total_bits += 1;
                    } else {
                        rfds.clear(fd);
                    }
                }
            }
        }
        if let Some(wfds) = writefds {
            for fd in 0..nfds {
                if wfds.is_set(fd) {
                    let ready = self
                        .interest_list
                        .iter()
                        .any(|m| m.fd == fd as i32 && (m.readiness & EpollFlags::OUT.0) != 0);
                    if ready {
                        total_bits += 1;
                    } else {
                        wfds.clear(fd);
                    }
                }
            }
        }
        total_bits
    }
}

/// Runs comprehensive self-tests on `io_multiplex` structs and ET/ONESHOT/poll/select logic.
pub fn verify_domain_io_multiplex() -> u32 {
    let mut passed = 0u32;
    let mut epoll = EpollInstance::sys_epoll_create1(0x0008_0000).unwrap();

    // 1. Register FD 5 with Edge-Triggered (EPOLLET | EPOLLIN) and FD 6 with ONESHOT (EPOLLONESHOT | EPOLLOUT)
    let ev5 = EpollEvent {
        events: EpollFlags::IN.union(EpollFlags::ET),
        u64_data: 500,
    };
    let ev6 = EpollEvent {
        events: EpollFlags::OUT.union(EpollFlags::ONESHOT),
        u64_data: 600,
    };
    if epoll.sys_epoll_ctl(EpollCtlOp::Add as u32, 5, Some(ev5)) == 0
        && epoll.sys_epoll_ctl(EpollCtlOp::Add as u32, 6, Some(ev6)) == 0
    {
        passed += 1;
    }

    // 2. Notify readiness on both FDs and harvest events via epoll_pwait
    epoll.notify_fd_readiness(5, EpollFlags::IN.0);
    epoll.notify_fd_readiness(6, EpollFlags::OUT.0);
    let mut out = [EpollEvent { events: EpollFlags(0), u64_data: 0 }; 4];
    if epoll.sys_epoll_pwait(&mut out) == 2 {
        passed += 1;
    }

    // 3. Second epoll_pwait without new edge or re-arm must return 0 events
    if epoll.sys_epoll_pwait(&mut out) == 0 {
        passed += 1;
    }

    // 4. Re-arm FD 6 via EPOLL_CTL_MOD and verify it fires again
    if epoll.sys_epoll_ctl(EpollCtlOp::Mod as u32, 6, Some(ev6)) == 0 && epoll.sys_epoll_pwait(&mut out) == 1 {
        passed += 1;
    }

    // 5. Verify ppoll and pselect6 detect ready FDs
    let mut pfds = [PollFd { fd: 5, events: EpollFlags::IN.0 as u16, revents: 0 }];
    let mut rfds = FdSet::new();
    rfds.set(5);
    if epoll.sys_ppoll(&mut pfds) == 1 && epoll.sys_pselect6(8, Some(&mut rfds), None) == 1 && rfds.is_set(5) {
        passed += 1;
    }

    passed
}
