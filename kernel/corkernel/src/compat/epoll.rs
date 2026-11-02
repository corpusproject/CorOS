//! CorOS Linux `epoll` Event Notification Subsystem (`epoll.rs`)
//!
//! Implements Linux high-performance I/O multiplexing:
//! - `epoll_create1(flags)`: Instantiates epoll instance (Red-Black tree of watched file descriptors)
//! - `epoll_ctl(epfd, op, fd, event)`: EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL
//! - `epoll_wait(epfd, events, maxevents, timeout)`: Level-Triggered & Edge-Triggered (EPOLLET) readiness dispatch
//! - Monitored Event Masks: EPOLLIN (0x01), EPOLLPRI (0x02), EPOLLOUT (0x04), EPOLLERR (0x08), EPOLLHUP (0x10), EPOLLET (0x80000000), EPOLLONESHOT (0x40000000)

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

pub const EPOLLIN: u32 = 0x00000001;
pub const EPOLLPRI: u32 = 0x00000002;
pub const EPOLLOUT: u32 = 0x00000004;
pub const EPOLLERR: u32 = 0x00000008;
pub const EPOLLHUP: u32 = 0x00000010;
pub const EPOLLRDNORM: u32 = 0x00000040;
pub const EPOLLRDBAND: u32 = 0x00000080;
pub const EPOLLWRNORM: u32 = 0x00000100;
pub const EPOLLWRBAND: u32 = 0x00000200;
pub const EPOLLMSG: u32 = 0x00000400;
pub const EPOLLRDHUP: u32 = 0x00002000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31; // Edge Triggered

/// Linux `epoll_data` union
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollData {
    pub u64_val: u64,
}

impl EpollData {
    pub fn from_fd(fd: i32) -> Self {
        Self { u64_val: fd as u64 }
    }

    pub fn from_u64(val: u64) -> Self {
        Self { u64_val: val }
    }
}

/// Linux `epoll_event` structure (12 bytes on x86_64, packed to 16 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// Registration entry inside an epoll interest list
#[derive(Debug, Clone)]
pub struct EpollEntry {
    pub fd: i32,
    pub events: u32,
    pub data: u64,
    pub last_reported_events: u32,
    pub active_revents: u32,
}

/// An epoll instance
pub struct EpollInstance {
    pub epfd: i32,
    pub interest_list: BTreeMap<i32, EpollEntry>,
    pub ready_list: Vec<i32>,
}

impl EpollInstance {
    pub fn new(epfd: i32) -> Self {
        Self {
            epfd,
            interest_list: BTreeMap::new(),
            ready_list: Vec::new(),
        }
    }

    /// `epoll_ctl` - Add, modify, or remove monitored file descriptor
    pub fn ctl(&mut self, op: i32, fd: i32, event: Option<&EpollEvent>) -> Result<(), i32> {
        match op {
            EPOLL_CTL_ADD => {
                if self.interest_list.contains_key(&fd) {
                    return Err(-17); // -EEXIST
                }
                let ev = event.ok_or(-22)?; // -EINVAL
                let entry = EpollEntry {
                    fd,
                    events: ev.events,
                    data: ev.data,
                    last_reported_events: 0,
                    active_revents: 0,
                };
                self.interest_list.insert(fd, entry);
                Ok(())
            }
            EPOLL_CTL_MOD => {
                let entry = self.interest_list.get_mut(&fd).ok_or(-2)?; // -ENOENT
                let ev = event.ok_or(-22)?;
                entry.events = ev.events;
                entry.data = ev.data;
                entry.last_reported_events = 0;
                Ok(())
            }
            EPOLL_CTL_DEL => {
                if self.interest_list.remove(&fd).is_some() {
                    self.ready_list.retain(|&ready_fd| ready_fd != fd);
                    Ok(())
                } else {
                    Err(-2) // -ENOENT
                }
            }
            _ => Err(-22),
        }
    }

    /// Trigger file descriptor readiness event from driver/socket
    pub fn notify_event(&mut self, fd: i32, revents: u32) {
        if let Some(entry) = self.interest_list.get_mut(&fd) {
            entry.active_revents |= revents;
            if !self.ready_list.contains(&fd) {
                self.ready_list.push(fd);
            }
        }
    }

    /// `epoll_wait` - Collect available ready events
    pub fn wait(&mut self, out_events: &mut [EpollEvent], maxevents: usize) -> Result<usize, i32> {
        if maxevents == 0 || out_events.is_empty() {
            return Err(-22);
        }

        let mut collected = 0;
        let mut still_ready = Vec::new();

        for &fd in &self.ready_list {
            if collected >= maxevents || collected >= out_events.len() {
                still_ready.push(fd);
                continue;
            }

            if let Some(entry) = self.interest_list.get_mut(&fd) {
                let matched = entry.events & entry.active_revents;
                if matched != 0 {
                    let is_edge = (entry.events & EPOLLET) != 0;
                    let is_oneshot = (entry.events & EPOLLONESHOT) != 0;

                    out_events[collected] = EpollEvent {
                        events: matched,
                        data: entry.data,
                    };
                    collected += 1;
                    entry.last_reported_events = matched;

                    if is_oneshot {
                        entry.events = 0; // Disable until rearmed with EPOLL_CTL_MOD
                        entry.active_revents = 0;
                    } else if is_edge {
                        // Edge-triggered clears active revents until next edge
                        entry.active_revents = 0;
                    } else {
                        // Level-triggered remains ready if still active
                        if entry.active_revents != 0 {
                            still_ready.push(fd);
                        }
                    }
                }
            }
        }

        self.ready_list = still_ready;
        Ok(collected)
    }
}

/// Global Epoll Table
pub struct EpollTable {
    instances: BTreeMap<i32, EpollInstance>,
    next_epfd: i32,
}

impl EpollTable {
    pub fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
            next_epfd: 100,
        }
    }

    pub fn create_instance(&mut self) -> i32 {
        let epfd = self.next_epfd;
        self.next_epfd += 1;
        self.instances.insert(epfd, EpollInstance::new(epfd));
        epfd
    }

    pub fn get_mut(&mut self, epfd: i32) -> Option<&mut EpollInstance> {
        self.instances.get_mut(&epfd)
    }

    pub fn close(&mut self, epfd: i32) -> bool {
        self.instances.remove(&epfd).is_some()
    }
}
