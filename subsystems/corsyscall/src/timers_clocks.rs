//! CorOS Syscall Domain Module: `timers_clocks`
//! High-Resolution Clocks & Timers (`clock_gettime`, `clock_getres`, `clock_nanosleep`, `nanosleep`, `gettimeofday`, `setitimer`, `timer_create`, `timerfd_create`).

use alloc::vec::Vec;

pub const EINVAL: i64 = -22;
pub const EAGAIN: i64 = -11;
pub const NSEC_PER_SEC: i64 = 1_000_000_000;
pub const USEC_PER_SEC: i64 = 1_000_000;
pub const TIMER_ABSTIME: u32 = 1;

/// POSIX Clock Identifiers (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`, etc.).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCputimeId = 2,
    ThreadCputimeId = 3,
    MonotonicRaw = 4,
    RealtimeCoarse = 5,
    MonotonicCoarse = 6,
    Boottime = 7,
}

impl ClockId {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Realtime),
            1 => Some(Self::Monotonic),
            2 => Some(Self::ProcessCputimeId),
            3 => Some(Self::ThreadCputimeId),
            4 => Some(Self::MonotonicRaw),
            5 => Some(Self::RealtimeCoarse),
            6 => Some(Self::MonotonicCoarse),
            7 => Some(Self::Boottime),
            _ => None,
        }
    }
}

/// Nanosecond precision time specification (`struct timespec`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.tv_sec >= 0 && self.tv_nsec >= 0 && self.tv_nsec < NSEC_PER_SEC
    }

    #[inline]
    pub const fn to_ns(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(NSEC_PER_SEC as u64)
            .saturating_add(self.tv_nsec as u64)
    }

    #[inline]
    pub const fn from_ns(ns: u64) -> Self {
        Self {
            tv_sec: (ns / (NSEC_PER_SEC as u64)) as i64,
            tv_nsec: (ns % (NSEC_PER_SEC as u64)) as i64,
        }
    }
}

/// Microsecond precision legacy time value (`struct timeval`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

impl Timeval {
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.tv_sec >= 0 && self.tv_usec >= 0 && self.tv_usec < USEC_PER_SEC
    }

    #[inline]
    pub const fn to_ns(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(NSEC_PER_SEC as u64)
            .saturating_add((self.tv_usec as u64).saturating_mul(1000))
    }
}

/// Interval timer specification (`struct itimerspec`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ItimerSpec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

#[derive(Clone, Copy, Debug)]
struct ArmedTimer {
    id: u32,
    clock: ClockId,
    deadline_ns: u64,
    interval_ns: u64,
    overruns: u64,
    is_timerfd: bool,
}

/// Hierarchical Kernel Timer Wheel & Clock Subsystem.
pub struct KernelTimerWheel {
    pub monotonic_ns: u64,
    pub realtime_offset_ns: u64,
    pub suspend_ns: u64,
    pub process_cpu_ns: u64,
    timers: Vec<ArmedTimer>,
    next_timer_id: u32,
}

impl KernelTimerWheel {
    pub fn new(epoch_realtime_sec: u64) -> Self {
        Self {
            monotonic_ns: 0,
            realtime_offset_ns: epoch_realtime_sec * (NSEC_PER_SEC as u64),
            suspend_ns: 0,
            process_cpu_ns: 0,
            timers: Vec::new(),
            next_timer_id: 1,
        }
    }

    fn read_clock_ns(&self, clock: ClockId) -> u64 {
        match clock {
            ClockId::Realtime | ClockId::RealtimeCoarse => self.realtime_offset_ns + self.monotonic_ns,
            ClockId::Monotonic | ClockId::MonotonicRaw | ClockId::MonotonicCoarse => self.monotonic_ns,
            ClockId::Boottime => self.monotonic_ns + self.suspend_ns,
            ClockId::ProcessCputimeId | ClockId::ThreadCputimeId => self.process_cpu_ns,
        }
    }

    /// Advances hardware clock ticks and fires any expired periodic or one-shot timers.
    pub fn advance_time_ns(&mut self, delta_ns: u64) -> u32 {
        self.monotonic_ns = self.monotonic_ns.saturating_add(delta_ns);
        self.process_cpu_ns = self.process_cpu_ns.saturating_add(delta_ns / 2);

        let mono = self.monotonic_ns;
        let real = self.realtime_offset_ns + mono;
        let boot = mono + self.suspend_ns;
        let cpu = self.process_cpu_ns;

        let mut fired_count = 0u32;
        for t in &mut self.timers {
            if t.deadline_ns == 0 {
                continue;
            }
            let now = match t.clock {
                ClockId::Realtime | ClockId::RealtimeCoarse => real,
                ClockId::Boottime => boot,
                ClockId::ProcessCputimeId | ClockId::ThreadCputimeId => cpu,
                _ => mono,
            };
            if now >= t.deadline_ns {
                fired_count += 1;
                if t.interval_ns > 0 {
                    let elapsed = now - t.deadline_ns;
                    let extra_ticks = elapsed / t.interval_ns + 1;
                    t.overruns = t.overruns.saturating_add(extra_ticks);
                    t.deadline_ns += extra_ticks * t.interval_ns;
                } else {
                    t.overruns = t.overruns.saturating_add(1);
                    t.deadline_ns = 0;
                }
            }
        }
        fired_count
    }

    /// `sys_clock_gettime`: Reads the current `Timespec` of `raw_clock`.
    pub fn sys_clock_gettime(&self, raw_clock: u32) -> Result<Timespec, i64> {
        let clock = ClockId::from_raw(raw_clock).ok_or(EINVAL)?;
        Ok(Timespec::from_ns(self.read_clock_ns(clock)))
    }

    /// `sys_clock_getres`: Returns the resolution of `raw_clock`.
    pub fn sys_clock_getres(&self, raw_clock: u32) -> Result<Timespec, i64> {
        let clock = ClockId::from_raw(raw_clock).ok_or(EINVAL)?;
        match clock {
            ClockId::RealtimeCoarse | ClockId::MonotonicCoarse => Ok(Timespec::new(0, 1_000_000)), // 1 ms
            _ => Ok(Timespec::new(0, 1)), // 1 ns
        }
    }

    /// `sys_gettimeofday`: Returns legacy `Timeval` from `CLOCK_REALTIME`.
    pub fn sys_gettimeofday(&self) -> Timeval {
        let ns = self.read_clock_ns(ClockId::Realtime);
        Timeval {
            tv_sec: (ns / (NSEC_PER_SEC as u64)) as i64,
            tv_usec: ((ns % (NSEC_PER_SEC as u64)) / 1000) as i64,
        }
    }

    /// `sys_clock_nanosleep`: Sleeps until relative or absolute `request` on `raw_clock`.
    pub fn sys_clock_nanosleep(&mut self, raw_clock: u32, flags: u32, request: Timespec) -> i64 {
        if !request.is_valid() {
            return EINVAL;
        }
        let clock = match ClockId::from_raw(raw_clock) {
            Some(c) => c,
            None => return EINVAL,
        };
        let req_ns = request.to_ns();
        let now_ns = self.read_clock_ns(clock);
        let delta = if (flags & TIMER_ABSTIME) != 0 {
            req_ns.saturating_sub(now_ns)
        } else {
            req_ns
        };
        self.advance_time_ns(delta);
        0
    }

    /// `sys_nanosleep`: Relative sleep on `CLOCK_MONOTONIC`.
    pub fn sys_nanosleep(&mut self, req: Timespec) -> i64 {
        self.sys_clock_nanosleep(ClockId::Monotonic as u32, 0, req)
    }

    /// `sys_timer_create`: Creates a POSIX per-process interval timer.
    pub fn sys_timer_create(&mut self, raw_clock: u32) -> i64 {
        let clock = match ClockId::from_raw(raw_clock) {
            Some(c) => c,
            None => return EINVAL,
        };
        let id = self.next_timer_id;
        self.next_timer_id += 1;
        self.timers.push(ArmedTimer {
            id,
            clock,
            deadline_ns: 0,
            interval_ns: 0,
            overruns: 0,
            is_timerfd: false,
        });
        id as i64
    }

    /// `sys_timerfd_create`: Creates a file-descriptor-backed timer and arms it.
    pub fn sys_timerfd_create(&mut self, raw_clock: u32, spec: ItimerSpec) -> i64 {
        if !spec.it_value.is_valid() || !spec.it_interval.is_valid() {
            return EINVAL;
        }
        let clock = match ClockId::from_raw(raw_clock) {
            Some(c) => c,
            None => return EINVAL,
        };
        let now = self.read_clock_ns(clock);
        let val_ns = spec.it_value.to_ns();
        let id = self.next_timer_id;
        self.next_timer_id += 1;
        self.timers.push(ArmedTimer {
            id,
            clock,
            deadline_ns: if val_ns > 0 { now + val_ns } else { 0 },
            interval_ns: spec.it_interval.to_ns(),
            overruns: 0,
            is_timerfd: true,
        });
        id as i64
    }

    /// Reads the 64-bit expiration count from a `timerfd`.
    pub fn timerfd_read(&mut self, timer_id: u32) -> Result<u64, i64> {
        let t = self
            .timers
            .iter_mut()
            .find(|t| t.id == timer_id && t.is_timerfd)
            .ok_or(EINVAL)?;
        if t.overruns == 0 {
            return Err(EAGAIN);
        }
        let count = t.overruns;
        t.overruns = 0;
        Ok(count)
    }

    /// `sys_setitimer`: Configures an interval timer using microsecond `Timeval`s.
    pub fn sys_setitimer(&mut self, value: Timeval, interval: Timeval) -> i64 {
        if !value.is_valid() || !interval.is_valid() {
            return EINVAL;
        }
        let spec = ItimerSpec {
            it_value: Timespec::from_ns(value.to_ns()),
            it_interval: Timespec::from_ns(interval.to_ns()),
        };
        self.sys_timerfd_create(ClockId::Realtime as u32, spec)
    }
}

/// Runs comprehensive self-tests on `timers_clocks` structs and timer wheel expiration logic.
pub fn verify_domain_timers_clocks() -> u32 {
    let mut passed = 0u32;
    let mut wheel = KernelTimerWheel::new(1_700_000_000);

    // 1. Verify clock_getres for monotonic vs coarse clock
    if wheel.sys_clock_getres(ClockId::Monotonic as u32) == Ok(Timespec::new(0, 1))
        && wheel.sys_clock_getres(ClockId::MonotonicCoarse as u32) == Ok(Timespec::new(0, 1_000_000))
    {
        passed += 1;
    }

    // 2. Verify nanosleep advances monotonic clock
    if wheel.sys_nanosleep(Timespec::new(0, 50_000_000)) == 0 {
        if let Ok(ts) = wheel.sys_clock_gettime(ClockId::Monotonic as u32) {
            if ts.tv_nsec == 50_000_000 {
                passed += 1;
            }
        }
    }

    // 3. Create periodic timerfd with 10ms initial expiry and 10ms interval
    let spec = ItimerSpec {
        it_value: Timespec::new(0, 10_000_000),
        it_interval: Timespec::new(0, 10_000_000),
    };
    let tfd = wheel.sys_timerfd_create(ClockId::Monotonic as u32, spec) as u32;
    if tfd > 0 && wheel.timerfd_read(tfd) == Err(EAGAIN) {
        passed += 1;
    }

    // 4. Advance clock by 35ms -> timer should have expired 3 times
    let fired = wheel.advance_time_ns(35_000_000);
    if fired == 1 && wheel.timerfd_read(tfd) == Ok(3) {
        passed += 1;
    }

    // 5. Verify gettimeofday reflects realtime epoch + elapsed
    let tv = wheel.sys_gettimeofday();
    if tv.tv_sec == 1_700_000_000 && tv.tv_usec == 85_000 {
        passed += 1;
    }

    passed
}
