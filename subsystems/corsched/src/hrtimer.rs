//! Nanosecond High-Resolution Timers (hrtimers).
//!
//! Implements nanosecond-precision kernel timers with:
//! - Support for multiple clock bases (`CLOCK_MONOTONIC`, `CLOCK_REALTIME`, `CLOCK_BOOTTIME`)
//! - Absolute, relative, and pinned timer programming modes
//! - Min-deadline sorted timer queue with early-event dispatch
//! - Periodic auto-restarting timers with overrun count calculation (`forward_timer`)
//! - Safe cancellation and next hardware interrupt deadline querying

extern crate alloc;

use alloc::vec::Vec;

pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_REALTIME: u32 = 2;
pub const CLOCK_BOOTTIME: u32 = 3;

/// Timer programming mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrTimerMode {
    Absolute,
    Relative,
    Pinned,
}

/// Execution state of a high-resolution timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrTimerState {
    Inactive,
    Enqueued,
    Running,
    Expired,
}

/// Action returned by a timer callback upon expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrTimerRestart {
    NoRestart,
    Restart,
}

/// High-resolution nanosecond timer structure.
#[derive(Debug, Clone)]
pub struct HrTimer {
    pub id: u64,
    pub expires_ns: u64,
    pub interval_ns: u64,
    pub clock_id: u32,
    pub mode: HrTimerMode,
    pub state: HrTimerState,
    pub func: fn(u64) -> HrTimerRestart,
    pub arg: u64,
    pub cpu_id: u32,
    pub overruns: u64,
}

impl HrTimer {
    pub fn new(id: u64, clock_id: u32, func: fn(u64) -> HrTimerRestart, arg: u64) -> Self {
        Self {
            id,
            expires_ns: 0,
            interval_ns: 0,
            clock_id,
            mode: HrTimerMode::Absolute,
            state: HrTimerState::Inactive,
            func,
            arg,
            cpu_id: 0,
            overruns: 0,
        }
    }
}

/// High-resolution timer queue managing sorted timer lists per CPU.
pub struct HrTimerQueue {
    pub timers: Vec<HrTimer>,
    pub cpu_id: u32,
    pub total_expired: u64,
}

impl HrTimerQueue {
    pub fn new(cpu_id: u32) -> Self {
        Self {
            timers: Vec::new(),
            cpu_id,
            total_expired: 0,
        }
    }

    /// Insert or start a timer with an expiration timestamp.
    pub fn start_timer(&mut self, mut timer: HrTimer, time_ns: u64, mode: HrTimerMode, now_ns: u64) {
        let abs_expires = match mode {
            HrTimerMode::Absolute => time_ns,
            HrTimerMode::Relative | HrTimerMode::Pinned => now_ns.saturating_add(time_ns),
        };

        timer.expires_ns = abs_expires;
        timer.mode = mode;
        timer.state = HrTimerState::Enqueued;
        timer.cpu_id = self.cpu_id;

        // Remove existing timer with same ID if present
        if let Some(pos) = self.timers.iter().position(|t| t.id == timer.id) {
            self.timers.remove(pos);
        }

        // Insert maintaining sorted order by expires_ns
        let insert_idx = self.timers.partition_point(|t| t.expires_ns <= timer.expires_ns);
        self.timers.insert(insert_idx, timer);
    }

    /// Cancel a timer by ID.
    pub fn cancel_timer(&mut self, id: u64) -> bool {
        if let Some(pos) = self.timers.iter().position(|t| t.id == id) {
            self.timers.remove(pos);
            true
        } else {
            false
        }
    }

    /// Forward a periodic timer past `now_ns` and compute overrun count.
    pub fn forward_timer(&mut self, id: u64, now_ns: u64, interval_ns: u64) -> u64 {
        if interval_ns == 0 {
            return 0;
        }

        if let Some(timer) = self.timers.iter_mut().find(|t| t.id == id) {
            if now_ns < timer.expires_ns {
                return 0;
            }

            let delta = now_ns - timer.expires_ns;
            let overruns = (delta / interval_ns) + 1;
            timer.expires_ns = timer.expires_ns.saturating_add(overruns * interval_ns);
            timer.interval_ns = interval_ns;
            timer.overruns += overruns;
            overruns
        } else {
            0
        }
    }

    /// Return the earliest pending deadline in nanoseconds, if any.
    pub fn next_expiry_ns(&self) -> Option<u64> {
        self.timers.first().map(|t| t.expires_ns)
    }

    /// Run all expired timers whose `expires_ns <= now_ns`.
    pub fn run_expired_timers(&mut self, now_ns: u64) -> usize {
        let mut expired_timers = Vec::new();

        // Partition expired timers
        while let Some(timer) = self.timers.first() {
            if timer.expires_ns <= now_ns {
                expired_timers.push(self.timers.remove(0));
            } else {
                break;
            }
        }

        let count = expired_timers.len();
        let mut to_requeue = Vec::new();

        for mut timer in expired_timers {
            timer.state = HrTimerState::Running;
            let restart = (timer.func)(timer.arg);

            if restart == HrTimerRestart::Restart && timer.interval_ns > 0 {
                // Forward periodic timer
                let delta = now_ns.saturating_sub(timer.expires_ns);
                let overruns = (delta / timer.interval_ns) + 1;
                timer.expires_ns = timer.expires_ns.saturating_add(overruns * timer.interval_ns);
                timer.overruns += overruns;
                timer.state = HrTimerState::Enqueued;
                to_requeue.push(timer);
            }
        }

        // Requeue periodic timers in sorted position
        for timer in to_requeue {
            let insert_idx = self.timers.partition_point(|t| t.expires_ns <= timer.expires_ns);
            self.timers.insert(insert_idx, timer);
        }

        self.total_expired += count as u64;
        count
    }
}
