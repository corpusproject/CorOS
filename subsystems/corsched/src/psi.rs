//! Pressure Stall Information (PSI).
//!
//! Implements CPU, memory, and I/O pressure accounting with:
//! - Dual-state tracking: `some` (at least one task stalled) and `full` (all non-idle tasks stalled)
//! - Nanosecond stall duration accumulation and microsecond conversion
//! - Exponential Moving Averages over 10-second, 60-second, and 300-second windows
//! - Configurable pressure event threshold triggers (e.g. for OOM prevention)
//! - Output formatting matching Linux `/proc/pressure/*` specifications

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// PSI monitored resource category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiResource {
    Cpu,
    Memory,
    Io,
}

/// Windowed pressure averages (in 1/100th of a percent, e.g. 1250 = 12.50%).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsiAverages {
    pub avg10: u32,
    pub avg60: u32,
    pub avg300: u32,
    pub total_us: u64,
}

impl PsiAverages {
    pub const fn zero() -> Self {
        Self {
            avg10: 0,
            avg60: 0,
            avg300: 0,
            total_us: 0,
        }
    }
}

/// Threshold trigger for pressure stall alerts.
#[derive(Debug, Clone)]
pub struct PsiTrigger {
    pub resource: PsiResource,
    pub is_full: bool,
    pub threshold_us: u64,
    pub window_ns: u64,
    pub last_event_ns: u64,
    pub fired_count: u64,
}

impl PsiTrigger {
    pub fn new(resource: PsiResource, is_full: bool, threshold_us: u64, window_ns: u64) -> Self {
        Self {
            resource,
            is_full,
            threshold_us,
            window_ns,
            last_event_ns: 0,
            fired_count: 0,
        }
    }
}

/// Accounting state for a single resource category.
#[derive(Debug, Clone)]
pub struct PsiResourceState {
    pub resource: PsiResource,
    pub stalled_some_tasks: u32,
    pub stalled_full_tasks: u32,
    pub some_stall_start_ns: u64,
    pub full_stall_start_ns: u64,
    pub total_some_ns: u64,
    pub total_full_ns: u64,
    pub some_averages: PsiAverages,
    pub full_averages: PsiAverages,
    pub last_decay_ns: u64,
}

impl PsiResourceState {
    pub fn new(resource: PsiResource) -> Self {
        Self {
            resource,
            stalled_some_tasks: 0,
            stalled_full_tasks: 0,
            some_stall_start_ns: 0,
            full_stall_start_ns: 0,
            total_some_ns: 0,
            total_full_ns: 0,
            some_averages: PsiAverages::zero(),
            full_averages: PsiAverages::zero(),
            last_decay_ns: 0,
        }
    }

    /// Record task entering a stall state.
    pub fn enter_stall(&mut self, is_full: bool, now_ns: u64) {
        if is_full {
            if self.stalled_full_tasks == 0 {
                self.full_stall_start_ns = now_ns;
            }
            self.stalled_full_tasks += 1;
        }

        if self.stalled_some_tasks == 0 {
            self.some_stall_start_ns = now_ns;
        }
        self.stalled_some_tasks += 1;
    }

    /// Record task exiting a stall state.
    pub fn exit_stall(&mut self, is_full: bool, now_ns: u64) {
        if is_full && self.stalled_full_tasks > 0 {
            self.stalled_full_tasks -= 1;
            if self.stalled_full_tasks == 0 && self.full_stall_start_ns > 0 {
                let delta = now_ns.saturating_sub(self.full_stall_start_ns);
                self.total_full_ns += delta;
                self.full_stall_start_ns = 0;
            }
        }

        if self.stalled_some_tasks > 0 {
            self.stalled_some_tasks -= 1;
            if self.stalled_some_tasks == 0 && self.some_stall_start_ns > 0 {
                let delta = now_ns.saturating_sub(self.some_stall_start_ns);
                self.total_some_ns += delta;
                self.some_stall_start_ns = 0;
            }
        }
    }

    /// Update windowed moving averages given elapsed physical time.
    pub fn update_averages(&mut self, now_ns: u64) {
        if self.last_decay_ns == 0 {
            self.last_decay_ns = now_ns;
            return;
        }

        let elapsed_ns = now_ns.saturating_sub(self.last_decay_ns);
        if elapsed_ns == 0 {
            return;
        }
        self.last_decay_ns = now_ns;

        // Add currently active stall duration
        let mut curr_some_ns = self.total_some_ns;
        if self.stalled_some_tasks > 0 && self.some_stall_start_ns > 0 {
            curr_some_ns += now_ns.saturating_sub(self.some_stall_start_ns);
        }

        let mut curr_full_ns = self.total_full_ns;
        if self.stalled_full_tasks > 0 && self.full_stall_start_ns > 0 {
            curr_full_ns += now_ns.saturating_sub(self.full_stall_start_ns);
        }

        self.some_averages.total_us = curr_some_ns / 1_000;
        self.full_averages.total_us = curr_full_ns / 1_000;

        // Calculate sample ratio (0..10,000 basis points)
        let some_pct = if elapsed_ns > 0 {
            ((curr_some_ns as u128 * 10_000) / (elapsed_ns as u128)).min(10_000) as u32
        } else {
            0
        };

        let full_pct = if elapsed_ns > 0 {
            ((curr_full_ns as u128 * 10_000) / (elapsed_ns as u128)).min(10_000) as u32
        } else {
            0
        };

        // Window decay approximations for 10s, 60s, 300s
        self.some_averages.avg10 = calc_ema(self.some_averages.avg10, some_pct, elapsed_ns, 10_000_000_000);
        self.some_averages.avg60 = calc_ema(self.some_averages.avg60, some_pct, elapsed_ns, 60_000_000_000);
        self.some_averages.avg300 = calc_ema(self.some_averages.avg300, some_pct, elapsed_ns, 300_000_000_000);

        self.full_averages.avg10 = calc_ema(self.full_averages.avg10, full_pct, elapsed_ns, 10_000_000_000);
        self.full_averages.avg60 = calc_ema(self.full_averages.avg60, full_pct, elapsed_ns, 60_000_000_000);
        self.full_averages.avg300 = calc_ema(self.full_averages.avg300, full_pct, elapsed_ns, 300_000_000_000);
    }
}

/// Compute Exponential Moving Average using fixed-point approximation:
/// $avg_{next} = avg_{prev} \times (1 - \alpha) + sample \times \alpha$ where $\alpha = \Delta t / (\tau + \Delta t)$.
fn calc_ema(prev_avg: u32, sample: u32, delta_ns: u64, window_ns: u64) -> u32 {
    let alpha_num = delta_ns as u128;
    let alpha_denom = (window_ns + delta_ns) as u128;

    let part1 = (prev_avg as u128) * (alpha_denom - alpha_num);
    let part2 = (sample as u128) * alpha_num;

    ((part1 + part2) / alpha_denom) as u32
}

/// PSI Pressure Stall Monitor managing CPU, Memory, and I/O tracking.
pub struct PsiMonitor {
    pub cpu: PsiResourceState,
    pub memory: PsiResourceState,
    pub io: PsiResourceState,
    pub triggers: Vec<PsiTrigger>,
}

impl PsiMonitor {
    pub fn new() -> Self {
        Self {
            cpu: PsiResourceState::new(PsiResource::Cpu),
            memory: PsiResourceState::new(PsiResource::Memory),
            io: PsiResourceState::new(PsiResource::Io),
            triggers: Vec::new(),
        }
    }

    /// Access resource state mutably.
    pub fn get_resource_mut(&mut self, res: PsiResource) -> &mut PsiResourceState {
        match res {
            PsiResource::Cpu => &mut self.cpu,
            PsiResource::Memory => &mut self.memory,
            PsiResource::Io => &mut self.io,
        }
    }

    /// Access resource state immutably.
    pub fn get_resource(&self, res: PsiResource) -> &PsiResourceState {
        match res {
            PsiResource::Cpu => &self.cpu,
            PsiResource::Memory => &self.memory,
            PsiResource::Io => &self.io,
        }
    }

    /// Register a pressure trigger threshold.
    pub fn register_trigger(&mut self, trigger: PsiTrigger) {
        self.triggers.push(trigger);
    }

    /// Update moving averages across all resources and evaluate triggers.
    pub fn update(&mut self, now_ns: u64) -> usize {
        self.cpu.update_averages(now_ns);
        self.memory.update_averages(now_ns);
        self.io.update_averages(now_ns);

        let mut triggered = 0;
        for trigger in &mut self.triggers {
            let total_us = match trigger.resource {
                PsiResource::Cpu => {
                    if trigger.is_full { self.cpu.full_averages.total_us } else { self.cpu.some_averages.total_us }
                }
                PsiResource::Memory => {
                    if trigger.is_full { self.memory.full_averages.total_us } else { self.memory.some_averages.total_us }
                }
                PsiResource::Io => {
                    if trigger.is_full { self.io.full_averages.total_us } else { self.io.some_averages.total_us }
                }
            };

            if total_us >= trigger.threshold_us && now_ns.saturating_sub(trigger.last_event_ns) >= trigger.window_ns {
                trigger.last_event_ns = now_ns;
                trigger.fired_count += 1;
                triggered += 1;
            }
        }

        triggered
    }

    /// Format pressure string for a resource matching Linux `/proc/pressure/*`.
    pub fn format_pressure(&self, res: PsiResource) -> String {
        use alloc::format;

        let state = self.get_resource(res);
        let some = state.some_averages;
        let full = state.full_averages;

        if res == PsiResource::Cpu {
            // CPU pressure only outputs "some" in Linux specification
            format!(
                "some avg10={}.{:02} avg60={}.{:02} avg300={}.{:02} total={}\n",
                some.avg10 / 100, some.avg10 % 100,
                some.avg60 / 100, some.avg60 % 100,
                some.avg300 / 100, some.avg300 % 100,
                some.total_us,
            )
        } else {
            format!(
                "some avg10={}.{:02} avg60={}.{:02} avg300={}.{:02} total={}\nfull avg10={}.{:02} avg60={}.{:02} avg300={}.{:02} total={}\n",
                some.avg10 / 100, some.avg10 % 100,
                some.avg60 / 100, some.avg60 % 100,
                some.avg300 / 100, some.avg300 % 100,
                some.total_us,
                full.avg10 / 100, full.avg10 % 100,
                full.avg60 / 100, full.avg60 % 100,
                full.avg300 / 100, full.avg300 % 100,
                full.total_us,
            )
        }
    }
}
