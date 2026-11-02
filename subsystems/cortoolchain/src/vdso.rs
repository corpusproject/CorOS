//! vDSO Shared Timekeeper Page & Fast User-Space Time (`vdso`)
//!
//! Provides seqlock-synchronized fast user-space `clock_gettime`, `gettimeofday`,
//! and `getcpu` without syscall overhead using calibrated TSC conversion.

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_MONOTONIC_RAW: u32 = 4;
pub const CLOCK_BOOTTIME: u32 = 7;

pub const VDSO_CLOCKMODE_TSC: u32 = 1;
pub const VDSO_CLOCKMODE_HPET: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdsoError {
    UnsupportedClock(u32),
    ClockModeDisabled,
    SeqlockContention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C, align(64))]
pub struct VdsoTimekeeperPage {
    pub seq: AtomicU32,
    pub clock_mode: u32,
    pub tsc_mult: u32,
    pub tsc_shift: u32,
    pub tsc_cycle_last: u64,
    pub real_sec: u64,
    pub real_nsec: u32,
    pub mono_sec: u64,
    pub mono_nsec: u32,
    pub boot_sec: u64,
    pub boot_nsec: u32,
    pub cpu_id: u32,
    pub numa_node: u32,
}

impl VdsoTimekeeperPage {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            clock_mode: VDSO_CLOCKMODE_TSC,
            tsc_mult: 0,
            tsc_shift: 0,
            tsc_cycle_last: 0,
            real_sec: 0,
            real_nsec: 0,
            mono_sec: 0,
            mono_nsec: 0,
            boot_sec: 0,
            boot_nsec: 0,
            cpu_id: 0,
            numa_node: 0,
        }
    }

    pub fn kernel_update_begin(&self) -> u32 {
        let prev = self.seq.fetch_add(1, Ordering::AcqRel);
        prev + 1
    }

    pub fn kernel_update_end(&self) {
        self.seq.fetch_add(1, Ordering::Release);
    }

    pub fn kernel_set_time(
        &mut self,
        real_sec: u64,
        real_nsec: u32,
        mono_sec: u64,
        mono_nsec: u32,
        tsc: u64,
        tsc_mult: u32,
        tsc_shift: u32,
    ) {
        self.kernel_update_begin();
        self.real_sec = real_sec;
        self.real_nsec = real_nsec;
        self.mono_sec = mono_sec;
        self.mono_nsec = mono_nsec;
        self.boot_sec = mono_sec;
        self.boot_nsec = mono_nsec;
        self.tsc_cycle_last = tsc;
        self.tsc_mult = tsc_mult;
        self.tsc_shift = tsc_shift;
        self.kernel_update_end();
    }

    pub fn vdso_clock_gettime(&self, clock_id: u32, current_tsc: u64) -> Result<TimeSpec, VdsoError> {
        if self.clock_mode != VDSO_CLOCKMODE_TSC {
            return Err(VdsoError::ClockModeDisabled);
        }

        let max_retries = 100;
        for _ in 0..max_retries {
            let s1 = self.seq.load(Ordering::Acquire);
            if (s1 & 1) != 0 {
                // Writer in progress, spin and retry
                core::hint::spin_loop();
                continue;
            }

            let tsc_last = self.tsc_cycle_last;
            let mult = self.tsc_mult;
            let shift = self.tsc_shift;

            let (sec, nsec) = match clock_id {
                CLOCK_REALTIME => (self.real_sec, self.real_nsec),
                CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW => (self.mono_sec, self.mono_nsec),
                CLOCK_BOOTTIME => (self.boot_sec, self.boot_nsec),
                other => return Err(VdsoError::UnsupportedClock(other)),
            };

            let s2 = self.seq.load(Ordering::Acquire);
            if s1 == s2 {
                // Consistent read achieved!
                let delta_tsc = current_tsc.saturating_sub(tsc_last);
                let delta_ns = ((delta_tsc as u128 * mult as u128) >> shift) as u64;

                let mut total_ns = nsec as u64 + delta_ns;
                let add_sec = total_ns / 1_000_000_000;
                total_ns %= 1_000_000_000;

                return Ok(TimeSpec {
                    tv_sec: (sec + add_sec) as i64,
                    tv_nsec: total_ns as i64,
                });
            }

            core::hint::spin_loop();
        }

        Err(VdsoError::SeqlockContention)
    }

    pub fn vdso_gettimeofday(&self, current_tsc: u64) -> Result<TimeVal, VdsoError> {
        let ts = self.vdso_clock_gettime(CLOCK_REALTIME, current_tsc)?;
        Ok(TimeVal {
            tv_sec: ts.tv_sec,
            tv_usec: ts.tv_nsec / 1000,
        })
    }

    pub fn vdso_getcpu(&self) -> (u32, u32) {
        (self.cpu_id, self.numa_node)
    }
}

pub fn verify_vdso() -> u32 {
    let mut check_count = 0u32;

    let mut page = VdsoTimekeeperPage::new();

    // Configure 3.0 GHz TSC parameters:
    // 1 TSC cycle = 1/3 ns = 0.333333 ns
    // mult = 349525, shift = 20 -> (1_000_000 * 349525) >> 20 = 333332.9 ns (~1/3 ms)
    let mult = 349525u32;
    let shift = 20u32;
    let base_tsc = 100_000_000u64;

    page.kernel_set_time(
        1700000000, // 2023-11-14 epoch
        500_000_000, // 0.5s
        120,        // 120s uptime
        250_000_000,
        base_tsc,
        mult,
        shift,
    );

    // Test 1: Realtime at exact baseline TSC
    let t0 = page.vdso_clock_gettime(CLOCK_REALTIME, base_tsc);
    if let Ok(ts) = t0 {
        if ts.tv_sec == 1700000000 && ts.tv_nsec == 500_000_000 {
            check_count += 1;
        }
    }

    // Test 2: Monotonic clock at baseline TSC
    let m0 = page.vdso_clock_gettime(CLOCK_MONOTONIC, base_tsc);
    if let Ok(ts) = m0 {
        if ts.tv_sec == 120 && ts.tv_nsec == 250_000_000 {
            check_count += 1;
        }
    }

    // Test 3: Interpolation after 3,000,000 TSC cycles (~1ms = 1_000_000 ns)
    let delta_cycles = 3_000_000u64;
    let t1 = page.vdso_clock_gettime(CLOCK_REALTIME, base_tsc + delta_cycles);
    if let Ok(ts) = t1 {
        // Delta ns = (3000000 * 349525) >> 20 = 999999 ns
        // Expect tv_nsec ~ 500_999_999
        let diff_ns = ts.tv_nsec - 500_000_000;
        if diff_ns >= 999_000 && diff_ns <= 1_001_000 {
            check_count += 1;
        }
    }

    // Test 4: TimeVal gettimeofday
    let tv_res = page.vdso_gettimeofday(base_tsc);
    if let Ok(tv) = tv_res {
        if tv.tv_sec == 1700000000 && tv.tv_usec == 500_000 {
            check_count += 1;
        }
    }

    // Test 5: getcpu
    page.cpu_id = 3;
    page.numa_node = 1;
    let (cpu, node) = page.vdso_getcpu();
    if cpu == 3 && node == 1 {
        check_count += 1;
    }

    // Test 6: Seqlock write detection
    // Simulate active kernel update
    page.seq.store(1, Ordering::Release); // odd sequence number
    let fail_res = page.vdso_clock_gettime(CLOCK_REALTIME, base_tsc);
    if fail_res == Err(VdsoError::SeqlockContention) {
        check_count += 1;
    }

    // Restore even sequence
    page.seq.store(2, Ordering::Release);
    let ok_res = page.vdso_clock_gettime(CLOCK_REALTIME, base_tsc);
    if ok_res.is_ok() {
        check_count += 1;
    }

    check_count
}
