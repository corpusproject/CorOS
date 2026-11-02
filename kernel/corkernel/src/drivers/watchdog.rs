//! Hardware Watchdog Timers & NMI Lockup Detector
//!
//! Bare-metal no_std pure Rust driver for hardware safety timers:
//! - Intel TCO (Total Cost of Ownership) Watchdog Timer (PCH / LPC I/O space)
//! - Hardware Watchdog feeding engine to prevent unexpected hardware resets
//! - Local APIC NMI Watchdog to detect kernel lockups / deadlocks in interrupt-disabled critical sections

#![allow(dead_code)]

use crate::arch::x86_64::cpu::{in16, out16, in8, out8};

pub const TCO_BASE_DEFAULT: u16 = 0x460;

// Intel TCO I/O Registers
pub const TCO1_RLD: u16 = 0x00;  // Reload Timer
pub const TCO1_TMR: u16 = 0x01;  // Timer Initial Value
pub const TCO1_DAT_IN: u16 = 0x02;
pub const TCO1_DAT_OUT: u16 = 0x03;
pub const TCO1_STS: u16 = 0x04;  // Status
pub const TCO2_STS: u16 = 0x06;
pub const TCO1_CNT: u16 = 0x08;  // Control (bit 11 = TMR_HLT)
pub const TCO2_CNT: u16 = 0x0A;

/// Hardware Watchdog Driver
pub struct HardwareWatchdog {
    pub tco_base: u16,
    pub timeout_seconds: u32,
    pub is_running: bool,
    pub last_pet_tick: u64,
}

impl HardwareWatchdog {
    pub fn new(timeout_seconds: u32) -> Self {
        Self {
            tco_base: TCO_BASE_DEFAULT,
            timeout_seconds,
            is_running: false,
            last_pet_tick: 0,
        }
    }

    /// Arm and start the hardware watchdog timer
    pub fn start(&mut self) {
        unsafe {
            // Set timeout value in ticks (approx 0.6 seconds per tick on Intel PCH)
            let ticks = (self.timeout_seconds * 10 / 6) as u8;
            out8(self.tco_base + TCO1_TMR, ticks);

            // Reload timer
            out16(self.tco_base + TCO1_RLD, 0x01);

            // Clear halt bit in TCO1_CNT (bit 11: 0 = running, 1 = halted)
            let mut cnt = in16(self.tco_base + TCO1_CNT);
            cnt &= !(1 << 11);
            out16(self.tco_base + TCO1_CNT, cnt);

            self.is_running = true;
        }
    }

    /// Pet / Kick the watchdog to reload timer counter and prevent reboot
    pub fn pet(&mut self, current_tick: u64) {
        if self.is_running {
            unsafe {
                out16(self.tco_base + TCO1_RLD, 0x01);
            }
            self.last_pet_tick = current_tick;
        }
    }

    /// Stop the watchdog timer (e.g. before graceful system shutdown)
    pub fn stop(&mut self) {
        if self.is_running {
            unsafe {
                let mut cnt = in16(self.tco_base + TCO1_CNT);
                cnt |= 1 << 11; // Set TCO_TMR_HLT
                out16(self.tco_base + TCO1_CNT, cnt);
            }
            self.is_running = false;
        }
    }
}

/// NMI Lockup Detector State
pub struct NmiLockupDetector {
    pub last_heartbeat_tsc: u64,
    pub max_lockup_cycles: u64,
    pub lockup_detected: bool,
}

impl NmiLockupDetector {
    pub fn new(tsc_frequency: u64) -> Self {
        Self {
            last_heartbeat_tsc: 0,
            max_lockup_cycles: tsc_frequency * 5, // 5 seconds threshold
            lockup_detected: false,
        }
    }

    /// Heartbeat signal called from the regular timer interrupt
    pub fn heartbeat(&mut self, current_tsc: u64) {
        self.last_heartbeat_tsc = current_tsc;
    }

    /// Evaluated inside the NMI handler to verify if timer IRQ has stalled
    pub fn check_for_lockup(&mut self, current_tsc: u64) -> bool {
        if current_tsc > self.last_heartbeat_tsc {
            let elapsed = current_tsc - self.last_heartbeat_tsc;
            if elapsed > self.max_lockup_cycles {
                self.lockup_detected = true;
                return true;
            }
        }
        false
    }
}
