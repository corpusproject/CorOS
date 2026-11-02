//! Motorola MC146818 Real-Time Clock (RTC) & CMOS Driver for CorOS.
//! 100% in-house implementation supporting:
//! - Hardware RTC register querying via I/O ports 0x70 & 0x71
//! - Update-In-Progress (UIP) polling to prevent reading tearing
//! - BCD (Binary Coded Decimal) to Binary integer translation
//! - 12-hour AM/PM to 24-hour mode normalization
//! - ACPI Century register (0x32) detection for year >= 2000

use crate::arch::x86_64::cpu;
use alloc::format;
use alloc::string::String;

pub const CMOS_PORT_INDEX: u16 = 0x70;
pub const CMOS_PORT_DATA: u16  = 0x71;

// RTC Registers
pub const RTC_REG_SECONDS: u8  = 0x00;
pub const RTC_REG_MINUTES: u8  = 0x02;
pub const RTC_REG_HOURS: u8    = 0x04;
pub const RTC_REG_DAY: u8      = 0x07;
pub const RTC_REG_MONTH: u8    = 0x08;
pub const RTC_REG_YEAR: u8     = 0x09;
pub const RTC_REG_STATUS_A: u8 = 0x0A;
pub const RTC_REG_STATUS_B: u8 = 0x0B;
pub const RTC_REG_CENTURY: u8  = 0x32; // Optional ACPI century register

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SystemTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl SystemTime {
    pub fn format_iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    pub fn format_short(&self) -> String {
        format!("{:02}:{:02} {:02}.{:02}.{:04}", self.hour, self.minute, self.day, self.month, self.year)
    }
}

pub struct RtcDriver;

impl RtcDriver {
    /// Read a single byte from a CMOS register.
    pub unsafe fn read_reg(reg: u8) -> u8 {
        cpu::out8(CMOS_PORT_INDEX, reg);
        cpu::in8(CMOS_PORT_DATA)
    }

    /// Check if RTC is currently updating internal registers (Status A bit 7).
    pub unsafe fn is_updating() -> bool {
        (Self::read_reg(RTC_REG_STATUS_A) & 0x80) != 0
    }

    /// Read raw CMOS time values safely by waiting until no update is in progress.
    pub unsafe fn read_raw_time() -> SystemTime {
        // Wait until RTC update cycle finishes
        while Self::is_updating() {
            core::hint::spin_loop();
        }

        let mut second = Self::read_reg(RTC_REG_SECONDS);
        let mut minute = Self::read_reg(RTC_REG_MINUTES);
        let mut hour = Self::read_reg(RTC_REG_HOURS);
        let mut day = Self::read_reg(RTC_REG_DAY);
        let mut month = Self::read_reg(RTC_REG_MONTH);
        let mut year = Self::read_reg(RTC_REG_YEAR) as u16;
        let century = Self::read_reg(RTC_REG_CENTURY);

        let status_b = Self::read_reg(RTC_REG_STATUS_B);
        let is_bcd = (status_b & 0x04) == 0;
        let is_24h = (status_b & 0x02) != 0;

        // Convert BCD to binary if required
        if is_bcd {
            second = ((second / 16) * 10) + (second & 0x0F);
            minute = ((minute / 16) * 10) + (minute & 0x0F);
            hour = (((hour & 0x7F) / 16) * 10) + (hour & 0x0F);
            day = ((day / 16) * 10) + (day & 0x0F);
            month = ((month / 16) * 10) + (month & 0x0F);
            year = ((year / 16) * 10) + (year & 0x0F);
        }

        // Convert 12h to 24h if necessary
        if !is_24h && (hour & 0x80) != 0 {
            hour = ((hour & 0x7F) + 12) % 24;
        }

        // Calculate 4-digit full year
        if century != 0 {
            let cent = if is_bcd { ((century / 16) * 10) + (century & 0x0F) } else { century };
            year += (cent as u16) * 100;
        } else {
            // Assume 2000s
            year += 2000;
        }

        SystemTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}
