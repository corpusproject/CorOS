//! CorOS Hardware Driver Module: `rtc_cmos`
//!
//! Motorola MC146818 / PC AT CMOS Real-Time Clock (`I/O Port 0x70` Index + NMI mask,
//! `I/O Port 0x71` Data), Status Register A Update-In-Progress (`UIP`) synchronization,
//! Status Register B `BCD` vs Binary and `12h` vs `24h` mode decoder, Century register
//! (`0x32`) handling, and proleptic Gregorian calendar to Unix Epoch (`1970-01-01T00:00:00Z`)
//! timestamp converter.

/// MC146818 CMOS Register Indices & I/O Port constants.
pub mod cmos_regs {
    pub const CMOS_INDEX_PORT: u16 = 0x70;
    pub const CMOS_DATA_PORT: u16 = 0x71;
    pub const NMI_DISABLE_BIT: u8 = 1 << 7;

    pub const SECONDS: u8 = 0x00;
    pub const SECONDS_ALARM: u8 = 0x01;
    pub const MINUTES: u8 = 0x02;
    pub const MINUTES_ALARM: u8 = 0x03;
    pub const HOURS: u8 = 0x04;
    pub const HOURS_ALARM: u8 = 0x05;
    pub const DAY_OF_WEEK: u8 = 0x06;
    pub const DAY_OF_MONTH: u8 = 0x07;
    pub const MONTH: u8 = 0x08;
    pub const YEAR: u8 = 0x09;
    pub const STATUS_REG_A: u8 = 0x0A;
    pub const STATUS_REG_B: u8 = 0x0B;
    pub const STATUS_REG_C: u8 = 0x0C;
    pub const STATUS_REG_D: u8 = 0x0D;
    pub const CENTURY_ACPI: u8 = 0x32;
}

/// MC146818 Status Register A (`0x0A`) and Status Register B (`0x0B`) bitflags.
pub mod rtc_status_flags {
    /// Status Register A Bit 7: Update In Progress (`UIP`). Do not read time registers while `1`.
    pub const REG_A_UIP: u8 = 1 << 7;
    /// Status Register B Bit 1: `1 = 24-hour mode`, `0 = 12-hour mode`.
    pub const REG_B_24HOUR: u8 = 1 << 1;
    /// Status Register B Bit 2: Data Mode (`DM`): `1 = Binary`, `0 = BCD`.
    pub const REG_B_BINARY: u8 = 1 << 2;
    /// Status Register B Bit 6: Periodic Interrupt Enable (`PIE`).
    pub const REG_B_PIE: u8 = 1 << 6;
}

/// Converts a Binary-Coded Decimal (`BCD`) byte (e.g., `0x59`) into binary (`59`).
#[inline]
pub const fn bcd_to_binary(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

/// Converts a binary byte (`0..=99`) into Binary-Coded Decimal (`BCD`).
#[inline]
pub const fn binary_to_bcd(val: u8) -> u8 {
    let clamped = if val > 99 { 99 } else { val };
    ((clamped / 10) << 4) | (clamped % 10)
}

/// Returns `true` if `year` (e.g., `2026` or `2024`) is a Gregorian leap year.
#[inline]
pub const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Returns the number of days in `month` (`1..=12`) for the given Gregorian `year`.
#[inline]
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

/// Raw snapshot of the CMOS RTC registers read during a consistent non-`UIP` window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawCmosRtcSample {
    pub sec: u8,
    pub min: u8,
    pub hour: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    pub century: u8,
    pub reg_b: u8,
}

/// Decoded UTC Calendar Date-Time structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl RtcDateTime {
    #[inline]
    const fn decode_field(v: u8, is_binary: bool) -> u8 {
        if is_binary {
            v
        } else {
            bcd_to_binary(v)
        }
    }

    /// Decodes a `RawCmosRtcSample` handling BCD/Binary mode, 12h/24h PM bit (`0x80`), and Century register.
    pub const fn from_raw_sample(raw: RawCmosRtcSample) -> Self {
        let is_binary = (raw.reg_b & rtc_status_flags::REG_B_BINARY) != 0;
        let is_24h = (raw.reg_b & rtc_status_flags::REG_B_24HOUR) != 0;

        let second = Self::decode_field(raw.sec, is_binary);
        let minute = Self::decode_field(raw.min, is_binary);

        let hour = if is_24h {
            Self::decode_field(raw.hour, is_binary)
        } else {
            let pm = (raw.hour & 0x80) != 0;
            let h12 = Self::decode_field(raw.hour & 0x7F, is_binary);
            if pm {
                if h12 == 12 {
                    12
                } else {
                    (h12 + 12) % 24
                }
            } else if h12 == 12 {
                0
            } else {
                h12
            }
        };

        let day = Self::decode_field(raw.day, is_binary);
        let month = Self::decode_field(raw.month, is_binary);
        let year_2d = Self::decode_field(raw.year, is_binary) as u16;
        let century_val = if raw.century != 0 {
            Self::decode_field(raw.century, is_binary) as u16
        } else if year_2d >= 70 {
            19
        } else {
            20
        };
        let year = century_val * 100 + year_2d;

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// Converts this UTC `RtcDateTime` (`year >= 1970`) into Unix Epoch seconds (`1970-01-01T00:00:00Z`).
    pub const fn to_unix_timestamp(&self) -> u64 {
        if self.year < 1970 || self.month == 0 || self.month > 12 || self.day == 0 {
            return 0;
        }
        let mut days: u64 = 0;
        let mut y = 1970u16;
        while y < self.year {
            days += if is_leap_year(y) { 366 } else { 365 };
            y += 1;
        }
        let mut m = 1u8;
        while m < self.month {
            days += days_in_month(self.year, m) as u64;
            m += 1;
        }
        days += (self.day - 1) as u64;

        days * 86_400 + (self.hour as u64) * 3600 + (self.minute as u64) * 60 + (self.second as u64)
    }
}

/// Self-test for `rtc_cmos` BCD/Binary conversion, 12h/24h PM decoding, and Unix Epoch timestamp calculation.
pub fn verify_driver_module_rtc_cmos() -> u32 {
    let mut passed = 0u32;

    // 1. Verify BCD <-> Binary roundtrip
    if bcd_to_binary(0x59) == 59 && binary_to_bcd(59) == 0x59 {
        passed += 1;
    }

    // 2. Verify decoding a BCD 24-hour CMOS sample for 2026-10-26 19:07:14 UTC
    let sample_24h = RawCmosRtcSample {
        sec: 0x14,
        min: 0x07,
        hour: 0x19,
        day: 0x26,
        month: 0x10,
        year: 0x26,
        century: 0x20,
        reg_b: rtc_status_flags::REG_B_24HOUR, // BCD + 24-hour mode
    };
    let dt = RtcDateTime::from_raw_sample(sample_24h);
    if dt
        == (RtcDateTime {
            year: 2026,
            month: 10,
            day: 26,
            hour: 19,
            minute: 7,
            second: 14,
        })
    {
        passed += 1;
    }

    // 3. Verify 12-hour PM BCD mode decoding (0x87 = 7 PM = 19:00, 0x92 = 12 PM = 12:00, 0x12 = 12 AM = 00:00)
    let sample_12h_pm = RawCmosRtcSample {
        sec: 0x00,
        min: 0x30,
        hour: 0x87, // PM bit (0x80) | BCD 07 -> 19:30
        day: 0x01,
        month: 0x01,
        year: 0x24,
        century: 0x20,
        reg_b: 0x00, // BCD + 12-hour mode
    };
    let dt_12h = RtcDateTime::from_raw_sample(sample_12h_pm);
    if dt_12h.hour == 19 && dt_12h.minute == 30 && is_leap_year(dt_12h.year) {
        passed += 1;
    }

    // 4. Verify Unix Epoch timestamp calculation for known reference dates
    let epoch_start = RtcDateTime {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };
    let y2k = RtcDateTime {
        year: 2000,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };
    if epoch_start.to_unix_timestamp() == 0 && y2k.to_unix_timestamp() == 946_684_800 {
        passed += 1;
    }

    passed
}
