//! TSC provides raw cycle observations; a masked-by-default PIT IRQ path gives
//! monotonic kernel ticks when explicitly initialized by the boot path.
use core::{arch::asm, sync::atomic::{AtomicU64, Ordering}};
use crate::arch::x86_64::{cpu, interrupts::{self, IrqHandler}};

static PIT_TICKS: AtomicU64 = AtomicU64::new(0);
pub const PIT_HZ_NOMINAL: u64 = 100;
const PIT_INPUT_HZ_NOMINAL: u64 = 1_193_182;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerInitError { Irq(interrupts::RegisterError), PicUnavailable }

extern "efiapi" fn pit_irq(_frame: &crate::arch::x86_64::idt::ExceptionFrame) {
    PIT_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Configure channel 0 at approximately 100 Hz and enable only IRQ0. The PIC
/// must already be remapped/masked; IDT vector 32 must be loaded.
/// # Safety
/// Invoke with interrupts disabled after IDT setup, before intentionally enabling IF.
pub unsafe fn initialize_pit_irq() -> Result<(), TimerInitError> {
    // Fail before consuming the one-shot IRQ registration if the legacy PIC
    // cannot route IRQ0. Caller keeps interrupts disabled during setup.
    if !crate::arch::x86_64::pic::is_active() { return Err(TimerInitError::PicUnavailable); }
    let divisor = (PIT_INPUT_HZ_NOMINAL / PIT_HZ_NOMINAL) as u16;
    unsafe { interrupts::register_pic_irq(32, pit_irq as IrqHandler) }.map_err(TimerInitError::Irq)?;
    unsafe {
        cpu::out8(0x43, 0x36);
        cpu::out8(0x40, divisor as u8);
        cpu::out8(0x40, (divisor >> 8) as u8);
        if !crate::arch::x86_64::pic::unmask(0) { return Err(TimerInitError::PicUnavailable); }
    }
    Ok(())
}

pub fn monotonic_ticks() -> u64 { PIT_TICKS.load(Ordering::Acquire) }
pub const fn ticks_to_ns(ticks: u64) -> Option<u64> {
    match ticks.checked_mul(1_000_000_000) {
        Some(n) => Some(n / PIT_HZ_NOMINAL),
        None => None,
    }
}
pub fn monotonic_time_ns() -> Option<u64> { ticks_to_ns(monotonic_ticks()) }
pub fn uptime_seconds() -> u64 { monotonic_ticks() / PIT_HZ_NOMINAL }

static APIC_TICKS: AtomicU64 = AtomicU64::new(0);
pub static CPU_FREQ_MHZ: AtomicU64 = AtomicU64::new(0);

extern "efiapi" fn apic_timer_irq(_frame: &crate::arch::x86_64::idt::ExceptionFrame) {
    APIC_TICKS.fetch_add(1, Ordering::Relaxed);
    crate::task::SCHEDULER.tick_preempt();
}

pub fn apic_ticks() -> u64 {
    APIC_TICKS.load(Ordering::Relaxed)
}

pub unsafe fn initialize_apic_timer(vector: u8) -> Result<(), interrupts::RegisterError> {
    interrupts::register_apic_irq(vector, interrupts::InterruptSource::LocalApicTimer, apic_timer_irq as IrqHandler)?;
    Ok(())
}

pub fn detect_cpu_frequency_mhz() -> u64 {
    let cached = CPU_FREQ_MHZ.load(Ordering::Acquire);
    if cached > 0 {
        return cached;
    }

    let max = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    if max >= 0x16 {
        let leaf16 = unsafe { core::arch::x86_64::__cpuid(0x16) };
        let base_mhz = leaf16.eax as u64;
        if base_mhz > 0 {
            CPU_FREQ_MHZ.store(base_mhz, Ordering::Release);
            return base_mhz;
        }
    }

    let fallback = 2600;
    CPU_FREQ_MHZ.store(fallback, Ordering::Release);
    fallback
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerTicks(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonotonicTime { pub ticks: TimerTicks, pub frequency_hz: Option<u64> }
pub trait TimerSource { fn now(&self) -> MonotonicTime; }

pub struct TscCounter { frequency_hz: Option<u64> }
impl TscCounter {
    pub fn detect() -> Option<Self> {
        let max = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
        if max < 0x8000_0007 { return None; }
        let features = unsafe { core::arch::x86_64::__cpuid(0x8000_0007) }.edx;
        if features & (1 << 8) == 0 { return None; }
        Some(Self { frequency_hz: None })
    }
    #[inline]
    pub fn read_ticks() -> TimerTicks {
        let low: u32; let high: u32;
        unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack)); }
        TimerTicks(((high as u64) << 32) | low as u64)
    }
}
impl TimerSource for TscCounter { fn now(&self) -> MonotonicTime { MonotonicTime { ticks: Self::read_ticks(), frequency_hz: self.frequency_hz } } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn nominal_tick_conversion_is_monotonic_and_checked() {
        assert_eq!(ticks_to_ns(0), Some(0));
        assert_eq!(ticks_to_ns(1), Some(10_000_000));
        assert_eq!(ticks_to_ns(100), Some(1_000_000_000));
        assert!(ticks_to_ns(u64::MAX).is_none());
        assert!(PIT_INPUT_HZ_NOMINAL / PIT_HZ_NOMINAL > 0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub weekday: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl RtcDateTime {
    pub fn month_str(&self) -> &'static str {
        match self.month {
            1 => "Oca",
            2 => "Sub",
            3 => "Mar",
            4 => "Nis",
            5 => "May",
            6 => "Haz",
            7 => "Tem",
            8 => "Agu",
            9 => "Eyl",
            10 => "Eki",
            11 => "Kas",
            12 => "Ara",
            _ => "Oca",
        }
    }

    pub fn weekday_str(&self) -> &'static str {
        // Sakamoto's algorithm for Gregorian day of week: 0 = Paz, 1 = Pzt, ..., 6 = Cmt
        let t = [0i32, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
        let mut y = self.year as i32;
        if self.month < 3 {
            y -= 1;
        }
        let m_idx = (self.month.saturating_sub(1) as usize).min(11);
        let dow = ((y + y / 4 - y / 100 + y / 400 + t[m_idx] + self.day as i32) % 7 + 7) % 7;
        match dow {
            0 => "Paz",
            1 => "Pzt",
            2 => "Sal",
            3 => "Car",
            4 => "Per",
            5 => "Cum",
            6 => "Cmt",
            _ => "Cmt",
        }
    }

    pub fn format_string(&self) -> alloc::string::String {
        alloc::format!(
            "{:02} {} {} {:02}:{:02}",
            self.day,
            self.month_str(),
            self.weekday_str(),
            self.hour,
            self.minute
        )
    }
}

pub fn read_rtc() -> RtcDateTime {
    unsafe {
        for _ in 0..10_000 {
            cpu::out8(0x70, 0x0A);
            if cpu::in8(0x71) & 0x80 == 0 {
                break;
            }
            cpu::pause();
        }

        let mut read_reg = |reg: u8| -> u8 {
            cpu::out8(0x70, reg);
            cpu::in8(0x71)
        };

        let mut sec = read_reg(0x00);
        let mut min = read_reg(0x02);
        let mut hour = read_reg(0x04);
        let weekday = read_reg(0x06);
        let mut day = read_reg(0x07);
        let mut month = read_reg(0x08);
        let mut year = read_reg(0x09);
        let reg_b = read_reg(0x0B);

        if (reg_b & 0x04) == 0 {
            let from_bcd = |v: u8| ((v >> 4) * 10) + (v & 0x0F);
            sec = from_bcd(sec);
            min = from_bcd(min);
            hour = ((hour & 0x0F) + (((hour & 0x70) >> 4) * 10)) | (hour & 0x80);
            day = from_bcd(day);
            month = from_bcd(month);
            year = from_bcd(year);
        }

        if (reg_b & 0x02) == 0 && (hour & 0x80) != 0 {
            hour = ((hour & 0x7F) + 12) % 24;
        }

        let hour_tr = (hour + 3) % 24;
        let final_year = if year > 0 && year < 100 { 2000 + (year as u16) } else { 2026 };
        let final_month = if month >= 1 && month <= 12 { month } else { 10 };
        let final_day = if day >= 1 && day <= 31 { day } else { 10 };
        let final_weekday = if weekday >= 1 && weekday <= 7 { weekday } else { 7 };

        RtcDateTime {
            year: final_year,
            month: final_month,
            day: final_day,
            weekday: final_weekday,
            hour: hour_tr,
            minute: min.clamp(0, 59),
            second: sec.clamp(0, 59),
        }
    }
}
