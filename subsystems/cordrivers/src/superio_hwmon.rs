//! CorOS Hardware Driver Module: `superio_hwmon`
//!
//! Nuvoton NCT6775 / NCT6776 / NCT6779 and ITE IT8728 LPC Super I/O Hardware Monitor
//! register bank state machine, ADC voltage rail scaling (`Vcore`, `+12V`, `+5V`,
//! `+3.3V`, `Vbat`), 9-bit `0.5 °C` PECI/Thermistor temperature sensor decoder,
//! Tachometer fan pulse-period-to-RPM converter, and PWM fan thermal curve controller.

/// LPC Super I/O Configuration Port constants.
pub mod superio_ports {
    pub const CFG_PORT_2E: u16 = 0x2E;
    pub const CFG_PORT_4E: u16 = 0x4E;
    pub const NUVOTON_EXT_MODE_KEY: u8 = 0x87;
    pub const NUVOTON_EXIT_MODE_KEY: u8 = 0xAA;
    pub const REG_CHIP_ID_HIGH: u8 = 0x20;
    pub const REG_CHIP_ID_LOW: u8 = 0x21;
    pub const REG_LOGICAL_DEVICE_NUMBER: u8 = 0x07;
    pub const LDN_HWMON_NUVOTON: u8 = 0x0B;
}

/// Known Nuvoton & ITE Super I/O 16-bit Chip IDs (`CR20:CR21`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperIoChipModel {
    NuvotonNct6775F,
    NuvotonNct6776F,
    NuvotonNct6779D,
    NuvotonNct6791D,
    IteIt8728F,
    IteIt8688E,
    Unknown(u16),
}

impl SuperIoChipModel {
    #[inline]
    pub const fn identify(chip_id: u16) -> Self {
        match chip_id & 0xFFF0 {
            0xB470 => Self::NuvotonNct6775F,
            0xC330 => Self::NuvotonNct6776F,
            0xC560 => Self::NuvotonNct6779D,
            0xC800 => Self::NuvotonNct6791D,
            0x8728 => Self::IteIt8728F,
            0x8688 => Self::IteIt8688E,
            _ => Self::Unknown(chip_id),
        }
    }
}

/// Nuvoton NCT6775 Banked Hardware Monitor Register Address (`(bank << 8) | reg`).
pub mod nct6775_hwmon_regs {
    pub const BANK_SELECT: u8 = 0x4E;
    /// Bank 0: Voltage readings (`8 mV` LSB raw ADC).
    pub const VCORE_ADC: u16 = 0x0020;
    pub const VIN1_12V_ADC: u16 = 0x0021;
    pub const AVCC_3V3_ADC: u16 = 0x0022;
    pub const VCC_3V3_ADC: u16 = 0x0023;
    pub const VIN2_5V_ADC: u16 = 0x0024;
    /// Bank 0: SYSTIN 8-bit integer °C (`0x0027`).
    pub const SYSTIN_TEMP: u16 = 0x0027;
    /// Bank 1: CPUTIN 9-bit `0.5 °C` (`0x0150` = integer MSB, `0x0151[7]` = 0.5 °C LSB).
    pub const CPUTIN_TEMP_MSB: u16 = 0x0150;
    pub const CPUTIN_TEMP_LSB: u16 = 0x0151;
    /// Bank 6: Fan RPM 16-bit Readings (`0x0656` = SYSFAN, `0x0658` = CPUFAN).
    pub const SYSFAN_RPM_HI: u16 = 0x0656;
    pub const CPUFAN_RPM_HI: u16 = 0x0658;
    /// Bank 0: PWM Output Duty Cycle (`0x0001` = SYSFAN PWM, `0x0003` = CPUFAN PWM, `0..=255`).
    pub const SYSFAN_PWM_DUTY: u16 = 0x0001;
    pub const CPUFAN_PWM_DUTY: u16 = 0x0003;
}

/// Converts a raw 8-bit Nuvoton ADC reading (`8 mV` per LSB) into millivolts, applying
/// an external resistor divider multiplier `(r_num / r_den)` for high-voltage rails:
/// - `Vcore`: direct `(1, 1)` -> `raw * 8 mV`
/// - `+3.3V`: internal 2x `(2, 1)` -> `raw * 16 mV`
/// - `+5.0V`: 4x divider `(4, 1)` -> `raw * 32 mV`
/// - `+12.0V`: 11:2 divider `(66, 10)` -> `(raw * 8 * 66) / 10 mV`
#[inline]
pub const fn decode_adc_millivolts(raw_adc: u8, divider_num: u32, divider_den: u32) -> u32 {
    if divider_den == 0 {
        return 0;
    }
    ((raw_adc as u32) * 8 * divider_num) / divider_den
}

/// Decodes a 9-bit signed two's-complement temperature sensor reading (`msb` = signed integer °C,
/// `lsb_bit7` = `0.5 °C` half-degree bit) into millidegrees Celsius (`m°C`).
#[inline]
pub const fn decode_temp_millicelsius(msb: u8, lsb: u8) -> i32 {
    let base_c = (msb as i8) as i32;
    let half_c = if (lsb & 0x80) != 0 { 500 } else { 0 };
    base_c * 1000 + half_c
}

/// Converts a 16-bit gated pulse period count (`1.35 MHz` reference clock, 2 pulses per revolution)
/// into Revolutions Per Minute (`RPM`).
#[inline]
pub const fn period_count_to_fan_rpm(period_count: u16, pulses_per_rev: u8) -> u32 {
    if period_count == 0 || period_count == 0xFFFF || pulses_per_rev == 0 {
        return 0;
    }
    let denom = (period_count as u32) * (pulses_per_rev as u32);
    2_700_000u32 / denom // (1_350_000 Hz * 60 sec) / (30 * denom) = 2_700_000 / denom
}

/// Piecewise-linear Thermal Fan PWM Controller (`0..=255` duty cycle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThermalPwmCurve {
    pub temp_min_mc: i32,
    pub temp_max_mc: i32,
    pub pwm_min_duty: u8,
    pub pwm_max_duty: u8,
    pub critical_temp_mc: i32,
}

impl ThermalPwmCurve {
    #[inline]
    pub const fn standard_cpu_curve() -> Self {
        Self {
            temp_min_mc: 40_000,     // 40.0 °C -> minimum fan speed
            temp_max_mc: 80_000,     // 80.0 °C -> 100% fan speed
            pwm_min_duty: 64,        // ~25% PWM duty cycle
            pwm_max_duty: 255,       // 100% PWM duty cycle
            critical_temp_mc: 95_000,// 95.0 °C -> emergency full blast
        }
    }

    /// Computes the target 8-bit PWM duty cycle (`0..=255`) for `current_temp_mc` (`m°C`).
    pub const fn compute_pwm_duty(&self, current_temp_mc: i32) -> u8 {
        if current_temp_mc >= self.critical_temp_mc || current_temp_mc >= self.temp_max_mc {
            return self.pwm_max_duty;
        }
        if current_temp_mc <= self.temp_min_mc {
            return self.pwm_min_duty;
        }
        let temp_span = (self.temp_max_mc - self.temp_min_mc) as i64;
        if temp_span <= 0 {
            return self.pwm_max_duty;
        }
        let pwm_span = (self.pwm_max_duty.saturating_sub(self.pwm_min_duty)) as i64;
        let delta = (current_temp_mc - self.temp_min_mc) as i64;
        let duty = (self.pwm_min_duty as i64) + (delta * pwm_span) / temp_span;
        duty as u8
    }
}

/// Complete snapshot of decoded motherboard hardware telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwmonTelemetrySnapshot {
    pub chip: SuperIoChipModel,
    pub vcore_mv: u32,
    pub rail_12v_mv: u32,
    pub rail_5v_mv: u32,
    pub rail_3v3_mv: u32,
    pub cpu_temp_mc: i32,
    pub sys_temp_mc: i32,
    pub cpu_fan_rpm: u32,
    pub cpu_pwm_duty: u8,
}

/// Self-test for `superio_hwmon` chip identification, voltage rail scaling, 0.5°C temperature decoding,
/// tachometer RPM conversion, and PWM thermal curve calculation.
pub fn verify_driver_module_superio_hwmon() -> u32 {
    let mut passed = 0u32;

    // 1. Verify Nuvoton NCT6775F and ITE IT8728F chip ID recognition
    if SuperIoChipModel::identify(0xB473) == SuperIoChipModel::NuvotonNct6775F
        && SuperIoChipModel::identify(0x8728) == SuperIoChipModel::IteIt8728F
    {
        passed += 1;
    }

    // 2. Verify ADC voltage scaling (Vcore = 135 * 8mV = 1080 mV; +12V = 228 * 52.8mV = 12038 mV)
    let vcore = decode_adc_millivolts(135, 1, 1);
    let v12 = decode_adc_millivolts(228, 66, 10);
    let v5 = decode_adc_millivolts(156, 4, 1);
    if vcore == 1080 && v12 == 12_038 && v5 == 4992 {
        passed += 1;
    }

    // 3. Verify 9-bit 0.5°C temperature decoding and Tachometer RPM conversion
    let cpu_temp = decode_temp_millicelsius(60, 0x80); // 60.5 °C -> 60_500 m°C
    let rpm = period_count_to_fan_rpm(1000, 2); // 2_700_000 / 2000 = 1350 RPM
    if cpu_temp == 60_500 && rpm == 1350 {
        passed += 1;
    }

    // 4. Verify piecewise-linear PWM fan duty cycle at 60.0 °C (midpoint between 40°C and 80°C)
    let curve = ThermalPwmCurve::standard_cpu_curve();
    let duty = curve.compute_pwm_duty(60_000);
    if duty == 159 && curve.compute_pwm_duty(90_000) == 255 {
        passed += 1;
    }

    passed
}
