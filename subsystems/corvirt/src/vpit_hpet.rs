//! Emulated Intel 8254 Programmable Interval Timer (`PIT` — 3 channels, modes 0..5,
//! 1.193182 MHz base crystal oscillator, counter latch & read-back command)
//! and Virtual High Precision Event Timer (`HPET` — 64-bit main counter + 3 comparator timers).

/// Nominal frequency of the Intel 8254 PIT crystal oscillator in Hz (`1,193,182 Hz`).
pub const PIT_OSCILLATOR_HZ: u64 = 1_193_182;

/// Operating mode of an 8254 PIT channel (`Modes 0..=5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PitOperatingMode {
    InterruptOnTerminalCount = 0,
    HardwareRetriggerableOneShot = 1,
    RateGenerator = 2,
    SquareWaveGenerator = 3,
    SoftwareTriggeredStrobe = 4,
    HardwareTriggeredStrobe = 5,
}

impl PitOperatingMode {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::InterruptOnTerminalCount,
            1 => Self::HardwareRetriggerableOneShot,
            2 | 6 => Self::RateGenerator,
            3 | 7 => Self::SquareWaveGenerator,
            4 => Self::SoftwareTriggeredStrobe,
            _ => Self::HardwareTriggeredStrobe,
        }
    }
}

/// Read/Write access policy for a PIT channel counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PitAccessMode {
    LatchCountValue,
    LowByteOnly,
    HighByteOnly,
    LowByteThenHighByte,
}

/// Single channel state of the Intel 8254 Programmable Interval Timer.
#[derive(Debug, Clone)]
pub struct PitChannel {
    pub channel_index: u8,
    pub reload_value: u16,
    pub current_count: u16,
    pub latched_count: Option<u16>,
    pub latched_status: Option<u8>,
    pub mode: PitOperatingMode,
    pub access_mode: PitAccessMode,
    pub bcd_mode: bool,
    pub write_high_byte_next: bool,
    pub read_high_byte_next: bool,
    pub output_pin_high: bool,
    pub gate_input_high: bool,
    pub null_count_flag: bool,
}

impl PitChannel {
    pub const fn new(channel_index: u8) -> Self {
        Self {
            channel_index,
            reload_value: 0, // 0 represents 65536 ticks in 8254 hardware
            current_count: 0,
            latched_count: None,
            latched_status: None,
            mode: PitOperatingMode::RateGenerator,
            access_mode: PitAccessMode::LowByteThenHighByte,
            bcd_mode: false,
            write_high_byte_next: false,
            read_high_byte_next: false,
            output_pin_high: true,
            gate_input_high: true,
            null_count_flag: true,
        }
    }

    /// Returns the effective 32-bit divisor (`65536` when `reload_value == 0`).
    pub const fn effective_divisor(&self) -> u32 {
        if self.reload_value == 0 {
            65_536
        } else {
            self.reload_value as u32
        }
    }

    /// Latches the current 16-bit counter value if not already latched.
    pub fn latch_count(&mut self) {
        if self.latched_count.is_none() {
            self.latched_count = Some(self.current_count);
            self.read_high_byte_next = false;
        }
    }

    /// Latches the 8-bit status byte for a Read-Back command (`0x43`).
    pub fn latch_status(&mut self) {
        if self.latched_status.is_none() {
            let rw_bits = match self.access_mode {
                PitAccessMode::LatchCountValue => 0,
                PitAccessMode::LowByteOnly => 1,
                PitAccessMode::HighByteOnly => 2,
                PitAccessMode::LowByteThenHighByte => 3,
            };
            let status = ((self.output_pin_high as u8) << 7)
                | ((self.null_count_flag as u8) << 6)
                | (rw_bits << 4)
                | ((self.mode as u8) << 1)
                | (self.bcd_mode as u8);
            self.latched_status = Some(status);
        }
    }

    /// Writes a byte to the channel data port (`0x40..=0x42`).
    pub fn write_data_byte(&mut self, byte: u8) {
        match self.access_mode {
            PitAccessMode::LowByteOnly => {
                self.reload_value = byte as u16;
                self.load_counter();
            }
            PitAccessMode::HighByteOnly => {
                self.reload_value = (byte as u16) << 8;
                self.load_counter();
            }
            PitAccessMode::LowByteThenHighByte | PitAccessMode::LatchCountValue => {
                if !self.write_high_byte_next {
                    self.reload_value = (self.reload_value & 0xFF00) | (byte as u16);
                    self.write_high_byte_next = true;
                } else {
                    self.reload_value = (self.reload_value & 0x00FF) | ((byte as u16) << 8);
                    self.write_high_byte_next = false;
                    self.load_counter();
                }
            }
        }
    }

    fn load_counter(&mut self) {
        self.current_count = self.reload_value;
        self.null_count_flag = false;
        self.output_pin_high = !matches!(self.mode, PitOperatingMode::InterruptOnTerminalCount);
    }

    /// Reads a byte from the channel data port (`0x40..=0x42`), honoring latched status and count first.
    pub fn read_data_byte(&mut self) -> u8 {
        if let Some(status) = self.latched_status.take() {
            return status;
        }
        let source_count = self.latched_count.unwrap_or(self.current_count);
        match self.access_mode {
            PitAccessMode::LowByteOnly => {
                self.latched_count = None;
                (source_count & 0xFF) as u8
            }
            PitAccessMode::HighByteOnly => {
                self.latched_count = None;
                ((source_count >> 8) & 0xFF) as u8
            }
            PitAccessMode::LowByteThenHighByte | PitAccessMode::LatchCountValue => {
                if !self.read_high_byte_next {
                    self.read_high_byte_next = true;
                    (source_count & 0xFF) as u8
                } else {
                    self.read_high_byte_next = false;
                    self.latched_count = None;
                    ((source_count >> 8) & 0xFF) as u8
                }
            }
        }
    }

    /// Advances the PIT channel by `oscillator_ticks` and returns the number of terminal count events fired.
    pub fn advance_ticks(&mut self, oscillator_ticks: u64) -> u64 {
        if !self.gate_input_high || oscillator_ticks == 0 {
            return 0;
        }
        let divisor = self.effective_divisor() as u64;
        let current = if self.current_count == 0 {
            divisor
        } else {
            self.current_count as u64
        };

        match self.mode {
            PitOperatingMode::InterruptOnTerminalCount
            | PitOperatingMode::HardwareRetriggerableOneShot => {
                if oscillator_ticks >= current {
                    let previously_low = !self.output_pin_high;
                    self.output_pin_high = true;
                    let rem = (oscillator_ticks - current) % 65_536;
                    self.current_count = ((65_536 - rem) & 0xFFFF) as u16;
                    u64::from(previously_low)
                } else {
                    self.current_count = (current - oscillator_ticks) as u16;
                    0
                }
            }
            PitOperatingMode::RateGenerator
            | PitOperatingMode::SquareWaveGenerator
            | PitOperatingMode::SoftwareTriggeredStrobe
            | PitOperatingMode::HardwareTriggeredStrobe => {
                if oscillator_ticks < current {
                    self.current_count = (current - oscillator_ticks) as u16;
                    0
                } else {
                    let after_first = oscillator_ticks - current;
                    let wraps = 1 + (after_first / divisor);
                    let rem = after_first % divisor;
                    let next_val = divisor - rem;
                    self.current_count = (next_val & 0xFFFF) as u16;
                    self.output_pin_high = true;
                    wraps
                }
            }
        }
    }
}

/// Complete 3-Channel Intel 8254 PIT (`ports 0x40..=0x43`).
#[derive(Debug, Clone)]
pub struct VirtualPit8254 {
    pub channels: [PitChannel; 3],
}

impl VirtualPit8254 {
    pub const fn new() -> Self {
        Self {
            channels: [
                PitChannel::new(0),
                PitChannel::new(1),
                PitChannel::new(2),
            ],
        }
    }

    /// Processes a write to the PIT Mode/Command register (`port 0x43`).
    pub fn write_command_port(&mut self, cmd: u8) {
        let sc = (cmd >> 6) & 0x03;
        if sc == 0b11 {
            // Read-Back command (8254 specific)
            let latch_count = (cmd & (1 << 5)) == 0;
            let latch_status = (cmd & (1 << 4)) == 0;
            for ch_idx in 0..3 {
                if (cmd & (1 << (ch_idx + 1))) != 0 {
                    if latch_status {
                        self.channels[ch_idx].latch_status();
                    }
                    if latch_count {
                        self.channels[ch_idx].latch_count();
                    }
                }
            }
            return;
        }

        let ch_idx = sc as usize;
        let rw_code = (cmd >> 4) & 0x03;
        if rw_code == 0 {
            self.channels[ch_idx].latch_count();
            return;
        }

        let ch = &mut self.channels[ch_idx];
        ch.access_mode = match rw_code {
            1 => PitAccessMode::LowByteOnly,
            2 => PitAccessMode::HighByteOnly,
            _ => PitAccessMode::LowByteThenHighByte,
        };
        ch.mode = PitOperatingMode::from_bits((cmd >> 1) & 0x07);
        ch.bcd_mode = (cmd & 1) != 0;
        ch.write_high_byte_next = false;
        ch.read_high_byte_next = false;
        ch.null_count_flag = true;
        ch.output_pin_high = !matches!(ch.mode, PitOperatingMode::InterruptOnTerminalCount);
    }
}

/// Single comparator timer block in the Virtual HPET.
#[derive(Debug, Clone, Copy)]
pub struct HpetComparatorTimer {
    pub timer_index: u8,
    pub config_and_cap: u64,
    pub comparator_value: u64,
    pub period_ticks: u64,
    pub fsb_int_route: u64,
}

impl HpetComparatorTimer {
    pub const fn new(timer_index: u8) -> Self {
        // Periodic capable (bit 4) | 64-bit capable (bit 5) | valid routing mask in upper 32 bits
        let default_cap = (1u64 << 4) | (1u64 << 5) | (0x00FF_FFFFu64 << 32);
        Self {
            timer_index,
            config_and_cap: default_cap,
            comparator_value: u64::MAX,
            period_ticks: 0,
            fsb_int_route: 0,
        }
    }

    pub const fn is_interrupt_enabled(&self) -> bool {
        (self.config_and_cap & (1 << 2)) != 0
    }

    pub const fn is_periodic(&self) -> bool {
        (self.config_and_cap & (1 << 3)) != 0
    }

    pub const fn ioapic_route_pin(&self) -> u8 {
        ((self.config_and_cap >> 9) & 0x1F) as u8
    }
}

/// Virtual High Precision Event Timer (`HPET`, `0xFED0_0000`) with 64-bit main counter and 3 comparators.
#[derive(Debug, Clone)]
pub struct VirtualHpet {
    pub general_capabilities: u64,
    pub general_config: u64,
    pub general_intr_status: u64,
    pub main_counter: u64,
    pub timers: [HpetComparatorTimer; 3],
}

impl VirtualHpet {
    /// Creates a Virtual HPET with a 100 MHz clock period (`10,000,000 femtoseconds` per tick).
    pub const fn new() -> Self {
        let clk_period_fs: u64 = 10_000_000; // 10 ns (100 MHz)
        let vendor_id: u64 = 0x8086;
        let leg_rt_cap: u64 = 1 << 15;
        let count_size_cap: u64 = 1 << 13; // 64-bit main counter
        let num_tim_cap: u64 = 2 << 8; // 3 timers (N-1 = 2)
        let rev_id: u64 = 1;
        let caps = (clk_period_fs << 32)
            | (vendor_id << 16)
            | leg_rt_cap
            | count_size_cap
            | num_tim_cap
            | rev_id;

        Self {
            general_capabilities: caps,
            general_config: 0,
            general_intr_status: 0,
            main_counter: 0,
            timers: [
                HpetComparatorTimer::new(0),
                HpetComparatorTimer::new(1),
                HpetComparatorTimer::new(2),
            ],
        }
    }

    pub const fn is_enabled(&self) -> bool {
        (self.general_config & 1) != 0
    }

    /// Configures a comparator timer in one-shot or periodic mode.
    pub fn configure_timer(
        &mut self,
        timer_idx: usize,
        comparator_ticks: u64,
        periodic: bool,
        ioapic_pin: u8,
    ) {
        if timer_idx < 3 {
            let t = &mut self.timers[timer_idx];
            let mut cfg = t.config_and_cap & !((0x1F << 9) | (1 << 3) | (1 << 2));
            cfg |= 1 << 2; // INT_ENB_CNF
            if periodic {
                cfg |= 1 << 3; // TYPE_CNF (periodic)
            }
            cfg |= ((ioapic_pin & 0x1F) as u64) << 9;
            t.config_and_cap = cfg;
            t.comparator_value = comparator_ticks;
            t.period_ticks = if periodic { comparator_ticks } else { 0 };
        }
    }

    /// Advances the HPET main counter by `delta_ticks` and returns a bitmask of timers (`bits 0..2`) that fired.
    pub fn advance_counter(&mut self, delta_ticks: u64) -> u8 {
        if !self.is_enabled() || delta_ticks == 0 {
            return 0;
        }
        let prev = self.main_counter;
        let next = prev.wrapping_add(delta_ticks);
        self.main_counter = next;

        let mut fired_mask = 0u8;
        for (idx, timer) in self.timers.iter_mut().enumerate() {
            if prev < timer.comparator_value && next >= timer.comparator_value {
                if timer.is_interrupt_enabled() {
                    fired_mask |= 1 << idx;
                    self.general_intr_status |= 1 << idx;
                }
                if timer.is_periodic() && timer.period_ticks > 0 {
                    let elapsed_past = next - timer.comparator_value;
                    let periods = (elapsed_past / timer.period_ticks) + 1;
                    timer.comparator_value = timer
                        .comparator_value
                        .wrapping_add(periods.saturating_mul(timer.period_ticks));
                } else {
                    timer.comparator_value = u64::MAX;
                }
            }
        }
        fired_mask
    }
}
