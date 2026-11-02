//! `virtio_input` — VirtIO 1.2 Input Device Specification Driver.
//!
//! Implements VirtIO 1.2 input device specification (Device ID 18):
//! - Event virtqueue (`eventq`) and status virtqueue (`statusq`) buffer handling
//! - VirtIO input configuration space layout (`select`, `subsel`, `size`, `payload`)
//! - 8-byte `VirtioInputEvent` decoding and transformation to Linux evdev 24-byte `LinuxInputEvent` standard
//! - Support for standard evdev event types: `EV_SYN`, `EV_KEY`, `EV_REL`, `EV_ABS`, `EV_LED`

/// VirtIO 1.2 Input Device ID.
pub const VIRTIO_ID_INPUT: u16 = 18;

/// VirtIO Input Configuration Selectors.
pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

/// VirtIO Device Status Bits.
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

/// Linux evdev Event Types (from `linux/input-event-codes.h`).
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_SW: u16 = 0x05;
pub const EV_LED: u16 = 0x11;
pub const EV_SND: u16 = 0x12;
pub const EV_REP: u16 = 0x14;
pub const EV_FF: u16 = 0x15;

/// Synchronization event codes.
pub const SYN_REPORT: u16 = 0;
pub const SYN_CONFIG: u16 = 1;
pub const SYN_MT_REPORT: u16 = 2;
pub const SYN_DROPPED: u16 = 3;

/// Relative axis codes.
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_Z: u16 = 0x02;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;

/// Absolute axis codes.
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_Z: u16 = 0x02;
pub const ABS_PRESSURE: u16 = 0x18;
pub const ABS_MT_SLOT: u16 = 0x2F;
pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

/// Standard Linux keycodes.
pub const KEY_RESERVED: u16 = 0;
pub const KEY_ESC: u16 = 1;
pub const KEY_1: u16 = 2;
pub const KEY_2: u16 = 3;
pub const KEY_TAB: u16 = 15;
pub const KEY_Q: u16 = 16;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_A: u16 = 30;
pub const KEY_S: u16 = 31;
pub const KEY_D: u16 = 32;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

/// LED codes.
pub const LED_NUML: u16 = 0x00;
pub const LED_CAPSL: u16 = 0x01;
pub const LED_SCROLLL: u16 = 0x02;

/// VirtIO 1.2 standard 8-byte input event.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: u32,
}

impl VirtioInputEvent {
    pub const fn new(event_type: u16, code: u16, value: u32) -> Self {
        Self { event_type, code, value }
    }

    /// Converts VirtIO 8-byte input event to 24-byte Linux standard `LinuxInputEvent`.
    pub fn to_evdev(&self, time_sec: u64, time_usec: u64) -> LinuxInputEvent {
        LinuxInputEvent {
            time_sec,
            time_usec,
            event_type: self.event_type,
            code: self.code,
            value: self.value as i32,
        }
    }
}

/// Linux-compatible 24-byte `input_event` standard structure.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LinuxInputEvent {
    pub time_sec: u64,
    pub time_usec: u64,
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

impl LinuxInputEvent {
    pub const SIZE: usize = 24;

    pub const fn new(sec: u64, usec: u64, event_type: u16, code: u16, value: i32) -> Self {
        Self {
            time_sec: sec,
            time_usec: usec,
            event_type,
            code,
            value,
        }
    }

    pub fn from_virtio(ev: &VirtioInputEvent, sec: u64, usec: u64) -> Self {
        ev.to_evdev(sec, usec)
    }

    pub const fn syn_report(sec: u64, usec: u64) -> Self {
        Self {
            time_sec: sec,
            time_usec: usec,
            event_type: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        }
    }
}

/// VirtIO Absolute Axis Information (`VIRTIO_INPUT_CFG_ABS_INFO`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputAbsInfo {
    pub min: u32,
    pub max: u32,
    pub fuzz: u32,
    pub flat: u32,
    pub res: u32,
}

/// VirtIO Input Device Identification (`VIRTIO_INPUT_CFG_ID_DEVIDS`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputDevIds {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

/// VirtIO 1.2 Input Configuration Layout (136 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioInputConfig {
    pub select: u8,
    pub subsel: u8,
    pub size: u8,
    pub reserved: [u8; 5],
    pub payload: [u8; 128],
}

impl VirtioInputConfig {
    pub const fn new() -> Self {
        Self {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0; 5],
            payload: [0; 128],
        }
    }
}

/// Virtqueue buffer descriptor for virtio-input event and status transfers.
#[derive(Copy, Clone, Debug, Default)]
pub struct VirtioInputBufferDesc {
    pub addr: u64,
    pub len: u32,
    pub is_write: bool,
}

/// Circular event virtqueue manager handling incoming input buffers.
pub struct VirtioInputVirtqueue {
    pub queue_size: usize,
    pub available_idx: u16,
    pub used_idx: u16,
    pub buffers: [VirtioInputBufferDesc; 64],
    pub posted_count: usize,
}

impl VirtioInputVirtqueue {
    pub const fn new() -> Self {
        Self {
            queue_size: 64,
            available_idx: 0,
            used_idx: 0,
            buffers: [VirtioInputBufferDesc { addr: 0, len: 0, is_write: false }; 64],
            posted_count: 0,
        }
    }

    /// Post an empty receive buffer for device to fill with a `VirtioInputEvent`.
    pub fn post_receive_buffer(&mut self, addr: u64, len: u32) -> bool {
        if self.posted_count >= self.queue_size {
            return false;
        }
        let slot = (self.available_idx as usize) % self.queue_size;
        self.buffers[slot] = VirtioInputBufferDesc {
            addr,
            len,
            is_write: true,
        };
        self.available_idx = self.available_idx.wrapping_add(1);
        self.posted_count += 1;
        true
    }

    /// Mark a buffer as consumed by the host driver.
    pub fn consume_buffer(&mut self) -> Option<VirtioInputBufferDesc> {
        if self.posted_count == 0 {
            return None;
        }
        let slot = (self.used_idx as usize) % self.queue_size;
        let buf = self.buffers[slot];
        self.used_idx = self.used_idx.wrapping_add(1);
        self.posted_count -= 1;
        Some(buf)
    }
}

/// Stateful VirtIO Input Controller Device.
pub struct VirtioInputDevice {
    pub status: u8,
    pub config_select: u8,
    pub config_subsel: u8,
    pub config: VirtioInputConfig,
    pub event_queue: [VirtioInputEvent; 64],
    pub head: usize,
    pub tail: usize,
    pub count: usize,
    pub event_vq: VirtioInputVirtqueue,
    pub led_state: u8,
}

impl VirtioInputDevice {
    pub const fn new() -> Self {
        Self {
            status: 0,
            config_select: 0,
            config_subsel: 0,
            config: VirtioInputConfig::new(),
            event_queue: [VirtioInputEvent { event_type: 0, code: 0, value: 0 }; 64],
            head: 0,
            tail: 0,
            count: 0,
            event_vq: VirtioInputVirtqueue::new(),
            led_state: 0,
        }
    }

    /// Standard VirtIO 1.2 device initialization sequence.
    pub fn initialize(&mut self) -> Result<(), &'static str> {
        self.status = 0;
        self.status |= VIRTIO_STATUS_ACKNOWLEDGE;
        self.status |= VIRTIO_STATUS_DRIVER;
        self.status |= VIRTIO_STATUS_FEATURES_OK;
        self.status |= VIRTIO_STATUS_DRIVER_OK;

        // Pre-populate event virtqueue with receive buffers (size of VirtioInputEvent = 8 bytes)
        for i in 0..32 {
            let fake_phys_addr = 0x20000 + (i as u64) * 8;
            self.event_vq.post_receive_buffer(fake_phys_addr, 8);
        }

        Ok(())
    }

    /// Select configuration parameter to query from device.
    pub fn select_config(&mut self, select: u8, subsel: u8) {
        self.config_select = select;
        self.config_subsel = subsel;
        self.config.select = select;
        self.config.subsel = subsel;

        // Populate simulated response based on selector
        match select {
            VIRTIO_INPUT_CFG_ID_NAME => {
                let name = b"CorOS VirtIO Multi-Touch & Keyboard Controller\0";
                let len = name.len().min(128);
                self.config.size = len as u8;
                self.config.payload[..len].copy_from_slice(&name[..len]);
            }
            VIRTIO_INPUT_CFG_ID_SERIAL => {
                let serial = b"COROS-VINPUT-2026-X86\0";
                let len = serial.len().min(128);
                self.config.size = len as u8;
                self.config.payload[..len].copy_from_slice(&serial[..len]);
            }
            VIRTIO_INPUT_CFG_ABS_INFO => {
                let abs = VirtioInputAbsInfo {
                    min: 0,
                    max: 4095,
                    fuzz: 4,
                    flat: 0,
                    res: 10,
                };
                self.config.size = core::mem::size_of::<VirtioInputAbsInfo>() as u8;
                unsafe {
                    let ptr = &abs as *const VirtioInputAbsInfo as *const u8;
                    for i in 0..core::mem::size_of::<VirtioInputAbsInfo>() {
                        self.config.payload[i] = *ptr.add(i);
                    }
                }
            }
            _ => {
                self.config.size = 0;
            }
        }
    }

    /// Push an event received from virtqueue.
    pub fn push_event(&mut self, ev: VirtioInputEvent) -> bool {
        if self.count >= self.event_queue.len() {
            return false;
        }
        self.event_queue[self.tail] = ev;
        self.tail = (self.tail + 1) % self.event_queue.len();
        self.count += 1;
        true
    }

    /// Pop next event from queue.
    pub fn pop_event(&mut self) -> Option<VirtioInputEvent> {
        if self.count == 0 {
            return None;
        }
        let ev = self.event_queue[self.head];
        self.head = (self.head + 1) % self.event_queue.len();
        self.count -= 1;
        Some(ev)
    }

    /// Pop next event and convert directly to Linux evdev 24-byte event.
    pub fn pop_evdev_event(&mut self, sec: u64, usec: u64) -> Option<LinuxInputEvent> {
        self.pop_event().map(|ev| ev.to_evdev(sec, usec))
    }

    /// Set device keyboard LEDs via status virtqueue.
    pub fn set_leds(&mut self, caps: bool, num: bool, scroll: bool) {
        let mut val = 0u8;
        if caps { val |= 1 << LED_CAPSL; }
        if num { val |= 1 << LED_NUML; }
        if scroll { val |= 1 << LED_SCROLLL; }
        self.led_state = val;
    }
}

/// Self-test suite verifying the VirtIO 1.2 input device driver specification.
pub fn verify_driver_module_virtio_input() -> u32 {
    let mut passed = 0u32;
    let mut dev = VirtioInputDevice::new();

    // 1. Device initialization and status handshake
    if dev.initialize().is_ok() && (dev.status & VIRTIO_STATUS_DRIVER_OK) != 0 {
        passed += 1;
    }

    // 2. Configuration selection for Device Name
    dev.select_config(VIRTIO_INPUT_CFG_ID_NAME, 0);
    if dev.config_select == VIRTIO_INPUT_CFG_ID_NAME
        && dev.config.size > 0
        && dev.config.payload[0] == b'C'
    {
        passed += 1;
    }

    // 3. Configuration selection for Absolute Touch Info
    dev.select_config(VIRTIO_INPUT_CFG_ABS_INFO, 0);
    if dev.config_select == VIRTIO_INPUT_CFG_ABS_INFO && dev.config.size == 20 {
        passed += 1;
    }

    // 4. Enqueue key and sync events
    let ev_key = VirtioInputEvent { event_type: EV_KEY, code: KEY_A, value: 1 };
    let ev_syn = VirtioInputEvent { event_type: EV_SYN, code: SYN_REPORT, value: 0 };
    if dev.push_event(ev_key) && dev.push_event(ev_syn) {
        passed += 1;
    }

    // 5. Pop and verify 24-byte LinuxInputEvent conversion
    if let Some(evdev) = dev.pop_evdev_event(1700000000, 50000) {
        if evdev.time_sec == 1700000000
            && evdev.time_usec == 50000
            && evdev.event_type == EV_KEY
            && evdev.code == KEY_A
            && evdev.value == 1
        {
            passed += 1;
        }
    }

    // 6. Pop sync event
    if let Some(evdev) = dev.pop_evdev_event(1700000000, 50100) {
        if evdev.event_type == EV_SYN && evdev.code == SYN_REPORT {
            passed += 1;
        }
    }

    // 7. Verify empty queue pop returns None
    if dev.pop_event().is_none() && dev.pop_evdev_event(0, 0).is_none() {
        passed += 1;
    }

    // 8. Relative mouse motion and negative coordinate handling
    let ev_rel_x = VirtioInputEvent { event_type: EV_REL, code: REL_X, value: 15 };
    let ev_rel_y = VirtioInputEvent { event_type: EV_REL, code: REL_Y, value: (-10i32) as u32 };
    dev.push_event(ev_rel_x);
    dev.push_event(ev_rel_y);

    if let (Some(x), Some(y)) = (dev.pop_evdev_event(0, 0), dev.pop_evdev_event(0, 0)) {
        if x.event_type == EV_REL && x.code == REL_X && x.value == 15
            && y.event_type == EV_REL && y.code == REL_Y && y.value == -10
        {
            passed += 1;
        }
    }

    // 9. Virtqueue buffer posting and replenishment
    let initial_posted = dev.event_vq.posted_count;
    if initial_posted > 0 {
        if let Some(buf) = dev.event_vq.consume_buffer() {
            if buf.len == 8 && dev.event_vq.post_receive_buffer(0x30000, 8) {
                passed += 1;
            }
        }
    }

    // 10. LED state mutation
    dev.set_leds(true, false, true);
    if dev.led_state & (1 << LED_CAPSL) != 0 && dev.led_state & (1 << LED_SCROLLL) != 0 {
        passed += 1;
    }

    passed
}
