//! High-Performance PS/2 Keyboard and Mouse Subsystem for CorOS
//!
//! Provides hardware interrupt and polled input processing, 3-byte mouse packet
//! decoding with self-healing desync recovery, sensitivity acceleration, button
//! tracking, atomic ring buffers, and extended scancode translation.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crate::arch::x86_64::{cpu, idt::ExceptionFrame, interrupts, pic};

pub mod evdev;
pub mod evdev_bridge;

pub use evdev_bridge::{EvdevBridge, GLOBAL_EVDEV_BRIDGE};
pub use evdev::{InputEvent, EvdevDevice, EvdevHub, EV_SYN, EV_KEY, EV_REL, EV_ABS};

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

// Global Mouse State
pub static MOUSE_X: AtomicI32 = AtomicI32::new(450);
pub static MOUSE_Y: AtomicI32 = AtomicI32::new(280);
pub static MOUSE_LEFT: AtomicBool = AtomicBool::new(false);
pub static MOUSE_RIGHT: AtomicBool = AtomicBool::new(false);
pub static MOUSE_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SCREEN_WIDTH: AtomicUsize = AtomicUsize::new(1024);
pub static SCREEN_HEIGHT: AtomicUsize = AtomicUsize::new(768);

// Global Keyboard State & Lock-Free SPSC Ring Buffer
pub static LAST_SCANCODE: AtomicU8 = AtomicU8::new(0x1C);
pub static LAST_KEY_CHAR: AtomicU8 = AtomicU8::new(b'K');
pub static KEY_PRESS_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SHIFT_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static CTRL_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static ALT_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTENDED_SCANCODE: AtomicBool = AtomicBool::new(false);

const KEY_BUF_SIZE: usize = 128;
static KEY_BUFFER: [AtomicU32; KEY_BUF_SIZE] = [const { AtomicU32::new(0) }; KEY_BUF_SIZE];
static KEY_HEAD: AtomicUsize = AtomicUsize::new(0);
static KEY_TAIL: AtomicUsize = AtomicUsize::new(0);

pub fn push_char(ch: char) {
    let head = KEY_HEAD.load(Ordering::Relaxed);
    let next_head = (head + 1) % KEY_BUF_SIZE;
    let tail = KEY_TAIL.load(Ordering::Acquire);
    if next_head != tail {
        KEY_BUFFER[head].store(ch as u32, Ordering::Release);
        KEY_HEAD.store(next_head, Ordering::Release);
    }
}

pub fn pop_char() -> Option<char> {
    let tail = KEY_TAIL.load(Ordering::Relaxed);
    let head = KEY_HEAD.load(Ordering::Acquire);
    if head == tail {
        None
    } else {
        let code = KEY_BUFFER[tail].load(Ordering::Acquire);
        KEY_TAIL.store((tail + 1) % KEY_BUF_SIZE, Ordering::Release);
        char::from_u32(code)
    }
}

// Interactive UI State
pub static CLICK_COUNTER: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_BUTTON_ID: AtomicU8 = AtomicU8::new(1); // 1: Turbo 10x, 2: SMP 4-Core, 3: Reset Wave

// Internal atomic mouse packet state with self-healing desynchronization recovery
static PACKET_BYTE_0: AtomicU8 = AtomicU8::new(0);
static PACKET_BYTE_1: AtomicU8 = AtomicU8::new(0);
static PACKET_INDEX: AtomicUsize = AtomicUsize::new(0);
static PACKET_LAST_TICK: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
unsafe fn io_wait() {
    cpu::out8(0x80, 0);
}

unsafe fn wait_write() -> bool {
    for _ in 0..100_000 {
        io_wait();
        if cpu::in8(STATUS_PORT) & 0x02 == 0 {
            return true;
        }
    }
    false
}

unsafe fn wait_read() -> bool {
    for _ in 0..100_000 {
        io_wait();
        if cpu::in8(STATUS_PORT) & 0x01 != 0 {
            return true;
        }
    }
    false
}

unsafe fn write_mouse(byte: u8) -> bool {
    if !wait_write() { return false; }
    cpu::out8(COMMAND_PORT, 0xD4);
    if !wait_write() { return false; }
    cpu::out8(DATA_PORT, byte);
    true
}

unsafe fn read_data() -> u8 {
    if wait_read() {
        cpu::in8(DATA_PORT)
    } else {
        0
    }
}

/// Initializes PS/2 Keyboard and Mouse hardware and registers IRQ handlers.
pub unsafe fn initialize(screen_w: usize, screen_h: usize) {
    cpu::disable_interrupts();
    crate::diagnostics::serial::write_str("[PS/2] Initializing Keyboard and Mouse Subsystem...\r\n");

    // Set initial mouse position near middle
    MOUSE_X.store((screen_w / 2) as i32, Ordering::Relaxed);
    MOUSE_Y.store((screen_h / 2) as i32, Ordering::Relaxed);
    SCREEN_WIDTH.store(screen_w, Ordering::Relaxed);
    SCREEN_HEIGHT.store(screen_h, Ordering::Relaxed);

    // Register PIC IRQ handlers (Vector 33 = IRQ 1, Vector 44 = IRQ 12)
    let _ = interrupts::register_pic_irq(33, keyboard_irq_handler);
    let _ = interrupts::register_pic_irq(44, mouse_irq_handler);

    // Unmask IRQ 1 (Keyboard) and IRQ 12 (Mouse)
    pic::unmask(1);
    pic::unmask(12);

    // Flush any pending data in output buffer
    while cpu::in8(STATUS_PORT) & 0x01 != 0 {
        let _ = cpu::in8(DATA_PORT);
    }

    // 1. Disable First (Keyboard) and Second (Mouse) ports during configuration
    wait_write();
    cpu::out8(COMMAND_PORT, 0xAD);
    wait_write();
    cpu::out8(COMMAND_PORT, 0xA7);

    // Flush buffer again
    while cpu::in8(STATUS_PORT) & 0x01 != 0 {
        let _ = cpu::in8(DATA_PORT);
    }

    // 2. Read Controller Configuration Byte
    wait_write();
    cpu::out8(COMMAND_PORT, 0x20);
    let mut config = read_data();
    crate::diagnostics::serial::write_u64("[PS/2] Config Before: ", config as u64);

    // Enable IRQ 1 (bit 0), IRQ 12 (bit 1), System Flag (bit 2), Translation to Set 1 (bit 6)
    config |= 0x47;
    // Clear clock disables (bit 4, bit 5)
    config &= !0x30;

    // Write modified configuration byte
    wait_write();
    cpu::out8(COMMAND_PORT, 0x60);
    wait_write();
    cpu::out8(DATA_PORT, config);
    crate::diagnostics::serial::write_u64("[PS/2] Config Written: ", config as u64);

    // 3. Enable First PS/2 port (Keyboard)
    wait_write();
    cpu::out8(COMMAND_PORT, 0xAE);

    // 4. Enable Second PS/2 port (Mouse)
    wait_write();
    cpu::out8(COMMAND_PORT, 0xA8);

    // 5. Enable Keyboard scanning
    wait_write();
    cpu::out8(DATA_PORT, 0xF4);
    let kbd_ack = read_data();
    crate::diagnostics::serial::write_u64("[PS/2] Keyboard 0xF4 ACK: ", kbd_ack as u64);

    // 6. Reset Mouse (0xFF)
    write_mouse(0xFF);
    let m_ack = read_data();
    let m_bat = read_data();
    let m_id = read_data();
    crate::diagnostics::serial::write_u64("[PS/2] Mouse 0xFF ACK: ", m_ack as u64);
    crate::diagnostics::serial::write_u64("[PS/2] Mouse BAT: ", m_bat as u64);
    crate::diagnostics::serial::write_u64("[PS/2] Mouse ID: ", m_id as u64);

    // 7. Set mouse defaults (0xF6)
    write_mouse(0xF6);
    let f6_ack = read_data();
    crate::diagnostics::serial::write_u64("[PS/2] Mouse 0xF6 ACK: ", f6_ack as u64);

    // 8. Set Sample Rate to 100 Hz (0xF3, 100)
    write_mouse(0xF3);
    let _ = read_data();
    write_mouse(100);
    let _ = read_data();

    // 9. Enable packet streaming mode (0xF4)
    write_mouse(0xF4);
    let f4_ack = read_data();
    crate::diagnostics::serial::write_u64("[PS/2] Mouse 0xF4 ACK: ", f4_ack as u64);

    // Final flush of buffer
    while cpu::in8(STATUS_PORT) & 0x01 != 0 {
        let _ = cpu::in8(DATA_PORT);
    }
    crate::diagnostics::serial::write_str("[PS/2] Mouse streaming online!\r\n");
    cpu::enable_interrupts();
}

pub extern "efiapi" fn keyboard_irq_handler(_frame: &ExceptionFrame) {
    unsafe {
        let status = cpu::in8(STATUS_PORT);
        if status & 0x01 != 0 {
            let byte = cpu::in8(DATA_PORT);
            if status & 0x20 == 0 {
                process_scancode(byte);
            } else {
                let sw = SCREEN_WIDTH.load(Ordering::Relaxed);
                let sh = SCREEN_HEIGHT.load(Ordering::Relaxed);
                process_mouse_byte(byte, sw, sh);
            }
        }
    }
}

pub extern "efiapi" fn mouse_irq_handler(_frame: &ExceptionFrame) {
    unsafe {
        let status = cpu::in8(STATUS_PORT);
        if status & 0x01 != 0 {
            let byte = cpu::in8(DATA_PORT);
            if status & 0x20 != 0 {
                let sw = SCREEN_WIDTH.load(Ordering::Relaxed);
                let sh = SCREEN_HEIGHT.load(Ordering::Relaxed);
                process_mouse_byte(byte, sw, sh);
            } else {
                process_scancode(byte);
            }
        }
    }
}

/// Polls port 0x60 for any buffered keyboard or mouse input (called inside render loop).
pub fn poll_input(screen_w: usize, screen_h: usize) {
    SCREEN_WIDTH.store(screen_w, Ordering::Relaxed);
    SCREEN_HEIGHT.store(screen_h, Ordering::Relaxed);
    unsafe {
        for _ in 0..128 {
            let status = cpu::in8(STATUS_PORT);
            if status & 0x01 == 0 {
                break;
            }
            let byte = cpu::in8(DATA_PORT);
            if status & 0x20 != 0 {
                // Auxiliary device = Mouse
                process_mouse_byte(byte, screen_w, screen_h);
            } else {
                // Keyboard
                process_scancode(byte);
            }
        }
    }
}

fn process_mouse_byte(byte: u8, screen_w: usize, screen_h: usize) {
    let now_tick = crate::time::TscCounter::read_ticks().0;
    let last_tick = PACKET_LAST_TICK.swap(now_tick, Ordering::Relaxed);
    let mut idx = PACKET_INDEX.load(Ordering::Acquire);

    // Automatic self-healing timeout recovery:
    // If more than ~80ms (approx 200,000,000 ticks) elapsed between bytes,
    // the previous packet was definitely truncated; reset to wait for byte 0.
    if idx > 0 && now_tick.saturating_sub(last_tick) > 200_000_000 {
        idx = 0;
        PACKET_INDEX.store(0, Ordering::Release);
    }

    if idx == 0 {
        // Bit 3 of byte 0 must always be 1 for valid alignment in standard PS/2 protocol.
        // Also discard obvious overflow packets (bits 6 and 7).
        if byte & 0x08 == 0 || byte & 0xC0 != 0 {
            return;
        }
        PACKET_BYTE_0.store(byte, Ordering::Relaxed);
        PACKET_INDEX.store(1, Ordering::Release);
    } else if idx == 1 {
        PACKET_BYTE_1.store(byte, Ordering::Relaxed);
        PACKET_INDEX.store(2, Ordering::Release);
    } else if idx == 2 {
        PACKET_INDEX.store(0, Ordering::Release);

        let flags = PACKET_BYTE_0.load(Ordering::Relaxed);
        let raw_dx = PACKET_BYTE_1.load(Ordering::Relaxed);
        let raw_dy = byte;

        // Discard overflow packets
        if flags & 0xC0 != 0 {
            return;
        }

        // Standard PS/2 9-bit signed deltas:
        // flags bit 4: X sign bit (1 = negative)
        // flags bit 5: Y sign bit (1 = negative)
        let dx: i32 = if flags & 0x10 != 0 {
            (raw_dx as i32) - 256
        } else {
            raw_dx as i32
        };

        let dy: i32 = if flags & 0x20 != 0 {
            (raw_dy as i32) - 256
        } else {
            raw_dy as i32
        };

        // Ignore massive glitches / spikes (> 180 pixels in one delta)
        if dx.abs() > 180 || dy.abs() > 180 {
            return;
        }

        // Update Buttons
        let left = flags & 0x01 != 0;
        let right = flags & 0x02 != 0;
        let prev_left = MOUSE_LEFT.swap(left, Ordering::Relaxed);
        MOUSE_RIGHT.store(right, Ordering::Relaxed);

        if left && !prev_left {
            CLICK_COUNTER.fetch_add(1, Ordering::Relaxed);
        }

        // Responsive Speed Scaling & Dynamic Acceleration:
        // Raw delta is scaled 2x for normal dragging, 3x for fast swipes
        let max_d = dx.abs().max(dy.abs());
        let multiplier = if max_d > 8 {
            3
        } else if max_d > 1 {
            2
        } else {
            1
        };

        let scaled_dx = dx * multiplier;
        let scaled_dy = dy * multiplier;

        // Clamp to screen boundaries
        let curr_x = MOUSE_X.load(Ordering::Relaxed);
        let curr_y = MOUSE_Y.load(Ordering::Relaxed);
        let new_x = (curr_x + scaled_dx).clamp(0, (screen_w.saturating_sub(1)) as i32);
        let new_y = (curr_y - scaled_dy).clamp(0, (screen_h.saturating_sub(1)) as i32);

        MOUSE_X.store(new_x, Ordering::Relaxed);
        MOUSE_Y.store(new_y, Ordering::Relaxed);
        let count = MOUSE_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
        if count == 0 || count % 100 == 0 {
            crate::diagnostics::serial::write_str("[MOUSE] Motion: (");
            crate::diagnostics::serial::write_u64("", new_x as u64);
            crate::diagnostics::serial::write_str(", ");
            crate::diagnostics::serial::write_u64("", new_y as u64);
            crate::diagnostics::serial::write_str(")\r\n");
        }
    }
}

fn process_scancode(scancode: u8) {
    if scancode == 0xE0 {
        EXTENDED_SCANCODE.store(true, Ordering::Relaxed);
        return;
    }

    let is_extended = EXTENDED_SCANCODE.swap(false, Ordering::Relaxed);

    if is_extended {
        // Extended Key Processing (Arrow keys, Home, End, Delete, Super)
        if scancode >= 0x80 {
            // Extended key released; ignore
            return;
        }

        LAST_SCANCODE.store(scancode, Ordering::Relaxed);
        KEY_PRESS_COUNT.fetch_add(1, Ordering::Relaxed);

        let ch_opt = match scancode {
            0x48 => Some('\u{87}'), // Up Arrow
            0x50 => Some('\u{88}'), // Down Arrow
            0x4B => Some('\u{89}'), // Left Arrow
            0x4D => Some('\u{8A}'), // Right Arrow
            0x53 => Some('\x7F'),   // Delete key
            0x47 => Some('\u{8B}'), // Home
            0x4F => Some('\u{8C}'), // End
            0x49 => Some('\u{8D}'), // Page Up
            0x51 => Some('\u{8E}'), // Page Down
            0x5B | 0x5C => Some('\u{80}'), // Windows Super Key
            0x1D => {
                // Right Ctrl pressed
                CTRL_ACTIVE.store(true, Ordering::Relaxed);
                None
            }
            0x38 => {
                // Right Alt pressed
                ALT_ACTIVE.store(true, Ordering::Relaxed);
                None
            }
            _ => None,
        };

        if let Some(ch) = ch_opt {
            crate::diagnostics::serial::write_str("[KEY-EXT] Scancode: ");
            crate::diagnostics::serial::write_u64("", scancode as u64);
            crate::diagnostics::serial::write_str("\r\n");
            LAST_KEY_CHAR.store(ch as u8, Ordering::Relaxed);
            push_char(ch);
        }
        return;
    }

    // Modifier key tracking
    if scancode == 0x2A || scancode == 0x36 {
        // Shift pressed
        SHIFT_ACTIVE.store(true, Ordering::Relaxed);
        return;
    } else if scancode == 0xAA || scancode == 0xB6 {
        // Shift released
        SHIFT_ACTIVE.store(false, Ordering::Relaxed);
        return;
    } else if scancode == 0x1D {
        // Left Ctrl pressed
        CTRL_ACTIVE.store(true, Ordering::Relaxed);
        return;
    } else if scancode == 0x9D {
        // Left Ctrl released
        CTRL_ACTIVE.store(false, Ordering::Relaxed);
        return;
    } else if scancode == 0x38 {
        // Left Alt pressed
        ALT_ACTIVE.store(true, Ordering::Relaxed);
        return;
    } else if scancode == 0xB8 {
        // Left Alt released
        ALT_ACTIVE.store(false, Ordering::Relaxed);
        return;
    }

    // Standard Key Press (Scancode < 0x80)
    if scancode < 0x80 {
        LAST_SCANCODE.store(scancode, Ordering::Relaxed);
        KEY_PRESS_COUNT.fetch_add(1, Ordering::Relaxed);
        let shift = SHIFT_ACTIVE.load(Ordering::Relaxed);
        let ctrl = CTRL_ACTIVE.load(Ordering::Relaxed);
        let alt = ALT_ACTIVE.load(Ordering::Relaxed);

        let ch_opt = if alt && scancode == 0x0F {
            Some('\u{83}') // Alt + Tab Task Switcher
        } else if ctrl {
            match scancode {
                0x2E => Some('\x03'), // Ctrl + C
                0x2F => Some('\x16'), // Ctrl + V
                0x2C => Some('\x1A'), // Ctrl + Z
                0x1F => Some('\x13'), // Ctrl + S
                0x1E => Some('\x01'), // Ctrl + A
                0x13 => Some('\x12'), // Ctrl + R (Run Dialog)
                0x0F => Some('\u{86}'), // Ctrl + Tab (Task View)
                _ => scancode_to_char(scancode, shift),
            }
        } else {
            scancode_to_char(scancode, shift)
        };

        if let Some(ch) = ch_opt {
            crate::diagnostics::serial::write_str("[KEY] ");
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            crate::diagnostics::serial::write_str(s);
            crate::diagnostics::serial::write_str("\r\n");
            LAST_KEY_CHAR.store(ch as u8, Ordering::Relaxed);
            push_char(ch);
        }
    }
}

pub fn scancode_to_char(code: u8, shift: bool) -> Option<char> {
    match code {
        0x01 => Some('\x1B'), // Esc
        0x3B => Some('\u{81}'), // F1 key (Help)
        0x3C => Some('\u{82}'), // F2 key (Rename)
        0x3D => Some('\u{83}'), // F3 key (Task Switcher)
        0x3E => Some('\u{84}'), // F4 key
        0x3F => Some('\u{85}'), // F5 key (Refresh)
        0x02 => Some(if shift { '!' } else { '1' }),
        0x03 => Some(if shift { '@' } else { '2' }),
        0x04 => Some(if shift { '#' } else { '3' }),
        0x05 => Some(if shift { '$' } else { '4' }),
        0x06 => Some(if shift { '%' } else { '5' }),
        0x07 => Some(if shift { '^' } else { '6' }),
        0x08 => Some(if shift { '&' } else { '7' }),
        0x09 => Some(if shift { '*' } else { '8' }),
        0x0A => Some(if shift { '(' } else { '9' }),
        0x0B => Some(if shift { ')' } else { '0' }),
        0x0C => Some(if shift { '_' } else { '-' }),
        0x0D => Some(if shift { '+' } else { '=' }),
        0x0E => Some('\x08'), // Backspace
        0x0F => Some('\t'),   // Tab
        0x10 => Some(if shift { 'Q' } else { 'q' }),
        0x11 => Some(if shift { 'W' } else { 'w' }),
        0x12 => Some(if shift { 'E' } else { 'e' }),
        0x13 => Some(if shift { 'R' } else { 'r' }),
        0x14 => Some(if shift { 'T' } else { 't' }),
        0x15 => Some(if shift { 'Y' } else { 'y' }),
        0x16 => Some(if shift { 'U' } else { 'u' }),
        0x17 => Some(if shift { 'I' } else { 'i' }),
        0x18 => Some(if shift { 'O' } else { 'o' }),
        0x19 => Some(if shift { 'P' } else { 'p' }),
        0x1A => Some(if shift { '{' } else { '[' }),
        0x1B => Some(if shift { '}' } else { ']' }),
        0x1C => Some('\n'),   // Enter
        0x1E => Some(if shift { 'A' } else { 'a' }),
        0x1F => Some(if shift { 'S' } else { 's' }),
        0x20 => Some(if shift { 'D' } else { 'd' }),
        0x21 => Some(if shift { 'F' } else { 'f' }),
        0x22 => Some(if shift { 'G' } else { 'g' }),
        0x23 => Some(if shift { 'H' } else { 'h' }),
        0x24 => Some(if shift { 'J' } else { 'j' }),
        0x25 => Some(if shift { 'K' } else { 'k' }),
        0x26 => Some(if shift { 'L' } else { 'l' }),
        0x27 => Some(if shift { ':' } else { ';' }),
        0x28 => Some(if shift { '"' } else { '\'' }),
        0x29 => Some(if shift { '~' } else { '`' }),
        0x2B => Some(if shift { '|' } else { '\\' }),
        0x2C => Some(if shift { 'Z' } else { 'z' }),
        0x2D => Some(if shift { 'X' } else { 'x' }),
        0x2E => Some(if shift { 'C' } else { 'c' }),
        0x2F => Some(if shift { 'V' } else { 'v' }),
        0x30 => Some(if shift { 'B' } else { 'b' }),
        0x31 => Some(if shift { 'N' } else { 'n' }),
        0x32 => Some(if shift { 'M' } else { 'm' }),
        0x33 => Some(if shift { '<' } else { ',' }),
        0x34 => Some(if shift { '>' } else { '.' }),
        0x35 => Some(if shift { '?' } else { '/' }),
        0x39 => Some(' '),
        0x47 => Some('\u{8B}'), // Keypad 7 / Home
        0x48 => Some('\u{87}'), // Keypad 8 / Up
        0x49 => Some('\u{8D}'), // Keypad 9 / Page Up
        0x4B => Some('\u{89}'), // Keypad 4 / Left
        0x4C => Some('5'),      // Keypad 5
        0x4D => Some('\u{8A}'), // Keypad 6 / Right
        0x4F => Some('\u{8C}'), // Keypad 1 / End
        0x50 => Some('\u{88}'), // Keypad 2 / Down
        0x51 => Some('\u{8E}'), // Keypad 3 / Page Down
        0x52 => Some('0'),      // Keypad 0 / Insert
        0x53 => Some('\x7F'),   // Delete key
        0x5B | 0x5C => Some('\u{80}'), // Windows Super Key
        _ => None,
    }
}
