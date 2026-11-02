#![no_std]
//! `corinput` — CorOS Linux `evdev` Input Subsystem, Keymaps, Multi-Touch Gesture & Gamepad Engine.
//!
//! Provides a Linux-compatible input stack in pure `#![no_std]` Rust:
//! 1. [`evdev_core`]: 24-byte `InputEvent` packing/unpacking, event codes, timestamps, and client ring queues.
//! 2. [`keymap_xkb`]: Keyboard scan code translation, modifier state machine, US/TR-Q layouts, and dead-key compose.
//! 3. [`autorepeat_typematic`]: Typematic delay and rate timer progression with repeated event generation.
//! 4. [`mt_protocol_b`]: Multi-Touch Protocol Type B stateful slot tracking, tracking IDs, and contact lifecycle.
//! 5. [`touchpad_gestures`]: Precision touchpad palm rejection boundary, 2-finger scroll velocity, and pinch-to-zoom.
//! 6. [`gamepad_hid`]: Gamepad analog stick normalization, radial deadzones, trigger pressure, and HID rumble reports.
//! 7. [`serio_bus`]: PS/2 serio bus port command response processing and packet decoding for keyboard/mouse.
//! 8. [`uinput_virtual`]: Userspace virtual input device synthesizer (`/dev/uinput`), `UI_SET_EVBIT`, and event synthesis.
//! 9. [`led_triggers`]: Kernel LED class triggers and keyboard LED state changes on NumLock, CapsLock, ScrollLock.

extern crate alloc;

pub mod autorepeat_typematic;
pub mod evdev_core;
pub mod gamepad_hid;
pub mod keymap_xkb;
pub mod led_triggers;
pub mod mt_protocol_b;
pub mod serio_bus;
pub mod touchpad_gestures;
pub mod uinput_virtual;

pub use autorepeat_typematic::{TypematicConfig, TypematicRepeatState};
pub use evdev_core::{abs_codes, ev_types, key_codes, rel_codes, syn_codes, EvdevClientQueue, InputEvent};
pub use gamepad_hid::{gamepad_buttons, GamepadFilter, GamepadState, RumbleEffect};
pub use keymap_xkb::{
    modifiers, ps2_scancode_to_keycode, DeadKeyState, KeymapLayout, XkbKeyboardTranslator,
};
pub use led_triggers::{KeyboardLedController, LedIndicator, LedTrigger};
pub use mt_protocol_b::{MtSlot, MtSlotTable};
pub use serio_bus::{ps2_commands, Ps2KeyEvent, Ps2MousePacket, SerioPort, SerioPortType};
pub use touchpad_gestures::{int_distance, TouchpadGesture, TouchpadGestureRecognizer};
pub use uinput_virtual::{uinput_ioctls, AbsAxisInfo, VirtualInputDevice};

/// Executes comprehensive authentic self-tests across all 9 `corinput` modules.
/// Returns the dynamic count of passed tests (> 0).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. evdev_core: 24-byte InputEvent packing/unpacking, event codes, timestamps, and ring buffer queue
    if test_evdev_core() {
        passed += 1;
    }

    // 2. keymap_xkb: keyboard scan code to keycode translation, modifier state machine (Shift, Ctrl, Alt, CapsLock)
    if test_keymap_xkb() {
        passed += 1;
    }

    // 3. autorepeat_typematic: typematic delay and rate timer progression, repeated event generation
    if test_autorepeat_typematic() {
        passed += 1;
    }

    // 4. mt_protocol_b: multi-touch slot tracking, tracking ID assignment, touch contact lifecycle
    if test_mt_protocol_b() {
        passed += 1;
    }

    // 5. touchpad_gestures: 2-finger scroll velocity, pinch-to-zoom calculation, palm rejection boundary
    if test_touchpad_gestures() {
        passed += 1;
    }

    // 6. gamepad_hid: analog stick normalization, radial deadzone calculation, trigger pressure, rumble packet
    if test_gamepad_hid() {
        passed += 1;
    }

    // 7. serio_bus: PS/2 serio bus port command response and packet decoding
    if test_serio_bus() {
        passed += 1;
    }

    // 8. uinput_virtual: virtual input device creation, UI_SET_EVBIT, event synthesis
    if test_uinput_virtual() {
        passed += 1;
    }

    // 9. led_triggers: LED state changes on NumLock, CapsLock, ScrollLock
    if test_led_triggers() {
        passed += 1;
    }

    passed
}

fn test_evdev_core() -> bool {
    // 1. Verify structure size matches standard Linux 24-byte input_event
    if core::mem::size_of::<InputEvent>() != 24 {
        return false;
    }

    // 2. Verify packing into 24-byte little-endian wire format
    let original = InputEvent::new(1_700_000_000, 456_789, ev_types::EV_KEY, key_codes::KEY_A, 1);
    let bytes = original.to_bytes();
    if bytes.len() != 24 {
        return false;
    }

    // 3. Verify unpacking from wire format restores exact fields
    let unpacked = InputEvent::from_bytes(&bytes);
    if unpacked != original {
        return false;
    }

    // 4. Verify ring buffer enqueue, capacity enforcement, SYN_DROPPED on overflow, and dequeue
    let mut queue = EvdevClientQueue::new(3);
    if !queue.is_empty() || queue.len() != 0 {
        return false;
    }

    let ev1 = InputEvent::new(1, 0, ev_types::EV_KEY, key_codes::KEY_1, 1);
    let ev2 = InputEvent::new(1, 1, ev_types::EV_KEY, key_codes::KEY_2, 1);
    let ev3 = InputEvent::new(1, 2, ev_types::EV_KEY, key_codes::KEY_3, 1);
    queue.push_event(ev1);
    queue.push_event(ev2);
    queue.push_event(ev3);
    if queue.len() != 3 {
        return false;
    }

    // Overflow attempt: queue is at max capacity 3
    let ev_overflow = InputEvent::new(1, 3, ev_types::EV_KEY, key_codes::KEY_A, 1);
    queue.push_event(ev_overflow);
    if queue.len() != 3 || !queue.dropped_overflow {
        return false;
    }

    // Pop one event to make room
    let popped1 = queue.pop_event();
    if popped1 != Some(ev1) || queue.len() != 2 {
        return false;
    }

    // Push new event: must inject SYN_DROPPED first, then the event
    // Queue capacity is 3; with 2 existing items [ev2, ev3], fitting 2 new items
    // (SYN_DROPPED + ev_after) requires oldest ev2 to be dropped, yielding [ev3, SYN_DROPPED, ev_after].
    let ev_after = InputEvent::new(2, 0, ev_types::EV_KEY, key_codes::KEY_B, 1);
    queue.push_event(ev_after);
    if queue.dropped_overflow || queue.len() != 3 {
        return false;
    }

    let popped3 = queue.pop_event();
    let popped_syn = queue.pop_event();
    let popped_after = queue.pop_event();

    if popped3 != Some(ev3)
        || !matches!(popped_syn, Some(e) if e.event_type == ev_types::EV_SYN && e.code == syn_codes::SYN_DROPPED)
        || popped_after != Some(ev_after)
        || !queue.is_empty()
    {
        return false;
    }

    // Secondary verification: Recovery with ample capacity (no drop needed)
    let mut q2 = EvdevClientQueue::new(4);
    q2.push_event(ev1);
    q2.push_event(ev2);
    q2.push_event(ev3);
    let ev4 = InputEvent::new(1, 4, ev_types::EV_KEY, key_codes::KEY_C, 1);
    q2.push_event(ev4);
    // Overflow attempt: queue is at max capacity 4
    q2.push_event(ev_overflow);
    if !q2.dropped_overflow || q2.len() != 4 {
        return false;
    }
    // Pop two events so len is 2
    let _ = q2.pop_event();
    let _ = q2.pop_event();
    if q2.len() != 2 {
        return false;
    }
    // Push new event: exactly 2 slots available (4 - 2), so both SYN_DROPPED and ev_after fit
    q2.push_event(ev_after);
    if q2.dropped_overflow || q2.len() != 4 {
        return false;
    }
    let p3 = q2.pop_event();
    let p4 = q2.pop_event();
    let p_syn = q2.pop_event();
    let p_after = q2.pop_event();

    p3 == Some(ev3)
        && p4 == Some(ev4)
        && matches!(p_syn, Some(e) if e.event_type == ev_types::EV_SYN && e.code == syn_codes::SYN_DROPPED)
        && p_after == Some(ev_after)
        && q2.is_empty()
}

fn test_keymap_xkb() -> bool {
    // 1. Verify PS/2 Set 1 scancode to Linux keycode translation
    if ps2_scancode_to_keycode(0x1E, false) != Some(key_codes::KEY_A) {
        return false;
    }
    if ps2_scancode_to_keycode(0x2A, false) != Some(key_codes::KEY_LEFTSHIFT) {
        return false;
    }
    if ps2_scancode_to_keycode(0x3A, false) != Some(key_codes::KEY_CAPSLOCK) {
        return false;
    }
    if ps2_scancode_to_keycode(0x1D, false) != Some(key_codes::KEY_LEFTCTRL) {
        return false;
    }
    if ps2_scancode_to_keycode(0x38, false) != Some(key_codes::KEY_LEFTALT) {
        return false;
    }
    if ps2_scancode_to_keycode(0x1D, true) != Some(key_codes::KEY_RIGHTCTRL) {
        return false;
    }
    if ps2_scancode_to_keycode(0x5B, true) != Some(125) {
        return false;
    }

    // 2. Verify modifier state machine (Shift, Ctrl, Alt, CapsLock)
    let mut translator = XkbKeyboardTranslator::new(KeymapLayout::UsQwerty);
    if translator.is_shift_active() || translator.is_caps_lock_active() || translator.is_ctrl_active() || translator.is_alt_active() {
        return false;
    }

    // Initial lowercase 'a'
    if translator.translate_keycode(key_codes::KEY_A) != Some('a') {
        return false;
    }

    // Shift pressed -> uppercase 'A'
    translator.update_modifier(key_codes::KEY_LEFTSHIFT, true);
    if !translator.is_shift_active() || translator.translate_keycode(key_codes::KEY_A) != Some('A') {
        return false;
    }

    // Shift released -> lowercase 'a'
    translator.update_modifier(key_codes::KEY_LEFTSHIFT, false);
    if translator.is_shift_active() || translator.translate_keycode(key_codes::KEY_A) != Some('a') {
        return false;
    }

    // CapsLock toggled on -> uppercase 'A'
    translator.update_modifier(key_codes::KEY_CAPSLOCK, true);
    if !translator.is_caps_lock_active() || translator.translate_keycode(key_codes::KEY_A) != Some('A') {
        return false;
    }

    // Key release of CapsLock must retain locked state
    translator.update_modifier(key_codes::KEY_CAPSLOCK, false);
    if !translator.is_caps_lock_active() {
        return false;
    }

    // Both CapsLock and Shift active -> XOR inversion produces lowercase 'a'
    translator.update_modifier(key_codes::KEY_LEFTSHIFT, true);
    if translator.translate_keycode(key_codes::KEY_A) != Some('a') {
        return false;
    }
    translator.update_modifier(key_codes::KEY_LEFTSHIFT, false);

    // CapsLock toggled off
    translator.update_modifier(key_codes::KEY_CAPSLOCK, true);
    if translator.is_caps_lock_active() || translator.translate_keycode(key_codes::KEY_A) != Some('a') {
        return false;
    }

    // Ctrl and Alt tracking
    translator.update_modifier(key_codes::KEY_LEFTCTRL, true);
    if !translator.is_ctrl_active() {
        return false;
    }
    translator.update_modifier(key_codes::KEY_LEFTCTRL, false);

    translator.update_modifier(key_codes::KEY_LEFTALT, true);
    if !translator.is_alt_active() {
        return false;
    }
    translator.update_modifier(key_codes::KEY_LEFTALT, false);

    // 3. Verify Turkish-Q layout mappings
    let mut tr_translator = XkbKeyboardTranslator::new(KeymapLayout::TurkishQ);
    if tr_translator.translate_keycode(23) != Some('ı') {
        return false;
    }
    tr_translator.update_modifier(key_codes::KEY_LEFTSHIFT, true);
    if tr_translator.translate_keycode(23) != Some('I') {
        return false;
    }
    if tr_translator.translate_keycode(26) != Some('Ğ') {
        return false;
    }

    // 4. Verify dead-key compose (Acute + 'e' -> 'é')
    translator.set_dead_key(DeadKeyState::Acute);
    let composed = translator.translate_keycode(key_codes::KEY_E);
    composed == Some('é') && translator.dead_key == DeadKeyState::None
}

fn test_autorepeat_typematic() -> bool {
    let mut repeat = TypematicRepeatState::new(TypematicConfig {
        delay_ms: 250,
        period_ms: 33,
    });

    if repeat.is_active() || repeat.poll_repeat(500).is_some() {
        return false;
    }

    // Press key 30 at time 1000ms
    repeat.key_down(key_codes::KEY_A, 1000);
    if !repeat.is_active() || repeat.active_key() != Some(key_codes::KEY_A) {
        return false;
    }

    // Before delay (250ms), no repeats emitted
    if repeat.poll_repeat(1100).is_some() || repeat.poll_repeat(1249).is_some() {
        return false;
    }

    // At t = 1250ms (1000 + 250), first repeat triggers
    let r1 = repeat.poll_repeat(1250);
    if r1 != Some(key_codes::KEY_A) {
        return false;
    }

    // Between periods (33ms), no repeat
    if repeat.poll_repeat(1260).is_some() {
        return false;
    }

    // At t = 1283ms (1250 + 33), second repeat triggers
    let r2 = repeat.poll_repeat(1283);
    if r2 != Some(key_codes::KEY_A) {
        return false;
    }

    // At t = 1316ms (1283 + 33), third repeat triggers
    let r3 = repeat.poll_repeat(1316);
    if r3 != Some(key_codes::KEY_A) {
        return false;
    }

    // Key released at t = 1320ms -> repeats immediately cease
    repeat.key_up(key_codes::KEY_A);
    !repeat.is_active() && repeat.poll_repeat(1349).is_none()
}

fn test_mt_protocol_b() -> bool {
    let mut table = MtSlotTable::new(4);
    if table.count_active_contacts() != 0 || table.find_free_slot() != Some(0) {
        return false;
    }

    // Contact 1 down on slot 0
    table.select_slot(0);
    table.set_contact_down(150, 250, 70);
    if table.count_active_contacts() != 1 {
        return false;
    }

    let slot0 = match table.get_slot(0) {
        Some(s) => s,
        None => return false,
    };
    if !slot0.is_active() || slot0.tracking_id != 1 || slot0.x != 150 || slot0.y != 250 || slot0.pressure != 70 {
        return false;
    }

    // Contact 2 down on slot 1
    table.select_slot(1);
    table.set_contact_down(450, 550, 85);
    if table.count_active_contacts() != 2 {
        return false;
    }
    let slot1 = match table.get_slot(1) {
        Some(s) => s,
        None => return false,
    };
    if !slot1.is_active() || slot1.tracking_id != 2 {
        return false;
    }

    // Move contact on slot 0 (tracking ID must be preserved)
    table.select_slot(0);
    table.set_contact_move(160, 260, 75);
    let slot0_moved = match table.get_slot(0) {
        Some(s) => s,
        None => return false,
    };
    if slot0_moved.tracking_id != 1 || slot0_moved.x != 160 || slot0_moved.y != 260 {
        return false;
    }

    // Verify active tracking IDs
    let tids = table.active_tracking_ids();
    if tids.len() != 2 || tids[0] != 1 || tids[1] != 2 {
        return false;
    }

    // Contact 1 up on slot 0 -> slot becomes inactive (tracking_id = -1)
    table.select_slot(0);
    table.set_contact_up();
    if table.get_slot(0).map(|s| s.is_active()) != Some(false) || table.count_active_contacts() != 1 {
        return false;
    }

    // Contact 2 up on slot 1
    table.select_slot(1);
    table.set_contact_up();
    table.count_active_contacts() == 0
}

fn test_touchpad_gestures() -> bool {
    let mut recognizer = TouchpadGestureRecognizer::new();

    // 1. Palm rejection boundary: contacts at pad boundary edges or excessive pressure
    if !recognizer.is_palm(20, 300, 50) {
        return false;
    }
    if !recognizer.is_palm(980, 300, 50) {
        return false;
    }
    if !recognizer.is_palm(500, 300, 200) {
        return false;
    }
    if recognizer.is_palm(500, 300, 60) {
        return false;
    }

    let palm_gesture = recognizer.process_contacts(&[(20, 300, 50)]);
    if palm_gesture != TouchpadGesture::None {
        return false;
    }

    // 2. Single tap recognition
    let tap = recognizer.process_contacts(&[(500, 300, 60)]);
    if tap != (TouchpadGesture::SingleTap { x: 500, y: 300 }) {
        return false;
    }

    // 3. Two-finger scroll and scroll velocity calculation
    let _first_frame = recognizer.process_contacts(&[(400, 300, 60), (500, 300, 60)]);
    let scroll_gesture = recognizer.process_contacts(&[(400, 330, 60), (500, 330, 60)]);
    if scroll_gesture != (TouchpadGesture::TwoFingerScroll { dx: 0, dy: 30 }) {
        return false;
    }
    let (vx, vy) = recognizer.calculate_scroll_velocity(16); // 16ms frame delta
    if vy < 1500 || vx != 0 {
        return false;
    }

    // 4. Pinch-to-zoom calculation
    // Reset contacts: fingers at distance 100
    let _pinch_start = recognizer.process_contacts(&[(400, 300, 60), (500, 300, 60)]);
    // Fingers spread apart to distance 200 (delta = +100 >= min_pinch_distance)
    let pinch_gesture = recognizer.process_contacts(&[(350, 300, 60), (550, 300, 60)]);
    match pinch_gesture {
        TouchpadGesture::PinchZoom { scale_delta } => scale_delta > 0.5,
        _ => false,
    }
}

fn test_gamepad_hid() -> bool {
    let filter = GamepadFilter::new(4000);

    // 1. Radial deadzone filtering inside boundary
    let dist_inner = filter.radial_distance(1200, -1600); // 2000 < 4000
    if dist_inner != 2000 {
        return false;
    }
    if filter.filter_stick(1200, -1600) != (0, 0) {
        return false;
    }
    if filter.normalize_stick(1200, -1600) != (0.0, 0.0) {
        return false;
    }

    // 2. Radial distance and stick normalization outside deadzone
    let dist_outer = filter.radial_distance(16000, 12000); // 20000 > 4000
    if dist_outer != 20000 {
        return false;
    }
    if filter.filter_stick(16000, 12000) != (16000, 12000) {
        return false;
    }
    let (nx, ny) = filter.normalize_stick(16000, 12000);
    if nx <= 0.4 || ny <= 0.3 || (nx * nx + ny * ny) > 1.01 {
        return false;
    }

    // 3. Trigger pressure calculation
    if GamepadFilter::normalize_trigger(10, 15) != 0.0 {
        return false;
    }
    let trig_pressure = GamepadFilter::normalize_trigger(135, 15);
    if trig_pressure < 0.49 || trig_pressure > 0.51 {
        return false;
    }
    if GamepadFilter::trigger_pressure_percent(135, 15) != 50 {
        return false;
    }

    // 4. Force feedback rumble packet generation
    let rumble = RumbleEffect::new(0x8000, 0x4000, 750);
    let packet = rumble.create_rumble_packet();
    packet[0] == 0x05
        && packet[1] == 0x03
        && packet[3] == 0x40
        && packet[5] == 0x80
        && u16::from_le_bytes([packet[6], packet[7]]) == 750
}

fn test_serio_bus() -> bool {
    let mut kbd_port = SerioPort::new(SerioPortType::I8042Kbd);
    let mut aux_port = SerioPort::new(SerioPortType::I8042Aux);

    // 1. Port command response
    let reset_resp = kbd_port.process_command(ps2_commands::CMD_RESET);
    if reset_resp != [ps2_commands::RESP_ACK, ps2_commands::RESP_BAT_OK] {
        return false;
    }

    let kbd_ident = kbd_port.process_command(ps2_commands::CMD_IDENTIFY);
    if kbd_ident != [ps2_commands::RESP_ACK, 0xAB, 0x83] {
        return false;
    }

    let mouse_ident = aux_port.process_command(ps2_commands::CMD_IDENTIFY);
    if mouse_ident != [ps2_commands::RESP_ACK, 0x00] {
        return false;
    }

    // 2. PS/2 mouse packet decoding
    // Flags 0x29 (0b00101001: Y negative, sync bit set, left button pressed), dx = 25, dy = -15 (241 - 256 = -15)
    let mouse_packet = [0x29u8, 25u8, 241u8];
    let decoded_mouse = match SerioPort::decode_mouse_packet(&mouse_packet) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !decoded_mouse.left_button || decoded_mouse.right_button || decoded_mouse.dx != 25 || decoded_mouse.dy != -15 {
        return false;
    }

    // 3. PS/2 keyboard stream packet decoding
    // Make event for key 0x1E ('A')
    let key_make = match kbd_port.decode_keyboard_byte(0x1E) {
        Some(k) => k,
        None => return false,
    };
    if key_make.scancode != 0x1E || key_make.is_break || key_make.is_extended {
        return false;
    }

    // Break event for key 0x1E ('A' released: 0x9E)
    let key_break = match kbd_port.decode_keyboard_byte(0x9E) {
        Some(k) => k,
        None => return false,
    };
    if key_break.scancode != 0x1E || !key_break.is_break || key_break.is_extended {
        return false;
    }

    // Extended key prefix sequence (0xE0 followed by 0x5B for Super key)
    if kbd_port.decode_keyboard_byte(0xE0).is_some() {
        return false;
    }
    let key_ext = match kbd_port.decode_keyboard_byte(0x5B) {
        Some(k) => k,
        None => return false,
    };
    key_ext.scancode == 0x5B && !key_ext.is_break && key_ext.is_extended
}

fn test_uinput_virtual() -> bool {
    let mut dev = VirtualInputDevice::new("virt-input-kb", 0x1234, 0xABCD);
    if dev.is_created {
        return false;
    }

    // Event synthesis before creation must fail
    if dev.synthesize_event(ev_types::EV_KEY, key_codes::KEY_A, 1, 10, 0).is_ok() {
        return false;
    }

    // Configure device capability bits
    dev.set_evbit(ev_types::EV_KEY);
    dev.set_evbit(ev_types::EV_SYN);
    dev.set_keybit(key_codes::KEY_A);

    if !dev.has_evbit(ev_types::EV_KEY) || !dev.has_keybit(key_codes::KEY_A) {
        return false;
    }
    if dev.has_evbit(ev_types::EV_REL) || dev.has_keybit(key_codes::KEY_B) {
        return false;
    }

    // Create virtual device
    if !dev.create_device() || !dev.is_created {
        return false;
    }

    // Synthesize registered key press
    let ev = match dev.synthesize_event(ev_types::EV_KEY, key_codes::KEY_A, 1, 100, 200) {
        Ok(e) => e,
        Err(_) => return false,
    };
    if ev.event_type != ev_types::EV_KEY || ev.code != key_codes::KEY_A || ev.value != 1 {
        return false;
    }

    // Synthesizing unregistered key or event type must fail
    if dev.synthesize_event(ev_types::EV_KEY, key_codes::KEY_B, 1, 100, 200).is_ok() {
        return false;
    }
    if dev.synthesize_event(ev_types::EV_REL, rel_codes::REL_X, 5, 100, 200).is_ok() {
        return false;
    }

    // Synthesize key event pair (press + syn report)
    let [key_ev, syn_ev] = match dev.synthesize_key_event(key_codes::KEY_A, true, 150, 300) {
        Ok(pair) => pair,
        Err(_) => return false,
    };
    key_ev.value == 1 && syn_ev.event_type == ev_types::EV_SYN && syn_ev.code == syn_codes::SYN_REPORT
}

fn test_led_triggers() -> bool {
    let mut leds = KeyboardLedController::new();

    // Initial state: all LEDs unlit
    if leds.is_caps_lock_lit() || leds.is_num_lock_lit() || leds.is_scroll_lock_lit() {
        return false;
    }
    if leds.to_ps2_led_byte() != 0x00 {
        return false;
    }

    // CapsLock on -> bit 2 set
    leds.set_caps_lock(true);
    if !leds.is_caps_lock_lit() || leds.caps_lock.brightness != 255 || leds.to_ps2_led_byte() != 0x04 {
        return false;
    }

    // NumLock on -> bit 1 set (0x04 | 0x02 = 0x06)
    leds.set_num_lock(true);
    if !leds.is_num_lock_lit() || leds.to_ps2_led_byte() != 0x06 {
        return false;
    }

    // ScrollLock on -> bit 0 set (0x06 | 0x01 = 0x07)
    leds.set_scroll_lock(true);
    if !leds.is_scroll_lock_lit() || leds.to_ps2_led_byte() != 0x07 {
        return false;
    }

    // Turn off CapsLock -> bit 2 cleared (0x03)
    leds.set_caps_lock(false);
    if leds.is_caps_lock_lit() || leds.to_ps2_led_byte() != 0x03 {
        return false;
    }

    // Update from XKB modifier bitflags
    leds.update_from_modifiers(modifiers::LOCK_CAPS);
    if !leds.is_caps_lock_lit() || leds.is_num_lock_lit() {
        return false;
    }

    leds.update_from_modifiers(modifiers::NUM_LOCK);
    !leds.is_caps_lock_lit() && leds.is_num_lock_lit()
}
