//! Native COM1 16550-style early serial output. Hardware presence and VM
//! routing are unverified. Port instructions are confined to this module.
use crate::arch::x86_64::cpu;
const COM1: u16 = 0x3f8;
static mut READY: bool = false;

/// # Safety
/// This claims and reconfigures COM1 for early CorOS diagnostics.
pub unsafe fn initialize() -> bool {
    READY = false;
    if !probe_com1_scratch() { return false; }
    cpu::out8(COM1 + 1, 0x00);
    cpu::out8(COM1 + 3, 0x80);
    cpu::out8(COM1, 0x01);
    cpu::out8(COM1 + 1, 0x00);
    cpu::out8(COM1 + 3, 0x03);
    cpu::out8(COM1 + 2, 0xc7);
    cpu::out8(COM1 + 4, 0x0b);
    READY = true;
    true
}
unsafe fn probe_com1_scratch() -> bool {
    let saved = cpu::in8(COM1 + 7);
    cpu::out8(COM1 + 7, 0x5a);
    let first = cpu::in8(COM1 + 7);
    cpu::out8(COM1 + 7, 0xa5);
    let second = cpu::in8(COM1 + 7);
    cpu::out8(COM1 + 7, saved);
    scratch_values_match(first, second)
}
pub fn write_byte(byte: u8) {
    if !unsafe { READY } { return; }
    for _ in 0..100_000 {
        if unsafe { cpu::in8(COM1 + 5) } & 0x20 != 0 {
            unsafe { cpu::out8(COM1, byte); }
            return;
        }
        core::hint::spin_loop();
    }
}
pub fn write_str(text: &str) { for byte in text.bytes() { write_byte(byte); } }
pub fn write_u64(label: &str, mut value: u64) {
    write_str(label);
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    if value == 0 { digits[0] = b'0'; len = 1; }
    while value != 0 && len < digits.len() { digits[len] = b'0' + (value % 10) as u8; value /= 10; len += 1; }
    while len != 0 { len -= 1; write_byte(digits[len]); }
    write_str("\r\n");
}

#[cfg(test)]
mod tests {
    #[test]
    fn scratch_probe_requires_both_test_patterns_to_round_trip() {
        assert!(super::scratch_values_match(0x5a, 0xa5));
        assert!(!super::scratch_values_match(0xff, 0xff));
        assert!(!super::scratch_values_match(0x5a, 0xff));
    }
}

const fn scratch_values_match(first: u8, second: u8) -> bool {
    first == 0x5a && second == 0xa5
}
