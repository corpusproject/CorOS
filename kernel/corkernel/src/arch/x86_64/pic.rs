//! Legacy 8259 PIC fallback. Initialization remaps then masks every line;
//! Legacy 8259 PIC: remap, mask every line, and explicitly unmask only after
//! IDT handlers and routing are ready.
use core::sync::atomic::{AtomicBool, Ordering};
use super::cpu;
const MASTER_CMD: u16 = 0x20; const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xa0; const SLAVE_DATA: u16 = 0xa1;
static ACTIVE: AtomicBool = AtomicBool::new(false);
unsafe fn io_wait() { unsafe { cpu::out8(0x80, 0); } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpuriousAction { Deliver, DropNoEoi, DropMasterCascadeEoi }

const fn spurious_action(vector: u8, in_service: u8) -> SpuriousAction {
    match vector {
        0x27 if in_service & 0x80 == 0 => SpuriousAction::DropNoEoi,
        0x2f if in_service & 0x80 == 0 => SpuriousAction::DropMasterCascadeEoi,
        _ => SpuriousAction::Deliver,
    }
}

/// Reports whether the legacy PIC has been remapped and masked.
/// This is a source-state check only; it does not prove firmware routing.
pub fn is_active() -> bool { ACTIVE.load(Ordering::Acquire) }

/// # Safety
/// Run once with interrupts disabled before enabling any PIC-routed IRQ.
pub unsafe fn initialize_masked() {
    unsafe {
        cpu::out8(MASTER_CMD, 0x11); cpu::out8(SLAVE_CMD, 0x11);
        io_wait();
        cpu::out8(MASTER_DATA, 0x20); cpu::out8(SLAVE_DATA, 0x28);
        io_wait();
        cpu::out8(MASTER_DATA, 4); cpu::out8(SLAVE_DATA, 2);
        io_wait();
        cpu::out8(MASTER_DATA, 1); cpu::out8(SLAVE_DATA, 1);
        io_wait();
        cpu::out8(MASTER_DATA, 0xff); cpu::out8(SLAVE_DATA, 0xff);
    }
    ACTIVE.store(true, Ordering::Release);
}
/// # Safety
/// Caller must have registered a handler and prepared the device route.
pub unsafe fn unmask(irq: u8) -> bool {
    if irq >= 16 || !ACTIVE.load(Ordering::Acquire)
        || !super::interrupts::has_pic_handler(32 + irq) { return false; }
    unsafe {
        let (port, bit) = if irq < 8 { (MASTER_DATA, irq) } else { (SLAVE_DATA, irq - 8) };
        let mask = cpu::in8(port);
        cpu::out8(port, mask & !(1 << bit));
        if irq >= 8 { let master = cpu::in8(MASTER_DATA); cpu::out8(MASTER_DATA, master & !(1 << 2)); }
    }
    true
}

/// Detects PIC IRQ7/IRQ15 spurious delivery before calling a registered
/// handler. Spurious IRQ7 gets no EOI; spurious IRQ15 acknowledges only the
/// master cascade. Returns true when the handler must be skipped.
pub(super) fn discard_spurious(vector: u8) -> bool {
    if !ACTIVE.load(Ordering::Acquire) { return false; }
    unsafe {
        match vector {
            0x27 => {
                cpu::out8(MASTER_CMD, 0x0b);
                spurious_action(vector, cpu::in8(MASTER_CMD)) == SpuriousAction::DropNoEoi
            }
            0x2f => {
                cpu::out8(SLAVE_CMD, 0x0b);
                if spurious_action(vector, cpu::in8(SLAVE_CMD)) == SpuriousAction::DropMasterCascadeEoi {
                    cpu::out8(MASTER_CMD, 0x20); true
                } else { false }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{spurious_action, SpuriousAction};

    #[test]
    fn pic_spurious_irq_policy_uses_controller_isr_state() {
        assert_eq!(spurious_action(0x27, 0), SpuriousAction::DropNoEoi);
        assert_eq!(spurious_action(0x27, 0x80), SpuriousAction::Deliver);
        assert_eq!(spurious_action(0x2f, 0), SpuriousAction::DropMasterCascadeEoi);
        assert_eq!(spurious_action(0x2f, 0x80), SpuriousAction::Deliver);
        assert_eq!(spurious_action(0x20, 0), SpuriousAction::Deliver);
    }
}

pub(super) fn eoi(vector: u8) {
    if !ACTIVE.load(Ordering::Acquire) || !(0x20..=0x2f).contains(&vector) { return; }
    unsafe {
        if vector >= 0x28 { cpu::out8(SLAVE_CMD, 0x20); }
        cpu::out8(MASTER_CMD, 0x20);
    }
}
