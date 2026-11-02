//! Bounded static IRQ registry. Handler context is interrupt context: handlers
//! must not block, allocate, log through a lock, or call scheduler code.
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use super::idt::ExceptionFrame;

pub const FIRST_IRQ_VECTOR: u8 = 32;
pub const LAST_IRQ_VECTOR: u8 = 47;
pub type IrqHandler = extern "efiapi" fn(&ExceptionFrame);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError { NotIrqVector, AlreadyRegistered, ControllerUnavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InterruptSource { Unknown = 0, LegacyPic = 1, LocalApicTimer = 2, LocalApicError = 3, IoApic = 4, SpuriousLocalApic = 5, CpuException = 6 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EoiController { None, LegacyPic, LocalApic, Unknown }

pub const fn eoi_controller(source: InterruptSource) -> EoiController {
    match source {
        InterruptSource::LegacyPic => EoiController::LegacyPic,
        InterruptSource::LocalApicTimer | InterruptSource::LocalApicError | InterruptSource::IoApic => EoiController::LocalApic,
        InterruptSource::SpuriousLocalApic | InterruptSource::CpuException => EoiController::None,
        InterruptSource::Unknown => EoiController::Unknown,
    }
}
static HANDLERS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
static SOURCES: [AtomicU8; 16] = [const { AtomicU8::new(InterruptSource::Unknown as u8) }; 16];

pub const fn is_exception(vector: u8) -> bool { vector < 32 }
pub const fn is_irq(vector: u8) -> bool { vector >= FIRST_IRQ_VECTOR && vector <= LAST_IRQ_VECTOR }

/// Registers a legacy PIC handler while its controller is initialized/masked.
/// APIC and IOAPIC registration is deliberately not exposed yet.
/// # Safety
/// Caller must keep this PIC line masked and local interrupts disabled until
/// registration completes; this kernel has no SMP-safe publication protocol.
pub unsafe fn register_pic_irq(vector: u8, handler: IrqHandler) -> Result<(), RegisterError> {
    if !is_irq(vector) { return Err(RegisterError::NotIrqVector); }
    if !super::pic::is_active() { return Err(RegisterError::ControllerUnavailable); }
    let index = (vector - FIRST_IRQ_VECTOR) as usize;
    HANDLERS[index]
        .compare_exchange(0, handler as usize, Ordering::Release, Ordering::Relaxed)
        .map(|_| {
            SOURCES[index].store(InterruptSource::LegacyPic as u8, Ordering::Release);
        }).map_err(|_| RegisterError::AlreadyRegistered)
}

/// Registers a Local APIC interrupt handler for the given vector.
pub unsafe fn register_apic_irq(vector: u8, source: InterruptSource, handler: IrqHandler) -> Result<(), RegisterError> {
    if !is_irq(vector) { return Err(RegisterError::NotIrqVector); }
    let index = (vector - FIRST_IRQ_VECTOR) as usize;
    HANDLERS[index]
        .compare_exchange(0, handler as usize, Ordering::Release, Ordering::Relaxed)
        .map(|_| {
            SOURCES[index].store(source as u8, Ordering::Release);
        }).map_err(|_| RegisterError::AlreadyRegistered)
}

pub(super) fn has_pic_handler(vector: u8) -> bool {
    if !is_irq(vector) { return false; }
    let index = (vector - FIRST_IRQ_VECTOR) as usize;
    SOURCES[index].load(Ordering::Acquire) == InterruptSource::LegacyPic as u8
        && HANDLERS[index].load(Ordering::Acquire) != 0
}

pub(super) fn dispatch(frame: &ExceptionFrame) {
    if frame.vector > u8::MAX as u64 { crate::arch::x86_64::idt::fatal_exception(frame); }
    let vector = frame.vector as u8;
    if !is_irq(vector) { crate::arch::x86_64::idt::fatal_exception(frame); }
    let index = (vector - FIRST_IRQ_VECTOR) as usize;
    let source = match SOURCES[index].load(Ordering::Acquire) as u8 {
        1 => InterruptSource::LegacyPic,
        2 => InterruptSource::LocalApicTimer,
        3 => InterruptSource::LocalApicError,
        4 => InterruptSource::IoApic,
        5 => InterruptSource::SpuriousLocalApic,
        _ => InterruptSource::Unknown,
    };
    match eoi_controller(source) {
        EoiController::LegacyPic => {
            if super::pic::discard_spurious(vector) { return; }
        }
        EoiController::LocalApic => {}
        EoiController::Unknown => crate::arch::x86_64::idt::fatal_exception(frame),
        EoiController::None => return,
    }
    let slot = &HANDLERS[index];
    let function = slot.load(Ordering::Acquire);
    if function == 0 { crate::arch::x86_64::idt::fatal_exception(frame); }
    // SAFETY: only register_pic_irq or register_apic_irq publishes an ABI-compatible function pointer.
    let handler: IrqHandler = unsafe { core::mem::transmute(function) };
    handler(frame);
    match eoi_controller(source) {
        EoiController::LegacyPic => {
            super::pic::eoi(vector);
            super::apic::send_eoi();
        }
        EoiController::LocalApic => super::apic::send_eoi(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eoi_policy_separates_sources_and_spurious_interrupts() {
        assert_eq!(eoi_controller(InterruptSource::LegacyPic), EoiController::LegacyPic);
        assert_eq!(eoi_controller(InterruptSource::LocalApicTimer), EoiController::LocalApic);
        assert_eq!(eoi_controller(InterruptSource::LocalApicError), EoiController::LocalApic);
        assert_eq!(eoi_controller(InterruptSource::IoApic), EoiController::LocalApic);
        assert_eq!(eoi_controller(InterruptSource::SpuriousLocalApic), EoiController::None);
        assert_eq!(eoi_controller(InterruptSource::CpuException), EoiController::None);
        assert_eq!(eoi_controller(InterruptSource::Unknown), EoiController::Unknown);
    }
    #[test] fn vectors_separate_cpu_faults_from_legacy_irqs() {
        assert!(is_exception(14)); assert!(!is_irq(14));
        assert!(is_irq(32)); assert!(is_irq(47)); assert!(!is_irq(48));
    }
}
