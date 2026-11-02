//! APIC discovery and an xAPIC mapped-MMIO register wrapper. No mapping is
//! installed here; x2APIC MSR access and IRQ routing remain unavailable.
use crate::arch::x86_64::cpu;
use core::ptr::NonNull;
const IA32_APIC_BASE: u32 = 0x1b;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicMode { XApic, X2Apic }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApicInfo { pub physical_base: u64, pub mode: ApicMode }
pub fn detect_local_apic() -> Option<LocalApicInfo> {
    let features = unsafe { core::arch::x86_64::__cpuid(1) };
    if features.edx & ((1 << 9) | (1 << 5)) != ((1 << 9) | (1 << 5)) { return None; }
    // SAFETY: IA32_APIC_BASE is the architectural APIC base MSR.
    let value = unsafe { cpu::read_msr(IA32_APIC_BASE) };
    if value & (1 << 11) == 0 { return None; }
    Some(LocalApicInfo { physical_base: value & 0x000f_ffff_ffff_f000, mode: if value & (1 << 10) != 0 { ApicMode::X2Apic } else { ApicMode::XApic } })
}

/// Access to a Local APIC after a caller has installed its UC MMIO mapping.
/// This wrapper does not create or own that mapping.
pub struct MappedLocalApic { base: NonNull<u32> }
impl MappedLocalApic {
    /// # Safety
    /// `base` must point to the complete xAPIC register page mapped as
    /// uncacheable MMIO, writable, and valid for this object's lifetime; the
    /// detected APIC mode must be `XApic` (the x2APIC MSR path is unavailable).
    pub unsafe fn from_mapped_mmio(base: NonNull<u32>) -> Self { Self { base } }
    fn register(&self, offset: usize) -> *mut u32 { unsafe { self.base.as_ptr().cast::<u8>().add(offset).cast::<u32>() } }
    pub fn apic_id(&self) -> u8 { (unsafe { self.register(0x20).read_volatile() } >> 24) as u8 }
    pub fn end_of_interrupt(&self) { unsafe { self.register(0xb0).write_volatile(0); } }
    /// Enables the APIC software interface and selects a spurious vector.
    /// # Safety
    /// The vector must be present in the active IDT and not assigned to another device.
    pub unsafe fn enable_spurious_vector(&self, vector: u8) -> bool {
        if !(32..=47).contains(&vector) { return false; }
        let value = unsafe { self.register(0xf0).read_volatile() };
        unsafe { self.register(0xf0).write_volatile((value & !0xff) | vector as u32 | (1 << 8)); }
        true
    }
    /// Programs a masked, one-shot timer. The initial count must be obtained by
    /// hardware calibration; this API does not claim a calibrated duration.
    /// # Safety
    /// The vector must be installed in the active IDT before the timer is unmasked.
    pub unsafe fn program_masked_timer(&self, vector: u8, initial_count: u32) -> bool {
        if !(32..=47).contains(&vector) || initial_count == 0 { return false; }
        unsafe {
            self.register(0x320).write_volatile((1 << 16) | vector as u32);
            self.register(0x3e0).write_volatile(0x3); // divide by 16
            self.register(0x380).write_volatile(initial_count);
        }
        true
    }
    pub fn mask_timer(&self) { unsafe { self.register(0x320).write_volatile((1 << 16) | 0x40); } }

    /// Programs an unmasked periodic timer for the system scheduler.
    ///
    /// # Safety
    /// Vector must be valid and installed in IDT.
    pub unsafe fn start_periodic_timer(&self, vector: u8, initial_count: u32) -> bool {
        if !(32..=47).contains(&vector) || initial_count == 0 { return false; }
        unsafe {
            // Divide by 16
            self.register(0x3e0).write_volatile(0x3);
            // Periodic mode (bit 17 = 1, bit 16 mask = 0)
            self.register(0x320).write_volatile((1 << 17) | vector as u32);
            // Set initial counter
            self.register(0x380).write_volatile(initial_count);
        }
        true
    }
}

unsafe impl Send for MappedLocalApic {}
unsafe impl Sync for MappedLocalApic {}

static GLOBAL_APIC: crate::sync::SpinLock<Option<MappedLocalApic>> = crate::sync::SpinLock::new(None);

/// Installs the global Local APIC instance for system IRQs and EOI signaling.
pub fn set_global_apic(apic: MappedLocalApic) {
    let mut guard = GLOBAL_APIC.lock_irqsave();
    *guard = Some(apic);
}

/// Dispatches an End of Interrupt (EOI) to the local APIC.
pub fn send_eoi() {
    let guard = GLOBAL_APIC.lock_irqsave();
    if let Some(apic) = guard.as_ref() {
        apic.end_of_interrupt();
    }
}

