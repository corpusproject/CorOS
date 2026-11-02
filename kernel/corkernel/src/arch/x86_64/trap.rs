//! x86_64 Trap & Interrupt implementation of the HAL `TrapOps` trait.

use crate::arch::traits::TrapOps;
use super::{gdt, idt};
use core::sync::atomic::{AtomicBool, Ordering};

static TRAPS_ACTIVE: AtomicBool = AtomicBool::new(false);

pub struct X86Trap;

impl TrapOps for X86Trap {
    fn initialize() {
        initialize();
    }

    fn register_handler(_vector: u8, _handler: usize) {
        // x86_64 IDT has pre-compiled assembly ISR stubs installed during idt::initialize()
    }

    fn is_active() -> bool {
        is_active()
    }
}

pub fn initialize() {
    unsafe {
        gdt::initialize();
        idt::initialize();
    }
    TRAPS_ACTIVE.store(true, Ordering::Release);
}

pub fn is_active() -> bool {
    TRAPS_ACTIVE.load(Ordering::Acquire)
}
