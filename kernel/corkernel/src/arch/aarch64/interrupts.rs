//! AArch64 Interrupts, VBAR_EL1 Exception Vectors, and ARM GICv2/v3 Driver.

use crate::arch::traits::TrapOps;
use core::sync::atomic::{AtomicBool, Ordering};

pub const VBAR_ALIGN: usize = 2048;

// Offsets for the 16 VBAR_EL1 exception vectors
pub const VEC_CUR_EL_SP0_SYNC: usize   = 0x000;
pub const VEC_CUR_EL_SP0_IRQ: usize    = 0x080;
pub const VEC_CUR_EL_SP0_FIQ: usize    = 0x100;
pub const VEC_CUR_EL_SP0_SERROR: usize = 0x180;
pub const VEC_CUR_EL_SPX_SYNC: usize   = 0x200;
pub const VEC_CUR_EL_SPX_IRQ: usize    = 0x280;
pub const VEC_CUR_EL_SPX_FIQ: usize    = 0x300;
pub const VEC_CUR_EL_SPX_SERROR: usize = 0x380;
pub const VEC_LOWER_AARCH64_SYNC: usize   = 0x400;
pub const VEC_LOWER_AARCH64_IRQ: usize    = 0x480;
pub const VEC_LOWER_AARCH64_FIQ: usize    = 0x500;
pub const VEC_LOWER_AARCH64_SERROR: usize = 0x580;
pub const VEC_LOWER_AARCH32_SYNC: usize   = 0x600;
pub const VEC_LOWER_AARCH32_IRQ: usize    = 0x680;
pub const VEC_LOWER_AARCH32_FIQ: usize    = 0x700;
pub const VEC_LOWER_AARCH32_SERROR: usize = 0x780;

/// Saved AArch64 exception register frame.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AArch64ExceptionFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64, // Frame pointer (FP)
    pub x30: u64, // Link register (LR)
    pub sp: u64,
    pub elr: u64,  // Exception Link Register (PC where exception occurred)
    pub spsr: u64, // Saved Process Status Register
    pub esr: u64,  // Exception Syndrome Register
    pub far: u64,  // Fault Address Register
}

// ARM GICv2 Hardware MMIO Register Offsets
pub const GICD_CTLR: usize       = 0x000;
pub const GICD_TYPER: usize      = 0x004;
pub const GICD_ISENABLER: usize  = 0x100;
pub const GICD_ICENABLER: usize  = 0x180;
pub const GICD_ISPENDR: usize    = 0x200;
pub const GICD_ICPENDR: usize    = 0x280;
pub const GICD_IPRIORITYR: usize = 0x400;
pub const GICD_ITARGETSR: usize  = 0x800;
pub const GICD_ICFGR: usize      = 0xC00;
pub const GICD_SGIR: usize       = 0xF00;

pub const GICC_CTLR: usize  = 0x000;
pub const GICC_PMR: usize   = 0x004;
pub const GICC_BPR: usize   = 0x008;
pub const GICC_IAR: usize   = 0x00C;
pub const GICC_EOIR: usize  = 0x010;
pub const GICC_HPPIR: usize = 0x018;

/// Generic Interrupt Controller (GICv2) MMIO Manager.
pub struct GicV2 {
    dist_base: usize,
    cpu_base: usize,
}

impl GicV2 {
    pub const fn new(dist_base: usize, cpu_base: usize) -> Self {
        Self { dist_base, cpu_base }
    }

    pub unsafe fn initialize(&self) {
        // Disable Distributor
        self.write_dist(GICD_CTLR, 0);

        // Read number of supported interrupts
        let typer = self.read_dist(GICD_TYPER);
        let max_irqs = (32 * ((typer & 0x1F) + 1)) as usize;

        // Disable and clear all interrupts
        for i in (32..max_irqs).step_by(32) {
            let offset = (i / 32) * 4;
            self.write_dist(GICD_ICENABLER + offset, 0xFFFF_FFFF);
            self.write_dist(GICD_ICPENDR + offset, 0xFFFF_FFFF);
        }

        // Set all priorities to moderate level (0xA0)
        for i in (0..max_irqs).step_by(4) {
            self.write_dist(GICD_IPRIORITYR + i, 0xA0A0_A0A0);
        }

        // Target SPI interrupts to primary CPU core 0
        for i in (32..max_irqs).step_by(4) {
            self.write_dist(GICD_ITARGETSR + i, 0x0101_0101);
        }

        // Enable Distributor
        self.write_dist(GICD_CTLR, 1);

        // Configure CPU Interface: unmask all priorities (PMR = 0xFF) and enable signaling
        self.write_cpu(GICC_PMR, 0xFF);
        self.write_cpu(GICC_CTLR, 1);
    }

    pub unsafe fn enable_irq(&self, irq: u32) {
        let reg = GICD_ISENABLER + ((irq as usize / 32) * 4);
        let bit = 1 << (irq % 32);
        self.write_dist(reg, bit);
    }

    pub unsafe fn acknowledge_irq(&self) -> u32 {
        self.read_cpu(GICC_IAR) & 0x3FF
    }

    pub unsafe fn end_of_interrupt(&self, irq: u32) {
        self.write_cpu(GICC_EOIR, irq & 0x3FF);
    }

    unsafe fn write_dist(&self, offset: usize, val: u32) {
        core::ptr::write_volatile((self.dist_base + offset) as *mut u32, val);
    }

    unsafe fn read_dist(&self, offset: usize) -> u32 {
        core::ptr::read_volatile((self.dist_base + offset) as *const u32)
    }

    unsafe fn write_cpu(&self, offset: usize, val: u32) {
        core::ptr::write_volatile((self.cpu_base + offset) as *mut u32, val);
    }

    unsafe fn read_cpu(&self, offset: usize) -> u32 {
        core::ptr::read_volatile((self.cpu_base + offset) as *const u32)
    }
}

static GIC_ACTIVE: AtomicBool = AtomicBool::new(false);
static GIC_INSTANCE: GicV2 = GicV2::new(0x0800_0000, 0x0801_0000); // Standard QEMU virt GIC addresses

pub struct AArch64Trap;

impl TrapOps for AArch64Trap {
    fn initialize() {
        initialize();
    }

    fn register_handler(_vector: u8, _handler: usize) {
        // Dynamic vector registration hook
    }

    fn is_active() -> bool {
        is_active()
    }
}

pub fn initialize() {
    unsafe {
        GIC_INSTANCE.initialize();
    }
    GIC_ACTIVE.store(true, Ordering::Release);
}

pub fn is_active() -> bool {
    GIC_ACTIVE.load(Ordering::Acquire)
}

pub fn gic() -> &'static GicV2 {
    &GIC_INSTANCE
}
