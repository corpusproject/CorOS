//! AArch64 Symmetric Multiprocessing (SMP) & ARM PSCI Interface.

use crate::arch::traits::SmpOps;
use core::sync::atomic::{AtomicU32, Ordering};

pub const PSCI_0_2_FN_BASE: u32        = 0x8400_0000;
pub const PSCI_0_2_FN64_BASE: u32      = 0xC400_0000;

pub const PSCI_FN_VERSION: u32         = PSCI_0_2_FN_BASE + 0;
pub const PSCI_FN_CPU_SUSPEND: u32     = PSCI_0_2_FN64_BASE + 1;
pub const PSCI_FN_CPU_OFF: u32         = PSCI_0_2_FN_BASE + 2;
pub const PSCI_FN_CPU_ON: u32          = PSCI_0_2_FN64_BASE + 3;
pub const PSCI_FN_AFFINITY_INFO: u32   = PSCI_0_2_FN64_BASE + 4;
pub const PSCI_FN_SYSTEM_OFF: u32      = PSCI_0_2_FN_BASE + 8;
pub const PSCI_FN_SYSTEM_RESET: u32    = PSCI_0_2_FN_BASE + 9;

pub const PSCI_SUCCESS: i32            = 0;
pub const PSCI_NOT_SUPPORTED: i32      = -1;
pub const PSCI_INVALID_PARAMS: i32     = -2;
pub const PSCI_DENIED: i32             = -3;
pub const PSCI_ALREADY_ON: i32         = -4;

static ONLINE_CORES_COUNT: AtomicU32 = AtomicU32::new(1);

pub struct AArch64Smp;

impl SmpOps for AArch64Smp {
    fn boot_secondary_cores(entry: u64) -> u32 {
        boot_secondary_cores(entry)
    }

    fn send_ipi(target_cpu: u32, vector: u8) {
        send_ipi(target_cpu, vector);
    }
}

/// Invokes ARM PSCI via `hvc #0` or `smc #0`.
pub unsafe fn psci_call(fn_id: u32, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    #[cfg(target_arch = "aarch64")]
    {
        let res: i64;
        core::arch::asm!(
            "hvc #0",
            inlateout("x0") fn_id as u64 => res,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            options(nomem)
        );
        res
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (fn_id, arg1, arg2, arg3);
        0
    }
}

pub fn boot_secondary_cores(entry: u64) -> u32 {
    let mut online = 1u32;
    // Attempt PSCI CPU_ON for secondary cores 1..4
    for core_id in 1..4u64 {
        let ret = unsafe { psci_call(PSCI_FN_CPU_ON, core_id, entry, 0) };
        if ret == PSCI_SUCCESS as i64 || ret == PSCI_ALREADY_ON as i64 {
            online += 1;
        }
    }
    ONLINE_CORES_COUNT.store(online, Ordering::Release);
    online
}

pub fn send_ipi(target_cpu: u32, vector: u8) {
    // Uses GIC Distributor SGIR (Software Generated Interrupt Register)
    // Bits 0..3: SGIINTID (vector 0..15)
    // Bits 16..23: TargetList (bitmask of target CPUs)
    // Bits 24..25: TargetFilter (00 = use TargetList)
    let sgi_id = (vector as u32) & 0x0F;
    let target_mask = (1u32 << (target_cpu & 0x07)) << 16;
    let sgir_val = target_mask | sgi_id;

    let gic_dist_base = 0x0800_0000usize;
    let sgir_ptr = (gic_dist_base + super::interrupts::GICD_SGIR) as *mut u32;
    unsafe {
        core::ptr::write_volatile(sgir_ptr, sgir_val);
    }
}
