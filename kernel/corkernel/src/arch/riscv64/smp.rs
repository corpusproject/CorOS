//! RISC-V Symmetric Multiprocessing (SMP) & SBI Hart State Management (HSM).

use crate::arch::traits::SmpOps;
use core::sync::atomic::{AtomicU32, Ordering};

pub const SBI_EID_HSM: usize = 0x48534D; // "HSM"
pub const SBI_EID_SPI: usize = 0x735049; // "sPI"

pub const SBI_HSM_HART_START: usize      = 0;
pub const SBI_HSM_HART_STOP: usize       = 1;
pub const SBI_HSM_HART_GET_STATUS: usize = 2;

pub const SBI_HSM_STATUS_STARTED: usize = 0;
pub const SBI_HSM_STATUS_STOPPED: usize = 1;

static ONLINE_HARTS_COUNT: AtomicU32 = AtomicU32::new(1);

pub struct Riscv64Smp;

impl SmpOps for Riscv64Smp {
    fn boot_secondary_cores(entry: u64) -> u32 {
        boot_secondary_cores(entry)
    }

    fn send_ipi(target_cpu: u32, vector: u8) {
        send_ipi(target_cpu, vector);
    }
}

pub fn boot_secondary_cores(entry: u64) -> u32 {
    let mut online = 1u32;
    for hart_id in 1..4usize {
        let err: isize;
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") SBI_EID_HSM,
                in("a6") SBI_HSM_HART_START,
                in("a0") hart_id,
                in("a1") entry as usize,
                in("a2") 0usize, // opaque parameter
                lateout("a0") err,
                options(nomem)
            );
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = (hart_id, entry);
            err = 0;
        }

        if err == 0 {
            online += 1;
        }
    }
    ONLINE_HARTS_COUNT.store(online, Ordering::Release);
    online
}

pub fn send_ipi(target_cpu: u32, vector: u8) {
    let hart_mask = 1usize << (target_cpu as usize);
    let _ = vector;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EID_SPI,
            in("a6") 0usize, // FID 0 (sbi_send_ipi)
            in("a0") hart_mask,
            in("a1") 0usize, // hart_mask_base
            options(nomem)
        );
    }
}
