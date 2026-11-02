//! KVM / CorVirt Paravirtual Hypercall ABI (`VMCALL` on Intel VT-x / `VMMCALL` on AMD-V).
//! Register calling convention:
//! - `RAX`: Hypercall number (`HC_*`)
//! - `RBX`: Argument 0
//! - `RCX`: Argument 1
//! - `RDX`: Argument 2
//! - `RSI`: Argument 3
//! - Return status is written back into Guest `RAX`.

use crate::vcpu_scheduler::VcpuContext;
use crate::virq_chip::VirtualLocalApic;

/// Paravirtual Hypercall opcodes (`HC_*`).
pub mod hypercall_opcodes {
    pub const HC_NOP: u64 = 0;
    pub const HC_VAPIC_POLL_IRQ: u64 = 1;
    pub const HC_FLUSH_TLB_RANGE: u64 = 2;
    pub const HC_SEND_IPI_MASK: u64 = 3;
    pub const HC_SCHED_YIELD: u64 = 4;
    pub const HC_CLOCK_SYNC: u64 = 5;
}

/// Paravirtual Hypercall return status codes (`RAX`).
pub mod hypercall_status {
    pub const HC_STATUS_SUCCESS: i64 = 0;
    pub const HC_STATUS_ENOSYS: i64 = -38;
    pub const HC_STATUS_EINVAL: i64 = -22;
    pub const HC_STATUS_EPERM: i64 = -1;
}

/// Side-effect summary produced by dispatching a guest hypercall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypercallOutcome {
    NoOp,
    PolledVector(Option<u8>),
    FlushedTlbPages {
        base_gva: u64,
        page_count: u64,
        asid: u32,
    },
    DeliveredIpiCount {
        vector: u8,
        recipient_count: u32,
    },
    YieldedToVcpu {
        target_vcpu_id: u32,
    },
    SyncedKvmClock {
        guest_ns: u64,
    },
    Rejected(i64),
}

/// Host paravirtual hypercall dispatcher state (`CorVirtHypercallDispatcher`).
#[derive(Debug, Clone)]
pub struct CorVirtHypercallDispatcher {
    pub host_monotonic_ns: u64,
    pub total_hypercalls_dispatched: u64,
    pub total_tlb_shootdowns_pages: u64,
    pub total_pv_ipis_sent: u64,
    pub total_sched_yields: u64,
}

impl CorVirtHypercallDispatcher {
    pub const fn new(initial_host_ns: u64) -> Self {
        Self {
            host_monotonic_ns: initial_host_ns,
            total_hypercalls_dispatched: 0,
            total_tlb_shootdowns_pages: 0,
            total_pv_ipis_sent: 0,
            total_sched_yields: 0,
        }
    }

    /// Dispatches a `VMCALL` / `VMMCALL` instruction executed at `cpl` (`0..=3`),
    /// updates `vcpu.gprs.rax` with the hypercall return value, advances `vcpu.gprs.rip`
    /// by `instruction_length`, and returns a structured `HypercallOutcome`.
    pub fn dispatch_hypercall(
        &mut self,
        vcpu: &mut VcpuContext,
        cpl: u8,
        instruction_length: u64,
        lapics: &mut [VirtualLocalApic],
    ) -> HypercallOutcome {
        self.total_hypercalls_dispatched += 1;
        vcpu.total_vm_exits += 1;
        vcpu.gprs.rip = vcpu.gprs.rip.wrapping_add(instruction_length);

        // Only Ring 0 (CPL == 0) guest kernel code is permitted to invoke hypercalls.
        if cpl != 0 {
            vcpu.gprs.rax = hypercall_status::HC_STATUS_EPERM as u64;
            return HypercallOutcome::Rejected(hypercall_status::HC_STATUS_EPERM);
        }

        let opcode = vcpu.gprs.rax;
        let arg0 = vcpu.gprs.rbx;
        let arg1 = vcpu.gprs.rcx;
        let arg2 = vcpu.gprs.rdx;

        match opcode {
            hypercall_opcodes::HC_NOP => {
                vcpu.gprs.rax = hypercall_status::HC_STATUS_SUCCESS as u64;
                HypercallOutcome::NoOp
            }
            hypercall_opcodes::HC_VAPIC_POLL_IRQ => {
                let apic_idx = vcpu.apic_id as usize;
                let claimed = if let Some(lapic) = lapics.get_mut(apic_idx) {
                    lapic.claim_deliverable_vector()
                } else {
                    None
                };
                vcpu.gprs.rax = claimed.map(|v| v as u64).unwrap_or(0);
                HypercallOutcome::PolledVector(claimed)
            }
            hypercall_opcodes::HC_FLUSH_TLB_RANGE => {
                // arg0 = page-aligned base GVA, arg1 = page count (1..=65536), arg2 = ASID/VPID
                if (arg0 & 0xFFF) != 0 || arg1 == 0 || arg1 > 65_536 {
                    vcpu.gprs.rax = hypercall_status::HC_STATUS_EINVAL as u64;
                    return HypercallOutcome::Rejected(hypercall_status::HC_STATUS_EINVAL);
                }
                self.total_tlb_shootdowns_pages =
                    self.total_tlb_shootdowns_pages.saturating_add(arg1);
                vcpu.gprs.rax = arg1;
                HypercallOutcome::FlushedTlbPages {
                    base_gva: arg0,
                    page_count: arg1,
                    asid: arg2 as u32,
                }
            }
            hypercall_opcodes::HC_SEND_IPI_MASK => {
                // arg0 = 64-bit destination vCPU bitmask, arg1 = interrupt vector (16..=255), arg2 = level_triggered
                let dest_mask = arg0;
                let vector = (arg1 & 0xFF) as u8;
                let level_trig = (arg2 & 1) != 0;
                if vector < 16 || dest_mask == 0 {
                    vcpu.gprs.rax = hypercall_status::HC_STATUS_EINVAL as u64;
                    return HypercallOutcome::Rejected(hypercall_status::HC_STATUS_EINVAL);
                }

                let mut delivered = 0u32;
                for (idx, lapic) in lapics.iter_mut().enumerate() {
                    if idx < 64 && ((dest_mask >> idx) & 1) != 0 {
                        lapic.accept_interrupt(vector, level_trig);
                        delivered += 1;
                    }
                }
                self.total_pv_ipis_sent = self.total_pv_ipis_sent.saturating_add(delivered as u64);
                vcpu.gprs.rax = delivered as u64;
                HypercallOutcome::DeliveredIpiCount {
                    vector,
                    recipient_count: delivered,
                }
            }
            hypercall_opcodes::HC_SCHED_YIELD => {
                // arg0 = target vCPU ID to boost/yield to
                let target_vcpu_id = arg0 as u32;
                self.total_sched_yields += 1;
                vcpu.gprs.rax = hypercall_status::HC_STATUS_SUCCESS as u64;
                HypercallOutcome::YieldedToVcpu { target_vcpu_id }
            }
            hypercall_opcodes::HC_CLOCK_SYNC => {
                // arg0 = guest TSC offset adjustment in nanoseconds
                let guest_ns = self.host_monotonic_ns.wrapping_add(arg0);
                vcpu.sregs.tsc_offset = arg0;
                vcpu.gprs.rax = guest_ns;
                HypercallOutcome::SyncedKvmClock { guest_ns }
            }
            _ => {
                vcpu.gprs.rax = hypercall_status::HC_STATUS_ENOSYS as u64;
                HypercallOutcome::Rejected(hypercall_status::HC_STATUS_ENOSYS)
            }
        }
    }
}
